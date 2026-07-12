use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use anyhow::Context;

const HEADER_BYTES: u64 = 8;
const SEGMENT_MAX_BYTES: u64 = 4 * 1024 * 1024;

/// One unacknowledged record returned from the WAL head.
pub struct WalEntry {
    pub segment: u64,
    pub offset: u64,
    pub payload: Vec<u8>,
}

#[derive(Clone, Copy)]
struct RecordMeta {
    segment: u64,
    offset: u64,
    payload_len: u32,
}

#[derive(Clone, Copy)]
struct Cursor {
    segment: u64,
    offset: u64,
}

/// Append-only disk queue used to preserve telemetry during export failures.
pub struct Wal {
    dir: PathBuf,
    max_bytes: u64,
    active_segment: u64,
    active_file: File,
    cursor: Cursor,
    records: VecDeque<RecordMeta>,
}

impl Wal {
    /// Opens an existing WAL or creates an empty one at `dir`.
    pub fn open(dir: &Path, max_bytes: u64) -> anyhow::Result<Self> {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("creating WAL directory {}", dir.display()))?;
        let mut segments = segment_sequences(dir)?;
        if segments.is_empty() {
            segments.push(0);
        }
        let active_segment = segments.last().copied().unwrap_or(0);
        let active_file = open_segment(dir, active_segment)?;
        let cursor = read_cursor(dir)?.unwrap_or(Cursor {
            segment: segments.first().copied().unwrap_or(active_segment),
            offset: 0,
        });
        let mut records = VecDeque::new();
        for segment in segments {
            scan_segment(dir, segment, cursor, &mut records)?;
        }

        let mut wal = Self {
            dir: dir.to_path_buf(),
            max_bytes,
            active_segment,
            active_file,
            cursor,
            records,
        };
        wal.enforce_cap()?;
        Ok(wal)
    }

    /// Appends and durably flushes one encoded OTLP request.
    pub fn append(&mut self, payload: &[u8]) -> anyhow::Result<()> {
        let payload_len = u32::try_from(payload.len()).context("WAL payload exceeds u32 length")?;
        let record_len = HEADER_BYTES + u64::from(payload_len);
        let active_len = self
            .active_file
            .metadata()
            .context("reading WAL active segment metadata")?
            .len();
        if active_len > 0 && active_len + record_len > SEGMENT_MAX_BYTES {
            self.active_segment = self
                .active_segment
                .checked_add(1)
                .context("WAL segment sequence exhausted")?;
            self.active_file = open_segment(&self.dir, self.active_segment)?;
        }
        let offset = self
            .active_file
            .seek(SeekFrom::End(0))
            .context("seeking WAL active segment")?;
        self.active_file
            .write_all(&payload_len.to_le_bytes())
            .context("writing WAL record length")?;
        self.active_file
            .write_all(&crc32(payload).to_le_bytes())
            .context("writing WAL record checksum")?;
        self.active_file
            .write_all(payload)
            .context("writing WAL record payload")?;
        self.active_file
            .sync_data()
            .context("syncing WAL active segment")?;
        self.records.push_back(RecordMeta {
            segment: self.active_segment,
            offset,
            payload_len,
        });
        self.enforce_cap()?;
        Ok(())
    }

    /// Returns the oldest unacknowledged record.
    #[expect(
        clippy::should_implement_trait,
        reason = "Wal::next is the locked fallible public API and cannot implement Iterator"
    )]
    pub fn next(&mut self) -> anyhow::Result<Option<WalEntry>> {
        loop {
            let Some(record) = self.records.front().copied() else {
                return Ok(None);
            };
            let path = segment_path(&self.dir, record.segment);
            let mut file = File::open(&path)
                .with_context(|| format!("opening WAL segment {}", path.display()))?;
            file.seek(SeekFrom::Start(record.offset))
                .with_context(|| format!("seeking WAL segment {}", path.display()))?;
            let mut header = [0_u8; HEADER_BYTES as usize];
            file.read_exact(&mut header)
                .with_context(|| format!("reading WAL segment header {}", path.display()))?;
            let expected_crc = u32::from_le_bytes(
                header[4..]
                    .try_into()
                    .context("WAL checksum header has invalid length")?,
            );
            let mut payload = vec![0; record.payload_len as usize];
            file.read_exact(&mut payload)
                .with_context(|| format!("reading WAL segment {}", path.display()))?;
            if crc32(&payload) != expected_crc {
                tracing::warn!(
                    segment = record.segment,
                    offset = record.offset,
                    "skipping WAL record with invalid CRC"
                );
                self.records.pop_front();
                continue;
            }
            return Ok(Some(WalEntry {
                segment: record.segment,
                offset: record.offset,
                payload,
            }));
        }
    }

    /// Acknowledges the current head entry.
    pub fn ack(&mut self, entry: &WalEntry) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.records.front().is_some_and(
                |record| record.segment == entry.segment && record.offset == entry.offset
            ),
            "WAL entry is not the current head"
        );
        self.records.pop_front();
        self.cursor = if let Some(next) = self.records.front() {
            Cursor {
                segment: next.segment,
                offset: next.offset,
            }
        } else {
            Cursor {
                segment: self.active_segment,
                offset: self
                    .active_file
                    .seek(SeekFrom::End(0))
                    .context("seeking WAL active segment")?,
            }
        };
        persist_cursor(&self.dir, self.cursor)?;
        self.delete_fully_acked_segments()?;
        Ok(())
    }

    /// Returns the number of unacknowledged records.
    pub fn pending(&self) -> u64 {
        self.records.len() as u64
    }

    fn delete_fully_acked_segments(&self) -> anyhow::Result<()> {
        for segment in segment_sequences(&self.dir)? {
            if segment < self.cursor.segment && segment != self.active_segment {
                let path = segment_path(&self.dir, segment);
                std::fs::remove_file(&path).with_context(|| {
                    format!("deleting acknowledged WAL segment {}", path.display())
                })?;
            }
        }
        Ok(())
    }

    fn enforce_cap(&mut self) -> anyhow::Result<()> {
        let mut segments = segment_sequences(&self.dir)?;
        while total_segment_bytes(&self.dir, &segments)? > self.max_bytes {
            let Some(oldest) = segments.first().copied() else {
                break;
            };
            if oldest == self.active_segment {
                self.active_segment = self
                    .active_segment
                    .checked_add(1)
                    .context("WAL segment sequence exhausted")?;
                self.active_file = open_segment(&self.dir, self.active_segment)?;
                segments.push(self.active_segment);
            }
            tracing::warn!(segment = oldest, "evicting oldest WAL segment at capacity");
            let path = segment_path(&self.dir, oldest);
            std::fs::remove_file(&path)
                .with_context(|| format!("evicting WAL segment {}", path.display()))?;
            self.records.retain(|record| record.segment != oldest);
            segments.remove(0);
            self.cursor = if let Some(next) = self.records.front() {
                Cursor {
                    segment: next.segment,
                    offset: next.offset,
                }
            } else {
                Cursor {
                    segment: self.active_segment,
                    offset: self
                        .active_file
                        .seek(SeekFrom::End(0))
                        .context("seeking WAL active segment")?,
                }
            };
            persist_cursor(&self.dir, self.cursor)?;
        }
        Ok(())
    }
}

fn total_segment_bytes(dir: &Path, segments: &[u64]) -> anyhow::Result<u64> {
    segments.iter().try_fold(0_u64, |total, segment| {
        let path = segment_path(dir, *segment);
        let len = std::fs::metadata(&path)
            .with_context(|| format!("reading WAL segment metadata {}", path.display()))?
            .len();
        total.checked_add(len).context("WAL byte total overflow")
    })
}

fn segment_sequences(dir: &Path) -> anyhow::Result<Vec<u64>> {
    let mut sequences = Vec::new();
    for entry in std::fs::read_dir(dir)
        .with_context(|| format!("reading WAL directory {}", dir.display()))?
    {
        let entry = entry.with_context(|| format!("reading WAL directory {}", dir.display()))?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let Some(sequence) = name
            .strip_prefix("wal-")
            .and_then(|value| value.strip_suffix(".log"))
            .and_then(|value| value.parse::<u64>().ok())
        else {
            continue;
        };
        sequences.push(sequence);
    }
    sequences.sort_unstable();
    Ok(sequences)
}

/// Rebuilds the pending-record index for one segment and repairs its tail.
///
/// A crash mid-append can leave a torn record (header and/or partial payload)
/// at the end of the file. The torn bytes must be truncated away here: later
/// appends land at physical EOF, and once a valid record follows the torn one
/// the next scan would misread the torn header as a real record and consume
/// the valid record's bytes as its payload, silently losing it.
fn scan_segment(
    dir: &Path,
    segment: u64,
    cursor: Cursor,
    records: &mut VecDeque<RecordMeta>,
) -> anyhow::Result<()> {
    let path = segment_path(dir, segment);
    // why: write (not append) access — truncating the torn tail below needs
    // set_len, which Windows denies on append-only handles.
    let mut file = OpenOptions::new()
        .read(true)
        .create(true)
        .write(true)
        .truncate(false)
        .open(&path)
        .with_context(|| format!("opening WAL segment {}", path.display()))?;
    let file_len = file
        .metadata()
        .with_context(|| format!("reading WAL segment metadata {}", path.display()))?
        .len();
    let mut offset = 0;
    while offset + HEADER_BYTES <= file_len {
        file.seek(SeekFrom::Start(offset))
            .with_context(|| format!("seeking WAL segment {}", path.display()))?;
        let mut header = [0_u8; HEADER_BYTES as usize];
        file.read_exact(&mut header)
            .with_context(|| format!("reading WAL segment header {}", path.display()))?;
        let payload_len = u32::from_le_bytes(header[..4].try_into().context("WAL length header")?);
        let record_len = HEADER_BYTES + u64::from(payload_len);
        if offset + record_len > file_len {
            break;
        }
        if segment > cursor.segment || (segment == cursor.segment && offset >= cursor.offset) {
            records.push_back(RecordMeta {
                segment,
                offset,
                payload_len,
            });
        }
        offset += record_len;
    }
    if offset < file_len {
        tracing::warn!(
            segment,
            valid_end = offset,
            file_len,
            "truncating torn record at WAL segment tail"
        );
        file.set_len(offset)
            .with_context(|| format!("truncating torn WAL segment tail {}", path.display()))?;
        file.sync_all()
            .with_context(|| format!("syncing truncated WAL segment {}", path.display()))?;
    }
    Ok(())
}

fn read_cursor(dir: &Path) -> anyhow::Result<Option<Cursor>> {
    let path = dir.join("cursor");
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("reading WAL cursor {}", path.display()));
        }
    };
    anyhow::ensure!(bytes.len() == 16, "WAL cursor must be exactly 16 bytes");
    let segment = u64::from_le_bytes(bytes[..8].try_into().context("WAL cursor segment")?);
    let offset = u64::from_le_bytes(bytes[8..].try_into().context("WAL cursor offset")?);
    Ok(Some(Cursor { segment, offset }))
}

fn persist_cursor(dir: &Path, cursor: Cursor) -> anyhow::Result<()> {
    let path = dir.join("cursor");
    let temp_path = dir.join("cursor.tmp");
    let mut file = File::create(&temp_path)
        .with_context(|| format!("creating WAL cursor temp file {}", temp_path.display()))?;
    file.write_all(&cursor.segment.to_le_bytes())
        .context("writing WAL cursor segment")?;
    file.write_all(&cursor.offset.to_le_bytes())
        .context("writing WAL cursor offset")?;
    file.sync_all().context("syncing WAL cursor temp file")?;
    drop(file);
    std::fs::rename(&temp_path, &path).with_context(|| {
        format!(
            "atomically replacing WAL cursor {} with {}",
            path.display(),
            temp_path.display()
        )
    })
}

fn open_segment(dir: &Path, segment: u64) -> anyhow::Result<File> {
    let path = segment_path(dir, segment);
    OpenOptions::new()
        .read(true)
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("opening WAL segment {}", path.display()))
}

fn segment_path(dir: &Path, sequence: u64) -> PathBuf {
    dir.join(format!("wal-{sequence}.log"))
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & (0_u32.wrapping_sub(crc & 1)));
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use std::io::{Seek, SeekFrom, Write};

    use super::*;

    #[test]
    fn wal_round_trip_should_persist_pending_entries_across_reopen() {
        let temp = tempfile::tempdir().expect("temp dir");
        let mut wal = Wal::open(temp.path(), 64 * 1024 * 1024).expect("open WAL");
        wal.append(b"first").expect("append first");
        wal.append(b"second").expect("append second");
        drop(wal);

        let mut reopened = Wal::open(temp.path(), 64 * 1024 * 1024).expect("reopen WAL");
        let first = reopened.next().expect("read WAL").expect("first entry");

        assert_eq!(reopened.pending(), 2);
        assert_eq!(first.payload, b"first");
    }

    #[test]
    fn ack_cursor_should_be_durable_across_reopen() {
        let temp = tempfile::tempdir().expect("temp dir");
        let mut wal = Wal::open(temp.path(), 64 * 1024 * 1024).expect("open WAL");
        wal.append(b"acked").expect("append acked");
        wal.append(b"pending").expect("append pending");
        let entry = wal.next().expect("read WAL").expect("acked entry");
        wal.ack(&entry).expect("ack entry");
        drop(wal);

        let mut reopened = Wal::open(temp.path(), 64 * 1024 * 1024).expect("reopen WAL");
        let pending = reopened
            .next()
            .expect("read reopened WAL")
            .expect("pending entry");

        assert_eq!(reopened.pending(), 1);
        assert_eq!(pending.payload, b"pending");
    }

    #[test]
    fn cap_eviction_should_drop_oldest_segment_and_keep_pending_count_correct() {
        let temp = tempfile::tempdir().expect("temp dir");
        let mut wal = Wal::open(temp.path(), 5 * 1024 * 1024).expect("open WAL");
        let oldest = vec![1_u8; 3 * 1024 * 1024];
        let newest = vec![2_u8; 3 * 1024 * 1024];
        wal.append(&oldest).expect("append oldest segment");
        wal.append(&newest).expect("append newest segment");

        let entry = wal.next().expect("read WAL").expect("newest entry");

        assert_eq!(wal.pending(), 1);
        assert_eq!(entry.payload, newest);
    }

    #[test]
    fn torn_tail_should_be_truncated_on_open_so_later_appends_stay_parseable() {
        let temp = tempfile::tempdir().expect("temp dir");
        let mut wal = Wal::open(temp.path(), 64 * 1024 * 1024).expect("open WAL");
        wal.append(b"first").expect("append first");
        drop(wal);

        // Simulate a crash mid-append: a full header claiming a 100-byte
        // payload, followed by only 10 payload bytes.
        let segment_path = temp.path().join("wal-0.log");
        let mut segment = OpenOptions::new()
            .append(true)
            .open(&segment_path)
            .expect("open segment for torn write");
        segment
            .write_all(&100_u32.to_le_bytes())
            .expect("write torn length");
        segment
            .write_all(&0xdead_beef_u32.to_le_bytes())
            .expect("write torn checksum");
        segment
            .write_all(&[9_u8; 10])
            .expect("write torn partial payload");
        segment.sync_data().expect("sync torn record");
        drop(segment);

        // First restart must repair the tail before appending after it.
        let mut restarted = Wal::open(temp.path(), 64 * 1024 * 1024).expect("reopen after crash");
        let survivor = vec![7_u8; 120];
        restarted.append(&survivor).expect("append after torn tail");
        drop(restarted);

        // Second restart must still see both durable records.
        let mut reopened = Wal::open(temp.path(), 64 * 1024 * 1024).expect("second reopen");
        let mut payloads = Vec::new();
        while let Some(entry) = reopened.next().expect("drain reopened WAL") {
            payloads.push(entry.payload.clone());
            reopened.ack(&entry).expect("ack drained entry");
        }

        assert_eq!(payloads, vec![b"first".to_vec(), survivor]);
    }

    #[test]
    fn crc_corrupt_record_should_be_skipped_without_failing_next() {
        let temp = tempfile::tempdir().expect("temp dir");
        let mut wal = Wal::open(temp.path(), 64 * 1024 * 1024).expect("open WAL");
        wal.append(b"corrupt-me").expect("append corrupt candidate");
        wal.append(b"survivor").expect("append survivor");
        drop(wal);

        let segment_path = temp.path().join("wal-0.log");
        let mut segment = OpenOptions::new()
            .write(true)
            .open(segment_path)
            .expect("open segment for corruption");
        segment
            .seek(SeekFrom::Start(HEADER_BYTES))
            .expect("seek payload");
        segment.write_all(b"X").expect("corrupt payload byte");
        segment.sync_data().expect("sync corruption");

        let mut reopened = Wal::open(temp.path(), 64 * 1024 * 1024).expect("reopen WAL");
        let entry = reopened
            .next()
            .expect("corrupt record should not fail")
            .expect("surviving entry");

        assert_eq!(reopened.pending(), 1);
        assert_eq!(entry.payload, b"survivor");
    }
}
