use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context;
use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
use opentelemetry_proto::tonic::common::v1::{AnyValue, InstrumentationScope, KeyValue, any_value};
use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};
use opentelemetry_proto::tonic::resource::v1::Resource;

/// One normalized log record ready for OTLP conversion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogRecordSample {
    pub ts_ms: i64,
    pub severity: i32,
    pub body: String,
    pub attrs: Vec<(String, String)>,
}

/// Checkpointed reader for one explicitly configured log file.
pub struct FileTailer {
    path: PathBuf,
    checkpoint_path: PathBuf,
    offset: u64,
    signature: u128,
    pending_offset: u64,
    pending_signature: u128,
}

impl FileTailer {
    /// Upper bound on bytes consumed from the file per poll. Bounds tailer
    /// memory and keeps one exported batch comfortably below common OTLP/gRPC
    /// message-size limits (tonic decodes at most 4 MiB by default).
    pub const MAX_POLL_BYTES: u64 = 512 * 1024;
    /// Upper bound on records returned per poll so floods of tiny lines
    /// cannot blow up the per-record OTLP encoding overhead.
    pub const MAX_POLL_RECORDS: usize = 4096;

    /// Opens a file tailer and its path-specific checkpoint.
    ///
    /// A file seen for the first time (no checkpoint on disk) is tailed from
    /// its current end, mirroring the journald follower's `--since now`.
    pub fn new(path: PathBuf, checkpoint_dir: &Path) -> anyhow::Result<Self> {
        let metadata = std::fs::metadata(&path)
            .with_context(|| format!("reading log file metadata {}", path.display()))?;
        std::fs::create_dir_all(checkpoint_dir).with_context(|| {
            format!(
                "creating log checkpoint directory {}",
                checkpoint_dir.display()
            )
        })?;
        let checkpoint_path = checkpoint_path(checkpoint_dir, &path);
        let signature = file_signature(&metadata);
        let offset = match read_checkpoint(&checkpoint_path)? {
            Some(checkpoint)
                if checkpoint.signature == signature && checkpoint.offset <= metadata.len() =>
            {
                checkpoint.offset
            }
            // The checkpointed file was rotated or truncated since the last
            // run: read its replacement from the top so nothing is skipped.
            Some(_) => 0,
            // why: shipping a large pre-existing backlog on first acquaintance
            // would flood the collector and could exceed request-size limits;
            // history before the agent existed is not this agent's job.
            None => metadata.len(),
        };
        Ok(Self {
            checkpoint_path,
            path,
            offset,
            signature,
            pending_offset: offset,
            pending_signature: signature,
        })
    }

    /// Returns complete lines added since the last poll, bounded per call by
    /// [`Self::MAX_POLL_BYTES`] and [`Self::MAX_POLL_RECORDS`]; a backlog is
    /// drained across successive polls.
    pub fn poll(&mut self) -> anyhow::Result<Vec<LogRecordSample>> {
        let metadata = std::fs::metadata(&self.path)
            .with_context(|| format!("reading log file metadata {}", self.path.display()))?;
        let signature = file_signature(&metadata);
        let start_offset = if signature != self.signature || metadata.len() < self.offset {
            0
        } else {
            self.offset
        };
        let mut file = File::open(&self.path)
            .with_context(|| format!("opening log file {}", self.path.display()))?;
        file.seek(SeekFrom::Start(start_offset))
            .with_context(|| format!("seeking log file {}", self.path.display()))?;
        let mut bytes = Vec::new();
        file.take(Self::MAX_POLL_BYTES)
            .read_to_end(&mut bytes)
            .with_context(|| format!("reading log file {}", self.path.display()))?;
        let window_full = bytes.len() as u64 == Self::MAX_POLL_BYTES;
        let ts_ms = unix_millis_now()?;
        let source = self.path.to_string_lossy();
        let mut records = Vec::new();
        let mut consumed = 0_usize;
        for line in bytes.split_inclusive(|byte| *byte == b'\n') {
            if records.len() == Self::MAX_POLL_RECORDS {
                break;
            }
            let complete = line.last() == Some(&b'\n');
            // why: a single line longer than the whole poll window would
            // stall the tailer forever; ship the window as one split record.
            let split_oversized_line = window_full && consumed == 0;
            if !complete && !split_oversized_line {
                // Incomplete tail line: wait for its newline on a later poll.
                break;
            }
            let body = if complete {
                &line[..line.len() - 1]
            } else {
                line
            };
            let body = body.strip_suffix(b"\r").unwrap_or(body);
            records.push(LogRecordSample {
                ts_ms,
                severity: 0,
                body: String::from_utf8_lossy(body).into_owned(),
                attrs: vec![("log.source".to_owned(), source.to_string())],
            });
            consumed += line.len();
        }
        self.pending_offset = start_offset
            .checked_add(u64::try_from(consumed).context("consumed log bytes exceed u64")?)
            .context("log checkpoint offset overflow")?;
        self.pending_signature = signature;
        Ok(records)
    }

    /// Persists the last complete-line offset after durable delivery.
    pub fn persist_checkpoint(&mut self) -> anyhow::Result<()> {
        let temp_path = self.checkpoint_path.with_extension("checkpoint.tmp");
        let mut file = File::create(&temp_path).with_context(|| {
            format!("creating log checkpoint temp file {}", temp_path.display())
        })?;
        file.write_all(&self.pending_offset.to_le_bytes())
            .context("writing log checkpoint offset")?;
        file.write_all(&self.pending_signature.to_le_bytes())
            .context("writing log checkpoint signature")?;
        file.sync_all().context("syncing log checkpoint")?;
        drop(file);
        replace_checkpoint(&temp_path, &self.checkpoint_path).with_context(|| {
            format!(
                "atomically replacing log checkpoint {}",
                self.checkpoint_path.display()
            )
        })?;
        self.offset = self.pending_offset;
        self.signature = self.pending_signature;
        Ok(())
    }
}

#[cfg(not(windows))]
fn replace_checkpoint(temp_path: &Path, checkpoint_path: &Path) -> std::io::Result<()> {
    std::fs::rename(temp_path, checkpoint_path)
}

#[cfg(windows)]
fn replace_checkpoint(temp_path: &Path, checkpoint_path: &Path) -> std::io::Result<()> {
    match std::fs::rename(temp_path, checkpoint_path) {
        Ok(()) => Ok(()),
        Err(_error) if checkpoint_path.exists() => {
            std::fs::remove_file(checkpoint_path)?;
            std::fs::rename(temp_path, checkpoint_path)
        }
        Err(error) => Err(error),
    }
}

#[derive(Clone, Copy)]
struct Checkpoint {
    offset: u64,
    signature: u128,
}

fn read_checkpoint(path: &Path) -> anyhow::Result<Option<Checkpoint>> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("reading log checkpoint {}", path.display()));
        }
    };
    anyhow::ensure!(bytes.len() == 24, "log checkpoint must be exactly 24 bytes");
    let offset = u64::from_le_bytes(bytes[..8].try_into().context("log checkpoint offset")?);
    let signature = u128::from_le_bytes(bytes[8..].try_into().context("log checkpoint signature")?);
    Ok(Some(Checkpoint { offset, signature }))
}

#[cfg(unix)]
fn file_signature(metadata: &std::fs::Metadata) -> u128 {
    use std::os::unix::fs::MetadataExt;

    (u128::from(metadata.dev()) << 64) | u128::from(metadata.ino())
}

#[cfg(windows)]
fn file_signature(metadata: &std::fs::Metadata) -> u128 {
    use std::os::windows::fs::MetadataExt;

    u128::from(metadata.creation_time())
}

fn checkpoint_path(checkpoint_dir: &Path, path: &Path) -> PathBuf {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in path.as_os_str().to_string_lossy().as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    checkpoint_dir.join(format!("file-{hash:016x}.checkpoint"))
}

fn unix_millis_now() -> anyhow::Result<i64> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the UNIX epoch")?;
    i64::try_from(elapsed.as_millis()).context("system clock exceeds i64 millisecond range")
}

/// Parses one `journalctl --output=json` record.
pub fn parse_journald_line(json_line: &str) -> Option<LogRecordSample> {
    let value: serde_json::Value = serde_json::from_str(json_line).ok()?;
    let timestamp_us = json_i64(value.get("__REALTIME_TIMESTAMP")?)?;
    let body = value.get("MESSAGE")?.as_str()?.to_owned();
    let severity = value
        .get("PRIORITY")
        .and_then(json_i64)
        .map_or(0, journald_priority_to_severity);
    let mut attrs = Vec::with_capacity(2);
    if let Some(unit) = value
        .get("_SYSTEMD_UNIT")
        .and_then(serde_json::Value::as_str)
    {
        attrs.push(("_SYSTEMD_UNIT".to_owned(), unit.to_owned()));
    }
    attrs.push(("log.source".to_owned(), "journald".to_owned()));
    Some(LogRecordSample {
        ts_ms: timestamp_us / 1_000,
        severity,
        body,
        attrs,
    })
}

fn json_i64(value: &serde_json::Value) -> Option<i64> {
    value
        .as_i64()
        .or_else(|| value.as_str()?.parse::<i64>().ok())
}

fn journald_priority_to_severity(priority: i64) -> i32 {
    match priority {
        0..=2 => 21,
        3 => 17,
        4 => 13,
        5 | 6 => 9,
        7 => 5,
        _ => 0,
    }
}

fn string_attr(key: &str, value: &str) -> KeyValue {
    KeyValue {
        key: key.to_owned(),
        value: Some(AnyValue {
            value: Some(any_value::Value::StringValue(value.to_owned())),
        }),
        ..Default::default()
    }
}

/// Builds one resource-scoped OTLP logs request from normalized records.
pub fn build_logs_export_request(
    node_id: &str,
    host_name: &str,
    records: &[LogRecordSample],
) -> ExportLogsServiceRequest {
    let log_records = records
        .iter()
        .map(|record| LogRecord {
            time_unix_nano: u64::try_from(record.ts_ms.max(0)).unwrap_or(0) * 1_000_000,
            severity_number: record.severity,
            body: Some(AnyValue {
                value: Some(any_value::Value::StringValue(record.body.clone())),
            }),
            attributes: record
                .attrs
                .iter()
                .map(|(key, value)| string_attr(key, value))
                .collect(),
            ..Default::default()
        })
        .collect();

    ExportLogsServiceRequest {
        resource_logs: vec![ResourceLogs {
            resource: Some(Resource {
                attributes: vec![
                    string_attr("crossx.node.id", node_id),
                    string_attr("host.name", host_name),
                ],
                ..Default::default()
            }),
            scope_logs: vec![ScopeLogs {
                scope: Some(InstrumentationScope {
                    name: "crossx-agent".to_owned(),
                    ..Default::default()
                }),
                log_records,
                ..Default::default()
            }],
            ..Default::default()
        }],
    }
}

#[cfg(test)]
mod tests {
    use std::fs::OpenOptions;
    use std::io::Write;

    use super::*;

    #[test]
    fn file_tailer_should_start_at_end_of_preexisting_file_when_no_checkpoint_exists() {
        let temp = tempfile::tempdir().expect("temp dir");
        let path = temp.path().join("app.log");
        std::fs::write(&path, b"historical line\n").expect("seed pre-existing log");
        let mut tailer = FileTailer::new(path.clone(), temp.path()).expect("create tailer");
        let mut file = OpenOptions::new()
            .append(true)
            .open(path)
            .expect("open log for append");
        file.write_all(b"fresh line\n").expect("append fresh line");

        let bodies = tailer
            .poll()
            .expect("poll after append")
            .into_iter()
            .map(|record| record.body)
            .collect::<Vec<_>>();

        assert_eq!(bodies, vec!["fresh line".to_owned()]);
    }

    #[test]
    fn poll_should_split_large_backlog_into_bounded_batches() {
        let temp = tempfile::tempdir().expect("temp dir");
        let path = temp.path().join("app.log");
        std::fs::write(&path, b"").expect("seed empty log");
        let mut tailer = FileTailer::new(path.clone(), temp.path()).expect("create tailer");
        // Enough 100-byte lines to exceed both the byte and the record bound.
        let total_lines = 10_000_usize;
        let line = format!("{}\n", "x".repeat(99));
        std::fs::write(&path, line.repeat(total_lines)).expect("write backlog");

        let mut batch_sizes = Vec::new();
        loop {
            let records = tailer.poll().expect("poll bounded batch");
            if records.is_empty() {
                break;
            }
            let batch_bytes = records
                .iter()
                .map(|record| record.body.len() as u64 + 1)
                .sum::<u64>();
            assert!(records.len() <= FileTailer::MAX_POLL_RECORDS);
            assert!(batch_bytes <= FileTailer::MAX_POLL_BYTES);
            batch_sizes.push(records.len());
            tailer
                .persist_checkpoint()
                .expect("persist batch checkpoint");
        }

        assert!(batch_sizes.len() >= 2, "backlog should take several polls");
        assert_eq!(batch_sizes.iter().sum::<usize>(), total_lines);
    }

    #[test]
    fn poll_should_ship_line_longer_than_window_as_split_record() {
        let temp = tempfile::tempdir().expect("temp dir");
        let path = temp.path().join("app.log");
        std::fs::write(&path, b"").expect("seed empty log");
        let mut tailer = FileTailer::new(path.clone(), temp.path()).expect("create tailer");
        let window = usize::try_from(FileTailer::MAX_POLL_BYTES).expect("window fits usize");
        let mut content = "a".repeat(window + 100);
        content.push('\n');
        content.push_str("tail\n");
        std::fs::write(&path, content).expect("write oversized line");

        let first = tailer.poll().expect("poll window-filling split");
        tailer
            .persist_checkpoint()
            .expect("persist split checkpoint");
        let second = tailer.poll().expect("poll line remainder");

        assert_eq!(
            first
                .iter()
                .map(|record| record.body.len())
                .collect::<Vec<_>>(),
            vec![window]
        );
        assert_eq!(
            second
                .into_iter()
                .map(|record| record.body)
                .collect::<Vec<_>>(),
            vec!["a".repeat(100), "tail".to_owned()]
        );
    }

    #[test]
    fn file_tailer_should_hold_partial_line_until_newline_arrives() {
        let temp = tempfile::tempdir().expect("temp dir");
        let path = temp.path().join("app.log");
        std::fs::write(&path, b"").expect("seed empty log");
        let mut tailer = FileTailer::new(path.clone(), temp.path()).expect("create tailer");
        std::fs::write(&path, b"complete\npartial").expect("write partial log");

        let first = tailer.poll().expect("first poll");
        tailer
            .persist_checkpoint()
            .expect("persist complete first line");
        let mut file = OpenOptions::new()
            .append(true)
            .open(path)
            .expect("open log for append");
        file.write_all(b"-done\n").expect("complete partial line");
        let second = tailer.poll().expect("second poll");
        let bodies = (
            first
                .into_iter()
                .map(|record| record.body)
                .collect::<Vec<_>>(),
            second
                .into_iter()
                .map(|record| record.body)
                .collect::<Vec<_>>(),
        );

        assert_eq!(
            bodies,
            (vec!["complete".to_owned()], vec!["partial-done".to_owned()])
        );
    }

    #[test]
    fn file_tailer_should_restart_at_zero_when_file_rotates_smaller() {
        let temp = tempfile::tempdir().expect("temp dir");
        let path = temp.path().join("app.log");
        std::fs::write(&path, b"long original line\n").expect("seed log");
        let mut tailer = FileTailer::new(path.clone(), temp.path()).expect("create tailer");
        tailer.poll().expect("consume original log");
        std::fs::remove_file(&path).expect("remove rotated file");
        std::fs::write(&path, b"new\n").expect("write replacement log");

        let records = tailer.poll().expect("poll replacement log");
        let bodies = records
            .into_iter()
            .map(|record| record.body)
            .collect::<Vec<_>>();

        assert_eq!(bodies, vec!["new".to_owned()]);
    }

    #[test]
    fn file_tailer_should_resume_from_persisted_checkpoint_in_new_instance() {
        let temp = tempfile::tempdir().expect("temp dir");
        let path = temp.path().join("app.log");
        std::fs::write(&path, b"first\n").expect("seed log");
        let mut tailer = FileTailer::new(path.clone(), temp.path()).expect("create tailer");
        tailer.poll().expect("consume first line");
        tailer.persist_checkpoint().expect("persist checkpoint");
        let mut file = OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("open log for append");
        file.write_all(b"second\n").expect("append second line");
        drop(tailer);

        let mut resumed = FileTailer::new(path, temp.path()).expect("resume tailer");
        let records = resumed.poll().expect("poll resumed tailer");
        let bodies = records
            .into_iter()
            .map(|record| record.body)
            .collect::<Vec<_>>();

        assert_eq!(bodies, vec!["second".to_owned()]);
    }

    #[test]
    fn file_tailer_should_repeat_uncheckpointed_lines_after_failed_handoff() {
        let temp = tempfile::tempdir().expect("temp dir");
        let path = temp.path().join("app.log");
        std::fs::write(&path, b"").expect("seed empty log");
        let mut tailer = FileTailer::new(path.clone(), temp.path()).expect("create tailer");
        std::fs::write(&path, b"not-durable-yet\n").expect("write undelivered line");

        // Compare bodies, not whole records: ts_ms is stamped per poll and the
        // two polls may land on different milliseconds.
        let bodies = |records: Vec<LogRecordSample>| {
            records
                .into_iter()
                .map(|record| record.body)
                .collect::<Vec<_>>()
        };
        let first = bodies(tailer.poll().expect("first poll"));
        let retried = bodies(tailer.poll().expect("retry poll"));

        assert_eq!(first, vec!["not-durable-yet".to_owned()]);
        assert_eq!(first, retried);
    }

    #[test]
    fn parse_journald_line_should_map_timestamp_priority_message_and_unit() {
        let record = parse_journald_line(
            r#"{"__REALTIME_TIMESTAMP":"1700000000123456","PRIORITY":"4","MESSAGE":"disk warm","_SYSTEMD_UNIT":"crossx.service"}"#,
        )
        .expect("valid journald record");

        assert_eq!(
            (record.ts_ms, record.severity, record.body, record.attrs),
            (
                1_700_000_000_123,
                13,
                "disk warm".to_owned(),
                vec![
                    ("_SYSTEMD_UNIT".to_owned(), "crossx.service".to_owned()),
                    ("log.source".to_owned(), "journald".to_owned()),
                ],
            )
        );
    }

    #[test]
    fn parse_journald_line_should_return_none_when_required_fields_are_missing() {
        let missing_timestamp = parse_journald_line(r#"{"MESSAGE":"no timestamp"}"#);
        let missing_message = parse_journald_line(r#"{"__REALTIME_TIMESTAMP":"1700000000123456"}"#);

        assert!(missing_timestamp.is_none() && missing_message.is_none());
    }

    #[test]
    fn parse_journald_line_should_use_unspecified_for_missing_or_invalid_priority() {
        let missing = parse_journald_line(
            r#"{"__REALTIME_TIMESTAMP":"1700000000123456","MESSAGE":"missing"}"#,
        )
        .expect("priority is optional");
        let invalid = parse_journald_line(
            r#"{"__REALTIME_TIMESTAMP":"1700000000123456","PRIORITY":"nope","MESSAGE":"invalid"}"#,
        )
        .expect("invalid priority is tolerated");

        assert_eq!((missing.severity, invalid.severity), (0, 0));
    }

    #[test]
    fn parse_journald_line_should_map_all_syslog_priority_buckets() {
        let severities = (0..=7)
            .map(|priority| {
                parse_journald_line(&format!(
                    r#"{{"__REALTIME_TIMESTAMP":"1000","PRIORITY":"{priority}","MESSAGE":"fixture"}}"#
                ))
                .expect("valid priority fixture")
                .severity
            })
            .collect::<Vec<_>>();

        assert_eq!(severities, [21, 21, 21, 17, 13, 9, 9, 5]);
    }

    #[test]
    fn build_logs_export_request_should_map_resource_scope_record_and_attributes() {
        let records = vec![LogRecordSample {
            ts_ms: 1_700_000_000_123,
            severity: 13,
            body: "disk warm".to_owned(),
            attrs: vec![("log.source".to_owned(), "/var/log/syslog".to_owned())],
        }];

        let request = build_logs_export_request("node-test", "host-test", &records);
        let resource_logs = &request.resource_logs[0];
        let resource = resource_logs.resource.as_ref().expect("resource");
        let attrs = resource
            .attributes
            .iter()
            .map(|attr| {
                (
                    &attr.key,
                    attr.value.as_ref().and_then(|value| value.value.as_ref()),
                )
            })
            .collect::<Vec<_>>();
        let scope_logs = &resource_logs.scope_logs[0];
        let scope = scope_logs.scope.as_ref().expect("scope");
        let record = &scope_logs.log_records[0];

        assert!(attrs.iter().any(|(key, value)| {
            key.as_str() == "crossx.node.id"
                && matches!(value, Some(any_value::Value::StringValue(value)) if value == "node-test")
        }));
        assert!(attrs.iter().any(|(key, value)| {
            key.as_str() == "host.name"
                && matches!(value, Some(any_value::Value::StringValue(value)) if value == "host-test")
        }));
        assert_eq!(scope.name, "crossx-agent");
        assert_eq!(record.time_unix_nano, 1_700_000_000_123_000_000);
        assert_eq!(record.severity_number, 13);
        assert!(matches!(
            record.body.as_ref().and_then(|body| body.value.as_ref()),
            Some(any_value::Value::StringValue(value)) if value == "disk warm"
        ));
        assert!(record.attributes.iter().any(|attr| {
            attr.key == "log.source"
                && matches!(
                    attr.value.as_ref().and_then(|value| value.value.as_ref()),
                    Some(any_value::Value::StringValue(value)) if value == "/var/log/syslog"
                )
        }));
    }
}
