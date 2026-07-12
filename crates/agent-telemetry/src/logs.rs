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
    /// Opens a file tailer and its path-specific checkpoint.
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
        let offset = read_checkpoint(&checkpoint_path)?
            .filter(|checkpoint| {
                checkpoint.signature == signature && checkpoint.offset <= metadata.len()
            })
            .map_or(0, |checkpoint| checkpoint.offset);
        Ok(Self {
            checkpoint_path,
            path,
            offset,
            signature,
            pending_offset: offset,
            pending_signature: signature,
        })
    }

    /// Returns complete lines added since the last poll.
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
        file.read_to_end(&mut bytes)
            .with_context(|| format!("reading log file {}", self.path.display()))?;
        let Some(complete_len) = bytes
            .iter()
            .rposition(|byte| *byte == b'\n')
            .map(|index| index + 1)
        else {
            self.pending_offset = start_offset;
            self.pending_signature = signature;
            return Ok(Vec::new());
        };
        let ts_ms = unix_millis_now()?;
        let source = self.path.to_string_lossy();
        let records = bytes[..complete_len - 1]
            .split(|byte| *byte == b'\n')
            .map(|line| {
                let line = line.strip_suffix(b"\r").unwrap_or(line);
                LogRecordSample {
                    ts_ms,
                    severity: 0,
                    body: String::from_utf8_lossy(line).into_owned(),
                    attrs: vec![("log.source".to_owned(), source.to_string())],
                }
            })
            .collect();
        self.pending_offset = start_offset
            .checked_add(u64::try_from(complete_len).context("complete log bytes exceed u64")?)
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
    fn file_tailer_should_hold_partial_line_until_newline_arrives() {
        let temp = tempfile::tempdir().expect("temp dir");
        let path = temp.path().join("app.log");
        std::fs::write(&path, b"complete\npartial").expect("seed log");
        let mut tailer = FileTailer::new(path.clone(), temp.path()).expect("create tailer");

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
        std::fs::write(&path, b"not-durable-yet\n").expect("seed log");
        let mut tailer = FileTailer::new(path, temp.path()).expect("create tailer");

        let first = tailer.poll().expect("first poll");
        let retried = tailer.poll().expect("retry poll");

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
