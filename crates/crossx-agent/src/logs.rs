use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use agent_telemetry::logs::{FileTailer, LogRecordSample, build_logs_export_request};
use anyhow::Context;
use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
use opentelemetry_proto::tonic::collector::logs::v1::logs_service_client::LogsServiceClient;
use prost::Message;
use sysinfo::System;
use tonic::metadata::{Ascii, MetadataValue};
use tonic::transport::Channel;

use crate::config::AgentConfig;
use crate::wal::Wal;

const MAX_WAL_DRAIN_PER_TICK: usize = 32;
const RETRY_DELAYS: [Duration; 3] = [
    Duration::from_millis(500),
    Duration::from_secs(2),
    Duration::from_secs(8),
];
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Stateful logs export path with a signal-specific strict-FIFO WAL.
pub struct LogsExporter {
    wal: Wal,
}

impl LogsExporter {
    /// Opens the logs WAL below `<state_dir>/wal/logs`.
    pub fn open(cfg: &AgentConfig) -> anyhow::Result<Self> {
        let wal = Wal::open(&cfg.state_dir.join("wal").join("logs"), cfg.wal_max_bytes)?;
        Ok(Self { wal })
    }

    /// Durably accepts one batch, exporting immediately when FIFO ordering permits.
    ///
    /// A successful return means the records were either accepted by the collector or
    /// appended to the logs WAL, so source checkpoints may advance safely.
    pub async fn export_records(
        &mut self,
        cfg: &AgentConfig,
        host_name: &str,
        records: &[LogRecordSample],
    ) -> anyhow::Result<()> {
        if records.is_empty() {
            return Ok(());
        }
        let request = build_logs_export_request(&cfg.node_id, host_name, records);
        let payload = request.encode_to_vec();

        if self.wal.pending() > 0 {
            self.wal
                .append(&payload)
                .context("persisting fresh logs batch behind pending WAL entries")?;
            if let Err(error) = self.drain_wal(cfg).await {
                tracing::warn!("logs WAL drain stopped at its head: {error:#}");
            }
            return Ok(());
        }

        if let Err(error) = export_with_retry(cfg, request).await {
            self.wal
                .append(&payload)
                .context("persisting failed logs export to WAL")?;
            tracing::warn!("logs export failed; batch persisted to WAL: {error:#}");
        }
        Ok(())
    }

    async fn drain_wal(&mut self, cfg: &AgentConfig) -> anyhow::Result<()> {
        for _ in 0..MAX_WAL_DRAIN_PER_TICK {
            let Some(entry) = self.wal.next()? else {
                break;
            };
            let request = ExportLogsServiceRequest::decode(entry.payload.as_slice())
                .context("decoding logs request from WAL")?;
            export_with_retry(cfg, request)
                .await
                .context("exporting logs WAL head; entry remains queued")?;
            self.wal.ack(&entry)?;
        }
        Ok(())
    }
}

/// Polls configured files once and durably hands their complete lines to the exporter.
pub async fn run_logs_once(cfg: &AgentConfig) -> anyhow::Result<()> {
    if !cfg.logs.enabled {
        return Ok(());
    }
    let checkpoint_dir = cfg.state_dir.join("checkpoints").join("logs").join("files");
    let mut tailers = open_file_tailers(cfg, &checkpoint_dir)?;
    let mut exporter = LogsExporter::open(cfg)?;
    let host_name = System::host_name().unwrap_or_else(|| "unknown".to_owned());
    poll_files(cfg, &host_name, &mut exporter, &mut tailers).await
}

/// Runs the enabled log sources forever at the agent collection cadence.
pub async fn run_logs_loop(cfg: &AgentConfig) -> anyhow::Result<()> {
    if !cfg.logs.enabled {
        return Ok(());
    }
    let checkpoint_root = cfg.state_dir.join("checkpoints").join("logs");
    let mut tailers = open_file_tailers(cfg, &checkpoint_root.join("files"))?;
    let mut exporter = LogsExporter::open(cfg)?;
    let host_name = System::host_name().unwrap_or_else(|| "unknown".to_owned());
    let mut ticker = tokio::time::interval(Duration::from_secs(cfg.interval_secs.max(1)));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    #[cfg(unix)]
    let mut journald = if cfg.logs.journald {
        Some(JournaldFollower::spawn(&checkpoint_root.join("journald.cursor")).await?)
    } else {
        None
    };
    #[cfg(not(unix))]
    if cfg.logs.journald {
        tracing::warn!("journald collection is only supported on Unix hosts");
    }

    loop {
        #[cfg(unix)]
        tokio::select! {
            _ = ticker.tick() => {
                poll_files(cfg, &host_name, &mut exporter, &mut tailers).await?;
            }
            journal_record = next_journald_record(&mut journald) => {
                match journal_record? {
                    Some(record) => {
                        exporter.export_records(cfg, &host_name, std::slice::from_ref(&record)).await?;
                        if let Some(follower) = journald.as_mut() {
                            follower.persist_checkpoint()?;
                        }
                    }
                    None => {
                        tracing::warn!("journalctl follower exited; journald collection stopped");
                        journald = None;
                    }
                }
            }
        }

        #[cfg(not(unix))]
        {
            ticker.tick().await;
            poll_files(cfg, &host_name, &mut exporter, &mut tailers).await?;
        }
    }
}

fn open_file_tailers(cfg: &AgentConfig, checkpoint_dir: &Path) -> anyhow::Result<Vec<FileTailer>> {
    cfg.logs
        .files
        .iter()
        .cloned()
        .map(|path| FileTailer::new(path, checkpoint_dir))
        .collect()
}

async fn poll_files(
    cfg: &AgentConfig,
    host_name: &str,
    exporter: &mut LogsExporter,
    tailers: &mut [FileTailer],
) -> anyhow::Result<()> {
    for tailer in tailers {
        let records = tailer.poll()?;
        if records.is_empty() {
            continue;
        }
        exporter.export_records(cfg, host_name, &records).await?;
        tailer.persist_checkpoint()?;
    }
    Ok(())
}

async fn export_with_retry(
    cfg: &AgentConfig,
    request: ExportLogsServiceRequest,
) -> anyhow::Result<()> {
    let mut last_error = None;
    for attempt in 0..=RETRY_DELAYS.len() {
        if attempt > 0 {
            tokio::time::sleep(RETRY_DELAYS[attempt - 1] + jitter()).await;
        }
        match tokio::time::timeout(ATTEMPT_TIMEOUT, try_export(cfg, request.clone())).await {
            Ok(Ok(())) => return Ok(()),
            Ok(Err(error)) => {
                tracing::warn!(attempt, "OTLP logs export attempt failed: {error:#}");
                last_error = Some(error);
            }
            Err(_elapsed) => {
                let error = anyhow::anyhow!(
                    "logs export attempt timed out after {}s",
                    ATTEMPT_TIMEOUT.as_secs()
                );
                tracing::warn!(attempt, "OTLP logs export attempt failed: {error:#}");
                last_error = Some(error);
            }
        }
    }
    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("logs export failed without an error")))
}

async fn try_export(cfg: &AgentConfig, request: ExportLogsServiceRequest) -> anyhow::Result<()> {
    let channel = Channel::from_shared(cfg.collector_endpoint.clone())
        .with_context(|| format!("invalid collector endpoint {}", cfg.collector_endpoint))?
        .connect_timeout(CONNECT_TIMEOUT)
        .connect()
        .await
        .with_context(|| format!("connecting to collector {}", cfg.collector_endpoint))?;

    if cfg.auth_token.is_empty() {
        LogsServiceClient::new(channel)
            .export(request)
            .await
            .context("OTLP logs export rejected")?;
    } else {
        let bearer: MetadataValue<Ascii> = format!("Bearer {}", cfg.auth_token)
            .parse()
            .context("auth token contains characters invalid in gRPC metadata")?;
        let mut client =
            LogsServiceClient::with_interceptor(channel, move |mut req: tonic::Request<()>| {
                req.metadata_mut().insert("authorization", bearer.clone());
                Ok::<_, tonic::Status>(req)
            });
        client
            .export(request)
            .await
            .context("OTLP logs export rejected")?;
    }
    Ok(())
}

fn jitter() -> Duration {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.subsec_nanos());
    Duration::from_millis(u64::from(nanos % 250))
}

#[cfg(unix)]
struct JournaldFollower {
    child: tokio::process::Child,
    lines: tokio::io::Lines<tokio::io::BufReader<tokio::process::ChildStdout>>,
    checkpoint_path: std::path::PathBuf,
    pending_cursor: Option<String>,
}

#[cfg(unix)]
impl JournaldFollower {
    async fn spawn(checkpoint_path: &Path) -> anyhow::Result<Self> {
        use std::process::Stdio;
        use tokio::io::AsyncBufReadExt;

        if let Some(parent) = checkpoint_path.parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!(
                    "creating journald checkpoint directory {}",
                    parent.display()
                )
            })?;
        }
        let cursor = match std::fs::read_to_string(checkpoint_path) {
            Ok(cursor) => Some(cursor),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("reading journald checkpoint {}", checkpoint_path.display())
                });
            }
        };
        let mut command = tokio::process::Command::new("journalctl");
        command.args(["--follow", "--output=json"]);
        if let Some(cursor) = cursor.as_deref() {
            command.arg("--after-cursor").arg(cursor.trim());
        } else {
            command.args(["--since", "now"]);
        }
        let mut child = command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .context("spawning journalctl follower")?;
        let stdout = child
            .stdout
            .take()
            .context("journalctl stdout was not piped")?;
        Ok(Self {
            child,
            lines: tokio::io::BufReader::new(stdout).lines(),
            checkpoint_path: checkpoint_path.to_path_buf(),
            pending_cursor: None,
        })
    }

    async fn next(&mut self) -> anyhow::Result<Option<LogRecordSample>> {
        use agent_telemetry::logs::parse_journald_line;
        use tokio::io::AsyncBufReadExt;

        while let Some(line) = self
            .lines
            .next_line()
            .await
            .context("reading journalctl output")?
        {
            let Some(record) = parse_journald_line(&line) else {
                continue;
            };
            self.pending_cursor = serde_json::from_str::<serde_json::Value>(&line)
                .ok()
                .and_then(|value| value.get("__CURSOR")?.as_str().map(str::to_owned));
            return Ok(Some(record));
        }
        let status = self.child.wait().await.context("waiting for journalctl")?;
        anyhow::ensure!(status.success(), "journalctl exited with {status}");
        Ok(None)
    }

    fn persist_checkpoint(&mut self) -> anyhow::Result<()> {
        let Some(cursor) = self.pending_cursor.take() else {
            return Ok(());
        };
        let temp_path = self.checkpoint_path.with_extension("cursor.tmp");
        std::fs::write(&temp_path, cursor.as_bytes())
            .with_context(|| format!("writing journald checkpoint {}", temp_path.display()))?;
        std::fs::rename(&temp_path, &self.checkpoint_path).with_context(|| {
            format!(
                "replacing journald checkpoint {}",
                self.checkpoint_path.display()
            )
        })
    }
}

#[cfg(unix)]
async fn next_journald_record(
    follower: &mut Option<JournaldFollower>,
) -> anyhow::Result<Option<LogRecordSample>> {
    match follower {
        Some(follower) => follower.next().await,
        None => std::future::pending().await,
    }
}
