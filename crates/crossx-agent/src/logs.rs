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
///
/// Per-source failures — a missing or rotating file, a dying journalctl —
/// degrade to warnings and are retried on later ticks. Only unrecoverable
/// state such as a broken logs WAL ends the loop (spec §8: degradation must
/// stay bounded, and logs must never take metrics collection down).
pub async fn run_logs_loop(cfg: &AgentConfig) -> anyhow::Result<()> {
    if !cfg.logs.enabled {
        return Ok(());
    }
    let checkpoint_root = cfg.state_dir.join("checkpoints").join("logs");
    let file_checkpoint_dir = checkpoint_root.join("files");
    let mut sources = cfg
        .logs
        .files
        .iter()
        .map(|path| FileSource::new(path.clone(), &file_checkpoint_dir))
        .collect::<Vec<_>>();
    let mut exporter = LogsExporter::open(cfg)?;
    let host_name = System::host_name().unwrap_or_else(|| "unknown".to_owned());
    let mut ticker = tokio::time::interval(Duration::from_secs(cfg.interval_secs.max(1)));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    #[cfg(unix)]
    let mut journald =
        JournaldSource::new(cfg.logs.journald, checkpoint_root.join("journald.cursor"));
    #[cfg(not(unix))]
    if cfg.logs.journald {
        tracing::warn!("journald collection is only supported on Unix hosts");
    }

    loop {
        #[cfg(unix)]
        tokio::select! {
            _ = ticker.tick() => {
                journald.ensure_running().await;
                poll_file_sources(cfg, &host_name, &mut exporter, &mut sources).await;
            }
            journal_record = journald.next_record() => {
                if let Some(record) = journal_record {
                    match exporter.export_records(cfg, &host_name, std::slice::from_ref(&record)).await {
                        Ok(()) => journald.persist_checkpoint(),
                        Err(error) => tracing::warn!(
                            "journald record dropped; logs WAL rejected it: {error:#}"
                        ),
                    }
                }
            }
        }

        #[cfg(not(unix))]
        {
            ticker.tick().await;
            poll_file_sources(cfg, &host_name, &mut exporter, &mut sources).await;
        }
    }
}

// Strict single-pass helper backing `run_logs_once`: unlike the loop, the
// one-shot diagnostic mode should fail loudly on a broken source.
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

/// One configured log file, tailed leniently: absence and rotation windows
/// degrade to warnings, and the tailer is recreated from its persisted
/// checkpoint on a later tick.
pub struct FileSource {
    path: std::path::PathBuf,
    checkpoint_dir: std::path::PathBuf,
    tailer: Option<FileTailer>,
    // why: one warning per outage, not one per collection tick.
    unavailable_logged: bool,
}

impl FileSource {
    /// Declares a file source; the tailer itself is opened lazily per poll.
    pub fn new(path: std::path::PathBuf, checkpoint_dir: &Path) -> Self {
        Self {
            path,
            checkpoint_dir: checkpoint_dir.to_path_buf(),
            tailer: None,
            unavailable_logged: false,
        }
    }

    async fn poll_into(&mut self, cfg: &AgentConfig, host_name: &str, exporter: &mut LogsExporter) {
        if self.tailer.is_none() {
            match FileTailer::new(self.path.clone(), &self.checkpoint_dir) {
                Ok(tailer) => {
                    if self.unavailable_logged {
                        tracing::info!(path = %self.path.display(), "log file is available again");
                        self.unavailable_logged = false;
                    }
                    self.tailer = Some(tailer);
                }
                Err(error) => {
                    self.warn_unavailable(&error);
                    return;
                }
            }
        }
        let Some(tailer) = self.tailer.as_mut() else {
            return;
        };
        let records = match tailer.poll() {
            Ok(records) => records,
            Err(error) => {
                // why: rotation can remove the file between polls; drop the
                // tailer and recreate it from its checkpoint on a later tick.
                self.tailer = None;
                self.warn_unavailable(&error);
                return;
            }
        };
        if records.is_empty() {
            return;
        }
        if let Err(error) = exporter.export_records(cfg, host_name, &records).await {
            // Checkpoint not advanced: the same lines are re-read next tick.
            tracing::warn!(
                path = %self.path.display(),
                "logs batch was not accepted this tick: {error:#}"
            );
            return;
        }
        if let Err(error) = tailer.persist_checkpoint() {
            tracing::warn!(
                path = %self.path.display(),
                "log checkpoint persist failed; delivered lines may repeat: {error:#}"
            );
        }
    }

    fn warn_unavailable(&mut self, error: &anyhow::Error) {
        if !self.unavailable_logged {
            tracing::warn!(
                path = %self.path.display(),
                "log file unavailable; retrying every tick: {error:#}"
            );
            self.unavailable_logged = true;
        }
    }
}

/// Polls every file source once; per-source failures are logged and retried
/// on later ticks instead of aborting the logs loop.
pub async fn poll_file_sources(
    cfg: &AgentConfig,
    host_name: &str,
    exporter: &mut LogsExporter,
    sources: &mut [FileSource],
) {
    for source in sources {
        source.poll_into(cfg, host_name, exporter).await;
    }
}

/// Restart policy after a journalctl follower dies: an exit before producing
/// a single record strongly suggests journalctl rejected the stored cursor
/// (vacuumed journal, torn checkpoint file), so the next spawn falls back to
/// `--since now` instead of crash-looping on `--after-cursor`.
#[cfg_attr(
    all(not(unix), not(test)),
    expect(dead_code, reason = "only the Unix journald follower consults it")
)]
fn journald_should_skip_cursor_on_restart(
    spawned_with_cursor: bool,
    produced_any_record: bool,
) -> bool {
    spawned_with_cursor && !produced_any_record
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
    spawned_with_cursor: bool,
    produced_any_record: bool,
}

#[cfg(unix)]
impl JournaldFollower {
    async fn spawn(checkpoint_path: &Path, use_cursor: bool) -> anyhow::Result<Self> {
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
        let cursor = if use_cursor {
            match std::fs::read_to_string(checkpoint_path) {
                Ok(cursor) => Some(cursor),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!("reading journald checkpoint {}", checkpoint_path.display())
                    });
                }
            }
        } else {
            None
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
            spawned_with_cursor: cursor.is_some(),
            produced_any_record: false,
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
            self.produced_any_record = true;
            return Ok(Some(record));
        }
        let status = self.child.wait().await.context("waiting for journalctl")?;
        anyhow::ensure!(status.success(), "journalctl exited with {status}");
        Ok(None)
    }

    fn persist_checkpoint(&mut self) -> anyhow::Result<()> {
        use std::io::Write;

        let Some(cursor) = self.pending_cursor.take() else {
            return Ok(());
        };
        let temp_path = self.checkpoint_path.with_extension("cursor.tmp");
        let mut file = std::fs::File::create(&temp_path)
            .with_context(|| format!("creating journald checkpoint {}", temp_path.display()))?;
        file.write_all(cursor.as_bytes())
            .with_context(|| format!("writing journald checkpoint {}", temp_path.display()))?;
        // why: rename alone does not make the bytes durable — power loss could
        // otherwise leave an empty cursor file that journalctl then rejects.
        file.sync_all()
            .with_context(|| format!("syncing journald checkpoint {}", temp_path.display()))?;
        drop(file);
        std::fs::rename(&temp_path, &self.checkpoint_path).with_context(|| {
            format!(
                "replacing journald checkpoint {}",
                self.checkpoint_path.display()
            )
        })
    }
}

/// Journald collection that survives journalctl dying: the follower is
/// respawned on the next tick, falling back to `--since now` when the stored
/// cursor looks rejected.
#[cfg(unix)]
struct JournaldSource {
    enabled: bool,
    checkpoint_path: std::path::PathBuf,
    follower: Option<JournaldFollower>,
    skip_cursor: bool,
    // why: one warning per outage, not one per collection tick.
    unavailable_logged: bool,
}

#[cfg(unix)]
impl JournaldSource {
    fn new(enabled: bool, checkpoint_path: std::path::PathBuf) -> Self {
        Self {
            enabled,
            checkpoint_path,
            follower: None,
            skip_cursor: false,
            unavailable_logged: false,
        }
    }

    /// (Re)spawns journalctl when enabled and not currently running. Driven
    /// by the collection tick so a repeatedly dying journalctl cannot spawn
    /// in a hot loop.
    async fn ensure_running(&mut self) {
        if !self.enabled || self.follower.is_some() {
            return;
        }
        match JournaldFollower::spawn(&self.checkpoint_path, !self.skip_cursor).await {
            Ok(follower) => {
                if self.unavailable_logged {
                    tracing::info!("journalctl follower is running again");
                    self.unavailable_logged = false;
                }
                self.follower = Some(follower);
            }
            Err(error) => {
                if !self.unavailable_logged {
                    tracing::warn!("journalctl unavailable; retrying every tick: {error:#}");
                    self.unavailable_logged = true;
                }
            }
        }
    }

    /// Yields the next journald record; pends forever while no follower is
    /// running (`ensure_running` on the tick arm drives respawns).
    async fn next_record(&mut self) -> Option<LogRecordSample> {
        let Some(follower) = self.follower.as_mut() else {
            return std::future::pending().await;
        };
        match follower.next().await {
            Ok(Some(record)) => Some(record),
            Ok(None) => {
                self.on_follower_exit(None);
                None
            }
            Err(error) => {
                self.on_follower_exit(Some(error));
                None
            }
        }
    }

    fn on_follower_exit(&mut self, error: Option<anyhow::Error>) {
        let Some(follower) = self.follower.take() else {
            return;
        };
        self.skip_cursor = journald_should_skip_cursor_on_restart(
            follower.spawned_with_cursor,
            follower.produced_any_record,
        );
        let detail =
            error.map_or_else(|| "exited".to_owned(), |error| format!("failed: {error:#}"));
        if self.skip_cursor {
            tracing::warn!(
                "journalctl follower {detail}; respawning with --since now \
                 (the stored cursor looks rejected)"
            );
        } else {
            tracing::warn!("journalctl follower {detail}; respawning next tick");
        }
    }

    fn persist_checkpoint(&mut self) {
        let Some(follower) = self.follower.as_mut() else {
            return;
        };
        if let Err(error) = follower.persist_checkpoint() {
            tracing::warn!(
                "journald checkpoint persist failed; delivered records may repeat: {error:#}"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::journald_should_skip_cursor_on_restart;

    #[test]
    fn cursor_should_be_skipped_only_when_follower_died_before_any_record() {
        let scenarios = [
            // (spawned_with_cursor, produced_any_record) -> skip stored cursor
            ((true, false), true),
            ((true, true), false),
            ((false, false), false),
            ((false, true), false),
        ];

        for ((spawned_with_cursor, produced_any_record), expected) in scenarios {
            assert_eq!(
                journald_should_skip_cursor_on_restart(spawned_with_cursor, produced_any_record),
                expected,
                "spawned_with_cursor={spawned_with_cursor} produced_any_record={produced_any_record}"
            );
        }
    }
}
