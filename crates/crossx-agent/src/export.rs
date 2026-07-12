use std::time::{Duration, SystemTime, UNIX_EPOCH};

use agent_telemetry::{HostSampler, build_export_request};
use anyhow::Context;
use opentelemetry_proto::tonic::collector::metrics::v1::ExportMetricsServiceRequest;
use opentelemetry_proto::tonic::collector::metrics::v1::metrics_service_client::MetricsServiceClient;
use prost::Message;
use sysinfo::System;
use tonic::metadata::{Ascii, MetadataValue};
use tonic::transport::Channel;

use crate::config::AgentConfig;
use crate::wal::Wal;

const MAX_WAL_DRAIN_PER_TICK: usize = 32;

/// Backoff schedule (plan Task B3): one initial attempt plus one retry per
/// entry, each delay widened by jitter.
const RETRY_DELAYS: [Duration; 3] = [
    Duration::from_millis(500),
    Duration::from_secs(2),
    Duration::from_secs(8),
];

/// Hard bound on one connect + export attempt. Without it a collector that
/// accepts TCP but never answers (hung process, black-holing firewall,
/// half-open connection) would wedge `export_tick` — and with it the whole
/// run loop — forever (spec §8: degradation must stay bounded).
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(10);

/// Bounds connection establishment within an attempt so unroutable endpoints
/// fail faster than the OS connect timeout (which can reach minutes).
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Stateful metrics export path with strict FIFO disk backfill.
pub struct MetricsExporter {
    wal: Wal,
}

impl MetricsExporter {
    /// Opens the metrics WAL below `<state_dir>/wal/metrics`.
    pub fn open(cfg: &AgentConfig) -> anyhow::Result<Self> {
        let wal = Wal::open(
            &cfg.state_dir.join("wal").join("metrics"),
            cfg.wal_max_bytes,
        )?;
        Ok(Self { wal })
    }

    /// Samples and exports one tick, queueing it whenever direct delivery fails.
    pub async fn export_tick(
        &mut self,
        cfg: &AgentConfig,
        sampler: &mut HostSampler,
    ) -> anyhow::Result<()> {
        let samples = sampler.sample();
        let host_name = System::host_name().unwrap_or_else(|| "unknown".to_owned());
        let ts_ms = unix_millis_now()?;
        let request = build_export_request(&cfg.node_id, &host_name, ts_ms, &samples);
        let payload = request.encode_to_vec();

        if self.wal.pending() > 0 {
            self.wal.append(&payload)?;
            return self.drain_wal(cfg).await;
        }

        if let Err(error) = export_with_retry(cfg, request).await {
            self.wal
                .append(&payload)
                .context("persisting failed metrics export to WAL")?;
            return Err(error.context("metrics export failed; batch persisted to WAL"));
        }
        Ok(())
    }

    async fn drain_wal(&mut self, cfg: &AgentConfig) -> anyhow::Result<()> {
        for _ in 0..MAX_WAL_DRAIN_PER_TICK {
            let Some(entry) = self.wal.next()? else {
                break;
            };
            let request = ExportMetricsServiceRequest::decode(entry.payload.as_slice())
                .context("decoding metrics request from WAL")?;
            export_with_retry(cfg, request)
                .await
                .context("exporting metrics WAL head; entry remains queued")?;
            self.wal.ack(&entry)?;
        }
        Ok(())
    }
}

/// Samples one tick through a freshly opened persistent metrics exporter.
pub async fn export_tick(cfg: &AgentConfig, sampler: &mut HostSampler) -> anyhow::Result<()> {
    let mut exporter = MetricsExporter::open(cfg)?;
    exporter.export_tick(cfg, sampler).await
}

async fn export_with_retry(
    cfg: &AgentConfig,
    request: ExportMetricsServiceRequest,
) -> anyhow::Result<()> {
    let mut last_error = None;
    for attempt in 0..=RETRY_DELAYS.len() {
        if attempt > 0 {
            tokio::time::sleep(RETRY_DELAYS[attempt - 1] + jitter()).await;
        }
        match tokio::time::timeout(ATTEMPT_TIMEOUT, try_export(cfg, request.clone())).await {
            Ok(Ok(())) => return Ok(()),
            Ok(Err(error)) => {
                tracing::warn!(attempt, "OTLP export attempt failed: {error:#}");
                last_error = Some(error);
            }
            Err(_elapsed) => {
                let error = anyhow::anyhow!(
                    "export attempt timed out after {}s (collector accepted the connection but never answered?)",
                    ATTEMPT_TIMEOUT.as_secs()
                );
                tracing::warn!(attempt, "OTLP export attempt failed: {error:#}");
                last_error = Some(error);
            }
        }
    }
    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("export failed without a recorded error")))
}

async fn try_export(cfg: &AgentConfig, request: ExportMetricsServiceRequest) -> anyhow::Result<()> {
    let channel = Channel::from_shared(cfg.collector_endpoint.clone())
        .with_context(|| format!("invalid collector endpoint {}", cfg.collector_endpoint))?
        .connect_timeout(CONNECT_TIMEOUT)
        .connect()
        .await
        .with_context(|| format!("connecting to collector {}", cfg.collector_endpoint))?;

    if cfg.auth_token.is_empty() {
        MetricsServiceClient::new(channel)
            .export(request)
            .await
            .context("OTLP export rejected")?;
    } else {
        let bearer: MetadataValue<Ascii> = format!("Bearer {}", cfg.auth_token)
            .parse()
            .context("auth token contains characters invalid in gRPC metadata")?;
        let mut client =
            MetricsServiceClient::with_interceptor(channel, move |mut req: tonic::Request<()>| {
                req.metadata_mut().insert("authorization", bearer.clone());
                Ok::<_, tonic::Status>(req)
            });
        client
            .export(request)
            .await
            .context("OTLP export rejected")?;
    }
    Ok(())
}

fn unix_millis_now() -> anyhow::Result<i64> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the UNIX epoch")?;
    i64::try_from(elapsed.as_millis()).context("system clock exceeds i64 millisecond range")
}

/// 0..250ms derived from the clock's subsecond nanos — enough spread to
/// de-synchronize retry stampedes without pulling in a rand dependency.
fn jitter() -> Duration {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.subsec_nanos());
    Duration::from_millis(u64::from(nanos % 250))
}
