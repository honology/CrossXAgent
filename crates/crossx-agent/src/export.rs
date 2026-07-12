use std::time::{Duration, SystemTime, UNIX_EPOCH};

use agent_telemetry::{HostSampler, build_export_request};
use anyhow::Context;
use opentelemetry_proto::tonic::collector::metrics::v1::ExportMetricsServiceRequest;
use opentelemetry_proto::tonic::collector::metrics::v1::metrics_service_client::MetricsServiceClient;
use sysinfo::System;
use tonic::metadata::{Ascii, MetadataValue};
use tonic::transport::Channel;

use crate::config::AgentConfig;

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

/// Samples one tick and exports it over OTLP/gRPC, retrying on failure.
/// Each attempt is hard-bounded by [`ATTEMPT_TIMEOUT`], so one tick resolves
/// within ~51s worst case even against an unresponsive collector. The final
/// error is returned once the schedule is exhausted; the caller decides
/// whether to drop the batch (loop mode) or exit non-zero (--once).
pub async fn export_tick(cfg: &AgentConfig, sampler: &mut HostSampler) -> anyhow::Result<()> {
    let samples = sampler.sample();
    let host_name = System::host_name().unwrap_or_else(|| "unknown".to_owned());
    let ts_ms = unix_millis_now()?;
    let request = build_export_request(&cfg.node_id, &host_name, ts_ms, &samples);

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
