use std::future::{Ready, ready};
use std::io;
use std::task::{Context as TaskContext, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use agent_telemetry::{HostSampler, build_export_request};
use anyhow::Context;
use hyper_util::rt::TokioIo;
use opentelemetry_proto::tonic::collector::metrics::v1::ExportMetricsServiceRequest;
use opentelemetry_proto::tonic::collector::metrics::v1::metrics_service_client::MetricsServiceClient;
use prost::Message;
use sysinfo::System;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;
use tonic::codegen::Service;
use tonic::codegen::http::Uri;
use tonic::metadata::{Ascii, MetadataValue};
use tonic::transport::{Channel, Endpoint};

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

/// Tokio duplex transport accepted by the relay-backed exporter slot.
pub trait RelayTransportIo: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T> RelayTransportIo for T where T: AsyncRead + AsyncWrite + Send + Unpin {}

/// Type-erased relay pipe used by the exporter transport slot.
pub type RelayTransport = Box<dyn RelayTransportIo>;

/// Sending half used by the relay task to provide telemetry pipes.
pub type RelayTransportSender = mpsc::UnboundedSender<RelayTransport>;

/// Receiving half owned by the metrics exporter.
pub type RelayTransportReceiver = mpsc::UnboundedReceiver<RelayTransport>;

/// Creates the telemetry-pipe handoff between the relay task and exporter.
pub fn relay_transport_slot() -> (RelayTransportSender, RelayTransportReceiver) {
    mpsc::unbounded_channel()
}

enum ExportTransport {
    Direct,
    Relay {
        incoming: RelayTransportReceiver,
        channel: Option<Channel>,
    },
}

/// Stateful metrics export path with strict FIFO disk backfill.
pub struct MetricsExporter {
    wal: Wal,
    transport: ExportTransport,
}

impl MetricsExporter {
    /// Opens the metrics WAL below `<state_dir>/wal/metrics`.
    pub fn open(cfg: &AgentConfig) -> anyhow::Result<Self> {
        let wal = Wal::open(
            &cfg.state_dir.join("wal").join("metrics"),
            cfg.wal_max_bytes,
        )?;
        Ok(Self {
            wal,
            transport: ExportTransport::Direct,
        })
    }

    /// Opens the metrics WAL with a relay telemetry-pipe receiver.
    pub fn open_with_relay(
        cfg: &AgentConfig,
        incoming: RelayTransportReceiver,
    ) -> anyhow::Result<Self> {
        let mut exporter = Self::open(cfg)?;
        exporter.transport = ExportTransport::Relay {
            incoming,
            channel: None,
        };
        Ok(exporter)
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

        if let Err(error) = self.export_with_retry(cfg, request).await {
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
            self.export_with_retry(cfg, request)
                .await
                .context("exporting metrics WAL head; entry remains queued")?;
            self.wal.ack(&entry)?;
        }
        Ok(())
    }

    async fn export_with_retry(
        &mut self,
        cfg: &AgentConfig,
        request: ExportMetricsServiceRequest,
    ) -> anyhow::Result<()> {
        let mut last_error = None;
        for attempt in 0..=RETRY_DELAYS.len() {
            if attempt > 0 {
                tokio::time::sleep(RETRY_DELAYS[attempt - 1] + jitter()).await;
            }
            match tokio::time::timeout(ATTEMPT_TIMEOUT, self.try_export(cfg, request.clone())).await
            {
                Ok(Ok(())) => return Ok(()),
                Ok(Err(error)) => {
                    tracing::warn!(attempt, "OTLP export attempt failed: {error:#}");
                    last_error = Some(error);
                }
                Err(_elapsed) => {
                    self.discard_relay_channel();
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

    async fn try_export(
        &mut self,
        cfg: &AgentConfig,
        request: ExportMetricsServiceRequest,
    ) -> anyhow::Result<()> {
        let channel = match &mut self.transport {
            ExportTransport::Direct => direct_channel(cfg).await?,
            ExportTransport::Relay { incoming, channel } => {
                if channel.is_none() {
                    let pipe = incoming
                        .recv()
                        .await
                        .context("relay telemetry transport slot closed")?;
                    *channel = Some(channel_over_pipe(pipe).await?);
                }
                channel
                    .as_ref()
                    .context("relay channel was not installed")?
                    .clone()
            }
        };

        if let Err(error) = send_request(cfg, channel, request).await {
            // A failed HTTP/2 connection cannot be reused; the next attempt
            // must wait for the collector to dial a fresh relay pipe.
            self.discard_relay_channel();
            return Err(error);
        }
        Ok(())
    }

    fn discard_relay_channel(&mut self) {
        if let ExportTransport::Relay { channel, .. } = &mut self.transport {
            *channel = None;
        }
    }
}

/// Samples one tick through a freshly opened persistent metrics exporter.
pub async fn export_tick(cfg: &AgentConfig, sampler: &mut HostSampler) -> anyhow::Result<()> {
    let mut exporter = MetricsExporter::open(cfg)?;
    exporter.export_tick(cfg, sampler).await
}

async fn direct_channel(cfg: &AgentConfig) -> anyhow::Result<Channel> {
    let channel = Channel::from_shared(cfg.collector_endpoint.clone())
        .with_context(|| format!("invalid collector endpoint {}", cfg.collector_endpoint))?
        .connect_timeout(CONNECT_TIMEOUT)
        .connect()
        .await
        .with_context(|| format!("connecting to collector {}", cfg.collector_endpoint))?;
    Ok(channel)
}

async fn channel_over_pipe(pipe: RelayTransport) -> anyhow::Result<Channel> {
    Endpoint::from_static("http://relay-transport")
        .connect_with_connector(SingleUseConnector { pipe: Some(pipe) })
        .await
        .context("connecting OTLP client over relay pipe")
}

async fn send_request(
    cfg: &AgentConfig,
    channel: Channel,
    request: ExportMetricsServiceRequest,
) -> anyhow::Result<()> {
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

struct SingleUseConnector {
    pipe: Option<RelayTransport>,
}

impl Service<Uri> for SingleUseConnector {
    type Response = TokioIo<RelayTransport>;
    type Error = io::Error;
    type Future = Ready<Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut TaskContext<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _request: Uri) -> Self::Future {
        ready(
            self.pipe.take().map(TokioIo::new).ok_or_else(|| {
                io::Error::new(io::ErrorKind::BrokenPipe, "relay pipe already used")
            }),
        )
    }
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

#[cfg(test)]
mod tests {
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use opentelemetry_proto::tonic::collector::metrics::v1::ExportMetricsServiceResponse;
    use opentelemetry_proto::tonic::collector::metrics::v1::metrics_service_server::{
        MetricsService, MetricsServiceServer,
    };
    use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};
    use tokio::sync::mpsc;
    use tonic::transport::server::Connected;
    use tonic::{Request, Response, Status};

    use super::*;

    struct CapturingMetricsService {
        requests: mpsc::UnboundedSender<ExportMetricsServiceRequest>,
    }

    #[tonic::async_trait]
    impl MetricsService for CapturingMetricsService {
        async fn export(
            &self,
            request: Request<ExportMetricsServiceRequest>,
        ) -> Result<Response<ExportMetricsServiceResponse>, Status> {
            let _ = self.requests.send(request.into_inner());
            Ok(Response::new(ExportMetricsServiceResponse::default()))
        }
    }

    struct ServerDuplex(DuplexStream);

    impl Connected for ServerDuplex {
        type ConnectInfo = ();

        fn connect_info(&self) -> Self::ConnectInfo {}
    }

    impl AsyncRead for ServerDuplex {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_read(cx, buffer)
        }
    }

    impl AsyncWrite for ServerDuplex {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<Result<usize, io::Error>> {
            Pin::new(&mut self.0).poll_write(cx, bytes)
        }

        fn poll_flush(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Result<(), io::Error>> {
            Pin::new(&mut self.0).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Result<(), io::Error>> {
            Pin::new(&mut self.0).poll_shutdown(cx)
        }
    }

    #[tokio::test]
    async fn exporter_should_send_over_provided_duplex() {
        let (client_pipe, server_pipe) = tokio::io::duplex(64 * 1024);
        let (requests_tx, mut requests_rx) = mpsc::unbounded_channel();
        let server = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(MetricsServiceServer::new(CapturingMetricsService {
                    requests: requests_tx,
                }))
                .serve_with_incoming(tokio_stream::once(Ok::<_, io::Error>(ServerDuplex(
                    server_pipe,
                ))))
                .await
        });
        let state = tempfile::tempdir().expect("temp state dir");
        let cfg = AgentConfig {
            state_dir: state.path().to_path_buf(),
            collector_endpoint: "http://127.0.0.1:1".to_owned(),
            relay: crate::config::RelayConfig {
                enabled: true,
                ..crate::config::RelayConfig::default()
            },
            ..AgentConfig::default()
        };
        let (pipe_tx, pipe_rx) = relay_transport_slot();
        assert!(pipe_tx.send(Box::new(client_pipe)).is_ok());
        let mut exporter =
            MetricsExporter::open_with_relay(&cfg, pipe_rx).expect("open relay exporter");
        let request = ExportMetricsServiceRequest::default();

        exporter
            .try_export(&cfg, request)
            .await
            .expect("export over provided duplex");

        let received = tokio::time::timeout(Duration::from_secs(5), requests_rx.recv())
            .await
            .expect("mock server timed out")
            .expect("mock request channel closed");
        assert!(received.resource_metrics.is_empty());
        server.abort();
    }
}
