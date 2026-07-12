//! Integration tests driving the agent's export path (the same `run_once`
//! that `main --once` uses) against an in-process OTLP metrics mock.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use agent_telemetry::build_export_request;
use crossx_agent::export::MetricsExporter;
use crossx_agent::wal::Wal;
use crossx_agent::{AgentConfig, run_once};
use opentelemetry_proto::tonic::collector::metrics::v1::metrics_service_client::MetricsServiceClient;
use opentelemetry_proto::tonic::collector::metrics::v1::metrics_service_server::{
    MetricsService, MetricsServiceServer,
};
use opentelemetry_proto::tonic::collector::metrics::v1::{
    ExportMetricsServiceRequest, ExportMetricsServiceResponse,
};
use opentelemetry_proto::tonic::common::v1::any_value;
use prost::Message;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{Request, Response, Status};

struct CapturingMetricsService {
    requests: mpsc::UnboundedSender<ExportMetricsServiceRequest>,
    failures_remaining: AtomicUsize,
}

#[tonic::async_trait]
impl MetricsService for CapturingMetricsService {
    async fn export(
        &self,
        request: Request<ExportMetricsServiceRequest>,
    ) -> Result<Response<ExportMetricsServiceResponse>, Status> {
        if self
            .failures_remaining
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |remaining| {
                remaining.checked_sub(1)
            })
            .is_ok()
        {
            return Err(Status::unavailable("injected export failure"));
        }
        // A dropped receiver only means the assertion phase already ended.
        let _ = self.requests.send(request.into_inner());
        Ok(Response::new(ExportMetricsServiceResponse::default()))
    }
}

async fn spawn_mock_collector() -> (
    SocketAddr,
    mpsc::UnboundedReceiver<ExportMetricsServiceRequest>,
) {
    spawn_flaky_mock_collector(0).await
}

async fn spawn_flaky_mock_collector(
    failures: usize,
) -> (
    SocketAddr,
    mpsc::UnboundedReceiver<ExportMetricsServiceRequest>,
) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock listener");
    let addr = listener.local_addr().expect("mock listener addr");
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(MetricsServiceServer::new(CapturingMetricsService {
                requests: tx,
                failures_remaining: AtomicUsize::new(failures),
            }))
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .expect("mock collector server");
    });
    (addr, rx)
}

fn request_node_id(request: &ExportMetricsServiceRequest) -> Option<&str> {
    request
        .resource_metrics
        .first()
        .and_then(|rm| rm.resource.as_ref())
        .and_then(|resource| {
            resource
                .attributes
                .iter()
                .find(|kv| kv.key == "crossx.node.id")
        })
        .and_then(|kv| kv.value.as_ref())
        .and_then(|value| value.value.as_ref())
        .and_then(|value| match value {
            any_value::Value::StringValue(value) => Some(value.as_str()),
            _ => None,
        })
}

fn config_for(addr: SocketAddr) -> AgentConfig {
    AgentConfig {
        collector_endpoint: format!("http://{addr}"),
        node_id: "node-test".to_owned(),
        auth_token: String::new(),
        interval_secs: 5,
        ..AgentConfig::default()
    }
}

#[tokio::test]
async fn run_once_should_deliver_labeled_request_when_collector_is_reachable() {
    let (addr, mut requests) = spawn_mock_collector().await;
    let state = tempfile::tempdir().expect("temp state dir");
    let mut cfg = config_for(addr);
    cfg.state_dir = state.path().to_path_buf();

    run_once(&cfg).await.expect("run_once against live mock");

    let request = tokio::time::timeout(Duration::from_secs(5), requests.recv())
        .await
        .expect("no export request within 5s")
        .expect("request channel closed");

    let resource = request
        .resource_metrics
        .first()
        .and_then(|rm| rm.resource.as_ref())
        .expect("resource missing");
    let node_id = resource
        .attributes
        .iter()
        .find(|kv| kv.key == "crossx.node.id")
        .and_then(|kv| kv.value.as_ref())
        .and_then(|v| v.value.as_ref());
    assert!(
        matches!(node_id, Some(any_value::Value::StringValue(s)) if s == "node-test"),
        "crossx.node.id should be node-test, got {node_id:?}"
    );

    let metric_count: usize = request
        .resource_metrics
        .iter()
        .flat_map(|rm| rm.scope_metrics.iter())
        .map(|sm| sm.metrics.len())
        .sum();
    assert!(
        metric_count >= 5,
        "expected at least 5 metrics, got {metric_count}"
    );
}

#[tokio::test(start_paused = true)]
async fn run_once_should_fail_within_bounded_time_when_collector_accepts_but_never_responds() {
    // The bound listener's kernel backlog completes the TCP handshake, but
    // nothing ever accepts the connection or answers the HTTP/2 preface —
    // the classic hung/black-holed collector. Paused time auto-advances the
    // tokio clock, so the virtual retry budget elapses in wall-time
    // milliseconds; the 300s guard only trips if run_once hangs unbounded.
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind silent listener");
    let addr = listener.local_addr().expect("silent listener addr");
    let state = tempfile::tempdir().expect("temp state dir");
    let mut cfg = config_for(addr);
    cfg.state_dir = state.path().to_path_buf();

    let result = tokio::time::timeout(Duration::from_secs(300), run_once(&cfg)).await;

    let run_result =
        result.expect("run_once should give up within its bounded retry budget, not hang");
    assert!(
        run_result.is_err(),
        "export against an unresponsive collector should fail"
    );
}

#[tokio::test]
async fn run_once_should_fail_when_collector_port_is_dead() {
    // Reserve a port, then close the listener so nothing accepts on it.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("reserve port");
    let addr = listener.local_addr().expect("reserved addr");
    drop(listener);
    let state = tempfile::tempdir().expect("temp state dir");
    let mut cfg = config_for(addr);
    cfg.state_dir = state.path().to_path_buf();

    let result = run_once(&cfg).await;

    assert!(result.is_err(), "export against a dead port should fail");
}

#[tokio::test(start_paused = true)]
async fn export_loop_should_replay_wal_in_fifo_order_against_flaky_collector() {
    let (addr, mut requests) = spawn_flaky_mock_collector(4).await;
    let temp = tempfile::tempdir().expect("temp state dir");
    let mut cfg = config_for(addr);
    cfg.state_dir = temp.path().to_path_buf();
    cfg.node_id = "first".to_owned();
    let mut exporter = MetricsExporter::open(&cfg).expect("open exporter");
    let mut sampler = agent_telemetry::HostSampler::new();

    let first_result = exporter.export_tick(&cfg, &mut sampler).await;
    assert!(
        first_result.is_err(),
        "first batch should be queued after retries"
    );
    cfg.node_id = "second".to_owned();
    exporter
        .export_tick(&cfg, &mut sampler)
        .await
        .expect("drain queued batches");

    let first = requests.recv().await.expect("first accepted request");
    let second = requests.recv().await.expect("second accepted request");
    let ordered_node_ids = [request_node_id(&first), request_node_id(&second)];

    assert_eq!(ordered_node_ids, [Some("first"), Some("second")]);
}

#[tokio::test]
async fn kill_between_export_and_ack_should_replay_entry() {
    let (addr, mut requests) = spawn_mock_collector().await;
    let state = tempfile::tempdir().expect("temp state dir");
    let mut cfg = config_for(addr);
    cfg.state_dir = state.path().to_path_buf();
    let wal_dir = cfg.state_dir.join("wal").join("metrics");
    let mut wal = Wal::open(&wal_dir, cfg.wal_max_bytes).expect("open WAL");
    let request = build_export_request("replayed", "test-host", 1, &[]);
    wal.append(&request.encode_to_vec())
        .expect("append request");
    let entry = wal.next().expect("read WAL").expect("pending request");
    let replayed_request = ExportMetricsServiceRequest::decode(entry.payload.as_slice())
        .expect("decode pending request");
    let mut client = MetricsServiceClient::connect(cfg.collector_endpoint.clone())
        .await
        .expect("connect mock collector");
    client
        .export(replayed_request)
        .await
        .expect("export before simulated kill");
    drop(wal);

    cfg.node_id = "fresh".to_owned();
    let mut exporter = MetricsExporter::open(&cfg).expect("reopen exporter after kill");
    let mut sampler = agent_telemetry::HostSampler::new();
    exporter
        .export_tick(&cfg, &mut sampler)
        .await
        .expect("replay unacked request");

    let first = requests.recv().await.expect("pre-kill delivery");
    let second = requests.recv().await.expect("replayed delivery");
    let third = requests.recv().await.expect("fresh delivery");
    let delivered_node_ids = [
        request_node_id(&first),
        request_node_id(&second),
        request_node_id(&third),
    ];

    assert_eq!(
        delivered_node_ids,
        [Some("replayed"), Some("replayed"), Some("fresh")]
    );
}
