//! Integration tests driving the agent's export path (the same `run_once`
//! that `main --once` uses) against an in-process OTLP metrics mock.

use std::net::SocketAddr;
use std::time::Duration;

use crossx_agent::{AgentConfig, run_once};
use opentelemetry_proto::tonic::collector::metrics::v1::metrics_service_server::{
    MetricsService, MetricsServiceServer,
};
use opentelemetry_proto::tonic::collector::metrics::v1::{
    ExportMetricsServiceRequest, ExportMetricsServiceResponse,
};
use opentelemetry_proto::tonic::common::v1::any_value;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{Request, Response, Status};

struct CapturingMetricsService {
    requests: mpsc::UnboundedSender<ExportMetricsServiceRequest>,
}

#[tonic::async_trait]
impl MetricsService for CapturingMetricsService {
    async fn export(
        &self,
        request: Request<ExportMetricsServiceRequest>,
    ) -> Result<Response<ExportMetricsServiceResponse>, Status> {
        // A dropped receiver only means the assertion phase already ended.
        let _ = self.requests.send(request.into_inner());
        Ok(Response::new(ExportMetricsServiceResponse::default()))
    }
}

async fn spawn_mock_collector() -> (
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
            }))
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .expect("mock collector server");
    });
    (addr, rx)
}

fn config_for(addr: SocketAddr) -> AgentConfig {
    AgentConfig {
        collector_endpoint: format!("http://{addr}"),
        node_id: "node-test".to_owned(),
        auth_token: String::new(),
        interval_secs: 5,
    }
}

#[tokio::test]
async fn run_once_should_deliver_labeled_request_when_collector_is_reachable() {
    let (addr, mut requests) = spawn_mock_collector().await;
    let cfg = config_for(addr);

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

#[tokio::test]
async fn run_once_should_fail_when_collector_port_is_dead() {
    // Reserve a port, then close the listener so nothing accepts on it.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("reserve port");
    let addr = listener.local_addr().expect("reserved addr");
    drop(listener);
    let cfg = config_for(addr);

    let result = run_once(&cfg).await;

    assert!(result.is_err(), "export against a dead port should fail");
}
