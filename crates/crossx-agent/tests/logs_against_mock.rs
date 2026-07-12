use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use agent_telemetry::logs::LogRecordSample;
use crossx_agent::AgentConfig;
use crossx_agent::logs::{FileSource, LogsExporter, poll_file_sources, run_logs_loop};
use opentelemetry_proto::tonic::collector::logs::v1::logs_service_server::{
    LogsService, LogsServiceServer,
};
use opentelemetry_proto::tonic::collector::logs::v1::{
    ExportLogsServiceRequest, ExportLogsServiceResponse,
};
use opentelemetry_proto::tonic::common::v1::any_value;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{Request, Response, Status};

struct CapturingLogsService {
    requests: mpsc::UnboundedSender<ExportLogsServiceRequest>,
    failures_remaining: AtomicUsize,
}

#[tonic::async_trait]
impl LogsService for CapturingLogsService {
    async fn export(
        &self,
        request: Request<ExportLogsServiceRequest>,
    ) -> Result<Response<ExportLogsServiceResponse>, Status> {
        if self
            .failures_remaining
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |remaining| {
                remaining.checked_sub(1)
            })
            .is_ok()
        {
            return Err(Status::unavailable("injected logs export failure"));
        }
        let _ = self.requests.send(request.into_inner());
        Ok(Response::new(ExportLogsServiceResponse::default()))
    }
}

async fn spawn_flaky_logs_collector(
    failures: usize,
) -> (
    SocketAddr,
    mpsc::UnboundedReceiver<ExportLogsServiceRequest>,
) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind logs mock listener");
    let addr = listener.local_addr().expect("logs mock listener addr");
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(LogsServiceServer::new(CapturingLogsService {
                requests: tx,
                failures_remaining: AtomicUsize::new(failures),
            }))
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .expect("logs mock collector server");
    });
    (addr, rx)
}

fn config_for(addr: SocketAddr, state_dir: &std::path::Path) -> AgentConfig {
    AgentConfig {
        collector_endpoint: format!("http://{addr}"),
        node_id: "node-test".to_owned(),
        auth_token: String::new(),
        interval_secs: 5,
        state_dir: state_dir.to_path_buf(),
        ..AgentConfig::default()
    }
}

fn sample(body: &str, ts_ms: i64) -> LogRecordSample {
    LogRecordSample {
        ts_ms,
        severity: 9,
        body: body.to_owned(),
        attrs: vec![("log.source".to_owned(), "journald".to_owned())],
    }
}

fn request_body(request: &ExportLogsServiceRequest) -> Option<&str> {
    request
        .resource_logs
        .first()?
        .scope_logs
        .first()?
        .log_records
        .first()?
        .body
        .as_ref()?
        .value
        .as_ref()
        .and_then(|value| match value {
            any_value::Value::StringValue(value) => Some(value.as_str()),
            _ => None,
        })
}

#[tokio::test(start_paused = true)]
async fn logs_export_loop_should_replay_wal_in_fifo_order_against_flaky_collector() {
    let (addr, mut requests) = spawn_flaky_logs_collector(4).await;
    let state = tempfile::tempdir().expect("temp state dir");
    let cfg = config_for(addr, state.path());
    let mut exporter = LogsExporter::open(&cfg).expect("open logs exporter");

    exporter
        .export_records(&cfg, "host-test", &[sample("first", 1)])
        .await
        .expect("first logs batch should be durable in WAL");
    exporter
        .export_records(&cfg, "host-test", &[sample("second", 2)])
        .await
        .expect("second batch should queue and drain FIFO");

    let first = requests.recv().await.expect("first accepted logs request");
    let second = requests.recv().await.expect("second accepted logs request");

    assert_eq!(
        [request_body(&first), request_body(&second)],
        [Some("first"), Some("second")]
    );
    assert!(state.path().join("wal").join("logs").is_dir());
    assert!(!state.path().join("wal").join("metrics").exists());
}

#[tokio::test(start_paused = true)]
async fn run_logs_loop_should_keep_running_when_configured_log_file_is_missing() {
    let state = tempfile::tempdir().expect("temp state dir");
    let mut cfg = config_for("127.0.0.1:1".parse().expect("addr"), state.path());
    cfg.logs.enabled = true;
    cfg.logs.journald = false;
    cfg.logs.files = vec![state.path().join("does-not-exist.log")];

    // The loop must degrade to a warning and keep ticking, not return an
    // error (which would cancel the metrics loop in main's try_join).
    let outcome = tokio::time::timeout(Duration::from_millis(250), run_logs_loop(&cfg)).await;

    assert!(
        outcome.is_err(),
        "run_logs_loop returned instead of surviving a missing source: {outcome:?}"
    );
}

#[tokio::test(start_paused = true)]
async fn file_source_should_survive_rotation_window_and_resume_exporting() {
    let (addr, mut requests) = spawn_flaky_logs_collector(0).await;
    let state = tempfile::tempdir().expect("temp state dir");
    let cfg = config_for(addr, state.path());
    let mut exporter = LogsExporter::open(&cfg).expect("open logs exporter");
    let checkpoint_dir = state.path().join("checkpoints");
    let log_path = state.path().join("app.log");
    std::fs::write(&log_path, b"").expect("seed empty log");
    let mut sources = vec![FileSource::new(log_path.clone(), &checkpoint_dir)];

    std::fs::write(&log_path, b"line-one\n").expect("write first line");
    poll_file_sources(&cfg, "host-test", &mut exporter, &mut sources).await;
    // Rotation window: the file is briefly gone between remove and recreate.
    std::fs::remove_file(&log_path).expect("remove rotated log");
    poll_file_sources(&cfg, "host-test", &mut exporter, &mut sources).await;
    std::fs::write(&log_path, b"two\n").expect("recreate rotated log");
    poll_file_sources(&cfg, "host-test", &mut exporter, &mut sources).await;

    let first = requests.recv().await.expect("pre-rotation logs request");
    let second = requests.recv().await.expect("post-rotation logs request");

    assert_eq!(
        [request_body(&first), request_body(&second)],
        [Some("line-one"), Some("two")]
    );
}
