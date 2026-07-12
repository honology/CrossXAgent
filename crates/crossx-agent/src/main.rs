//! crossx-agent binary: samples host metrics and ships them to a
//! pulse-collector over OTLP/gRPC.
//
// TODO(crossx-pulse design spec §5, "Self-update"): keep the agent current
// via a cron-scheduled check pinned to the latest production GitHub release
// (checksum/signature-verified download, atomic binary swap, health-checked
// restart with rollback on failure). Post-v1; until it lands, bootstrap
// re-provisioning is the update path.

use std::path::PathBuf;
use std::time::Duration;

use agent_telemetry::HostSampler;
use clap::{Parser, Subcommand};
use crossx_agent::config::AgentConfig;
use crossx_agent::export;

#[derive(Parser)]
#[command(
    name = "crossx-agent",
    version,
    about = "CrossXCloud VM telemetry agent"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Sample host metrics and export them over OTLP/gRPC.
    Run {
        /// Path to a TOML config file.
        #[arg(long)]
        config: Option<PathBuf>,
        /// Export a single tick, then exit 0 on success / 1 on failure.
        #[arg(long)]
        once: bool,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    match cli.command {
        Command::Run { config, once } => {
            let cfg = AgentConfig::load(config.as_deref())?;
            if once {
                crossx_agent::run_once(&cfg).await
            } else {
                run_loop(&cfg).await
            }
        }
    }
}

/// Exports forever at the configured cadence, preserving failed batches in
/// the metrics WAL for strict-FIFO replay on later ticks.
async fn run_loop(cfg: &AgentConfig) -> anyhow::Result<()> {
    let mut sampler = HostSampler::new();
    let mut exporter = export::MetricsExporter::open(cfg)?;
    let mut ticker = tokio::time::interval(Duration::from_secs(cfg.interval_secs.max(1)));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        if let Err(error) = exporter.export_tick(cfg, &mut sampler).await {
            tracing::warn!("metrics export deferred to WAL: {error:#}");
        }
    }
}
