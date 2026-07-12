//! Library surface of the crossx-agent binary. It exists so integration
//! tests can drive exactly the export path `main` uses.

pub mod config;
pub mod export;
pub mod wal;

pub use config::AgentConfig;

use agent_telemetry::HostSampler;

/// Samples a single tick and exports it to the configured collector.
/// Backs `crossx-agent run --once`.
pub async fn run_once(cfg: &AgentConfig) -> anyhow::Result<()> {
    let mut sampler = HostSampler::new();
    export::export_tick(cfg, &mut sampler).await
}
