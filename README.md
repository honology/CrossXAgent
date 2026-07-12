# crossx-agent

crossx-agent is the unified VM-side daemon for CrossXCloud observability: it
samples host metrics (CPU, memory, network, disk, load) using OTel `system.*`
semantic conventions and ships them over OTLP/gRPC to a `pulse-collector`
instance. At M3 it will also own the crossx-relay connection for the VM —
one persistent Ed25519-authenticated registration serving multiplexed scopes
(telemetry now, SSH/SFTP proxy streams later). See the design spec in the
`crossx-pulse` repo: `docs/design/2026-07-12-pulse-observability-pipeline-design.md`.

Build and test:

```powershell
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
```

Run a single export tick against a local collector:

```powershell
cargo run -p crossx-agent -- run --once
```
