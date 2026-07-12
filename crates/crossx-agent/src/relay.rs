use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use crossx_agent::config::{AgentConfig, RelayConfig};
use crossx_agent::export::{RelayTransportIo, RelayTransportSender};
use crossx_relay::{Peer, PeerKind, ProxyHeader, ProxyStream, RelayConfig as PeerConfig};
use tokio::io::copy_bidirectional;
use tokio::net::TcpStream;

const INITIAL_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(60);

#[derive(Debug, Eq, PartialEq)]
enum ProxyRoute {
    Telemetry,
    LocalDial(u16),
}

fn route_proxy(header: &ProxyHeader, cfg: &RelayConfig) -> ProxyRoute {
    if header.port == cfg.telemetry_port {
        ProxyRoute::Telemetry
    } else {
        ProxyRoute::LocalDial(header.port)
    }
}

pub(super) async fn run(cfg: &AgentConfig, telemetry: RelayTransportSender) -> anyhow::Result<()> {
    let peer_cfg = load_peer_config(&cfg.relay)?;
    let target_id = if cfg.relay.target_id.is_empty() {
        cfg.node_id.as_str()
    } else {
        cfg.relay.target_id.as_str()
    };
    let mut backoff = INITIAL_BACKOFF;

    loop {
        let mut peer = match Peer::connect(&peer_cfg, PeerKind::Agent).await {
            Ok(peer) => peer,
            Err(error) => {
                tracing::warn!("relay connection failed: {error}");
                sleep_before_reconnect(&mut backoff).await;
                continue;
            }
        };
        if let Err(error) = peer.register(target_id, "tcp").await {
            tracing::warn!("relay registration failed: {error}");
            sleep_before_reconnect(&mut backoff).await;
            continue;
        }
        tracing::info!(target_id, "relay target registered");
        backoff = INITIAL_BACKOFF;

        loop {
            match peer.next_proxy().await {
                Ok(proxy) => route_stream(proxy, &cfg.relay, &telemetry)?,
                Err(error) => {
                    tracing::warn!("relay proxy loop failed: {error}");
                    sleep_before_reconnect(&mut backoff).await;
                    break;
                }
            }
        }
    }
}

fn route_stream(
    proxy: ProxyStream,
    cfg: &RelayConfig,
    telemetry: &RelayTransportSender,
) -> anyhow::Result<()> {
    match route_proxy(&proxy.header, cfg) {
        ProxyRoute::Telemetry => telemetry
            .send(Box::new(proxy.stream))
            .map_err(|_| anyhow::anyhow!("relay telemetry transport slot closed")),
        ProxyRoute::LocalDial(port) => {
            tokio::spawn(async move {
                if let Err(error) = forward_local(proxy.stream, port).await {
                    tracing::warn!(port, "relay local proxy failed: {error:#}");
                }
            });
            Ok(())
        }
    }
}

async fn forward_local(mut relay: impl RelayTransportIo, port: u16) -> anyhow::Result<()> {
    let mut local = TcpStream::connect(("127.0.0.1", port))
        .await
        .with_context(|| format!("dialing relay proxy destination 127.0.0.1:{port}"))?;
    // copy_bidirectional propagates EOF by shutting down the opposite writer,
    // preserving half-close in each direction.
    copy_bidirectional(&mut relay, &mut local)
        .await
        .with_context(|| format!("copying relay proxy traffic for 127.0.0.1:{port}"))?;
    Ok(())
}

fn load_peer_config(cfg: &RelayConfig) -> anyhow::Result<PeerConfig> {
    let root_cert_pem = std::fs::read(Path::new(&cfg.root_cert))
        .with_context(|| format!("reading relay root certificate {}", cfg.root_cert))?;
    let encoded_seed = std::fs::read_to_string(Path::new(&cfg.key_file))
        .with_context(|| format!("reading relay key file {}", cfg.key_file))?;
    let seed = STANDARD
        .decode(encoded_seed.trim())
        .context("decoding base64 relay Ed25519 seed")?;
    let seed_len = seed.len();
    let key_seed = seed.try_into().map_err(|_seed: Vec<u8>| {
        anyhow::anyhow!("relay Ed25519 seed must be exactly 32 bytes, got {seed_len}")
    })?;

    Ok(PeerConfig {
        addr: cfg.addr.clone(),
        root_cert_pem,
        key_seed,
        principal: cfg.principal.clone(),
    })
}

async fn sleep_before_reconnect(backoff: &mut Duration) {
    let delay = (*backoff + reconnect_jitter(*backoff)).min(MAX_BACKOFF);
    tokio::time::sleep(delay).await;
    *backoff = backoff.saturating_mul(2).min(MAX_BACKOFF);
}

fn reconnect_jitter(backoff: Duration) -> Duration {
    let ceiling_ms = u64::try_from(backoff.as_millis() / 4).unwrap_or(u64::MAX);
    if ceiling_ms == 0 {
        return Duration::ZERO;
    }
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.subsec_nanos());
    Duration::from_millis(u64::from(nanos) % ceiling_ms)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(port: u16) -> ProxyHeader {
        ProxyHeader {
            tunnel_id: "tunnel-test".to_owned(),
            proto: "tcp".to_owned(),
            port,
            client_addr: None,
        }
    }

    #[test]
    fn telemetry_port_should_route_to_exporter_transport_slot() {
        let cfg = RelayConfig {
            telemetry_port: 4317,
            ..RelayConfig::default()
        };

        assert_eq!(route_proxy(&header(4317), &cfg), ProxyRoute::Telemetry);
    }

    #[test]
    fn any_other_port_should_route_to_loopback_dial() {
        let cfg = RelayConfig {
            telemetry_port: 4317,
            ..RelayConfig::default()
        };

        assert_eq!(route_proxy(&header(22), &cfg), ProxyRoute::LocalDial(22));
    }
}
