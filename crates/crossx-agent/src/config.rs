use std::path::{Path, PathBuf};

use anyhow::Context;
use serde::Deserialize;

/// Log sources collected by the agent.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default)]
pub struct LogsConfig {
    /// Enables file and journald collection. Off by default for v1.
    pub enabled: bool,
    /// Explicit log file paths. Globs are intentionally unsupported in v1.
    pub files: Vec<PathBuf>,
    /// Follows the systemd journal on Unix hosts.
    pub journald: bool,
}

/// Relay connection and telemetry proxy settings.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default)]
pub struct RelayConfig {
    /// Enables relay transport. Direct OTLP remains the default.
    pub enabled: bool,
    /// Relay TCP authority, such as `relay.example.com:8443`.
    pub addr: String,
    /// Path to the pinned relay certificate PEM.
    pub root_cert: String,
    /// Path to the base64-encoded Ed25519 seed file.
    pub key_file: String,
    /// Path to the signed enrollment JSON (M1 enrollment auth). Empty selects the
    /// M0 pubkey path (authenticating as `principal`).
    pub enrollment_file: String,
    /// Registered relay principal (M0 pubkey path).
    pub principal: String,
    /// Registered target ID. Empty uses the agent node ID.
    pub target_id: String,
    /// Relay proxy port reserved for in-process OTLP telemetry.
    pub telemetry_port: u16,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            addr: String::new(),
            root_cert: String::new(),
            key_file: String::new(),
            enrollment_file: String::new(),
            principal: String::new(),
            target_id: String::new(),
            telemetry_port: 4317,
        }
    }
}

impl Default for LogsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            files: vec![PathBuf::from("/var/log/syslog")],
            journald: false,
        }
    }
}

/// Agent configuration: defaults, overlaid by a TOML file, overlaid by
/// `CROSSX_AGENT_*` environment variables.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default)]
pub struct AgentConfig {
    /// OTLP/gRPC collector endpoint, e.g. `http://127.0.0.1:4317`.
    pub collector_endpoint: String,
    /// Value of the `crossx.node.id` resource attribute — the join key
    /// between canvas compute nodes and their series (spec §6).
    pub node_id: String,
    /// Optional Bearer token sent as `authorization` request metadata.
    pub auth_token: String,
    /// Seconds between export ticks.
    pub interval_secs: u64,
    /// Persistent agent state root. Signal-specific WALs live below `wal/`.
    pub state_dir: PathBuf,
    /// Maximum bytes retained by each signal-specific WAL.
    pub wal_max_bytes: u64,
    /// File and journald collection settings.
    pub logs: LogsConfig,
    /// Relay transport settings.
    pub relay: RelayConfig,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            collector_endpoint: "http://127.0.0.1:4317".to_owned(),
            node_id: "node-dev".to_owned(),
            auth_token: String::new(),
            interval_secs: 5,
            state_dir: default_state_dir(),
            wal_max_bytes: 64 * 1024 * 1024,
            logs: LogsConfig::default(),
            relay: RelayConfig::default(),
        }
    }
}

impl AgentConfig {
    /// Loads configuration with precedence defaults < TOML file < env vars.
    pub fn load(path: Option<&Path>) -> anyhow::Result<Self> {
        let mut cfg = match path {
            Some(path) => {
                let raw = std::fs::read_to_string(path)
                    .with_context(|| format!("reading config file {}", path.display()))?;
                toml::from_str(&raw)
                    .with_context(|| format!("parsing config file {}", path.display()))?
            }
            None => Self::default(),
        };
        cfg.apply_env(|name| std::env::var(name).ok())?;
        Ok(cfg)
    }

    /// Applies `CROSSX_AGENT_*` overrides. The lookup is injected so tests
    /// can exercise precedence without mutating process-global env state.
    fn apply_env(&mut self, lookup: impl Fn(&str) -> Option<String>) -> anyhow::Result<()> {
        if let Some(value) = lookup("CROSSX_AGENT_COLLECTOR_ENDPOINT") {
            self.collector_endpoint = value;
        }
        if let Some(value) = lookup("CROSSX_AGENT_NODE_ID") {
            self.node_id = value;
        }
        if let Some(value) = lookup("CROSSX_AGENT_AUTH_TOKEN") {
            self.auth_token = value;
        }
        if let Some(value) = lookup("CROSSX_AGENT_INTERVAL_SECS") {
            self.interval_secs = value
                .parse()
                .context("CROSSX_AGENT_INTERVAL_SECS must be a non-negative integer")?;
        }
        if let Some(value) = lookup("CROSSX_AGENT_STATE_DIR") {
            self.state_dir = PathBuf::from(value);
        }
        if let Some(value) = lookup("CROSSX_AGENT_WAL_MAX_BYTES") {
            self.wal_max_bytes = value
                .parse()
                .context("CROSSX_AGENT_WAL_MAX_BYTES must be a non-negative integer")?;
        }
        if let Some(value) = lookup("CROSSX_AGENT_RELAY_ENABLED") {
            self.relay.enabled = value
                .parse()
                .context("CROSSX_AGENT_RELAY_ENABLED must be true or false")?;
        }
        if let Some(value) = lookup("CROSSX_AGENT_RELAY_ADDR") {
            self.relay.addr = value;
        }
        if let Some(value) = lookup("CROSSX_AGENT_RELAY_ROOT_CERT") {
            self.relay.root_cert = value;
        }
        if let Some(value) = lookup("CROSSX_AGENT_RELAY_KEY_FILE") {
            self.relay.key_file = value;
        }
        if let Some(value) = lookup("CROSSX_AGENT_RELAY_ENROLLMENT_FILE") {
            self.relay.enrollment_file = value;
        }
        if let Some(value) = lookup("CROSSX_AGENT_RELAY_PRINCIPAL") {
            self.relay.principal = value;
        }
        if let Some(value) = lookup("CROSSX_AGENT_RELAY_TARGET_ID") {
            self.relay.target_id = value;
        }
        if let Some(value) = lookup("CROSSX_AGENT_RELAY_TELEMETRY_PORT") {
            self.relay.telemetry_port = value
                .parse()
                .context("CROSSX_AGENT_RELAY_TELEMETRY_PORT must be a valid u16 port")?;
        }
        Ok(())
    }
}

fn default_state_dir() -> PathBuf {
    dirs_next::data_dir().map_or_else(
        || PathBuf::from(".").join("crossx-agent"),
        |dir| dir.join("crossx-agent"),
    )
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    #[test]
    fn default_config_should_target_local_collector_when_nothing_is_set() {
        let cfg = AgentConfig::default();

        assert_eq!(cfg.collector_endpoint, "http://127.0.0.1:4317");
        assert_eq!(cfg.node_id, "node-dev");
        assert_eq!(cfg.auth_token, "");
        assert_eq!(cfg.interval_secs, 5);
        assert!(cfg.state_dir.ends_with("crossx-agent"));
        assert_eq!(cfg.wal_max_bytes, 64 * 1024 * 1024);
        assert_eq!(cfg.logs, LogsConfig::default());
        assert_eq!(cfg.relay, RelayConfig::default());
    }

    #[test]
    fn toml_should_override_defaults_when_keys_are_present() {
        let cfg: AgentConfig = toml::from_str(
            r#"
            collector_endpoint = "http://10.0.0.9:4317"
            node_id = "node-abc"
            state_dir = "D:/crossx-state"
            wal_max_bytes = 2048
            "#,
        )
        .expect("valid TOML");

        assert_eq!(cfg.collector_endpoint, "http://10.0.0.9:4317");
        assert_eq!(cfg.node_id, "node-abc");
        assert_eq!(cfg.state_dir, Path::new("D:/crossx-state"));
        assert_eq!(cfg.wal_max_bytes, 2048);
        // Unset keys keep their defaults.
        assert_eq!(cfg.interval_secs, 5);
    }

    #[test]
    fn env_should_override_toml_when_both_are_set() {
        let mut cfg: AgentConfig = toml::from_str(r#"node_id = "from-toml""#).expect("valid TOML");

        cfg.apply_env(|name| match name {
            "CROSSX_AGENT_NODE_ID" => Some("from-env".to_owned()),
            "CROSSX_AGENT_INTERVAL_SECS" => Some("30".to_owned()),
            _ => None,
        })
        .expect("env overrides apply");

        assert_eq!(cfg.node_id, "from-env");
        assert_eq!(cfg.interval_secs, 30);
    }

    #[test]
    fn apply_env_should_fail_when_interval_is_not_an_integer() {
        let mut cfg = AgentConfig::default();

        let result =
            cfg.apply_env(|name| (name == "CROSSX_AGENT_INTERVAL_SECS").then(|| "soon".to_owned()));

        assert!(result.is_err());
    }

    #[test]
    fn env_should_override_state_dir_and_wal_max_bytes() {
        let mut cfg = AgentConfig::default();

        cfg.apply_env(|name| match name {
            "CROSSX_AGENT_STATE_DIR" => Some("D:/crossx-state".to_owned()),
            "CROSSX_AGENT_WAL_MAX_BYTES" => Some("4096".to_owned()),
            _ => None,
        })
        .expect("env overrides apply");

        assert_eq!(cfg.state_dir, Path::new("D:/crossx-state"));
        assert_eq!(cfg.wal_max_bytes, 4096);
    }

    #[test]
    fn load_should_read_toml_file_when_path_is_given() {
        let mut file = tempfile::NamedTempFile::new().expect("temp file");
        write!(file, r#"node_id = "node-from-file""#).expect("write config");

        let cfg = AgentConfig::load(Some(file.path())).expect("load config");

        assert_eq!(cfg.node_id, "node-from-file");
    }

    #[test]
    fn load_should_fail_when_file_is_missing() {
        let result = AgentConfig::load(Some(Path::new("Z:/definitely/not/here.toml")));

        assert!(result.is_err());
    }

    #[test]
    fn logs_toml_section_should_override_defaults() {
        let cfg: AgentConfig = toml::from_str(
            r#"
            [logs]
            enabled = true
            files = ["/var/log/messages", "/opt/crossx/app.log"]
            journald = true
            "#,
        )
        .expect("valid logs config");

        assert!(cfg.logs.enabled);
        assert_eq!(
            cfg.logs.files,
            [
                PathBuf::from("/var/log/messages"),
                PathBuf::from("/opt/crossx/app.log"),
            ]
        );
        assert!(cfg.logs.journald);
    }

    #[test]
    fn relay_toml_section_should_parse_all_locked_keys() {
        let cfg: AgentConfig = toml::from_str(
            r#"
            [relay]
            enabled = true
            addr = "relay.example.com:8443"
            root_cert = "C:/crossx/relay-cert.pem"
            key_file = "C:/crossx/agent.ed25519"
            enrollment_file = "C:/crossx/agent-enrollment.json"
            principal = "agent-prod"
            target_id = "target-prod"
            telemetry_port = 5317
            "#,
        )
        .expect("valid relay config");

        assert!(cfg.relay.enabled);
        assert_eq!(cfg.relay.addr, "relay.example.com:8443");
        assert_eq!(cfg.relay.root_cert, "C:/crossx/relay-cert.pem");
        assert_eq!(cfg.relay.key_file, "C:/crossx/agent.ed25519");
        assert_eq!(cfg.relay.enrollment_file, "C:/crossx/agent-enrollment.json");
        assert_eq!(cfg.relay.principal, "agent-prod");
        assert_eq!(cfg.relay.target_id, "target-prod");
        assert_eq!(cfg.relay.telemetry_port, 5317);
    }

    #[test]
    fn relay_env_should_override_toml_for_all_locked_keys() {
        let mut cfg = AgentConfig::default();

        cfg.apply_env(|name| match name {
            "CROSSX_AGENT_RELAY_ENABLED" => Some("true".to_owned()),
            "CROSSX_AGENT_RELAY_ADDR" => Some("127.0.0.1:8443".to_owned()),
            "CROSSX_AGENT_RELAY_ROOT_CERT" => Some("relay.pem".to_owned()),
            "CROSSX_AGENT_RELAY_KEY_FILE" => Some("agent.ed25519".to_owned()),
            "CROSSX_AGENT_RELAY_ENROLLMENT_FILE" => Some("agent-enrollment.json".to_owned()),
            "CROSSX_AGENT_RELAY_PRINCIPAL" => Some("agent-e2e".to_owned()),
            "CROSSX_AGENT_RELAY_TARGET_ID" => Some("e2e-node".to_owned()),
            "CROSSX_AGENT_RELAY_TELEMETRY_PORT" => Some("4318".to_owned()),
            _ => None,
        })
        .expect("relay env overrides apply");

        assert_eq!(
            cfg.relay,
            RelayConfig {
                enabled: true,
                addr: "127.0.0.1:8443".to_owned(),
                root_cert: "relay.pem".to_owned(),
                key_file: "agent.ed25519".to_owned(),
                enrollment_file: "agent-enrollment.json".to_owned(),
                principal: "agent-e2e".to_owned(),
                target_id: "e2e-node".to_owned(),
                telemetry_port: 4318,
            }
        );
    }
}
