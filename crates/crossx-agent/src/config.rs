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
}
