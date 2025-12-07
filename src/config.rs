use crate::error::{AgentError, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Application configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Server URL (default: https://app.telfin.io)
    pub server_url: String,
    /// Machine name (defaults to hostname)
    pub machine_name: String,
    /// WebSocket reconnect interval in seconds
    pub reconnect_interval: u64,
    /// Heartbeat interval in seconds
    pub heartbeat_interval: u64,
    /// Log level (trace, debug, info, warn, error)
    pub log_level: String,
    /// Shell command to spawn for sessions (default: None = use $SHELL or /bin/bash)
    /// Example: Some("ssh -tt localhost".to_string()) or Some("/bin/zsh".to_string())
    #[serde(default)]
    pub shell_command: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server_url: "https://app.telfin.io".to_string(),
            machine_name: crate::fingerprint::get_device_name(),
            reconnect_interval: 5,
            heartbeat_interval: 30,
            log_level: "info".to_string(),
            shell_command: None,
        }
    }
}

impl Config {
    /// Load configuration from file or create default
    pub fn load() -> Result<Self> {
        let config_path = Self::config_file_path()?;

        if config_path.exists() {
            let contents = std::fs::read_to_string(&config_path)?;
            let config: Config = serde_json::from_str(&contents)?;
            Ok(config)
        } else {
            Ok(Self::default())
        }
    }

    /// Save configuration to file
    pub fn save(&self) -> Result<()> {
        let config_path = Self::config_file_path()?;

        if let Some(parent) = config_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let contents = serde_json::to_string_pretty(self)?;
        std::fs::write(&config_path, contents)?;

        Ok(())
    }

    /// Get the config file path
    pub fn config_file_path() -> Result<PathBuf> {
        let config_dir = dirs::config_dir().ok_or_else(|| {
            AgentError::ConfigError("Could not find config directory".to_string())
        })?;

        Ok(config_dir.join("telfin").join("config.json"))
    }

    /// Get the state directory path
    pub fn state_dir() -> Result<PathBuf> {
        let state_dir = dirs::data_local_dir()
            .ok_or_else(|| AgentError::ConfigError("Could not find state directory".to_string()))?;

        let telfin_dir = state_dir.join("telfin");
        std::fs::create_dir_all(&telfin_dir)?;

        Ok(telfin_dir)
    }

    /// Get the PID file path
    pub fn pid_file_path() -> Result<PathBuf> {
        Ok(Self::state_dir()?.join("telfin-agent.pid"))
    }

    /// Get WebSocket URL
    pub fn websocket_url(&self) -> String {
        self.server_url
            .replace("https://", "wss://")
            .replace("http://", "ws://")
    }

    /// Get API base URL
    pub fn api_url(&self) -> String {
        format!("{}/api", self.server_url)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.server_url, "https://app.telfin.io");
        assert!(!config.machine_name.is_empty());
        assert_eq!(config.reconnect_interval, 5);
        assert_eq!(config.heartbeat_interval, 30);
    }

    #[test]
    fn test_websocket_url() {
        let mut config = Config::default();
        config.server_url = "https://app.telfin.io".to_string();
        assert_eq!(config.websocket_url(), "wss://app.telfin.io");

        config.server_url = "http://localhost:3000".to_string();
        assert_eq!(config.websocket_url(), "ws://localhost:3000");
    }

    #[test]
    fn test_api_url() {
        let mut config = Config::default();
        config.server_url = "https://app.telfin.io".to_string();
        assert_eq!(config.api_url(), "https://app.telfin.io/api");
    }
}
