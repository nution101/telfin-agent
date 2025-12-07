use crate::error::{AgentError, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Allowed shell commands for security
const ALLOWED_SHELLS: &[&str] = &[
    "/bin/bash",
    "/bin/sh",
    "/bin/zsh",
    "/usr/bin/bash",
    "/usr/bin/sh",
    "/usr/bin/zsh",
    "/usr/bin/fish",
    "/usr/local/bin/bash",
    "/usr/local/bin/zsh",
    "/usr/local/bin/fish",
];

#[cfg(windows)]
const ALLOWED_WINDOWS_SHELLS: &[&str] = &[
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
];

/// Application configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Server URL (default: https://gateway.telfin.io)
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
    /// Expected gateway certificate SHA-256 fingerprint (optional)
    /// Format: hex string like "AB:CD:EF:..." or "abcdef..."
    /// If None, standard certificate validation is used
    #[serde(default)]
    pub tls_cert_fingerprint: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server_url: "https://gateway.telfin.io".to_string(),
            machine_name: crate::fingerprint::get_device_name(),
            reconnect_interval: 5,
            heartbeat_interval: 15,
            log_level: "info".to_string(),
            shell_command: None,
            tls_cert_fingerprint: None,
        }
    }
}

impl Config {
    /// Load configuration from file or create default
    pub fn load() -> Result<Self> {
        let config_path = Self::config_file_path()?;

        let config = if config_path.exists() {
            let contents = std::fs::read_to_string(&config_path)?;
            serde_json::from_str(&contents)?
        } else {
            Self::default()
        };

        // Validate configuration
        config.validate()?;
        Ok(config)
    }

    /// Validate configuration values
    fn validate(&self) -> Result<()> {
        // Validate heartbeat_interval (5-300 seconds)
        if self.heartbeat_interval < 5 || self.heartbeat_interval > 300 {
            return Err(AgentError::ConfigError(format!(
                "heartbeat_interval must be between 5 and 300 seconds, got {}",
                self.heartbeat_interval
            )));
        }

        // Validate reconnect_interval (1-60 seconds)
        if self.reconnect_interval < 1 || self.reconnect_interval > 60 {
            return Err(AgentError::ConfigError(format!(
                "reconnect_interval must be between 1 and 60 seconds, got {}",
                self.reconnect_interval
            )));
        }

        // Validate shell_command if set
        if let Some(ref shell_cmd) = self.shell_command {
            let parts = shell_words::split(shell_cmd).map_err(|e| {
                AgentError::ConfigError(format!("Invalid shell_command syntax: {}", e))
            })?;

            if parts.is_empty() {
                return Err(AgentError::ConfigError("Empty shell_command".to_string()));
            }

            let cmd = &parts[0];

            #[cfg(not(windows))]
            {
                // Unix: must be absolute path
                if !cmd.starts_with('/') {
                    return Err(AgentError::ConfigError(
                        "shell_command must be an absolute path on Unix".to_string()
                    ));
                }

                // Check against allowed list
                if !ALLOWED_SHELLS.contains(&cmd.as_str()) {
                    return Err(AgentError::ConfigError(format!(
                        "shell_command '{}' not in allowed list: {:?}",
                        cmd, ALLOWED_SHELLS
                    )));
                }
            }

            #[cfg(windows)]
            {
                // Windows: check basename against allowed list
                let basename = std::path::Path::new(cmd)
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or(cmd);

                if !ALLOWED_WINDOWS_SHELLS.iter().any(|s| s.eq_ignore_ascii_case(basename)) {
                    return Err(AgentError::ConfigError(format!(
                        "shell_command '{}' not in allowed list: {:?}",
                        cmd, ALLOWED_WINDOWS_SHELLS
                    )));
                }
            }
        }

        // Validate tls_cert_fingerprint if set
        if let Some(ref fingerprint) = self.tls_cert_fingerprint {
            // Remove common separators
            let clean = fingerprint.replace(':', "").replace(' ', "");

            // Check if valid hex string
            if hex::decode(&clean).is_err() {
                return Err(AgentError::ConfigError(
                    "tls_cert_fingerprint must be a valid hex string".to_string()
                ));
            }

            // Check if 32 bytes (SHA-256)
            if clean.len() != 64 {
                return Err(AgentError::ConfigError(
                    "tls_cert_fingerprint must be 64 hex characters (32 bytes for SHA-256)".to_string()
                ));
            }
        }

        Ok(())
    }

    /// Save configuration to file
    #[allow(dead_code)]
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
    #[allow(dead_code)]
    pub fn state_dir() -> Result<PathBuf> {
        let state_dir = dirs::data_local_dir()
            .ok_or_else(|| AgentError::ConfigError("Could not find state directory".to_string()))?;

        let telfin_dir = state_dir.join("telfin");
        std::fs::create_dir_all(&telfin_dir)?;

        Ok(telfin_dir)
    }

    /// Get the PID file path
    #[allow(dead_code)]
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
    #[allow(dead_code)]
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
        assert_eq!(config.server_url, "https://gateway.telfin.io");
        assert!(!config.machine_name.is_empty());
        assert_eq!(config.reconnect_interval, 5);
        assert_eq!(config.heartbeat_interval, 15);
    }

    #[test]
    fn test_websocket_url() {
        let mut config = Config::default();
        assert_eq!(config.websocket_url(), "wss://gateway.telfin.io");

        config.server_url = "http://localhost:3000".to_string();
        assert_eq!(config.websocket_url(), "ws://localhost:3000");
    }

    #[test]
    fn test_api_url() {
        let config = Config::default();
        assert_eq!(config.api_url(), "https://gateway.telfin.io/api");
    }

    #[test]
    fn test_validate_heartbeat_interval() {
        let mut config = Config::default();

        // Test too low
        config.heartbeat_interval = 4;
        assert!(config.validate().is_err());

        // Test too high
        config.heartbeat_interval = 301;
        assert!(config.validate().is_err());

        // Test valid values
        config.heartbeat_interval = 5;
        assert!(config.validate().is_ok());

        config.heartbeat_interval = 300;
        assert!(config.validate().is_ok());

        config.heartbeat_interval = 30;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_reconnect_interval() {
        let mut config = Config::default();

        // Test too low
        config.reconnect_interval = 0;
        assert!(config.validate().is_err());

        // Test too high
        config.reconnect_interval = 61;
        assert!(config.validate().is_err());

        // Test valid values
        config.reconnect_interval = 1;
        assert!(config.validate().is_ok());

        config.reconnect_interval = 60;
        assert!(config.validate().is_ok());

        config.reconnect_interval = 5;
        assert!(config.validate().is_ok());
    }

    #[test]
    #[cfg(not(windows))]
    fn test_validate_shell_command_unix() {
        let mut config = Config::default();

        // Valid shells - should pass
        config.shell_command = Some("/bin/bash".to_string());
        assert!(config.validate().is_ok());

        config.shell_command = Some("/bin/sh".to_string());
        assert!(config.validate().is_ok());

        config.shell_command = Some("/bin/zsh".to_string());
        assert!(config.validate().is_ok());

        config.shell_command = Some("/usr/bin/bash".to_string());
        assert!(config.validate().is_ok());

        config.shell_command = Some("/usr/local/bin/fish".to_string());
        assert!(config.validate().is_ok());

        // Valid shell with arguments - should pass
        config.shell_command = Some("/bin/bash -l".to_string());
        assert!(config.validate().is_ok());

        // Relative path - should fail
        config.shell_command = Some("bash".to_string());
        assert!(config.validate().is_err());

        config.shell_command = Some("./bash".to_string());
        assert!(config.validate().is_err());

        // Not in allowed list - should fail
        config.shell_command = Some("/bin/malicious".to_string());
        assert!(config.validate().is_err());

        config.shell_command = Some("/usr/bin/python".to_string());
        assert!(config.validate().is_err());

        // Empty command - should fail
        config.shell_command = Some("".to_string());
        assert!(config.validate().is_err());

        // None - should pass
        config.shell_command = None;
        assert!(config.validate().is_ok());
    }

    #[test]
    #[cfg(windows)]
    fn test_validate_shell_command_windows() {
        let mut config = Config::default();

        // Valid shells - should pass
        config.shell_command = Some("cmd.exe".to_string());
        assert!(config.validate().is_ok());

        config.shell_command = Some("powershell.exe".to_string());
        assert!(config.validate().is_ok());

        config.shell_command = Some("pwsh.exe".to_string());
        assert!(config.validate().is_ok());

        // Case insensitive - should pass
        config.shell_command = Some("CMD.EXE".to_string());
        assert!(config.validate().is_ok());

        config.shell_command = Some("PowerShell.exe".to_string());
        assert!(config.validate().is_ok());

        // With full path - should pass
        config.shell_command = Some("C:\\Windows\\System32\\cmd.exe".to_string());
        assert!(config.validate().is_ok());

        // With arguments - should pass
        config.shell_command = Some("powershell.exe -NoProfile".to_string());
        assert!(config.validate().is_ok());

        // Not in allowed list - should fail
        config.shell_command = Some("malicious.exe".to_string());
        assert!(config.validate().is_err());

        config.shell_command = Some("python.exe".to_string());
        assert!(config.validate().is_err());

        // Empty command - should fail
        config.shell_command = Some("".to_string());
        assert!(config.validate().is_err());

        // None - should pass
        config.shell_command = None;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_shell_command_syntax_error() {
        let mut config = Config::default();

        // Invalid shell syntax (unclosed quote)
        config.shell_command = Some("/bin/bash -c 'unclosed".to_string());
        assert!(config.validate().is_err());
    }
}
