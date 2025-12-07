use thiserror::Error;

/// Main error type for telfin-agent
#[derive(Error, Debug)]
#[allow(clippy::result_large_err)]
pub enum AgentError {
    #[error("Authentication failed: {0}")]
    AuthError(String),

    #[error("WebSocket error: {0}")]
    WebSocketError(#[from] tokio_tungstenite::tungstenite::Error),

    #[error("HTTP request failed: {0}")]
    HttpError(#[from] reqwest::Error),

    #[error("Keychain error: {0}")]
    KeychainError(String),

    #[error("PTY error: {0}")]
    PtyError(String),

    #[error("Protocol error: {0}")]
    ProtocolError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    SerdeError(#[from] serde_json::Error),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Not logged in. Run: telfin login")]
    NotLoggedIn,

    #[error("Device code flow expired")]
    DeviceCodeExpired,

    #[error("Session not found: {0}")]
    SessionNotFound(u32),

    #[error("Session error: {0}")]
    SessionError(String),

    #[error("Rate limit exceeded")]
    RateLimited,

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, AgentError>;

impl From<anyhow::Error> for AgentError {
    fn from(err: anyhow::Error) -> Self {
        AgentError::Other(err.to_string())
    }
}

impl From<String> for AgentError {
    fn from(err: String) -> Self {
        AgentError::Other(err)
    }
}
