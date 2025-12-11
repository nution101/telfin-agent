use crate::auth;
use crate::config::Config;
use crate::error::{AgentError, Result};
use crate::health;
use crate::keychain;
use crate::network;
use crate::protocol::{DataSubType, Message, MessageType, ResizePayload};
use futures_util::{SinkExt, StreamExt};
use portable_pty::{native_pty_system, CommandBuilder, PtySize};
use std::collections::HashMap;
use std::io::Read;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::{mpsc, watch, Mutex};
use tokio::time::{interval, Duration};
use tokio_tungstenite::tungstenite::http::Request;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};
use uuid::Uuid;

const MAX_CONCURRENT_SESSIONS: usize = 10;
const MESSAGE_BURST_LIMIT: usize = 100;
const RATE_LIMIT_WINDOW_SECS: u64 = 1;
const SESSION_IDLE_TIMEOUT_SECS: u64 = 3600;
/// Refresh token 5 minutes before expiry
const TOKEN_REFRESH_THRESHOLD_SECS: u64 = 300;
/// Maximum backoff for token refresh retries
const MAX_REFRESH_BACKOFF_SECS: u64 = 300;

/// Simple semver comparison - returns true if latest > current
fn needs_update(current: &str, latest: &str) -> bool {
    let parse_version = |v: &str| -> Option<(u32, u32, u32)> {
        let parts: Vec<&str> = v.trim_start_matches('v').splitn(3, '.').collect();
        if parts.len() >= 2 {
            let major = parts[0].parse().ok()?;
            let minor = parts[1].parse().ok()?;
            let patch = parts.get(2).and_then(|p| p.parse().ok()).unwrap_or(0);
            Some((major, minor, patch))
        } else {
            None
        }
    };

    match (parse_version(current), parse_version(latest)) {
        (Some(cur), Some(lat)) => lat > cur,
        _ => false, // Can't compare, don't update
    }
}

#[allow(dead_code)]
type WsStream = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

/// Main agent that manages the WebSocket connection and PTY sessions
pub struct Agent {
    config: Config,
    token: String,
    fingerprint: String,
    sessions: Arc<Mutex<HashMap<Uuid, Session>>>,
    message_count: Arc<AtomicUsize>,
    last_rate_reset: Arc<Mutex<std::time::Instant>>,
    /// Persistent PTY that survives tunnel reconnects
    persistent_pty: Arc<Mutex<Option<PersistentPty>>>,
}

/// Persistent PTY state that survives tunnel disconnects
#[allow(dead_code)]
struct PersistentPty {
    /// Channel to send input to the PTY
    input_tx: mpsc::Sender<Vec<u8>>,
    /// Current session ID (updated on reconnect)
    current_session_id: Arc<Mutex<Uuid>>,
    /// The child process (shell)
    _child: Box<dyn portable_pty::Child + Send + Sync>,
    /// PTY output reader task
    reader_task: tokio::task::JoinHandle<()>,
    /// PTY input writer task  
    writer_task: tokio::task::JoinHandle<()>,
    /// Last activity timestamp
    last_activity: std::time::Instant,
}

struct Session {
    #[allow(dead_code)]
    id: Uuid,
    input_tx: mpsc::Sender<Vec<u8>>,
    resize_tx: mpsc::Sender<(u16, u16)>,
    _child: Box<dyn portable_pty::Child + Send + Sync>,
    reader_task: tokio::task::JoinHandle<()>,
    writer_task: tokio::task::JoinHandle<()>,
    last_activity: std::time::Instant,
}

impl Agent {
    /// Create a new agent instance
    pub fn new(config: Config, token: String, fingerprint: String) -> Result<Self> {
        Ok(Self {
            config,
            token,
            fingerprint,
            sessions: Arc::new(Mutex::new(HashMap::new())),
            message_count: Arc::new(AtomicUsize::new(0)),
            last_rate_reset: Arc::new(Mutex::new(std::time::Instant::now())),
            persistent_pty: Arc::new(Mutex::new(None)),
        })
    }

    /// Test connection to gateway without running the full event loop
    /// Returns Ok(()) if connection succeeds, Err otherwise
    pub async fn test_connection(&self) -> Result<()> {
        // Build WebSocket URL
        let ws_url = format!(
            "{}/ws/agent?machine={}&fingerprint={}",
            self.config.websocket_url(),
            urlencoding::encode(&self.config.machine_name),
            self.fingerprint
        );

        // Extract host from URL for Host header
        let url = url::Url::parse(&ws_url)
            .map_err(|e| AgentError::ConfigError(format!("Invalid WebSocket URL: {}", e)))?;
        let host = url
            .host_str()
            .ok_or_else(|| AgentError::ConfigError("WebSocket URL missing host".to_string()))?;
        let port = url
            .port_or_known_default()
            .ok_or_else(|| AgentError::ConfigError("WebSocket URL missing port".to_string()))?;
        let host_header =
            if (url.scheme() == "wss" && port == 443) || (url.scheme() == "ws" && port == 80) {
                host.to_string()
            } else {
                format!("{}:{}", host, port)
            };

        // Build WebSocket request with Authorization and Fingerprint headers
        let request = tokio_tungstenite::tungstenite::http::Request::builder()
            .uri(&ws_url)
            .header("Authorization", format!("Bearer {}", self.token))
            .header("X-Telfin-Fingerprint", &self.fingerprint)
            .header(
                "Sec-WebSocket-Key",
                tokio_tungstenite::tungstenite::handshake::client::generate_key(),
            )
            .header("Sec-WebSocket-Version", "13")
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Host", host_header)
            .body(())
            .map_err(|e| {
                AgentError::ConfigError(format!("Failed to build WebSocket request: {}", e))
            })?;

        // Attempt connection with timeout
        let connect_future = connect_async(request);
        let timeout_duration = Duration::from_secs(10);

        match tokio::time::timeout(timeout_duration, connect_future).await {
            Ok(Ok((ws_stream, _))) => {
                // Successfully connected, close cleanly
                let (mut write, _read) = ws_stream.split();
                let _ = write.close().await;
                tracing::info!("Connection test successful");
                Ok(())
            }
            Ok(Err(e)) => {
                tracing::error!("Connection test failed: {}", e);
                Err(AgentError::ConnectionError(e.to_string()))
            }
            Err(_) => {
                tracing::error!("Connection test timed out");
                Err(AgentError::ConnectionError(
                    "Connection timed out after 10 seconds".to_string(),
                ))
            }
        }
    }

    /// Run the agent with graceful shutdown support
    pub async fn run(&mut self, mut shutdown_rx: watch::Receiver<bool>) -> Result<()> {
        tracing::info!(
            "Starting Telfin agent for machine: {}",
            self.config.machine_name
        );

        // Initialize health monitoring
        health::init();
        health::spawn_watchdog();

        let mut backoff = Duration::from_secs(1);
        let max_backoff = Duration::from_secs(60);
        // Threshold for considering a connection "successful" - if we were connected
        // for at least this long, reset the backoff on disconnect
        let success_threshold = Duration::from_secs(10);

        // Extract gateway host for network checks
        let gateway_host = network::extract_host(&self.config.server_url)
            .unwrap_or_else(|| "gateway.telfin.io".to_string());

        loop {
            // PHASE 2: Network-aware reconnection
            // Check network before attempting connection to avoid spinning
            if !network::can_reach_host(&gateway_host) {
                tracing::warn!("Network unreachable, waiting for connectivity...");
                if !network::wait_for_network(&gateway_host, Duration::from_secs(300)).await {
                    tracing::error!("Network wait timeout, will retry...");
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    continue;
                }
            }

            // Check and refresh token before connecting
            if let Err(e) = self.ensure_valid_token().await {
                tracing::error!("Failed to ensure valid token: {}", e);
                // Still try to connect with current token - gateway will reject if invalid
            }

            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        tracing::info!("Shutdown signal received, cleaning up...");
                        self.cleanup_sessions().await;
                        return Ok(());
                    }
                }
                result = self.connect_and_run() => {
                    let connection_duration = result.1;

                    // PERSISTENT SESSIONS: Don't cleanup PTY on disconnect!
                    // We keep the PTY alive so users can reconnect to the same shell.
                    // Only cleanup ephemeral sessions (old non-persistent sessions)
                    let session_count = self.sessions.lock().await.len();
                    if session_count > 0 {
                        tracing::info!(
                            "Connection ended, cleaning up {} ephemeral session(s) (persistent PTY kept alive)",
                            session_count
                        );
                        self.cleanup_sessions().await;
                    }

                    // Log persistent PTY status
                    if self.persistent_pty.lock().await.is_some() {
                        tracing::info!("Persistent PTY still running - will reattach on reconnect");
                    }

                    match result.0 {
                        Ok(_) => {
                            tracing::info!("Connection closed cleanly after {:?}", connection_duration);
                            backoff = Duration::from_secs(1);
                        }
                        Err(e) => {
                            // If we were connected for a reasonable time, this was a working
                            // connection that got disconnected (e.g., idle timeout) - reset backoff
                            if connection_duration >= success_threshold {
                                tracing::info!(
                                    "Connection dropped after {:?} ({}), reconnecting immediately...",
                                    connection_duration, e
                                );
                                backoff = Duration::from_secs(1);
                            } else {
                                tracing::warn!("Connection error after {:?}: {}", connection_duration, e);
                                tracing::info!("Reconnecting in {:?}...", backoff);
                                tokio::time::sleep(backoff).await;
                                // Exponential backoff
                                backoff = (backoff * 2).min(max_backoff);
                            }
                        }
                    }
                }
            }
        }
    }

    /// Ensure we have a valid token, refreshing if necessary
    async fn ensure_valid_token(&mut self) -> Result<()> {
        // Check if current token is expiring soon
        if !auth::token_expiring_soon(&self.token, TOKEN_REFRESH_THRESHOLD_SECS) {
            return Ok(());
        }

        tracing::info!("Access token expiring soon, attempting refresh...");

        // Get refresh token from keychain
        let refresh_token = match keychain::get_refresh_token_async().await? {
            Some(token) => token,
            None => {
                tracing::warn!("No refresh token available, continuing with current token");
                return Ok(());
            }
        };

        // Attempt to refresh with exponential backoff
        let mut backoff = Duration::from_secs(1);
        let max_backoff = Duration::from_secs(MAX_REFRESH_BACKOFF_SECS);
        let max_attempts = 10;

        for attempt in 1..=max_attempts {
            match auth::refresh_access_token(&self.config.server_url, &refresh_token).await {
                Ok(token_pair) => {
                    // Save new tokens to keychain
                    keychain::save_token_async(token_pair.access_token.clone()).await?;
                    keychain::save_refresh_token_async(token_pair.refresh_token).await?;

                    // Update in-memory token
                    self.token = token_pair.access_token;

                    tracing::info!("Token refreshed successfully on attempt {}", attempt);
                    return Ok(());
                }
                Err(e) => {
                    tracing::warn!(
                        "Token refresh attempt {} failed: {}, retrying in {:?}",
                        attempt,
                        e,
                        backoff
                    );

                    if attempt < max_attempts {
                        // Add jitter to backoff (0-1 second)
                        let jitter = Duration::from_millis(rand::random::<u64>() % 1000);
                        tokio::time::sleep(backoff + jitter).await;
                        backoff = (backoff * 2).min(max_backoff);
                    }
                }
            }
        }

        tracing::warn!("All token refresh attempts failed, will try with current token");
        Ok(())
    }

    /// Connect to gateway and run the event loop.
    /// Returns (result, duration) where duration is how long the connection was active.
    async fn connect_and_run(&mut self) -> (Result<()>, Duration) {
        let start_time = std::time::Instant::now();

        match self.connect_and_run_inner().await {
            Ok(()) => (Ok(()), start_time.elapsed()),
            Err(e) => (Err(e), start_time.elapsed()),
        }
    }

    async fn connect_and_run_inner(&mut self) -> Result<()> {
        // Build WebSocket URL without sensitive token in query params
        let ws_url = format!(
            "{}/ws/agent?machine={}&fingerprint={}",
            self.config.websocket_url(),
            urlencoding::encode(&self.config.machine_name),
            self.fingerprint
        );

        // Extract host from URL for Host header
        let url = url::Url::parse(&ws_url)
            .map_err(|e| AgentError::ConfigError(format!("Invalid WebSocket URL: {}", e)))?;
        let host = url
            .host_str()
            .ok_or_else(|| AgentError::ConfigError("WebSocket URL missing host".to_string()))?;
        let port = url
            .port_or_known_default()
            .ok_or_else(|| AgentError::ConfigError("WebSocket URL missing port".to_string()))?;
        let host_header =
            if (url.scheme() == "wss" && port == 443) || (url.scheme() == "ws" && port == 80) {
                host.to_string()
            } else {
                format!("{}:{}", host, port)
            };

        // Build WebSocket request with Authorization and Fingerprint headers
        tracing::info!("Connecting to gateway...");
        let request = Request::builder()
            .uri(&ws_url)
            .header("Authorization", format!("Bearer {}", self.token))
            .header("X-Telfin-Fingerprint", &self.fingerprint)
            .header(
                "Sec-WebSocket-Key",
                tokio_tungstenite::tungstenite::handshake::client::generate_key(),
            )
            .header("Sec-WebSocket-Version", "13")
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Host", host_header)
            .body(())
            .map_err(|e| {
                AgentError::ConfigError(format!("Failed to build WebSocket request: {}", e))
            })?;

        let (ws_stream, _) = connect_async(request).await?;
        tracing::info!("Connected to gateway");

        let (mut write, mut read) = ws_stream.split();

        // Channel for outgoing messages
        let (tx, mut rx) = mpsc::channel::<WsMessage>(1024);

        // Spawn heartbeat task
        let tx_heartbeat = tx.clone();
        let heartbeat_interval = self.config.heartbeat_interval;
        let heartbeat_handle = tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(heartbeat_interval));
            loop {
                interval.tick().await;
                let heartbeat = Message::ping(Uuid::nil());
                if tx_heartbeat
                    .send(WsMessage::Binary(heartbeat.encode()))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });

        // Idle session cleanup interval
        let mut cleanup_interval = interval(Duration::from_secs(60));

        // Main event loop
        let result: Result<()> = loop {
            tokio::select! {
                _ = cleanup_interval.tick() => {
                    self.cleanup_idle_sessions().await;
                }
                Some(msg) = read.next() => {
                    match msg {
                        Ok(WsMessage::Binary(data)) => {
                            if let Err(e) = self.handle_message(&data, tx.clone()).await {
                                tracing::error!("Failed to handle message: {}", e);
                            }
                        }
                        Ok(WsMessage::Ping(data)) => {
                            let _ = tx.send(WsMessage::Pong(data)).await;
                        }
                        Ok(WsMessage::Pong(_)) => {
                            // Record heartbeat for health monitoring
                            health::record_heartbeat();
                        }
                        Ok(WsMessage::Close(_)) => {
                            tracing::info!("Server closed connection");
                            break Ok(());
                        }
                        Err(e) => {
                            break Err(e.into());
                        }
                        _ => {}
                    }
                }
                Some(msg) = rx.recv() => {
                    if let Err(e) = write.send(msg).await {
                        tracing::error!("Failed to send message: {}", e);
                        break Err(e.into());
                    }
                }
                else => break Ok(()),
            }
        };

        heartbeat_handle.abort();
        self.cleanup_sessions().await;
        result
    }

    async fn handle_message(&mut self, data: &[u8], tx: mpsc::Sender<WsMessage>) -> Result<()> {
        // Record activity for health monitoring
        health::record_activity();

        let msg = Message::decode(data)?;

        match msg.msg_type {
            MessageType::Data => {
                // Data messages can contain different sub-types
                if msg.payload.is_empty() {
                    tracing::warn!("Received empty Data message for session {}", msg.session_id);
                    return Ok(());
                }

                // PERSISTENT SESSION: Check if we have an existing PTY to reattach to
                let persistent_pty = self.persistent_pty.lock().await;

                if let Some(ref pty) = *persistent_pty {
                    // Reattach to existing PTY with new session ID
                    let old_session_id = *pty.current_session_id.lock().await;
                    if old_session_id != msg.session_id {
                        tracing::info!(
                            "Reattaching persistent PTY: {} -> {}",
                            old_session_id,
                            msg.session_id
                        );
                        *pty.current_session_id.lock().await = msg.session_id;
                    }
                    drop(persistent_pty);
                } else {
                    // No persistent PTY - create one
                    drop(persistent_pty);
                    tracing::info!("Starting new persistent PTY for session {}", msg.session_id);
                    self.start_persistent_pty(msg.session_id, tx.clone())
                        .await?;
                }

                // Check for sub-type in payload
                match msg.payload[0] {
                    0x00 => {
                        // Raw terminal data (skip sub-type byte)
                        self.handle_persistent_input(&msg.payload[1..]).await?;
                    }
                    0x01 => {
                        // Resize event (not yet implemented for persistent PTY)
                        let resize = ResizePayload::decode(&msg.payload)?;
                        tracing::debug!(
                            "Resize event: {}x{} (not applied to persistent PTY)",
                            resize.cols,
                            resize.rows
                        );
                    }
                    _ => {
                        // Assume raw data if no valid sub-type (backward compatibility)
                        self.handle_persistent_input(&msg.payload).await?;
                    }
                }
            }
            MessageType::Close => {
                tracing::info!("Ending session {}", msg.session_id);
                self.end_session(msg.session_id).await?;
            }
            MessageType::Ping => {
                // Respond with Pong
                let pong = Message::pong(msg.session_id);
                let _ = tx.send(WsMessage::Binary(pong.encode())).await;
            }
            MessageType::Pong => {
                // Heartbeat response received
            }
            MessageType::Error => {
                let error_msg = String::from_utf8_lossy(&msg.payload);
                tracing::error!(
                    "Received error from gateway for session {}: {}",
                    msg.session_id,
                    error_msg
                );
            }
            MessageType::VersionCheck => {
                // Version notification from gateway
                self.handle_version_check(&msg.payload).await;
            }
        }

        Ok(())
    }

    /// Handle input for the persistent PTY session
    async fn handle_persistent_input(&self, data: &[u8]) -> Result<()> {
        let persistent_pty = self.persistent_pty.lock().await;
        if let Some(ref pty) = *persistent_pty {
            pty.input_tx.send(data.to_vec()).await.map_err(|e| {
                AgentError::SessionError(format!("Failed to send input to PTY: {}", e))
            })?;
        } else {
            tracing::warn!("Received input but no persistent PTY exists");
        }
        Ok(())
    }

    /// Handle version check notification from gateway
    async fn handle_version_check(&self, payload: &[u8]) {
        // Parse version payload
        #[derive(serde::Deserialize)]
        struct VersionPayload {
            latest_version: String,
            #[allow(dead_code)]
            download_url: String,
        }

        let version_info: VersionPayload = match serde_json::from_slice(payload) {
            Ok(v) => v,
            Err(e) => {
                tracing::debug!("Failed to parse version payload: {}", e);
                return;
            }
        };

        let current_version = env!("CARGO_PKG_VERSION");

        // Compare versions (simple semver comparison)
        if needs_update(current_version, &version_info.latest_version) {
            tracing::info!(
                "New version available: {} -> {} (triggering auto-update)",
                current_version,
                version_info.latest_version
            );

            // Trigger auto-update
            match crate::update::auto_update_if_available().await {
                Ok(true) => {
                    tracing::info!("Auto-update successful, restarting...");
                    // Exit cleanly - service manager will restart us with new version
                    std::process::exit(0);
                }
                Ok(false) => {
                    tracing::debug!("No update performed");
                }
                Err(e) => {
                    tracing::error!("Auto-update failed: {}", e);
                }
            }
        } else {
            tracing::debug!(
                "Agent is up to date: {} >= {}",
                current_version,
                version_info.latest_version
            );
        }
    }

    /// Start a new persistent PTY session
    async fn start_persistent_pty(
        &mut self,
        session_id: Uuid,
        tx: mpsc::Sender<WsMessage>,
    ) -> Result<()> {
        let pty_system = native_pty_system();

        let pair = pty_system
            .openpty(PtySize {
                rows: 24,
                cols: 80,
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|e| AgentError::PtyError(format!("Failed to open PTY: {}", e)))?;

        // Build shell command based on config
        let cmd = match &self.config.shell_command {
            Some(shell_cmd) => {
                let parts = shell_words::split(shell_cmd).map_err(|e| {
                    AgentError::ConfigError(format!("Invalid shell_command: {}", e))
                })?;
                if parts.is_empty() {
                    return Err(AgentError::ConfigError("Empty shell_command".to_string()));
                }
                let mut cmd = CommandBuilder::new(&parts[0]);
                for arg in &parts[1..] {
                    cmd.arg(arg);
                }
                tracing::info!("Starting persistent PTY with shell: {}", shell_cmd);
                cmd
            }
            None => {
                #[cfg(unix)]
                let default_shell = "/bin/bash";
                #[cfg(windows)]
                let default_shell = "cmd.exe";
                let shell = std::env::var("SHELL").unwrap_or_else(|_| default_shell.to_string());
                tracing::info!("Starting persistent PTY with default shell: {}", shell);
                CommandBuilder::new(shell)
            }
        };

        let child = pair
            .slave
            .spawn_command(cmd)
            .map_err(|e| AgentError::PtyError(format!("Failed to spawn command: {}", e)))?;

        let mut reader = pair
            .master
            .try_clone_reader()
            .map_err(|e| AgentError::PtyError(format!("Failed to clone reader: {}", e)))?;

        let mut writer = pair
            .master
            .take_writer()
            .map_err(|e| AgentError::PtyError(format!("Failed to get writer: {}", e)))?;

        // Channel for input to PTY
        let (input_tx, mut input_rx) = mpsc::channel::<Vec<u8>>(1024);

        // Shared session ID that can be updated on reconnect
        let current_session_id = Arc::new(Mutex::new(session_id));
        let session_id_for_reader = current_session_id.clone();

        // Spawn task to read PTY output and send to WebSocket with current session ID
        let tx_output = tx.clone();
        let reader_task = tokio::task::spawn_blocking(move || {
            let mut buf = [0u8; 4096];
            let runtime = tokio::runtime::Handle::current();

            loop {
                match reader.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        // Get current session ID (may have changed on reconnect)
                        let session_id =
                            runtime.block_on(async { *session_id_for_reader.lock().await });

                        // Prepend sub-type byte for raw terminal data
                        let mut payload = Vec::with_capacity(n + 1);
                        payload.push(DataSubType::RawData as u8);
                        payload.extend_from_slice(&buf[..n]);

                        let msg = Message::data(session_id, payload);
                        if tx_output
                            .blocking_send(WsMessage::Binary(msg.encode()))
                            .is_err()
                        {
                            // Channel closed - connection dropped, but keep PTY running
                            tracing::debug!(
                                "Output channel closed, persistent PTY continues running"
                            );
                            break;
                        }
                    }
                    Err(e) => {
                        tracing::error!("Persistent PTY read error: {}", e);
                        break;
                    }
                }
            }
            tracing::info!("Persistent PTY reader task exited");
        });

        // Spawn task to handle input writes
        let writer_task = tokio::task::spawn_blocking(move || {
            use std::io::Write;
            while let Some(data) = input_rx.blocking_recv() {
                if writer.write_all(&data).is_err() || writer.flush().is_err() {
                    break;
                }
            }
            tracing::info!("Persistent PTY writer task exited");
        });

        let persistent_pty = PersistentPty {
            input_tx,
            current_session_id,
            _child: child,
            reader_task,
            writer_task,
            last_activity: std::time::Instant::now(),
        };

        *self.persistent_pty.lock().await = Some(persistent_pty);
        tracing::info!("Persistent PTY started with initial session {}", session_id);

        Ok(())
    }

    #[allow(dead_code)]
    async fn start_session(&mut self, session_id: Uuid, tx: mpsc::Sender<WsMessage>) -> Result<()> {
        let sessions = self.sessions.lock().await;
        if sessions.len() >= MAX_CONCURRENT_SESSIONS {
            tracing::warn!(
                "Session limit reached ({}), rejecting new session {}",
                MAX_CONCURRENT_SESSIONS,
                session_id
            );
            return Err(AgentError::SessionError(
                "Maximum concurrent sessions reached".to_string(),
            ));
        }
        drop(sessions);

        let pty_system = native_pty_system();

        let pair = pty_system
            .openpty(PtySize {
                rows: 24,
                cols: 80,
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|e| AgentError::PtyError(format!("Failed to open PTY: {}", e)))?;

        // Build shell command based on config
        let cmd = match &self.config.shell_command {
            Some(shell_cmd) => {
                // Parse command string into command + args using shell-words for proper quoting
                let parts = shell_words::split(shell_cmd).map_err(|e| {
                    AgentError::ConfigError(format!("Invalid shell_command: {}", e))
                })?;

                if parts.is_empty() {
                    return Err(AgentError::ConfigError("Empty shell_command".to_string()));
                }

                let mut cmd = CommandBuilder::new(&parts[0]);
                for arg in &parts[1..] {
                    cmd.arg(arg);
                }
                tracing::info!(
                    "Starting session {} with configured shell: {}",
                    session_id,
                    shell_cmd
                );
                cmd
            }
            None => {
                // Use system default shell
                #[cfg(unix)]
                let default_shell = "/bin/bash";
                #[cfg(windows)]
                let default_shell = "cmd.exe";

                let shell = std::env::var("SHELL").unwrap_or_else(|_| default_shell.to_string());
                tracing::info!(
                    "Starting session {} with default shell: {}",
                    session_id,
                    shell
                );
                CommandBuilder::new(shell)
            }
        };

        let child = pair
            .slave
            .spawn_command(cmd)
            .map_err(|e| AgentError::PtyError(format!("Failed to spawn command: {}", e)))?;

        let mut reader = pair
            .master
            .try_clone_reader()
            .map_err(|e| AgentError::PtyError(format!("Failed to clone reader: {}", e)))?;

        let mut writer = pair
            .master
            .take_writer()
            .map_err(|e| AgentError::PtyError(format!("Failed to get writer: {}", e)))?;

        // Channel for input to PTY
        let (input_tx, mut input_rx) = mpsc::channel::<Vec<u8>>(1024);

        // Channel for resize events
        let (resize_tx, _resize_rx) = mpsc::channel::<(u16, u16)>(10);

        // Spawn task to read PTY output and send to WebSocket
        let tx_output = tx.clone();
        let reader_task = tokio::task::spawn_blocking(move || {
            let mut buf = [0u8; 4096];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        // Prepend sub-type byte for raw terminal data
                        let mut payload = Vec::with_capacity(n + 1);
                        payload.push(DataSubType::RawData as u8);
                        payload.extend_from_slice(&buf[..n]);

                        let msg = Message::data(session_id, payload);
                        if tx_output
                            .blocking_send(WsMessage::Binary(msg.encode()))
                            .is_err()
                        {
                            break;
                        }
                    }
                    Err(e) => {
                        tracing::error!("PTY read error: {}", e);
                        break;
                    }
                }
            }
            tracing::debug!("Reader task for session {} exited", session_id);
        });

        // Spawn task to handle input writes
        let writer_task = tokio::task::spawn_blocking(move || {
            use std::io::Write;
            while let Some(data) = input_rx.blocking_recv() {
                if writer.write_all(&data).is_err() || writer.flush().is_err() {
                    break;
                }
            }
            tracing::debug!("Writer task for session {} exited", session_id);
        });

        // Note: PTY resize is not fully supported in this implementation
        // portable-pty doesn't provide async resize on master after writer is taken
        // For production, consider using a different PTY library or restructure

        let session = Session {
            id: session_id,
            input_tx,
            resize_tx,
            _child: child,
            reader_task,
            writer_task,
            last_activity: std::time::Instant::now(),
        };

        self.sessions.lock().await.insert(session_id, session);
        tracing::info!("Session {} started", session_id);

        Ok(())
    }

    #[allow(dead_code)]
    async fn check_rate_limit(&self) -> Result<()> {
        let mut last_reset = self.last_rate_reset.lock().await;
        let now = std::time::Instant::now();

        // Reset counter if window has passed
        if now.duration_since(*last_reset).as_secs() >= RATE_LIMIT_WINDOW_SECS {
            self.message_count.store(0, Ordering::SeqCst);
            *last_reset = now;
        }

        // Check and increment atomically while still holding lock
        let count = self.message_count.fetch_add(1, Ordering::SeqCst);
        if count >= MESSAGE_BURST_LIMIT {
            tracing::warn!("Rate limit exceeded: {} messages in window", count);
            return Err(AgentError::RateLimited);
        }

        Ok(())
        // Lock released here after both operations complete
    }

    #[allow(dead_code)]
    async fn handle_input(&mut self, session_id: Uuid, data: &[u8]) -> Result<()> {
        self.check_rate_limit().await?;

        let mut sessions = self.sessions.lock().await;
        let session = sessions.get_mut(&session_id).ok_or_else(|| {
            AgentError::SessionError(format!("Session not found: {}", session_id))
        })?;

        // Update activity timestamp
        session.last_activity = std::time::Instant::now();

        session
            .input_tx
            .send(data.to_vec())
            .await
            .map_err(|_| AgentError::PtyError("Failed to send input to PTY".to_string()))?;

        Ok(())
    }

    #[allow(dead_code)]
    async fn resize_terminal(&mut self, session_id: Uuid, cols: u16, rows: u16) -> Result<()> {
        let sessions = self.sessions.lock().await;
        let session = sessions.get(&session_id).ok_or_else(|| {
            AgentError::SessionError(format!("Session not found: {}", session_id))
        })?;

        // Send resize event (currently not fully implemented)
        let _ = session.resize_tx.try_send((cols, rows));

        tracing::debug!(
            "Resize signal sent for session {} to {}x{}",
            session_id,
            cols,
            rows
        );
        Ok(())
    }

    async fn end_session(&mut self, session_id: Uuid) -> Result<()> {
        let mut sessions = self.sessions.lock().await;
        if let Some(session) = sessions.remove(&session_id) {
            // Drop channels to signal tasks to stop
            drop(session.input_tx);
            drop(session.resize_tx);

            // Abort tasks
            session.reader_task.abort();
            session.writer_task.abort();

            tracing::info!("Session {} ended", session_id);
        }
        Ok(())
    }

    async fn cleanup_idle_sessions(&mut self) {
        let mut sessions = self.sessions.lock().await;
        let now = std::time::Instant::now();
        let timeout = std::time::Duration::from_secs(SESSION_IDLE_TIMEOUT_SECS);

        let expired: Vec<Uuid> = sessions
            .iter()
            .filter(|(_, session)| now.duration_since(session.last_activity) > timeout)
            .map(|(id, _)| *id)
            .collect();

        for session_id in expired {
            if let Some(session) = sessions.remove(&session_id) {
                tracing::info!(
                    "Closing idle session {} (inactive for >{}s)",
                    session_id,
                    SESSION_IDLE_TIMEOUT_SECS
                );
                drop(session.input_tx);
                drop(session.resize_tx);
                session.reader_task.abort();
                session.writer_task.abort();
            }
        }
    }

    async fn cleanup_sessions(&mut self) {
        let mut sessions = self.sessions.lock().await;
        let session_ids: Vec<Uuid> = sessions.keys().copied().collect();

        for session_id in session_ids {
            if let Some(session) = sessions.remove(&session_id) {
                // Drop channels to signal tasks to stop
                drop(session.input_tx);
                drop(session.resize_tx);

                // Abort tasks to ensure they stop
                session.reader_task.abort();
                session.writer_task.abort();

                tracing::info!("Cleaned up session {}", session_id);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_agent_creation() {
        let config = Config::default();
        let agent = Agent::new(
            config,
            "test-token".to_string(),
            "test-fingerprint".to_string(),
        );
        assert!(agent.is_ok());
    }
}
