use crate::config::Config;
use crate::error::{AgentError, Result};
use crate::protocol::{Message, MessageType, ResizePayload};
use futures_util::{SinkExt, StreamExt};
use portable_pty::{native_pty_system, CommandBuilder, PtySize};
use std::collections::HashMap;
use std::io::Read;
use std::sync::Arc;
use tokio::sync::{mpsc, watch, Mutex};
use tokio::time::{interval, Duration};
use tokio_tungstenite::tungstenite::http::Request;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};

#[allow(dead_code)]
type WsStream = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

/// Main agent that manages the WebSocket connection and PTY sessions
pub struct Agent {
    config: Config,
    token: String,
    fingerprint: String,
    sessions: Arc<Mutex<HashMap<u32, Session>>>,
}

struct Session {
    #[allow(dead_code)]
    id: u32,
    input_tx: mpsc::Sender<Vec<u8>>,
    resize_tx: mpsc::Sender<(u16, u16)>,
    _child: Box<dyn portable_pty::Child + Send + Sync>,
    reader_task: tokio::task::JoinHandle<()>,
    writer_task: tokio::task::JoinHandle<()>,
}

impl Agent {
    /// Create a new agent instance
    pub fn new(config: Config, token: String, fingerprint: String) -> Result<Self> {
        Ok(Self {
            config,
            token,
            fingerprint,
            sessions: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// Run the agent with graceful shutdown support
    pub async fn run(&mut self, mut shutdown_rx: watch::Receiver<bool>) -> Result<()> {
        tracing::info!(
            "Starting Telfin agent for machine: {}",
            self.config.machine_name
        );

        let mut backoff = Duration::from_secs(1);
        let max_backoff = Duration::from_secs(60);

        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        tracing::info!("Shutdown signal received, cleaning up...");
                        self.cleanup_sessions().await;
                        return Ok(());
                    }
                }
                result = self.connect_and_run() => {
                    match result {
                        Ok(_) => {
                            tracing::info!("Connection closed cleanly");
                            backoff = Duration::from_secs(1);
                        }
                        Err(e) => {
                            tracing::warn!("Connection error: {}", e);
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

    async fn connect_and_run(&mut self) -> Result<()> {
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

        // Build WebSocket request with Authorization header
        tracing::info!("Connecting to gateway...");
        let request = Request::builder()
            .uri(&ws_url)
            .header("Authorization", format!("Bearer {}", self.token))
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
                let heartbeat = Message::new(MessageType::Heartbeat, 0, vec![]);
                if tx_heartbeat
                    .send(WsMessage::Binary(heartbeat.encode()))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });

        // Main event loop
        let result: Result<()> = loop {
            tokio::select! {
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
                            // Heartbeat response
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
        let msg = Message::decode(data)?;

        match msg.msg_type {
            MessageType::SessionStart => {
                tracing::info!("Starting session {}", msg.session_id);
                self.start_session(msg.session_id, tx).await?;
            }
            MessageType::TerminalInput => {
                self.handle_input(msg.session_id, &msg.payload).await?;
            }
            MessageType::TerminalResize => {
                let resize = ResizePayload::decode(&msg.payload)?;
                self.resize_terminal(msg.session_id, resize.cols, resize.rows)
                    .await?;
            }
            MessageType::SessionEnd => {
                tracing::info!("Ending session {}", msg.session_id);
                self.end_session(msg.session_id).await?;
            }
            MessageType::Heartbeat => {
                // Heartbeat received, no action needed
            }
            _ => {
                tracing::warn!("Unhandled message type: {:?}", msg.msg_type);
            }
        }

        Ok(())
    }

    async fn start_session(&mut self, session_id: u32, tx: mpsc::Sender<WsMessage>) -> Result<()> {
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
                        let msg = Message::new(
                            MessageType::TerminalOutput,
                            session_id,
                            buf[..n].to_vec(),
                        );
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
        };

        self.sessions.lock().await.insert(session_id, session);
        tracing::info!("Session {} started", session_id);

        Ok(())
    }

    async fn handle_input(&mut self, session_id: u32, data: &[u8]) -> Result<()> {
        let sessions = self.sessions.lock().await;
        let session = sessions
            .get(&session_id)
            .ok_or_else(|| AgentError::SessionNotFound(session_id))?;

        session
            .input_tx
            .send(data.to_vec())
            .await
            .map_err(|_| AgentError::PtyError("Failed to send input to PTY".to_string()))?;

        Ok(())
    }

    async fn resize_terminal(&mut self, session_id: u32, cols: u16, rows: u16) -> Result<()> {
        let sessions = self.sessions.lock().await;
        let session = sessions
            .get(&session_id)
            .ok_or_else(|| AgentError::SessionNotFound(session_id))?;

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

    async fn end_session(&mut self, session_id: u32) -> Result<()> {
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

    async fn cleanup_sessions(&mut self) {
        let mut sessions = self.sessions.lock().await;
        let session_ids: Vec<u32> = sessions.keys().copied().collect();

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
