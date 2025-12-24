#![allow(clippy::result_large_err)]

use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

mod agent;
mod auth;
mod config;
mod error;
mod fingerprint;
mod health;
mod keychain;
mod network;
mod protocol;
mod service;
mod tls;
mod update;

use crate::error::Result;

#[derive(Parser)]
#[command(name = "telfin")]
#[command(about = "Telfin SSH Tunnel Agent", version, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Authenticate with Telfin (usually not needed - install/start auto-login)
    Login {
        #[arg(long, default_value = "https://gateway.telfin.io")]
        server: String,
    },
    /// Start the agent in foreground (use 'install' for background service)
    Start {
        #[arg(long)]
        machine_name: Option<String>,
        #[arg(long, default_value = "https://gateway.telfin.io")]
        server: String,
        /// Disable auto-update check on startup
        #[arg(long)]
        no_update: bool,
    },
    /// Check agent status and connection info
    Status,
    /// Logout and remove stored credentials
    Logout,
    /// Install and start as background service (recommended)
    Install {
        #[arg(long, default_value = "https://gateway.telfin.io")]
        server: String,
    },
    /// Uninstall background service
    Uninstall,
    /// Check for and install updates from GitHub releases
    Update {
        /// Only check for updates, don't install
        #[arg(long)]
        check: bool,
        /// Force update even if already on latest version
        #[arg(long)]
        force: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    // Install rustls crypto provider (required for TLS)
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    let cli = Cli::parse();

    // Initialize logging based on command
    // Interactive commands (login, install, status) should be quiet
    // Daemon mode (start) needs full logging for debugging
    let log_level = match &cli.command {
        Commands::Start { .. } => {
            // Daemon mode - full logging
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"))
        }
        _ => {
            // Interactive commands - errors only (unless RUST_LOG is set)
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("error"))
        }
    };

    tracing_subscriber::fmt()
        .with_env_filter(log_level)
        .init();

    match cli.command {
        Commands::Login { server } => {
            tracing::info!("Starting device authorization flow...");
            auth::device_code_flow(&server).await?;
            println!("\n✓ Login successful! Run 'telfin start' to connect your machine.");
            Ok(())
        }
        Commands::Start {
            machine_name,
            server,
            no_update,
        } => {
            // Auto-update on startup (unless disabled)
            // This ensures agents always run latest version
            if !no_update {
                tracing::info!("Checking for updates...");
                match update::auto_update_if_available().await {
                    Ok(true) => {
                        println!("✓ Updated to new version. Please restart the agent.");
                        std::process::exit(0);
                    }
                    Ok(false) => {
                        tracing::debug!("Already running latest version");
                    }
                    Err(e) => {
                        // Don't block on update errors - just log and continue
                        tracing::warn!("Auto-update check failed: {} (continuing anyway)", e);
                    }
                }
            }

            // Load or create config
            let mut config = config::Config::load()?;
            config.server_url = server.clone();

            if let Some(name) = machine_name {
                config.machine_name = name;
            }

            // Try to get stored agent token first
            let agent_token = match keychain::get_agent_token_async().await? {
                Some(token) => {
                    tracing::info!("Using stored agent token");
                    token
                }
                None => {
                    // No stored agent token, need to register
                    tracing::info!("No stored agent token, registering machine...");

                    // Get access token with automatic re-authentication if needed
                    // This uses the self-healing auth function that:
                    // 1. Tries stored token / refresh
                    // 2. Falls back to device-code flow if interactive
                    // 3. Writes pending auth request if daemon mode
                    let access_token = auth::get_valid_token_or_reauth(&server).await?;

                    // Register machine with gateway to get agent token
                    let registration =
                        auth::register_machine(&server, &access_token, &config.machine_name)
                            .await?;

                    // Save agent token to keychain for future use
                    keychain::save_agent_token_async(registration.agent_token.clone()).await?;

                    registration.agent_token
                }
            };

            // Generate device fingerprint
            let fingerprint = fingerprint::generate()?;

            // Create and run agent with agent token (not access token)
            let mut agent = agent::Agent::new(config.clone(), agent_token, fingerprint)?;

            // Check for updates in background if enabled
            if config.auto_update_check {
                tokio::spawn(async {
                    if let Some(version) = update::check_for_updates_quiet().await {
                        // Log only, don't print to stdout to avoid cluttering agent output
                        tracing::info!(
                            "Update {} available. Run 'telfin update' to install.",
                            version
                        );
                    }
                });
            }

            // Check if service is installed, suggest install for persistent operation
            if !service::is_installed() {
                println!(
                    "\nTip: Run 'telfin install' to run in the background and auto-start on boot."
                );
                println!("     Press Ctrl+C to stop this foreground session.\n");
            }

            // Handle graceful shutdown
            let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);

            tokio::spawn(async move {
                if let Err(e) = tokio::signal::ctrl_c().await {
                    tracing::error!("Failed to listen for shutdown signal: {}", e);
                } else {
                    tracing::info!("Received shutdown signal");
                    let _ = shutdown_tx.send(true);
                }
            });

            // Aggressive reconnection loop - never give up
            let mut backoff = std::time::Duration::from_secs(1);
            let max_backoff = std::time::Duration::from_secs(60);
            let mut consecutive_failures = 0;

            loop {
                // Check for shutdown before connecting
                if *shutdown_rx.borrow() {
                    tracing::info!("Shutdown requested, exiting");
                    break;
                }

                // Re-read agent token in case it was refreshed
                let current_agent_token = match keychain::get_agent_token_async().await {
                    Ok(Some(token)) => token,
                    Ok(None) => {
                        tracing::error!("Agent token missing, cannot reconnect");
                        break;
                    }
                    Err(e) => {
                        tracing::error!("Failed to get agent token: {}", e);
                        break;
                    }
                };

                // Regenerate fingerprint (in case network changed)
                let current_fingerprint = match fingerprint::generate() {
                    Ok(fp) => fp,
                    Err(e) => {
                        tracing::error!("Failed to generate fingerprint: {}", e);
                        tokio::time::sleep(backoff).await;
                        backoff = (backoff * 2).min(max_backoff);
                        continue;
                    }
                };

                let mut agent = match agent::Agent::new(
                    config.clone(),
                    current_agent_token,
                    current_fingerprint,
                ) {
                    Ok(a) => a,
                    Err(e) => {
                        tracing::error!("Failed to create agent: {}", e);
                        tokio::time::sleep(backoff).await;
                        backoff = (backoff * 2).min(max_backoff);
                        continue;
                    }
                };

                // Create a new receiver for this run
                let run_shutdown_rx = shutdown_rx.clone();

                match agent.run(run_shutdown_rx).await {
                    Ok(()) => {
                        // Graceful shutdown
                        if *shutdown_rx.borrow() {
                            tracing::info!("Agent stopped gracefully");
                            break;
                        }
                        // Server closed connection, reconnect
                        tracing::info!("Connection closed, reconnecting...");
                        consecutive_failures = 0;
                        backoff = std::time::Duration::from_secs(1);
                    }
                    Err(e) => {
                        consecutive_failures += 1;
                        tracing::warn!(
                            "Agent disconnected (attempt {}): {}. Reconnecting in {:?}...",
                            consecutive_failures,
                            e,
                            backoff
                        );
                    }
                }

                // Wait before reconnecting (unless shutdown)
                tokio::select! {
                    _ = tokio::time::sleep(backoff) => {}
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            tracing::info!("Shutdown during reconnect wait");
                            break;
                        }
                    }
                }

                // Exponential backoff with reset on success
                if consecutive_failures > 0 {
                    backoff = (backoff * 2).min(max_backoff);
                }
            }

            Ok(())
        }
        Commands::Status => {
            check_status().await?;
            Ok(())
        }
        Commands::Logout => {
            keychain::delete_token_async().await?;
            keychain::delete_refresh_token_async().await?;
            keychain::delete_agent_token_async().await?;
            keychain::clear_backup_tokens().await;
            println!("✓ Logged out successfully");
            Ok(())
        }
        Commands::Install { server } => {
            println!("╔════════════════════════════════════════════════════════════╗");
            println!("║              Telfin Agent Setup                            ║");
            println!("╚════════════════════════════════════════════════════════════╝\n");

            // Load config
            let mut config = config::Config::load()?;
            config.server_url = server.clone();

            // Step 1: Get valid access token (with automatic re-auth if needed)
            println!("Step 1/4: Checking authentication...");
            let access_token = match auth::get_valid_token_or_reauth(&server).await {
                Ok(token) => {
                    println!("Step 1/4: Authenticated ✓\n");
                    token
                }
                Err(e) => {
                    return Err(e);
                }
            };

            // Step 2: Test gateway connection
            println!("Step 2/4: Verifying gateway connection...");
            let registration =
                auth::register_machine(&server, &access_token, &config.machine_name).await?;

            // Save agent token to keychain for future use
            keychain::save_agent_token_async(registration.agent_token.clone()).await?;

            let fp = fingerprint::generate()?;

            // Quick connection test
            let test_agent = agent::Agent::new(config.clone(), registration.agent_token, fp)?;
            match test_agent.test_connection().await {
                Ok(_) => println!("✓ Connected to gateway successfully!\n"),
                Err(e) => {
                    return Err(error::AgentError::ConnectionError(format!(
                        "Failed to connect to gateway: {}. Check your network and try again.",
                        e
                    )));
                }
            }

            // Step 3: Install the service
            println!("Step 3/4: Installing background service...\n");
            service::install()?;

            // Step 4: Auto-start the service
            println!("\nStep 4/4: Starting service...");
            if let Err(e) = service::start_service() {
                tracing::warn!("Service installed but failed to start: {}", e);
                println!("Note: Service will start automatically on next login/reboot");
            }

            println!("\n╔════════════════════════════════════════════════════════════╗");
            println!("║              Setup Complete!                               ║");
            println!("╟────────────────────────────────────────────────────────────╢");
            println!("║  Your machine is now connected to Telfin.                  ║");
            println!("║  The agent will run in the background and auto-start.     ║");
            println!("║                                                            ║");
            println!("║  Commands:                                                 ║");
            println!("║    telfin status     - Check connection status             ║");
            println!("║    telfin uninstall  - Remove background service           ║");
            println!("╚════════════════════════════════════════════════════════════╝\n");
            Ok(())
        }
        Commands::Uninstall => {
            service::uninstall()?;
            Ok(())
        }
        Commands::Update { check, force } => {
            if check {
                // Just check for updates
                match update::check_for_updates().await {
                    Ok(status) => {
                        update::display_update_status(&status);
                        Ok(())
                    }
                    Err(e) => {
                        eprintln!("Failed to check for updates: {}", e);
                        Err(e)
                    }
                }
            } else {
                // Perform update
                update::perform_update(force).await
            }
        }
    }
}

async fn check_status() -> Result<()> {
    let config = config::Config::load()?;
    let fingerprint = fingerprint::generate()?;

    println!("Server: {}", config.server_url);
    println!("Machine: {}", config.machine_name);
    println!("Fingerprint: {}", &fingerprint[..16]);

    // Check service status
    let service_running = service::is_running();
    println!(
        "Service: {}",
        if service_running {
            "Running ✓"
        } else {
            "Not running"
        }
    );

    // Check agent token (most important - used for WebSocket connection)
    let agent_token = keychain::get_agent_token_async().await?;
    if let Some(ref token) = agent_token {
        if let Ok(claims) = auth::validate_token_locally(token) {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as usize;
            let remaining = claims.exp.saturating_sub(now);
            let days = remaining / 86400;
            let years = days / 365;
            if years > 0 {
                println!("Agent Token: Valid ({} years remaining) ✓", years);
            } else {
                println!("Agent Token: Valid ({} days remaining) ✓", days);
            }
        } else {
            println!("Agent Token: Expired (will re-register on next connect)");
        }
    } else {
        println!("Agent Token: Not registered yet");
    }

    // Check refresh token (used to get new access tokens)
    let refresh_token = keychain::get_refresh_token_async().await?;
    if let Some(ref token) = refresh_token {
        if let Ok(claims) = auth::validate_token_locally(token) {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as usize;
            let remaining = claims.exp.saturating_sub(now);
            let days = remaining / 86400;
            println!("Refresh Token: Valid ({} days remaining) ✓", days);
        } else {
            println!("Refresh Token: Expired");
            println!("  → Run 'telfin login' to re-authenticate");
        }
    } else {
        println!("Refresh Token: Not found");
        println!("  → Run 'telfin login' to authenticate");
    }

    // Check access token (short-lived, auto-refreshes)
    let access_token = keychain::get_token_async().await?;
    if let Some(ref token) = access_token {
        if let Ok(claims) = auth::validate_token_locally(token) {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as usize;
            let remaining = claims.exp.saturating_sub(now);
            let minutes = remaining / 60;
            println!("Access Token: Valid ({} min remaining)", minutes);
        } else {
            // Access token expired is normal - it auto-refreshes
            if refresh_token.is_some() {
                println!("Access Token: Expired (will auto-refresh)");
            } else {
                println!("Access Token: Expired");
            }
        }
    } else {
        println!("Access Token: Not found");
    }

    // Overall status
    println!();
    if agent_token.is_some() && service_running {
        println!("Status: Connected ✓");
    } else if agent_token.is_some() || refresh_token.is_some() {
        println!("Status: Authenticated (service not running)");
        if !service_running {
            println!("  → Run 'telfin install' to start the service");
        }
    } else {
        println!("Status: Not logged in");
        println!("Run 'telfin login' to authenticate");
    }

    Ok(())
}
