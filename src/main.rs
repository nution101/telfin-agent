#![allow(clippy::result_large_err)]

use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

mod agent;
mod auth;
mod config;
mod error;
mod fingerprint;
mod keychain;
mod protocol;
mod service;
mod tls;

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
}

#[tokio::main]
async fn main() -> Result<()> {
    // Install rustls crypto provider (required for TLS)
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

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
        } => {
            // Load or create config
            let mut config = config::Config::load()?;
            config.server_url = server.clone();

            if let Some(name) = machine_name {
                config.machine_name = name;
            }

            // Get access token from keychain, validate it, auto-login if missing or expired
            let access_token = match keychain::get_token_async().await? {
                Some(token) => {
                    // Validate token BEFORE claiming authenticated
                    if auth::validate_token_locally(&token).is_ok() {
                        tracing::debug!("Existing token is valid");
                        token
                    } else {
                        // Token expired - delete and re-authenticate automatically
                        tracing::info!("Token expired, starting fresh authentication");
                        keychain::delete_token_async().await.ok();
                        keychain::delete_refresh_token_async().await.ok();
                        println!("Session expired. Starting authentication...\n");
                        auth::device_code_flow(&server).await?;
                        println!("\n✓ Login successful!\n");
                        keychain::get_token_async()
                            .await?
                            .ok_or(error::AgentError::NotLoggedIn)?
                    }
                }
                None => {
                    println!("Not logged in. Starting authentication...\n");
                    auth::device_code_flow(&server).await?;
                    println!("\n✓ Login successful!\n");
                    keychain::get_token_async()
                        .await?
                        .ok_or(error::AgentError::NotLoggedIn)?
                }
            };

            // Check if token is expiring soon (within 5 minutes)
            if auth::token_expiring_soon(&access_token, 300) {
                tracing::warn!(
                    "Token will expire soon. Consider running 'telfin login' to refresh."
                );
            }

            // Register machine with gateway to get agent token
            let registration =
                auth::register_machine(&server, &access_token, &config.machine_name).await?;

            // Generate device fingerprint
            let fingerprint = fingerprint::generate()?;

            // Create and run agent with agent token (not access token)
            let mut agent =
                agent::Agent::new(config.clone(), registration.agent_token, fingerprint)?;

            // Check if service is installed, suggest install for persistent operation
            if !service::is_installed() {
                println!(
                    "\nTip: Run 'telfin install' to run in the background and auto-start on boot."
                );
                println!("     Press Ctrl+C to stop this foreground session.\n");
            }

            // Handle graceful shutdown
            let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

            tokio::spawn(async move {
                if let Err(e) = tokio::signal::ctrl_c().await {
                    tracing::error!("Failed to listen for shutdown signal: {}", e);
                } else {
                    tracing::info!("Received shutdown signal");
                    let _ = shutdown_tx.send(true);
                }
            });

            agent.run(shutdown_rx).await?;
            Ok(())
        }
        Commands::Status => {
            check_status().await?;
            Ok(())
        }
        Commands::Logout => {
            keychain::delete_token_async().await?;
            keychain::delete_refresh_token_async().await?;
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

            // Step 1: Check if logged in with VALID token, auto-login if missing or expired
            let access_token = match keychain::get_token_async().await? {
                Some(token) => {
                    // Validate token BEFORE claiming authenticated
                    if auth::validate_token_locally(&token).is_ok() {
                        println!("Step 1/4: Already authenticated ✓\n");
                        token
                    } else {
                        // Token expired - delete and re-authenticate automatically
                        keychain::delete_token_async().await.ok();
                        keychain::delete_refresh_token_async().await.ok();
                        println!("Step 1/4: Session expired, re-authenticating...\n");
                        auth::device_code_flow(&server).await?;
                        println!("\n✓ Authentication complete!\n");
                        keychain::get_token_async()
                            .await?
                            .ok_or(error::AgentError::NotLoggedIn)?
                    }
                }
                None => {
                    println!("Step 1/4: Authentication required\n");
                    auth::device_code_flow(&server).await?;
                    println!("\n✓ Authentication complete!\n");
                    keychain::get_token_async()
                        .await?
                        .ok_or(error::AgentError::NotLoggedIn)?
                }
            };

            // Step 2: Test gateway connection
            println!("Step 2/4: Verifying gateway connection...");
            let registration =
                auth::register_machine(&server, &access_token, &config.machine_name).await?;
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
    }
}

async fn check_status() -> Result<()> {
    let token = keychain::get_token_async().await?;

    if let Some(token) = token {
        let config = config::Config::load()?;
        let fingerprint = fingerprint::generate()?;

        println!("Status: Logged in");
        println!("Server: {}", config.server_url);
        println!("Machine: {}", config.machine_name);
        println!("Fingerprint: {}", &fingerprint[..16]);

        // Show token expiration info
        if let Ok(claims) = auth::validate_token_locally(&token) {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as usize;
            let remaining = claims.exp.saturating_sub(now);
            let hours = remaining / 3600;
            let minutes = (remaining % 3600) / 60;

            println!("Token expires in: {}h {}m", hours, minutes);

            if auth::token_expiring_soon(&token, 300) {
                println!("⚠ Warning: Token expiring soon. Run 'telfin login' to refresh.");
            }
        } else {
            println!("Token status: Invalid or expired");
            println!("Run 'telfin login' to authenticate again");
        }
    } else {
        println!("Status: Not logged in");
        println!("Run 'telfin login' to authenticate");
    }

    Ok(())
}
