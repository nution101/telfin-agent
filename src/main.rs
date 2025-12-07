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
    /// Authenticate with Telfin
    Login {
        #[arg(long, default_value = "https://gateway.telfin.io")]
        server: String,
    },
    /// Start the agent daemon
    Start {
        #[arg(long)]
        machine_name: Option<String>,
        #[arg(long, default_value = "https://gateway.telfin.io")]
        server: String,
    },
    /// Check agent status
    Status,
    /// Logout and remove credentials
    Logout,
    /// Install auto-start service
    Install,
    /// Uninstall auto-start service
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

            // Get access token from keychain (using async wrapper for Linux compatibility)
            let access_token = keychain::get_token_async()
                .await?
                .ok_or(error::AgentError::NotLoggedIn)?;

            // Validate token before use
            match auth::validate_token_locally(&access_token) {
                Ok(claims) => {
                    tracing::debug!("Token valid, expires at {}", claims.exp);
                }
                Err(e) => {
                    tracing::error!("Token validation failed: {}", e);
                    keychain::delete_token_async().await.ok();
                    return Err(error::AgentError::AuthError(
                        "Token is invalid or expired. Please run 'telfin login' again.".to_string(),
                    ));
                }
            }

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
            println!("✓ Logged out successfully");
            Ok(())
        }
        Commands::Install => {
            service::install()?;
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
