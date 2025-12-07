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
}

#[tokio::main]
async fn main() -> Result<()> {
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
            config.server_url = server;

            if let Some(name) = machine_name {
                config.machine_name = name;
            }

            // Get token from keychain
            let keychain = keychain::get_provider();
            let token = keychain
                .get_token()?
                .ok_or(error::AgentError::NotLoggedIn)?;

            // Generate device fingerprint
            let fingerprint = fingerprint::generate()?;

            // Create and run agent
            let mut agent = agent::Agent::new(config.clone(), token, fingerprint)?;

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
            let keychain = keychain::get_provider();
            keychain.delete_token()?;
            println!("✓ Logged out successfully");
            Ok(())
        }
    }
}

async fn check_status() -> Result<()> {
    let keychain = keychain::get_provider();
    let has_token = keychain.get_token()?.is_some();

    if has_token {
        let config = config::Config::load()?;
        let fingerprint = fingerprint::generate()?;

        println!("Status: Logged in");
        println!("Server: {}", config.server_url);
        println!("Machine: {}", config.machine_name);
        println!("Fingerprint: {}", &fingerprint[..16]);
    } else {
        println!("Status: Not logged in");
        println!("Run 'telfin login' to authenticate");
    }

    Ok(())
}
