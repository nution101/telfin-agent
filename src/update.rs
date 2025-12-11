//! Auto-update functionality for telfin-agent
//!
//! Checks GitHub releases and updates the binary with rollback support.

use crate::error::{AgentError, Result};
use semver::Version;
use std::env;
use std::path::PathBuf;

/// GitHub repository information
const GITHUB_OWNER: &str = "nution101";
const GITHUB_REPO: &str = "telfin-agent";

/// Current version from Cargo.toml
const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Update status returned from check
#[derive(Debug)]
pub struct UpdateStatus {
    pub current_version: Version,
    pub latest_version: Version,
    pub update_available: bool,
    pub release_url: String,
    #[allow(dead_code)]
    pub release_notes: Option<String>,
}

/// Silently check for updates on startup (with random jitter to avoid thundering herd)
/// Returns Some(version) if update is available, None otherwise
pub async fn check_for_updates_quiet() -> Option<Version> {
    // Add jitter (0-30s) to avoid all agents hitting GitHub at once
    let jitter = rand::random::<u64>() % 30;
    tokio::time::sleep(std::time::Duration::from_secs(jitter)).await;

    match check_for_updates().await {
        Ok(status) if status.update_available => {
            tracing::info!(
                "Update available: {} -> {}. Run 'telfin update' to install.",
                status.current_version,
                status.latest_version
            );
            Some(status.latest_version)
        }
        Ok(_) => {
            tracing::debug!("No update available");
            None
        }
        Err(e) => {
            tracing::debug!("Failed to check for updates: {}", e);
            None // Silent failure - don't interrupt agent operation
        }
    }
}

/// Automatically check and apply updates on startup
/// Returns Ok(true) if updated and restart needed, Ok(false) if no update, Err on failure
pub async fn auto_update_if_available() -> Result<bool> {
    // Quick check without jitter for startup
    let status = check_for_updates().await?;

    if !status.update_available {
        return Ok(false);
    }

    tracing::info!(
        "Auto-updating: {} -> {}",
        status.current_version,
        status.latest_version
    );

    // Perform the update (this will download and replace the binary)
    perform_update(false).await?;

    Ok(true)
}

/// Check for available updates on GitHub
pub async fn check_for_updates() -> Result<UpdateStatus> {
    let current = Version::parse(CURRENT_VERSION)
        .map_err(|e| AgentError::UpdateError(format!("Invalid current version: {}", e)))?;

    tracing::debug!("Checking for updates, current version: {}", current);

    // Use spawn_blocking since self_update uses blocking I/O
    let releases = tokio::task::spawn_blocking(|| {
        self_update::backends::github::ReleaseList::configure()
            .repo_owner(GITHUB_OWNER)
            .repo_name(GITHUB_REPO)
            .build()
            .map_err(|e| {
                AgentError::UpdateError(format!("Failed to configure release check: {}", e))
            })?
            .fetch()
            .map_err(|e| AgentError::UpdateError(format!("Failed to fetch releases: {}", e)))
    })
    .await
    .map_err(|e| AgentError::UpdateError(format!("Task join error: {}", e)))??;

    // Get the latest release (first in list)
    let latest_release = releases
        .first()
        .ok_or_else(|| AgentError::UpdateError("No releases found".to_string()))?;

    // Parse version (remove 'v' prefix if present)
    let version_str = latest_release.version.trim_start_matches('v');
    let latest = Version::parse(version_str).map_err(|e| {
        AgentError::UpdateError(format!("Invalid release version '{}': {}", version_str, e))
    })?;

    let update_available = latest > current;

    tracing::debug!(
        "Latest version: {}, update available: {}",
        latest,
        update_available
    );

    let release_url = format!(
        "https://github.com/{}/{}/releases/tag/v{}",
        GITHUB_OWNER, GITHUB_REPO, latest
    );

    Ok(UpdateStatus {
        current_version: current,
        latest_version: latest,
        update_available,
        release_url,
        release_notes: None, // Could parse from release body if needed
    })
}

/// Get the appropriate asset name for the current platform
fn get_platform_asset_name() -> Result<&'static str> {
    match (env::consts::OS, env::consts::ARCH) {
        ("linux", "x86_64") => Ok("telfin-linux-amd64.tar.gz"),
        ("linux", "aarch64") => Ok("telfin-linux-arm64.tar.gz"),
        ("macos", "x86_64") => Ok("telfin-darwin-amd64.tar.gz"),
        ("macos", "aarch64") => Ok("telfin-darwin-arm64.tar.gz"),
        ("windows", "x86_64") => Ok("telfin-windows-amd64.zip"),
        (os, arch) => Err(AgentError::UpdateError(format!(
            "Unsupported platform: {}-{}",
            os, arch
        ))),
    }
}

/// Get the target identifier for self_update asset matching
/// Maps Rust target triples to our custom asset naming convention
fn get_target_identifier() -> Result<&'static str> {
    match (env::consts::OS, env::consts::ARCH) {
        ("linux", "x86_64") => Ok("linux-amd64"),
        ("linux", "aarch64") => Ok("linux-arm64"),
        ("macos", "x86_64") => Ok("darwin-amd64"),
        ("macos", "aarch64") => Ok("darwin-arm64"),
        ("windows", "x86_64") => Ok("windows-amd64"),
        (os, arch) => Err(AgentError::UpdateError(format!(
            "Unsupported platform: {}-{}",
            os, arch
        ))),
    }
}

/// Get the binary name inside the archive
fn get_binary_name() -> &'static str {
    if cfg!(windows) {
        "telfin-agent.exe"
    } else {
        "telfin-agent"
    }
}

/// Perform the update with rollback support
pub async fn perform_update(force: bool) -> Result<()> {
    let status = check_for_updates().await?;

    if !status.update_available && !force {
        println!(
            "Already running the latest version ({})",
            status.current_version
        );
        return Ok(());
    }

    println!(
        "Updating from {} to {}...",
        status.current_version, status.latest_version
    );

    let _asset_name = get_platform_asset_name()?;
    let target_id = get_target_identifier()?;
    let binary_name = get_binary_name();

    // Get current executable path for backup
    let current_exe = env::current_exe().map_err(|e| {
        AgentError::UpdateError(format!("Cannot determine current executable: {}", e))
    })?;

    let backup_path = current_exe.with_extension("bak");

    tracing::info!(
        "Performing update: {} -> {}",
        status.current_version,
        status.latest_version
    );
    tracing::debug!("Current exe: {:?}", current_exe);
    tracing::debug!("Backup path: {:?}", backup_path);

    // Clone values for the blocking task
    let binary_name_owned = binary_name.to_string();
    let target_id_owned = target_id.to_string();
    let backup_path_clone = backup_path.clone();
    let current_exe_clone = current_exe.clone();

    // Use spawn_blocking since self_update uses blocking I/O
    let update_result = tokio::task::spawn_blocking(move || {
        self_update::backends::github::Update::configure()
            .repo_owner(GITHUB_OWNER)
            .repo_name(GITHUB_REPO)
            .bin_name(&binary_name_owned)
            .identifier(&target_id_owned)
            .current_version(CURRENT_VERSION)
            .show_download_progress(true)
            .show_output(true)
            .no_confirm(true)
            .build()
            .map_err(|e| AgentError::UpdateError(format!("Failed to configure update: {}", e)))?
            .update()
            .map_err(|e| {
                // Attempt rollback if backup exists
                if backup_path_clone.exists() {
                    tracing::warn!(
                        "Update failed, attempting rollback from {:?}",
                        backup_path_clone
                    );
                    if let Err(rollback_err) =
                        std::fs::rename(&backup_path_clone, &current_exe_clone)
                    {
                        tracing::error!("Rollback failed: {}", rollback_err);
                    } else {
                        tracing::info!("Rollback successful");
                    }
                }
                AgentError::UpdateError(format!("Update failed: {}", e))
            })
    })
    .await
    .map_err(|e| AgentError::UpdateError(format!("Task join error: {}", e)))??;

    if update_result.updated() {
        println!(
            "\n✅ Successfully updated to version {}",
            update_result.version()
        );
        println!("\nThe agent will use the new version on next restart.");
        println!("If running as a service, restart with:");
        print_restart_instructions();
    } else {
        println!("Already up to date ({})", update_result.version());
    }

    Ok(())
}

/// Print platform-specific restart instructions
fn print_restart_instructions() {
    #[cfg(target_os = "linux")]
    println!("  sudo systemctl restart telfin-agent");

    #[cfg(target_os = "macos")]
    println!("  launchctl kickstart -k gui/$(id -u)/io.telfin.agent");

    #[cfg(target_os = "windows")]
    println!("  Restart-Service TelfinAgent");
}

/// Display update status to user
pub fn display_update_status(status: &UpdateStatus) {
    if status.update_available {
        println!("📦 Update available!");
        println!("   Current version: {}", status.current_version);
        println!("   Latest version:  {}", status.latest_version);
        println!("   Release URL:     {}", status.release_url);
        println!();
        println!("Run 'telfin update' to install the update.");
    } else {
        println!(
            "✅ You're running the latest version ({})",
            status.current_version
        );
    }
}

/// Get the backup path for rollback
#[allow(dead_code)]
pub fn get_backup_path() -> Result<PathBuf> {
    let current_exe = env::current_exe().map_err(|e| {
        AgentError::UpdateError(format!("Cannot determine current executable: {}", e))
    })?;
    Ok(current_exe.with_extension("bak"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_parsing() {
        let v = Version::parse(CURRENT_VERSION);
        assert!(v.is_ok(), "Current version should be parseable");
    }

    #[test]
    fn test_platform_asset_name() {
        // This will pass or fail based on the running platform
        let result = get_platform_asset_name();
        // On CI, should succeed for supported platforms
        if cfg!(any(
            all(target_os = "linux", target_arch = "x86_64"),
            all(target_os = "linux", target_arch = "aarch64"),
            all(target_os = "macos", target_arch = "x86_64"),
            all(target_os = "macos", target_arch = "aarch64"),
            all(target_os = "windows", target_arch = "x86_64"),
        )) {
            assert!(result.is_ok());
        }
    }
}
