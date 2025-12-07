use crate::error::{AgentError, Result};
use std::fs;
use std::process::Command;

/// Check if the service is already installed
pub fn is_installed() -> bool {
    #[cfg(target_os = "linux")]
    {
        let home_dir = match dirs::home_dir() {
            Some(d) => d,
            None => return false,
        };
        home_dir
            .join(".config")
            .join("systemd")
            .join("user")
            .join("telfin-agent.service")
            .exists()
    }

    #[cfg(target_os = "macos")]
    {
        let home_dir = match dirs::home_dir() {
            Some(d) => d,
            None => return false,
        };
        home_dir
            .join("Library")
            .join("LaunchAgents")
            .join("io.telfin.agent.plist")
            .exists()
    }

    #[cfg(target_os = "windows")]
    {
        // Check if scheduled task exists
        let output = Command::new("schtasks")
            .args(["/query", "/tn", "TelfinAgent"])
            .output();
        matches!(output, Ok(o) if o.status.success())
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        false
    }
}

/// Start the installed service
pub fn start_service() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        let output = Command::new("systemctl")
            .args(["--user", "start", "telfin-agent"])
            .output()?;

        if !output.status.success() {
            return Err(AgentError::Other(format!(
                "Failed to start service: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }
        println!("✓ Telfin agent service started");
        Ok(())
    }

    #[cfg(target_os = "macos")]
    {
        let home_dir = dirs::home_dir()
            .ok_or_else(|| AgentError::ConfigError("Could not determine home directory".to_string()))?;
        let plist_file = home_dir
            .join("Library")
            .join("LaunchAgents")
            .join("io.telfin.agent.plist");

        // launchctl load also starts the service if RunAtLoad is true
        // But if it's already loaded, we need to kickstart it
        let output = Command::new("launchctl")
            .args(["kickstart", "-k", "gui/$UID/io.telfin.agent"])
            .output();

        // If kickstart fails, try load (might not be loaded yet)
        if output.is_err() || !output.as_ref().unwrap().status.success() {
            let _ = Command::new("launchctl")
                .args(["load", plist_file.to_str().unwrap()])
                .output()?;
        }

        println!("✓ Telfin agent service started");
        Ok(())
    }

    #[cfg(target_os = "windows")]
    {
        let output = Command::new("schtasks")
            .args(["/run", "/tn", "TelfinAgent"])
            .output()?;

        if !output.status.success() {
            return Err(AgentError::Other(format!(
                "Failed to start service: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }
        println!("✓ Telfin agent service started");
        Ok(())
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        Err(AgentError::Other(
            "Service start not supported on this platform".to_string(),
        ))
    }
}

/// Install the service/daemon for auto-start on system boot
pub fn install() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        install_systemd_service()
    }

    #[cfg(target_os = "macos")]
    {
        install_launchd_service()
    }

    #[cfg(target_os = "windows")]
    {
        install_windows_service()
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        Err(AgentError::Other(
            "Auto-start installation not supported on this platform".to_string(),
        ))
    }
}

/// Uninstall the service/daemon
pub fn uninstall() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        uninstall_systemd_service()
    }

    #[cfg(target_os = "macos")]
    {
        uninstall_launchd_service()
    }

    #[cfg(target_os = "windows")]
    {
        uninstall_windows_service()
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        Err(AgentError::Other(
            "Auto-start uninstallation not supported on this platform".to_string(),
        ))
    }
}

#[cfg(target_os = "linux")]
fn install_systemd_service() -> Result<()> {
    // Get the path to the current executable
    let exe_path = std::env::current_exe()?;

    // Create systemd user service directory
    let home_dir = dirs::home_dir()
        .ok_or_else(|| AgentError::ConfigError("Could not determine home directory".to_string()))?;

    let service_dir = home_dir.join(".config").join("systemd").join("user");

    fs::create_dir_all(&service_dir)?;

    let service_file = service_dir.join("telfin-agent.service");

    // Write systemd service file
    let service_content = format!(
        r#"[Unit]
Description=Telfin SSH Tunnel Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={} start
Restart=always
RestartSec=10

[Install]
WantedBy=default.target
"#,
        exe_path.display()
    );

    fs::write(&service_file, service_content)?;

    println!("Created systemd service at: {}", service_file.display());

    // Reload systemd daemon
    let output = Command::new("systemctl")
        .args(["--user", "daemon-reload"])
        .output()?;

    if !output.status.success() {
        return Err(AgentError::Other(format!(
            "Failed to reload systemd daemon: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    // Enable the service
    let output = Command::new("systemctl")
        .args(["--user", "enable", "telfin-agent"])
        .output()?;

    if !output.status.success() {
        return Err(AgentError::Other(format!(
            "Failed to enable service: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    // Enable lingering so service runs without user login
    let output = Command::new("loginctl").args(["enable-linger"]).output()?;

    if !output.status.success() {
        tracing::warn!(
            "Failed to enable lingering (service may not start on boot): {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    println!("\n✓ Telfin agent installed as systemd service");
    println!("\nService commands:");
    println!("  Start now:   systemctl --user start telfin-agent");
    println!("  Stop:        systemctl --user stop telfin-agent");
    println!("  Status:      systemctl --user status telfin-agent");
    println!("  View logs:   journalctl --user -u telfin-agent -f");

    Ok(())
}

#[cfg(target_os = "linux")]
fn uninstall_systemd_service() -> Result<()> {
    let home_dir = dirs::home_dir()
        .ok_or_else(|| AgentError::ConfigError("Could not determine home directory".to_string()))?;

    let service_file = home_dir
        .join(".config")
        .join("systemd")
        .join("user")
        .join("telfin-agent.service");

    // Stop the service
    let _ = Command::new("systemctl")
        .args(["--user", "stop", "telfin-agent"])
        .output();

    // Disable the service
    let _ = Command::new("systemctl")
        .args(["--user", "disable", "telfin-agent"])
        .output();

    // Remove service file
    if service_file.exists() {
        fs::remove_file(&service_file)?;
        println!("Removed systemd service file: {}", service_file.display());
    }

    // Reload systemd daemon
    let _ = Command::new("systemctl")
        .args(["--user", "daemon-reload"])
        .output();

    println!("✓ Telfin agent uninstalled");

    Ok(())
}

#[cfg(target_os = "macos")]
fn install_launchd_service() -> Result<()> {
    // Get the path to the current executable
    let exe_path = std::env::current_exe()?;

    // Get home directory for LaunchAgents
    let home_dir = dirs::home_dir()
        .ok_or_else(|| AgentError::ConfigError("Could not determine home directory".to_string()))?;

    let launch_agents_dir = home_dir.join("Library").join("LaunchAgents");
    fs::create_dir_all(&launch_agents_dir)?;

    let plist_file = launch_agents_dir.join("io.telfin.agent.plist");

    // Get log directory
    let log_dir = dirs::data_local_dir()
        .ok_or_else(|| AgentError::ConfigError("Could not find data directory".to_string()))?
        .join("telfin");
    fs::create_dir_all(&log_dir)?;

    let log_file = log_dir.join("agent.log");

    // Write launchd plist file
    let plist_content = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>io.telfin.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>{}</string>
        <string>start</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>{}</string>
    <key>StandardErrorPath</key>
    <string>{}</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>RUST_LOG</key>
        <string>info</string>
    </dict>
</dict>
</plist>
"#,
        exe_path.display(),
        log_file.display(),
        log_file.display()
    );

    fs::write(&plist_file, plist_content)?;

    println!("Created launchd service at: {}", plist_file.display());

    // Load the service
    let output = Command::new("launchctl")
        .args(["load", plist_file.to_str().unwrap()])
        .output()?;

    if !output.status.success() {
        return Err(AgentError::Other(format!(
            "Failed to load launchd service: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    println!("\n✓ Telfin agent installed as launchd service");
    println!("\nService commands:");
    println!("  Stop:        launchctl unload ~/Library/LaunchAgents/io.telfin.agent.plist");
    println!("  Start:       launchctl load ~/Library/LaunchAgents/io.telfin.agent.plist");
    println!("  View logs:   tail -f {}", log_file.display());

    Ok(())
}

#[cfg(target_os = "macos")]
fn uninstall_launchd_service() -> Result<()> {
    let home_dir = dirs::home_dir()
        .ok_or_else(|| AgentError::ConfigError("Could not determine home directory".to_string()))?;

    let plist_file = home_dir
        .join("Library")
        .join("LaunchAgents")
        .join("io.telfin.agent.plist");

    // Unload the service
    if plist_file.exists() {
        let _ = Command::new("launchctl")
            .args(["unload", plist_file.to_str().unwrap()])
            .output();

        // Remove plist file
        fs::remove_file(&plist_file)?;
        println!("Removed launchd service file: {}", plist_file.display());
    }

    println!("✓ Telfin agent uninstalled");

    Ok(())
}

#[cfg(target_os = "windows")]
fn install_windows_service() -> Result<()> {
    // Get the path to the current executable
    let exe_path = std::env::current_exe()?;

    // Create scheduled task using schtasks
    let task_command = format!("{} start", exe_path.display());

    let output = Command::new("schtasks")
        .args([
            "/create",
            "/tn",
            "TelfinAgent",
            "/tr",
            &task_command,
            "/sc",
            "onlogon",
            "/rl",
            "highest",
            "/f", // Force overwrite if exists
        ])
        .output()?;

    if !output.status.success() {
        return Err(AgentError::Other(format!(
            "Failed to create scheduled task: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    println!("\n✓ Telfin agent installed as Windows scheduled task");
    println!("\nTask commands:");
    println!("  Start now:   schtasks /run /tn TelfinAgent");
    println!("  Stop:        taskkill /f /im telfin.exe");
    println!("  Status:      schtasks /query /tn TelfinAgent");

    Ok(())
}

#[cfg(target_os = "windows")]
fn uninstall_windows_service() -> Result<()> {
    // Delete the scheduled task
    let output = Command::new("schtasks")
        .args(["/delete", "/tn", "TelfinAgent", "/f"])
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Don't error if task doesn't exist
        if !stderr.contains("cannot find") {
            return Err(AgentError::Other(format!(
                "Failed to delete scheduled task: {}",
                stderr
            )));
        }
    }

    println!("✓ Telfin agent uninstalled");

    Ok(())
}
