use crate::error::Result;
use sha2::{Digest, Sha256};

#[cfg(any(target_os = "macos", target_os = "windows"))]
use std::process::Command;

/// Get or create a unique installation ID stored locally
fn get_or_create_install_id() -> Result<String> {
    let state_dir = crate::config::Config::state_dir()?;
    let install_id_path = state_dir.join("install-id");

    if install_id_path.exists() {
        let id = std::fs::read_to_string(&install_id_path)?;
        Ok(id.trim().to_string())
    } else {
        let id = uuid::Uuid::new_v4().to_string();
        std::fs::write(&install_id_path, &id)?;
        tracing::debug!("Created new installation ID");
        Ok(id)
    }
}

#[cfg(target_os = "linux")]
fn get_primary_mac_address() -> Option<String> {
    let net_dir = std::path::Path::new("/sys/class/net");
    if !net_dir.exists() {
        return None;
    }

    if let Ok(entries) = std::fs::read_dir(net_dir) {
        for entry in entries.filter_map(|e| e.ok()) {
            let name = entry.file_name().to_string_lossy().to_string();
            // Skip loopback and virtual interfaces
            if name == "lo"
                || name.starts_with("veth")
                || name.starts_with("docker")
                || name.starts_with("br-")
            {
                continue;
            }

            let addr_path = entry.path().join("address");
            if let Ok(mac) = std::fs::read_to_string(addr_path) {
                let mac = mac.trim();
                // Skip empty or zero MACs
                if !mac.is_empty() && mac != "00:00:00:00:00:00" {
                    return Some(mac.to_string());
                }
            }
        }
    }
    None
}

#[cfg(not(target_os = "linux"))]
fn get_primary_mac_address() -> Option<String> {
    None
}

/// Generate a stable device fingerprint based on hardware identifiers
pub fn generate() -> Result<String> {
    let mut hasher = Sha256::new();

    // Add machine ID
    if let Ok(machine_id) = get_machine_id() {
        hasher.update(machine_id.as_bytes());
    }

    // Add hostname as fallback
    if let Ok(hostname) = hostname::get() {
        if let Some(hostname_str) = hostname.to_str() {
            hasher.update(hostname_str.as_bytes());
        }
    }

    // Add platform-specific identifiers
    #[cfg(target_os = "macos")]
    {
        if let Ok(uuid) = get_macos_uuid() {
            hasher.update(uuid.as_bytes());
        }
    }

    #[cfg(target_os = "linux")]
    {
        if let Ok(machine_id) = std::fs::read_to_string("/etc/machine-id") {
            hasher.update(machine_id.trim().as_bytes());
        } else if let Ok(machine_id) = std::fs::read_to_string("/var/lib/dbus/machine-id") {
            hasher.update(machine_id.trim().as_bytes());
        }
    }

    #[cfg(target_os = "windows")]
    {
        if let Ok(guid) = get_windows_guid() {
            hasher.update(guid.as_bytes());
        }
    }

    // Add MAC address (Linux)
    if let Some(mac) = get_primary_mac_address() {
        hasher.update(mac.as_bytes());
    }

    // Add installation-specific ID (unique per install, survives VM clones)
    if let Ok(install_id) = get_or_create_install_id() {
        hasher.update(install_id.as_bytes());
    }

    let result = hasher.finalize();
    Ok(hex::encode(result))
}

#[cfg(target_os = "linux")]
fn get_machine_id() -> Result<String> {
    if let Ok(id) = std::fs::read_to_string("/etc/machine-id") {
        Ok(id.trim().to_string())
    } else if let Ok(id) = std::fs::read_to_string("/var/lib/dbus/machine-id") {
        Ok(id.trim().to_string())
    } else {
        Err(crate::error::AgentError::Other(
            "Could not read machine-id".to_string(),
        ))
    }
}

#[cfg(target_os = "macos")]
fn get_machine_id() -> Result<String> {
    get_macos_uuid()
}

#[cfg(target_os = "windows")]
fn get_machine_id() -> Result<String> {
    get_windows_guid()
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn get_machine_id() -> Result<String> {
    Err(crate::error::AgentError::Other(
        "Unsupported platform".to_string(),
    ))
}

#[cfg(target_os = "macos")]
fn get_macos_uuid() -> Result<String> {
    let output = Command::new("/usr/sbin/ioreg")
        .args(["-rd1", "-c", "IOPlatformExpertDevice"])
        .output()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        if line.contains("IOPlatformUUID") {
            if let Some(uuid) = line.split('"').nth(3) {
                return Ok(uuid.to_string());
            }
        }
    }

    Err(crate::error::AgentError::Other(
        "Could not get macOS UUID".to_string(),
    ))
}

#[cfg(target_os = "windows")]
fn get_windows_guid() -> Result<String> {
    let output = Command::new("wmic")
        .args(["csproduct", "get", "UUID"])
        .output()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines().skip(1) {
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_string());
        }
    }

    Err(crate::error::AgentError::Other(
        "Could not get Windows GUID".to_string(),
    ))
}

/// Get a human-readable device name (hostname)
pub fn get_device_name() -> String {
    hostname::get()
        .ok()
        .and_then(|h| h.to_str().map(|s| s.to_string()))
        .unwrap_or_else(|| "unknown".to_string())
}

/// Get OS type as string
pub fn get_os_type() -> String {
    std::env::consts::OS.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fingerprint_generation() {
        let fp1 = generate().unwrap();

        // Should be 64 characters (SHA-256 hex)
        assert_eq!(fp1.len(), 64);

        // Should be valid hex
        assert!(fp1.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_device_name() {
        let name = get_device_name();
        assert!(!name.is_empty());
    }

    #[test]
    fn test_os_type() {
        let os = get_os_type();
        assert!(os == "linux" || os == "macos" || os == "windows");
    }

    #[test]
    fn test_install_id_persistence() {
        // First call creates the ID
        let id1 = get_or_create_install_id().unwrap();
        assert!(!id1.is_empty());
        assert_eq!(id1.len(), 36); // UUID v4 format

        // Second call returns same ID
        let id2 = get_or_create_install_id().unwrap();
        assert_eq!(id1, id2);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_mac_address_detection() {
        // MAC address may or may not be available depending on system
        // Just verify the function doesn't panic
        let _mac = get_primary_mac_address();
    }
}
