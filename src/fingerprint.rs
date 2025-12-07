use crate::error::Result;
use sha2::{Digest, Sha256};
use std::process::Command;

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

    let result = hasher.finalize();
    Ok(hex::encode(result))
}

fn get_machine_id() -> Result<String> {
    #[cfg(target_os = "linux")]
    {
        if let Ok(id) = std::fs::read_to_string("/etc/machine-id") {
            return Ok(id.trim().to_string());
        }
        if let Ok(id) = std::fs::read_to_string("/var/lib/dbus/machine-id") {
            return Ok(id.trim().to_string());
        }
        return Err(crate::error::AgentError::Other(
            "Could not read machine-id".to_string(),
        ));
    }

    #[cfg(target_os = "macos")]
    {
        return get_macos_uuid();
    }

    #[cfg(target_os = "windows")]
    {
        return get_windows_guid();
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        Err(crate::error::AgentError::Other(
            "Unsupported platform".to_string(),
        ))
    }
}

#[cfg(target_os = "macos")]
fn get_macos_uuid() -> Result<String> {
    let output = Command::new("ioreg")
        .args(&["-rd1", "-c", "IOPlatformExpertDevice"])
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
        .args(&["csproduct", "get", "UUID"])
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
        let fp2 = generate().unwrap();

        // Should be deterministic
        assert_eq!(fp1, fp2);

        // Should be 64 characters (SHA-256 hex)
        assert_eq!(fp1.len(), 64);
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
}
