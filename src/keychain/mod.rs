use crate::error::{AgentError, Result};

/// Platform-agnostic keychain interface
pub trait KeychainProvider: Send + Sync {
    /// Save authentication token to keychain
    fn save_token(&self, token: &str) -> Result<()>;

    /// Retrieve authentication token from keychain
    fn get_token(&self) -> Result<Option<String>>;

    /// Delete authentication token from keychain
    fn delete_token(&self) -> Result<()>;

    /// Save refresh token to keychain
    fn save_refresh_token(&self, token: &str) -> Result<()>;

    /// Retrieve refresh token from keychain
    fn get_refresh_token(&self) -> Result<Option<String>>;

    /// Delete refresh token from keychain
    fn delete_refresh_token(&self) -> Result<()>;
}

/// Async wrapper to save token using spawn_blocking
/// Required on Linux where secret-service uses zbus which conflicts with Tokio
pub async fn save_token_async(token: String) -> Result<()> {
    tokio::task::spawn_blocking(move || {
        let keychain = get_provider();
        keychain.save_token(&token)
    })
    .await
    .map_err(|e| AgentError::KeychainError(format!("Task join failed: {}", e)))?
}

/// Async wrapper to get token using spawn_blocking
/// Required on Linux where secret-service uses zbus which conflicts with Tokio
pub async fn get_token_async() -> Result<Option<String>> {
    tokio::task::spawn_blocking(|| {
        let keychain = get_provider();
        keychain.get_token()
    })
    .await
    .map_err(|e| AgentError::KeychainError(format!("Task join failed: {}", e)))?
}

/// Async wrapper to delete token using spawn_blocking
/// Required on Linux where secret-service uses zbus which conflicts with Tokio
pub async fn delete_token_async() -> Result<()> {
    tokio::task::spawn_blocking(|| {
        let keychain = get_provider();
        keychain.delete_token()
    })
    .await
    .map_err(|e| AgentError::KeychainError(format!("Task join failed: {}", e)))?
}

/// Async wrapper to save refresh token using spawn_blocking
pub async fn save_refresh_token_async(token: String) -> Result<()> {
    tokio::task::spawn_blocking(move || {
        let keychain = get_provider();
        keychain.save_refresh_token(&token)
    })
    .await
    .map_err(|e| AgentError::KeychainError(format!("Task join failed: {}", e)))?
}

/// Async wrapper to get refresh token using spawn_blocking
pub async fn get_refresh_token_async() -> Result<Option<String>> {
    tokio::task::spawn_blocking(|| {
        let keychain = get_provider();
        keychain.get_refresh_token()
    })
    .await
    .map_err(|e| AgentError::KeychainError(format!("Task join failed: {}", e)))?
}

/// Async wrapper to delete refresh token using spawn_blocking
pub async fn delete_refresh_token_async() -> Result<()> {
    tokio::task::spawn_blocking(|| {
        let keychain = get_provider();
        keychain.delete_refresh_token()
    })
    .await
    .map_err(|e| AgentError::KeychainError(format!("Task join failed: {}", e)))?
}

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;

/// Get the appropriate keychain provider for the current platform
pub fn get_provider() -> Box<dyn KeychainProvider> {
    #[cfg(target_os = "macos")]
    {
        Box::new(macos::MacOSKeychain::new())
    }

    #[cfg(target_os = "windows")]
    {
        Box::new(windows::WindowsKeychain::new())
    }

    #[cfg(target_os = "linux")]
    {
        Box::new(linux::LinuxKeychain::new())
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        compile_error!("Unsupported platform for keychain storage")
    }
}

pub const SERVICE_NAME: &str = "io.telfin.agent";
pub const ACCOUNT_NAME: &str = "auth_token";
pub const REFRESH_TOKEN_ACCOUNT: &str = "refresh_token";

// ============================================================================
// Phase 5: Credential Backup/Recovery
// 
// Provides file-based fallback when keychain access fails.
// Tokens are obfuscated (not truly encrypted) using XOR with machine fingerprint.
// This is defense-in-depth, not a replacement for proper keychain security.
// ============================================================================

/// Get the backup tokens file path
fn backup_tokens_path() -> std::path::PathBuf {
    dirs::data_local_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("telfin")
        .join(".tokens.bak")
}

/// Simple XOR obfuscation using machine fingerprint as key
/// This is NOT encryption - it's just obfuscation to prevent casual reading
fn obfuscate(data: &str, key: &str) -> Vec<u8> {
    let key_bytes = key.as_bytes();
    data.as_bytes()
        .iter()
        .enumerate()
        .map(|(i, b)| b ^ key_bytes[i % key_bytes.len()])
        .collect()
}

/// Deobfuscate data
fn deobfuscate(data: &[u8], key: &str) -> Option<String> {
    let key_bytes = key.as_bytes();
    let bytes: Vec<u8> = data
        .iter()
        .enumerate()
        .map(|(i, b)| b ^ key_bytes[i % key_bytes.len()])
        .collect();
    String::from_utf8(bytes).ok()
}

/// Backup tokens to file (obfuscated with machine fingerprint)
/// Called after successful keychain save
pub async fn backup_tokens(access_token: &str, refresh_token: &str) -> Result<()> {
    use crate::fingerprint;
    
    let fp = fingerprint::generate()
        .unwrap_or_else(|_| "fallback-key-12345".to_string());
    
    let path = backup_tokens_path();
    if let Some(parent) = path.parent() {
        let _ = tokio::fs::create_dir_all(parent).await;
    }
    
    // Format: access_token\nrefresh_token
    let combined = format!("{}\n{}", access_token, refresh_token);
    let obfuscated = obfuscate(&combined, &fp);
    
    tokio::fs::write(&path, obfuscated).await.map_err(|e| {
        AgentError::Other(format!("Failed to backup tokens: {}", e))
    })?;
    
    tracing::debug!("Tokens backed up to {:?}", path);
    Ok(())
}

/// Recover tokens from backup file
/// Returns (access_token, refresh_token) if successful
pub async fn recover_tokens() -> Result<(String, String)> {
    use crate::fingerprint;
    
    let fp = fingerprint::generate()
        .unwrap_or_else(|_| "fallback-key-12345".to_string());
    
    let path = backup_tokens_path();
    let data = tokio::fs::read(&path).await.map_err(|e| {
        AgentError::KeychainError(format!("No backup tokens: {}", e))
    })?;
    
    let combined = deobfuscate(&data, &fp).ok_or_else(|| {
        AgentError::KeychainError("Failed to deobfuscate backup tokens".to_string())
    })?;
    
    let parts: Vec<&str> = combined.splitn(2, '\n').collect();
    if parts.len() != 2 {
        return Err(AgentError::KeychainError("Invalid backup format".to_string()));
    }
    
    tracing::info!("Recovered tokens from backup file");
    Ok((parts[0].to_string(), parts[1].to_string()))
}

/// Get tokens with fallback to backup file
/// Tries keychain first, then backup file if keychain fails
pub async fn get_tokens_with_fallback() -> Result<(String, String)> {
    // Try keychain first
    if let (Ok(Some(access)), Ok(Some(refresh))) = 
        (get_token_async().await, get_refresh_token_async().await) 
    {
        return Ok((access, refresh));
    }
    
    tracing::warn!("Keychain failed, trying backup file...");
    recover_tokens().await
}

/// Clear backup tokens (call on logout)
pub async fn clear_backup_tokens() {
    let path = backup_tokens_path();
    let _ = tokio::fs::remove_file(&path).await;
}

