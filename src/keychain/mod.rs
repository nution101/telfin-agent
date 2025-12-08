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
