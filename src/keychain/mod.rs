use crate::error::{AgentError, Result};

/// Platform-agnostic keychain interface
pub trait KeychainProvider: Send + Sync {
    /// Save authentication token to keychain
    fn save_token(&self, token: &str) -> Result<()>;

    /// Retrieve authentication token from keychain
    fn get_token(&self) -> Result<Option<String>>;

    /// Delete authentication token from keychain
    fn delete_token(&self) -> Result<()>;
}

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "linux")]
mod linux;

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

const SERVICE_NAME: &str = "io.telfin.agent";
const ACCOUNT_NAME: &str = "auth_token";
