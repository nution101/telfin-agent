use crate::error::{AgentError, Result};
use crate::keychain::{KeychainProvider, ACCOUNT_NAME, REFRESH_TOKEN_ACCOUNT, SERVICE_NAME};
use security_framework::passwords::{
    delete_generic_password, get_generic_password, set_generic_password,
};

pub struct MacOSKeychain;

impl MacOSKeychain {
    pub fn new() -> Self {
        Self
    }
}

impl KeychainProvider for MacOSKeychain {
    fn save_token(&self, token: &str) -> Result<()> {
        // Delete existing token if present
        let _ = delete_generic_password(SERVICE_NAME, ACCOUNT_NAME);

        // Save new token
        set_generic_password(SERVICE_NAME, ACCOUNT_NAME, token.as_bytes())
            .map_err(|e| AgentError::KeychainError(format!("Failed to save token: {}", e)))?;

        Ok(())
    }

    fn get_token(&self) -> Result<Option<String>> {
        match get_generic_password(SERVICE_NAME, ACCOUNT_NAME) {
            Ok(password) => {
                let token = String::from_utf8(password.to_vec()).map_err(|e| {
                    AgentError::KeychainError(format!("Invalid token encoding: {}", e))
                })?;
                Ok(Some(token))
            }
            Err(_) => Ok(None),
        }
    }

    fn delete_token(&self) -> Result<()> {
        match delete_generic_password(SERVICE_NAME, ACCOUNT_NAME) {
            Ok(_) => Ok(()),
            Err(e) => {
                // If the error is "item not found", that's acceptable
                if e.to_string().contains("not found") {
                    Ok(())
                } else {
                    Err(AgentError::KeychainError(format!(
                        "Failed to delete token: {}",
                        e
                    )))
                }
            }
        }
    }

    fn save_refresh_token(&self, token: &str) -> Result<()> {
        // Delete existing refresh token if present
        let _ = delete_generic_password(SERVICE_NAME, REFRESH_TOKEN_ACCOUNT);

        // Save new refresh token
        set_generic_password(SERVICE_NAME, REFRESH_TOKEN_ACCOUNT, token.as_bytes()).map_err(
            |e| AgentError::KeychainError(format!("Failed to save refresh token: {}", e)),
        )?;

        Ok(())
    }

    fn get_refresh_token(&self) -> Result<Option<String>> {
        match get_generic_password(SERVICE_NAME, REFRESH_TOKEN_ACCOUNT) {
            Ok(password) => {
                let token = String::from_utf8(password.to_vec()).map_err(|e| {
                    AgentError::KeychainError(format!("Invalid refresh token encoding: {}", e))
                })?;
                Ok(Some(token))
            }
            Err(_) => Ok(None),
        }
    }

    fn delete_refresh_token(&self) -> Result<()> {
        match delete_generic_password(SERVICE_NAME, REFRESH_TOKEN_ACCOUNT) {
            Ok(_) => Ok(()),
            Err(e) => {
                // If the error is "item not found", that's acceptable
                if e.to_string().contains("not found") {
                    Ok(())
                } else {
                    Err(AgentError::KeychainError(format!(
                        "Failed to delete refresh token: {}",
                        e
                    )))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore] // Only run when explicitly requested
    fn test_macos_keychain() {
        let keychain = MacOSKeychain::new();

        // Clean up first
        let _ = keychain.delete_token();

        // Should be None initially
        assert!(keychain.get_token().unwrap().is_none());

        // Save token
        keychain.save_token("test-token-123").unwrap();

        // Should retrieve the same token
        let token = keychain.get_token().unwrap();
        assert_eq!(token, Some("test-token-123".to_string()));

        // Delete token
        keychain.delete_token().unwrap();

        // Should be None after deletion
        assert!(keychain.get_token().unwrap().is_none());
    }

    #[test]
    #[ignore] // Only run when explicitly requested
    fn test_macos_keychain_refresh_token() {
        let keychain = MacOSKeychain::new();

        // Clean up first
        let _ = keychain.delete_refresh_token();

        // Should be None initially
        assert!(keychain.get_refresh_token().unwrap().is_none());

        // Save refresh token
        keychain
            .save_refresh_token("test-refresh-token-123")
            .unwrap();

        // Should retrieve the same token
        let token = keychain.get_refresh_token().unwrap();
        assert_eq!(token, Some("test-refresh-token-123".to_string()));

        // Delete refresh token
        keychain.delete_refresh_token().unwrap();

        // Should be None after deletion
        assert!(keychain.get_refresh_token().unwrap().is_none());
    }
}
