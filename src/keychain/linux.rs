use crate::error::{AgentError, Result};
use crate::keychain::{KeychainProvider, ACCOUNT_NAME, REFRESH_TOKEN_ACCOUNT, SERVICE_NAME};

#[cfg(target_os = "linux")]
use secret_service::blocking::SecretService;
#[cfg(target_os = "linux")]
use secret_service::EncryptionType;
#[cfg(target_os = "linux")]
use std::collections::HashMap;

pub struct LinuxKeychain;

impl LinuxKeychain {
    pub fn new() -> Self {
        Self
    }

    #[cfg(target_os = "linux")]
    fn get_attributes() -> HashMap<&'static str, &'static str> {
        let mut attributes = HashMap::new();
        attributes.insert("service", SERVICE_NAME);
        attributes.insert("account", ACCOUNT_NAME);
        attributes
    }

    #[cfg(target_os = "linux")]
    fn get_refresh_attributes() -> HashMap<&'static str, &'static str> {
        let mut attributes = HashMap::new();
        attributes.insert("service", SERVICE_NAME);
        attributes.insert("account", REFRESH_TOKEN_ACCOUNT);
        attributes
    }
}

impl KeychainProvider for LinuxKeychain {
    #[cfg(target_os = "linux")]
    fn save_token(&self, token: &str) -> Result<()> {
        // Note: This is a synchronous operation that will block.
        // The KeychainProvider trait is sync, but callers should wrap this
        // in tokio::task::spawn_blocking when calling from async context.
        let ss = SecretService::connect(EncryptionType::Dh).map_err(|e| {
            AgentError::KeychainError(format!("Failed to connect to secret service: {}", e))
        })?;

        let collection = ss.get_default_collection().map_err(|e| {
            AgentError::KeychainError(format!("Failed to get default collection: {}", e))
        })?;

        // Unlock collection if needed
        if collection.is_locked().unwrap_or(false) {
            collection.unlock().map_err(|e| {
                AgentError::KeychainError(format!("Failed to unlock collection: {}", e))
            })?;
        }

        let attributes = Self::get_attributes();

        // Delete existing item if present
        if let Ok(items) = collection.search_items(attributes.clone()) {
            for item in items {
                let _ = item.delete();
            }
        }

        // Create new item
        collection
            .create_item(
                "Telfin Agent Token",
                attributes,
                token.as_bytes(),
                true, // replace
                "text/plain",
            )
            .map_err(|e| AgentError::KeychainError(format!("Failed to save token: {}", e)))?;

        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn get_token(&self) -> Result<Option<String>> {
        // Note: This is a synchronous operation that will block.
        // Callers should wrap in tokio::task::spawn_blocking when calling from async context.
        let ss = SecretService::connect(EncryptionType::Dh).map_err(|e| {
            AgentError::KeychainError(format!("Failed to connect to secret service: {}", e))
        })?;

        let collection = ss.get_default_collection().map_err(|e| {
            AgentError::KeychainError(format!("Failed to get default collection: {}", e))
        })?;

        // Unlock collection if needed
        if collection.is_locked().unwrap_or(false) {
            collection.unlock().map_err(|e| {
                AgentError::KeychainError(format!("Failed to unlock collection: {}", e))
            })?;
        }

        let attributes = Self::get_attributes();

        let items = collection
            .search_items(attributes)
            .map_err(|e| AgentError::KeychainError(format!("Failed to search items: {}", e)))?;

        if let Some(item) = items.first() {
            let secret = item
                .get_secret()
                .map_err(|e| AgentError::KeychainError(format!("Failed to get secret: {}", e)))?;

            let token = String::from_utf8(secret.to_vec())
                .map_err(|e| AgentError::KeychainError(format!("Invalid token encoding: {}", e)))?;

            Ok(Some(token))
        } else {
            Ok(None)
        }
    }

    #[cfg(target_os = "linux")]
    fn delete_token(&self) -> Result<()> {
        // Note: This is a synchronous operation that will block.
        // Callers should wrap in tokio::task::spawn_blocking when calling from async context.
        let ss = SecretService::connect(EncryptionType::Dh).map_err(|e| {
            AgentError::KeychainError(format!("Failed to connect to secret service: {}", e))
        })?;

        let collection = ss.get_default_collection().map_err(|e| {
            AgentError::KeychainError(format!("Failed to get default collection: {}", e))
        })?;

        // Unlock collection if needed
        if collection.is_locked().unwrap_or(false) {
            collection.unlock().map_err(|e| {
                AgentError::KeychainError(format!("Failed to unlock collection: {}", e))
            })?;
        }

        let attributes = Self::get_attributes();

        if let Ok(items) = collection.search_items(attributes) {
            for item in items {
                item.delete().map_err(|e| {
                    AgentError::KeychainError(format!("Failed to delete item: {}", e))
                })?;
            }
        }

        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn save_refresh_token(&self, token: &str) -> Result<()> {
        let ss = SecretService::connect(EncryptionType::Dh).map_err(|e| {
            AgentError::KeychainError(format!("Failed to connect to secret service: {}", e))
        })?;

        let collection = ss.get_default_collection().map_err(|e| {
            AgentError::KeychainError(format!("Failed to get default collection: {}", e))
        })?;

        if collection.is_locked().unwrap_or(false) {
            collection.unlock().map_err(|e| {
                AgentError::KeychainError(format!("Failed to unlock collection: {}", e))
            })?;
        }

        let attributes = Self::get_refresh_attributes();

        // Delete existing item if present
        if let Ok(items) = collection.search_items(attributes.clone()) {
            for item in items {
                let _ = item.delete();
            }
        }

        collection
            .create_item(
                "Telfin Agent Refresh Token",
                attributes,
                token.as_bytes(),
                true,
                "text/plain",
            )
            .map_err(|e| {
                AgentError::KeychainError(format!("Failed to save refresh token: {}", e))
            })?;

        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn get_refresh_token(&self) -> Result<Option<String>> {
        let ss = SecretService::connect(EncryptionType::Dh).map_err(|e| {
            AgentError::KeychainError(format!("Failed to connect to secret service: {}", e))
        })?;

        let collection = ss.get_default_collection().map_err(|e| {
            AgentError::KeychainError(format!("Failed to get default collection: {}", e))
        })?;

        if collection.is_locked().unwrap_or(false) {
            collection.unlock().map_err(|e| {
                AgentError::KeychainError(format!("Failed to unlock collection: {}", e))
            })?;
        }

        let attributes = Self::get_refresh_attributes();

        let items = collection
            .search_items(attributes)
            .map_err(|e| AgentError::KeychainError(format!("Failed to search items: {}", e)))?;

        if let Some(item) = items.first() {
            let secret = item
                .get_secret()
                .map_err(|e| AgentError::KeychainError(format!("Failed to get secret: {}", e)))?;

            let token = String::from_utf8(secret.to_vec()).map_err(|e| {
                AgentError::KeychainError(format!("Invalid refresh token encoding: {}", e))
            })?;

            Ok(Some(token))
        } else {
            Ok(None)
        }
    }

    #[cfg(target_os = "linux")]
    fn delete_refresh_token(&self) -> Result<()> {
        let ss = SecretService::connect(EncryptionType::Dh).map_err(|e| {
            AgentError::KeychainError(format!("Failed to connect to secret service: {}", e))
        })?;

        let collection = ss.get_default_collection().map_err(|e| {
            AgentError::KeychainError(format!("Failed to get default collection: {}", e))
        })?;

        if collection.is_locked().unwrap_or(false) {
            collection.unlock().map_err(|e| {
                AgentError::KeychainError(format!("Failed to unlock collection: {}", e))
            })?;
        }

        let attributes = Self::get_refresh_attributes();

        if let Ok(items) = collection.search_items(attributes) {
            for item in items {
                item.delete().map_err(|e| {
                    AgentError::KeychainError(format!("Failed to delete item: {}", e))
                })?;
            }
        }

        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    fn save_token(&self, _token: &str) -> Result<()> {
        Err(AgentError::KeychainError(
            "Not implemented for this platform".to_string(),
        ))
    }

    #[cfg(not(target_os = "linux"))]
    fn get_token(&self) -> Result<Option<String>> {
        Err(AgentError::KeychainError(
            "Not implemented for this platform".to_string(),
        ))
    }

    #[cfg(not(target_os = "linux"))]
    fn delete_token(&self) -> Result<()> {
        Err(AgentError::KeychainError(
            "Not implemented for this platform".to_string(),
        ))
    }

    #[cfg(not(target_os = "linux"))]
    fn save_refresh_token(&self, _token: &str) -> Result<()> {
        Err(AgentError::KeychainError(
            "Not implemented for this platform".to_string(),
        ))
    }

    #[cfg(not(target_os = "linux"))]
    fn get_refresh_token(&self) -> Result<Option<String>> {
        Err(AgentError::KeychainError(
            "Not implemented for this platform".to_string(),
        ))
    }

    #[cfg(not(target_os = "linux"))]
    fn delete_refresh_token(&self) -> Result<()> {
        Err(AgentError::KeychainError(
            "Not implemented for this platform".to_string(),
        ))
    }
}

#[cfg(test)]
#[cfg(target_os = "linux")]
mod tests {
    use super::*;

    #[test]
    #[ignore] // Only run when explicitly requested
    fn test_linux_keychain() {
        let keychain = LinuxKeychain::new();

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
    fn test_linux_keychain_refresh_token() {
        let keychain = LinuxKeychain::new();

        let _ = keychain.delete_refresh_token();

        assert!(keychain.get_refresh_token().unwrap().is_none());

        keychain
            .save_refresh_token("test-refresh-token-123")
            .unwrap();

        let token = keychain.get_refresh_token().unwrap();
        assert_eq!(token, Some("test-refresh-token-123".to_string()));

        keychain.delete_refresh_token().unwrap();

        assert!(keychain.get_refresh_token().unwrap().is_none());
    }
}
