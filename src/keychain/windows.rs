use crate::error::{AgentError, Result};
use crate::keychain::{KeychainProvider, ACCOUNT_NAME, SERVICE_NAME};

#[cfg(target_os = "windows")]
use windows::core::{PCWSTR, PWSTR};
#[cfg(target_os = "windows")]
use windows::Win32::Foundation::ERROR_NOT_FOUND;
#[cfg(target_os = "windows")]
use windows::Win32::Security::Credentials::{
    CredDeleteW, CredReadW, CredWriteW, CREDENTIALW, CREDENTIAL_ATTRIBUTEW,
    CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE_GENERIC,
};

pub struct WindowsKeychain;

impl WindowsKeychain {
    pub fn new() -> Self {
        Self
    }

    #[cfg(target_os = "windows")]
    fn target_name() -> Vec<u16> {
        use std::os::windows::ffi::OsStrExt;
        let name = format!("{}:{}", SERVICE_NAME, ACCOUNT_NAME);
        std::ffi::OsStr::new(&name)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }
}

impl KeychainProvider for WindowsKeychain {
    #[cfg(target_os = "windows")]
    fn save_token(&self, token: &str) -> Result<()> {
        use std::ptr;

        let target_name = Self::target_name();
        let token_bytes = token.as_bytes();

        let mut credential = CREDENTIALW {
            Flags: 0,
            Type: CRED_TYPE_GENERIC,
            TargetName: PWSTR(target_name.as_ptr() as *mut u16),
            Comment: PWSTR(ptr::null_mut()),
            LastWritten: Default::default(),
            CredentialBlobSize: token_bytes.len() as u32,
            CredentialBlob: token_bytes.as_ptr() as *mut u8,
            Persist: CRED_PERSIST_LOCAL_MACHINE,
            AttributeCount: 0,
            Attributes: ptr::null_mut(),
            TargetAlias: PWSTR(ptr::null_mut()),
            UserName: PWSTR(ptr::null_mut()),
        };

        unsafe {
            CredWriteW(&mut credential, 0)
                .map_err(|e| AgentError::KeychainError(format!("Failed to save token: {}", e)))?;
        }

        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn get_token(&self) -> Result<Option<String>> {
        use std::ptr;

        let target_name = Self::target_name();
        let mut credential_ptr: *mut CREDENTIALW = ptr::null_mut();

        unsafe {
            match CredReadW(
                PCWSTR(target_name.as_ptr()),
                CRED_TYPE_GENERIC,
                0,
                &mut credential_ptr,
            ) {
                Ok(_) => {
                    let credential = &*credential_ptr;
                    let blob = std::slice::from_raw_parts(
                        credential.CredentialBlob,
                        credential.CredentialBlobSize as usize,
                    );
                    let token = String::from_utf8(blob.to_vec()).map_err(|e| {
                        AgentError::KeychainError(format!("Invalid token encoding: {}", e))
                    })?;

                    // Free the credential
                    windows::Win32::Security::Credentials::CredFree(credential_ptr as *const _);

                    Ok(Some(token))
                }
                Err(e) => {
                    if e.code() == ERROR_NOT_FOUND.into() {
                        Ok(None)
                    } else {
                        Err(AgentError::KeychainError(format!(
                            "Failed to read token: {}",
                            e
                        )))
                    }
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    fn delete_token(&self) -> Result<()> {
        let target_name = Self::target_name();

        unsafe {
            match CredDeleteW(PCWSTR(target_name.as_ptr()), CRED_TYPE_GENERIC, 0) {
                Ok(_) => Ok(()),
                Err(e) => {
                    if e.code() == ERROR_NOT_FOUND.into() {
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
    }

    #[cfg(not(target_os = "windows"))]
    fn save_token(&self, _token: &str) -> Result<()> {
        Err(AgentError::KeychainError(
            "Not implemented for this platform".to_string(),
        ))
    }

    #[cfg(not(target_os = "windows"))]
    fn get_token(&self) -> Result<Option<String>> {
        Err(AgentError::KeychainError(
            "Not implemented for this platform".to_string(),
        ))
    }

    #[cfg(not(target_os = "windows"))]
    fn delete_token(&self) -> Result<()> {
        Err(AgentError::KeychainError(
            "Not implemented for this platform".to_string(),
        ))
    }
}
