use crate::error::{AgentError, Result};
use crate::fingerprint;
use crate::keychain;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use uuid::Uuid;

#[derive(Debug, Serialize)]
struct DeviceCodeRequest {
    device_name: String,
    os_type: String,
    device_fingerprint: String,
}

#[derive(Debug, Deserialize)]
struct DeviceCodeResponse {
    device_code: String,
    user_code: String,
    verification_uri: String,
    expires_in: u64,
    interval: u64,
}

#[derive(Debug, Serialize)]
struct TokenRequest {
    device_code: String,
    grant_type: String,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct RegisterMachineRequest {
    name: String,
    description: Option<String>,
    hostname: Option<String>,
}

#[derive(Debug, Deserialize)]
struct MachineInfo {
    id: Uuid,
    name: String,
}

#[derive(Debug, Deserialize)]
struct RegisterMachineResponse {
    machine: MachineInfo,
    agent_token: String,
}

/// Result of machine registration
pub struct MachineRegistration {
    pub machine_id: Uuid,
    pub agent_token: String,
}

/// Execute the device code authorization flow (RFC 8628)
pub async fn device_code_flow(server_url: &str) -> Result<()> {
    let client = Client::new();
    let api_url = format!("{}/api", server_url);

    // Step 1: Request device code
    tracing::info!("Requesting device code...");
    let device_code_resp = request_device_code(&client, &api_url).await?;

    // Step 2: Display user code and verification URL
    display_authorization_prompt(&device_code_resp);

    // Step 3: Poll for token
    tracing::info!("Waiting for authorization...");
    let token = poll_for_token(
        &client,
        &api_url,
        &device_code_resp.device_code,
        device_code_resp.interval,
        device_code_resp.expires_in,
    )
    .await?;

    // Step 4: Store token in keychain
    let keychain = keychain::get_provider();
    keychain.save_token(&token)?;

    tracing::info!("Token saved to keychain");
    Ok(())
}

async fn request_device_code(client: &Client, api_url: &str) -> Result<DeviceCodeResponse> {
    let device_name = fingerprint::get_device_name();
    let os_type = fingerprint::get_os_type();
    let device_fingerprint = fingerprint::generate()?;

    let request = DeviceCodeRequest {
        device_name,
        os_type,
        device_fingerprint,
    };

    let url = format!("{}/device/code", api_url);
    let response = client
        .post(&url)
        .json(&request)
        .send()
        .await?
        .error_for_status()?;

    let device_code: DeviceCodeResponse = response.json().await?;
    Ok(device_code)
}

fn display_authorization_prompt(resp: &DeviceCodeResponse) {
    println!("\n╔════════════════════════════════════════════════════════════╗");
    println!("║                 Device Authorization                      ║");
    println!("╟────────────────────────────────────────────────────────────╢");
    println!("║                                                            ║");
    println!(
        "║  1. Visit: {}                        ║",
        resp.verification_uri
    );
    println!("║                                                            ║");
    println!(
        "║  2. Enter code:  {}                            ║",
        resp.user_code
    );
    println!("║                                                            ║");
    println!(
        "║  Expires in {} minutes                                   ║",
        resp.expires_in / 60
    );
    println!("║                                                            ║");
    println!("╚════════════════════════════════════════════════════════════╝\n");
}

async fn poll_for_token(
    client: &Client,
    api_url: &str,
    device_code: &str,
    interval: u64,
    expires_in: u64,
) -> Result<String> {
    let url = format!("{}/device/token", api_url);
    let poll_interval = Duration::from_secs(interval.max(5));
    let max_attempts = (expires_in / interval).max(1);

    for attempt in 0..max_attempts {
        if attempt > 0 {
            tokio::time::sleep(poll_interval).await;
        }

        let request = TokenRequest {
            device_code: device_code.to_string(),
            grant_type: "urn:ietf:params:oauth:grant-type:device_code".to_string(),
        };

        let response = match client.post(&url).json(&request).send().await {
            Ok(resp) => resp,
            Err(e) => {
                tracing::warn!("Poll request failed: {}", e);
                continue;
            }
        };

        // Check for success (200) or pending (400)
        let status = response.status();
        let token_resp: TokenResponse = match response.json().await {
            Ok(resp) => resp,
            Err(e) => {
                tracing::warn!("Failed to parse response: {}", e);
                continue;
            }
        };

        if let Some(token) = token_resp.access_token {
            return Ok(token);
        }

        if let Some(error) = &token_resp.error {
            match error.as_str() {
                "authorization_pending" => {
                    print!(".");
                    std::io::Write::flush(&mut std::io::stdout()).ok();
                    continue;
                }
                "expired_token" => {
                    return Err(AgentError::DeviceCodeExpired);
                }
                _ => {
                    return Err(AgentError::AuthError(format!(
                        "Authorization failed: {}",
                        error
                    )));
                }
            }
        }

        // If status is not successful and no specific error, check status code
        if !status.is_success() {
            if status.as_u16() == 400 {
                // Assume authorization_pending
                print!(".");
                std::io::Write::flush(&mut std::io::stdout()).ok();
                continue;
            } else {
                return Err(AgentError::AuthError(format!(
                    "Unexpected status: {}",
                    status
                )));
            }
        }
    }

    Err(AgentError::DeviceCodeExpired)
}

/// Register or get existing machine with the gateway
/// Returns agent_token that can be used for WebSocket connection
pub async fn register_machine(
    server_url: &str,
    access_token: &str,
    machine_name: &str,
) -> Result<MachineRegistration> {
    let client = Client::new();
    let api_url = format!("{}/api/machines", server_url);

    tracing::info!("Registering machine with gateway...");

    let request = RegisterMachineRequest {
        name: machine_name.to_string(),
        description: Some(format!("Telfin Agent on {}", fingerprint::get_os_type())),
        hostname: Some(machine_name.to_string()),
    };

    let response = client
        .post(&api_url)
        .header("Authorization", format!("Bearer {}", access_token))
        .json(&request)
        .send()
        .await?;

    let status = response.status();
    if !status.is_success() {
        let error_text = response.text().await.unwrap_or_default();
        return Err(AgentError::AuthError(format!(
            "Failed to register machine: {} - {}",
            status, error_text
        )));
    }

    let resp: RegisterMachineResponse = response.json().await?;

    tracing::info!(
        "Machine registered: {} ({})",
        resp.machine.name,
        resp.machine.id
    );

    Ok(MachineRegistration {
        machine_id: resp.machine.id,
        agent_token: resp.agent_token,
    })
}

#[derive(Debug, Deserialize)]
pub struct TokenClaims {
    pub exp: usize,
    pub iat: usize,
    pub sub: String,
    #[serde(default)]
    pub machine_id: Option<String>,
}

/// Validate JWT token structure and expiration (local validation only)
/// Server validates signature - we check structure and expiration locally
pub fn validate_token_locally(token: &str) -> Result<TokenClaims> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.insecure_disable_signature_validation();
    validation.validate_exp = true;

    let token_data = decode::<TokenClaims>(
        token,
        &DecodingKey::from_secret(&[]),
        &validation,
    )
    .map_err(|e| AgentError::AuthError(format!("Invalid token: {}", e)))?;

    Ok(token_data.claims)
}

/// Check if token is expiring within given seconds
pub fn token_expiring_soon(token: &str, within_secs: u64) -> bool {
    if let Ok(claims) = validate_token_locally(token) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or(std::time::Duration::ZERO)
            .as_secs() as usize;
        claims.exp < now + within_secs as usize
    } else {
        true // Treat invalid tokens as expiring
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_device_code_request_structure() {
        let req = DeviceCodeRequest {
            device_name: "test-machine".to_string(),
            os_type: "linux".to_string(),
            device_fingerprint: "abc123".to_string(),
        };

        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("device_name"));
        assert!(json.contains("test-machine"));
    }

    #[test]
    fn test_validate_expired_token() {
        // Token with exp in the past (Jan 1, 2020)
        let expired_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIiwiZXhwIjoxNTc3ODM2ODAwLCJpYXQiOjE1Nzc4MzMyMDB9.fake";

        let result = validate_token_locally(expired_token);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AgentError::AuthError(_)));
    }

    #[test]
    fn test_validate_valid_token() {
        // Token with exp in the future (year 2030)
        let future_exp = 1893456000; // Jan 1, 2030
        let past_iat = 1577836800; // Jan 1, 2020

        // Minimal valid JWT structure (header.payload.signature)
        use base64::Engine;
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"alg":"HS256","typ":"JWT"}"#);
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
            format!(
                r#"{{"sub":"user123","exp":{},"iat":{}}}"#,
                future_exp, past_iat
            ),
        );
        let valid_token = format!("{}.{}.fake_signature", header, payload);

        let result = validate_token_locally(&valid_token);
        assert!(result.is_ok());
        let claims = result.unwrap();
        assert_eq!(claims.sub, "user123");
        assert_eq!(claims.exp, future_exp);
        assert_eq!(claims.iat, past_iat);
    }

    #[test]
    fn test_token_expiring_soon() {
        // Token expiring in 10 seconds
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as usize;
        let soon_exp = now + 10;

        use base64::Engine;
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"alg":"HS256","typ":"JWT"}"#);
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(format!(r#"{{"sub":"user123","exp":{},"iat":{}}}"#, soon_exp, now));
        let token = format!("{}.{}.fake_signature", header, payload);

        // Should be expiring within 60 seconds
        assert!(token_expiring_soon(&token, 60));

        // Should not be expiring within 5 seconds
        assert!(!token_expiring_soon(&token, 5));
    }

    #[test]
    fn test_token_expiring_soon_with_invalid_token() {
        let invalid_token = "not.a.valid.jwt";

        // Invalid tokens should be treated as expiring
        assert!(token_expiring_soon(invalid_token, 60));
    }

    #[test]
    fn test_token_claims_with_machine_id() {
        let future_exp = 1893456000;
        let past_iat = 1577836800;

        use base64::Engine;
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"alg":"HS256","typ":"JWT"}"#);
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
            format!(
                r#"{{"sub":"user123","exp":{},"iat":{},"machine_id":"machine456"}}"#,
                future_exp, past_iat
            ),
        );
        let token = format!("{}.{}.fake_signature", header, payload);

        let result = validate_token_locally(&token);
        assert!(result.is_ok());
        let claims = result.unwrap();
        assert_eq!(claims.machine_id, Some("machine456".to_string()));
    }
}
