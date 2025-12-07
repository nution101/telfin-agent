use crate::error::{AgentError, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};
use std::sync::Arc;

/// Certificate verifier that pins to a specific SHA-256 fingerprint
#[derive(Debug)]
pub struct PinnedCertVerifier {
    expected_fingerprint: Vec<u8>,
}

impl PinnedCertVerifier {
    pub fn new(fingerprint_hex: &str) -> Result<Self> {
        // Parse hex fingerprint (with or without colons)
        let clean = fingerprint_hex.replace(':', "").replace(' ', "");
        let bytes = hex::decode(&clean).map_err(|e| {
            AgentError::ConfigError(format!("Invalid certificate fingerprint: {}", e))
        })?;

        if bytes.len() != 32 {
            return Err(AgentError::ConfigError(
                "Certificate fingerprint must be 32 bytes (SHA-256)".to_string(),
            ));
        }

        Ok(Self {
            expected_fingerprint: bytes,
        })
    }

    fn verify_cert(&self, cert: &CertificateDer<'_>) -> std::result::Result<(), rustls::Error> {
        let mut hasher = Sha256::new();
        hasher.update(cert.as_ref());
        let fingerprint = hasher.finalize();

        if fingerprint.as_slice() == self.expected_fingerprint.as_slice() {
            Ok(())
        } else {
            tracing::error!(
                "Certificate fingerprint mismatch! Expected: {}, got: {}",
                hex::encode(&self.expected_fingerprint),
                hex::encode(&fingerprint)
            );
            Err(rustls::Error::General(
                "Certificate fingerprint mismatch".into(),
            ))
        }
    }
}

impl ServerCertVerifier for PinnedCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        self.verify_cert(end_entity)?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}

/// Build TLS config, optionally with certificate pinning
pub fn build_tls_config(fingerprint: Option<&str>) -> Result<rustls::ClientConfig> {
    let builder = rustls::ClientConfig::builder_with_provider(
        Arc::new(rustls::crypto::aws_lc_rs::default_provider())
    )
    .with_safe_default_protocol_versions()
    .map_err(|e| AgentError::ConfigError(format!("TLS protocol version error: {}", e)))?;

    if let Some(fp) = fingerprint {
        let verifier = Arc::new(PinnedCertVerifier::new(fp)?);
        Ok(builder
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth())
    } else {
        // Use default certificate validation with native roots
        let root_store =
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Ok(builder
            .with_root_certificates(root_store)
            .with_no_client_auth())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pinned_cert_verifier_new() {
        // Valid 64-char hex string (32 bytes)
        let fp = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        assert!(PinnedCertVerifier::new(fp).is_ok());

        // Valid with colons
        let fp_colons = "AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89";
        assert!(PinnedCertVerifier::new(fp_colons).is_ok());

        // Too short
        let fp_short = "abcdef01";
        assert!(PinnedCertVerifier::new(fp_short).is_err());

        // Invalid hex
        let fp_invalid = "gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg";
        assert!(PinnedCertVerifier::new(fp_invalid).is_err());
    }

    #[test]
    fn test_build_tls_config_default() {
        // Should succeed with no fingerprint
        assert!(build_tls_config(None).is_ok());
    }

    #[test]
    fn test_build_tls_config_pinned() {
        let fp = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        assert!(build_tls_config(Some(fp)).is_ok());
    }

    #[test]
    fn test_build_tls_config_invalid_fingerprint() {
        let fp_invalid = "not-a-valid-fingerprint";
        assert!(build_tls_config(Some(fp_invalid)).is_err());
    }
}
