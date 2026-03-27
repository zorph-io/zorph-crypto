use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use thiserror::Error;

use crate::{keys, sign};

#[derive(Debug, Error)]
pub enum TokenError {
    #[error("token expired")]
    Expired,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("malformed token: {0}")]
    Malformed(String),
}

const API_KEY_PREFIX: &str = "zrph_";

/// 32 random bytes → 64 hex chars.
pub fn generate_token() -> String {
    to_hex(&keys::random_bytes::<32>())
}

/// Prefixed API key: `zrph_` + 32 random bytes hex.
pub fn generate_api_key() -> String {
    format!("{API_KEY_PREFIX}{}", to_hex(&keys::random_bytes::<32>()))
}

/// Ed25519-signed token carrying an arbitrary payload with optional expiry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedToken {
    pub payload: Vec<u8>,
    /// Unix timestamp (seconds). `0` means no expiry.
    pub expires_at: u64,
    pub signature: Vec<u8>,
    pub signer_key: Vec<u8>,
}

impl SignedToken {
    /// Canonical message that gets signed: `expires_at(8 BE) || payload`.
    fn message(payload: &[u8], expires_at: u64) -> Vec<u8> {
        let mut msg = Vec::with_capacity(8 + payload.len());
        msg.extend_from_slice(&expires_at.to_be_bytes());
        msg.extend_from_slice(payload);
        msg
    }

    /// Serialize: `expires_at(8) || signature(64) || signer_key(32) || payload`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(104 + self.payload.len());
        out.extend_from_slice(&self.expires_at.to_be_bytes());
        out.extend_from_slice(&self.signature);
        out.extend_from_slice(&self.signer_key);
        out.extend_from_slice(&self.payload);
        out
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, TokenError> {
        const HEADER: usize = 8 + 64 + 32; // 104
        if data.len() < HEADER {
            return Err(TokenError::Malformed("too short".into()));
        }
        let expires_at = u64::from_be_bytes(
            data[..8]
                .try_into()
                .map_err(|_| TokenError::Malformed("bad expiry".into()))?,
        );
        let signature = data[8..72].to_vec();
        let signer_key = data[72..104].to_vec();
        let payload = data[104..].to_vec();

        Ok(Self {
            payload,
            expires_at,
            signature,
            signer_key,
        })
    }
}

/// Create a signed token. `expires_at = 0` means no expiry.
pub fn create_signed_token(
    signing_key: &SigningKey,
    payload: &[u8],
    expires_at: u64,
) -> SignedToken {
    let msg = SignedToken::message(payload, expires_at);
    let sig = sign::sign(signing_key, &msg);
    let vk = signing_key.verifying_key();

    SignedToken {
        payload: payload.to_vec(),
        expires_at,
        signature: sign::signature_to_bytes(&sig).to_vec(),
        signer_key: sign::verifying_key_to_bytes(&vk).to_vec(),
    }
}

/// Verify signature and expiry. `now` is the current unix timestamp.
///
/// Returns the payload on success.
pub fn verify_signed_token(
    verifying_key: &VerifyingKey,
    token: &SignedToken,
    now: u64,
) -> Result<Vec<u8>, TokenError> {
    // expiry check
    if token.expires_at > 0 && now > token.expires_at {
        return Err(TokenError::Expired);
    }

    // signer must match the expected key (constant-time)
    let expected = sign::verifying_key_to_bytes(verifying_key);
    if token.signer_key.len() != 32 || !bool::from(expected.ct_eq(token.signer_key.as_slice())) {
        return Err(TokenError::InvalidSignature);
    }

    // verify Ed25519 signature
    if token.signature.len() != 64 {
        return Err(TokenError::InvalidSignature);
    }
    let msg = SignedToken::message(&token.payload, token.expires_at);
    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(&token.signature);
    let sig = sign::signature_from_bytes(&sig_bytes);
    sign::verify(verifying_key, &msg, &sig).map_err(|_| TokenError::InvalidSignature)?;

    Ok(token.payload.clone())
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_length() {
        let t = generate_token();
        assert_eq!(t.len(), 64);
        assert!(t.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn api_key_prefix() {
        let k = generate_api_key();
        assert!(k.starts_with("zrph_"));
        assert_eq!(k.len(), 5 + 64);
    }

    #[test]
    fn tokens_are_unique() {
        let a = generate_token();
        let b = generate_token();
        assert_ne!(a, b);
    }
}
