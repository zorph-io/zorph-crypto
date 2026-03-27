//! Ed25519 digital signatures.
//!
//! Thin wrapper around [`ed25519_dalek`] providing key generation,
//! signing, verification, and byte-level serialization helpers.

use ed25519_dalek::{Signer, Verifier, SigningKey, VerifyingKey, Signature};
use rand::rngs::OsRng;
use thiserror::Error;

/// Errors returned by signature operations.
#[derive(Debug, Error)]
pub enum SignError {
    #[error("signature verification failed")]
    Verification,
    #[error("signing failed: {0}")]
    Signing(String),
    #[error("invalid key bytes: {0}")]
    InvalidKey(String),
    #[error("invalid signature bytes")]
    InvalidSignature,
}

/// Generates a random Ed25519 signing/verifying keypair.
pub fn generate_keypair() -> (SigningKey, VerifyingKey) {
    let signing = SigningKey::generate(&mut OsRng);
    let verifying = signing.verifying_key();
    (signing, verifying)
}

/// Signs `message` with the given Ed25519 [`SigningKey`].
pub fn sign(key: &SigningKey, message: &[u8]) -> Signature {
    key.sign(message)
}

/// Verifies an Ed25519 `signature` over `message` against the given [`VerifyingKey`].
pub fn verify(key: &VerifyingKey, message: &[u8], signature: &Signature) -> Result<(), SignError> {
    key.verify(message, signature)
        .map_err(|_| SignError::Verification)
}

/// Serializes a [`SigningKey`] to its 32-byte seed.
pub fn signing_key_to_bytes(key: &SigningKey) -> [u8; 32] {
    key.to_bytes()
}

/// Deserializes a [`SigningKey`] from a 32-byte seed.
pub fn signing_key_from_bytes(bytes: &[u8; 32]) -> SigningKey {
    SigningKey::from_bytes(bytes)
}

/// Serializes a [`VerifyingKey`] to its 32-byte compressed Edwards point.
pub fn verifying_key_to_bytes(key: &VerifyingKey) -> [u8; 32] {
    key.to_bytes()
}

/// Deserializes a [`VerifyingKey`] from 32 bytes.
pub fn verifying_key_from_bytes(bytes: &[u8; 32]) -> Result<VerifyingKey, SignError> {
    VerifyingKey::from_bytes(bytes)
        .map_err(|e| SignError::InvalidKey(e.to_string()))
}

/// Serializes a [`Signature`] to its 64-byte form.
pub fn signature_to_bytes(sig: &Signature) -> [u8; 64] {
    sig.to_bytes()
}

/// Deserializes a [`Signature`] from 64 bytes.
pub fn signature_from_bytes(bytes: &[u8; 64]) -> Signature {
    Signature::from_bytes(bytes)
}
