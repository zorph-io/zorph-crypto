use ed25519_dalek::{Signer, Verifier, SigningKey, VerifyingKey, Signature};
use rand::rngs::OsRng;
use thiserror::Error;

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

pub fn generate_keypair() -> (SigningKey, VerifyingKey) {
    let signing = SigningKey::generate(&mut OsRng);
    let verifying = signing.verifying_key();
    (signing, verifying)
}

pub fn sign(key: &SigningKey, message: &[u8]) -> Signature {
    key.sign(message)
}

pub fn verify(key: &VerifyingKey, message: &[u8], signature: &Signature) -> Result<(), SignError> {
    key.verify(message, signature)
        .map_err(|_| SignError::Verification)
}

// serialization — Ed25519 keys are 32 bytes, signatures are 64 bytes

pub fn signing_key_to_bytes(key: &SigningKey) -> [u8; 32] {
    key.to_bytes()
}

pub fn signing_key_from_bytes(bytes: &[u8; 32]) -> SigningKey {
    SigningKey::from_bytes(bytes)
}

pub fn verifying_key_to_bytes(key: &VerifyingKey) -> [u8; 32] {
    key.to_bytes()
}

pub fn verifying_key_from_bytes(bytes: &[u8; 32]) -> Result<VerifyingKey, SignError> {
    VerifyingKey::from_bytes(bytes)
        .map_err(|e| SignError::InvalidKey(e.to_string()))
}

pub fn signature_to_bytes(sig: &Signature) -> [u8; 64] {
    sig.to_bytes()
}

pub fn signature_from_bytes(bytes: &[u8; 64]) -> Signature {
    Signature::from_bytes(bytes)
}
