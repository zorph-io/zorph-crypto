use ed25519_dalek::{Signer, Verifier, SigningKey, VerifyingKey, Signature};
use rand::rngs::OsRng;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SignError {
    #[error("signature verification failed")]
    Verification,
    #[error("signing failed: {0}")]
    Signing(String),
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
