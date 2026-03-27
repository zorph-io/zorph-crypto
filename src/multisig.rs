use ed25519_dalek::{Signer, Verifier, SigningKey, VerifyingKey, Signature};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MultisigError {
    #[error("not enough valid signatures: got {got}, need {need}")]
    Threshold { got: usize, need: usize },
}

pub fn create_multisig(
    message: &[u8],
    signers: &[&SigningKey],
) -> Vec<(VerifyingKey, Signature)> {
    signers
        .iter()
        .map(|sk| {
            let vk = sk.verifying_key();
            let sig = sk.sign(message);
            (vk, sig)
        })
        .collect()
}

// verifies that at least `threshold` signatures are valid
pub fn verify_multisig(
    message: &[u8],
    signatures: &[(VerifyingKey, Signature)],
    threshold: usize,
) -> Result<(), MultisigError> {
    let valid = signatures
        .iter()
        .filter(|(pk, sig)| pk.verify(message, sig).is_ok())
        .count();

    if valid >= threshold {
        Ok(())
    } else {
        Err(MultisigError::Threshold {
            got: valid,
            need: threshold,
        })
    }
}
