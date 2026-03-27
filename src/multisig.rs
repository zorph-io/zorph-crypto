//! Threshold multisig: m-of-n Ed25519 signature verification.
//!
//! Collects Ed25519 signatures from multiple signers and verifies that
//! at least `threshold` unique valid signatures are present.
//! Duplicate public keys are deduplicated automatically.

use ed25519_dalek::{Signer, Verifier, SigningKey, VerifyingKey, Signature};
use thiserror::Error;

/// Returned when fewer than `threshold` valid unique signatures are provided.
#[derive(Debug, Error)]
pub enum MultisigError {
    #[error("not enough valid signatures: got {got}, need {need}")]
    Threshold { got: usize, need: usize },
}

/// Signs `message` with each key in `signers`, returning `(verifying_key, signature)` pairs.
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

/// Verifies that at least `threshold` unique valid signatures exist for `message`.
///
/// Deduplicates by public key — the same key cannot be counted twice.
pub fn verify_multisig(
    message: &[u8],
    signatures: &[(VerifyingKey, Signature)],
    threshold: usize,
) -> Result<(), MultisigError> {
    let mut seen_keys = Vec::with_capacity(signatures.len());
    let mut valid = 0usize;

    for (pk, sig) in signatures {
        let pk_bytes = pk.to_bytes();
        if seen_keys.contains(&pk_bytes) {
            continue;
        }
        if pk.verify(message, sig).is_ok() {
            seen_keys.push(pk_bytes);
            valid += 1;
        }
    }

    if valid >= threshold {
        Ok(())
    } else {
        Err(MultisigError::Threshold {
            got: valid,
            need: threshold,
        })
    }
}
