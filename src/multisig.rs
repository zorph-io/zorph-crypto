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

// verifies that at least `threshold` unique signatures are valid.
// deduplicates by public key — same key can't be counted twice.
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
