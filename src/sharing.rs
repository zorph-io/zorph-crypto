//! Shamir's Secret Sharing.
//!
//! Splits a secret into `n` shares with a threshold of `k` — any `k` shares
//! can reconstruct the original secret, but fewer than `k` reveal nothing.
//! Operates on arbitrary binary data (hex-encoded internally for the shamir crate).

use thiserror::Error;

/// Errors returned by split and reconstruct operations.
#[derive(Debug, Error)]
pub enum SharingError {
    #[error("sharing operation failed: {0}")]
    Operation(String),
    #[error("recovery failed: insufficient or invalid shares")]
    Recovery,
}

/// A single share of a split secret.
#[derive(Clone, Debug)]
pub struct Share {
    /// 1-based share index.
    pub index: u8,
    /// Opaque share data.
    pub data: Vec<u8>,
}

/// Splits `secret` into `n` shares with threshold `k`.
///
/// Requires `k >= 2` and `n >= k`. The secret must not be empty.
pub fn split(secret: &[u8], k: u8, n: u8) -> Result<Vec<Share>, SharingError> {
    if secret.is_empty() {
        return Err(SharingError::Operation("secret must not be empty".into()));
    }
    if k < 2 {
        return Err(SharingError::Operation("threshold must be at least 2".into()));
    }
    if n < k {
        return Err(SharingError::Operation(format!(
            "total shares ({n}) must be >= threshold ({k})"
        )));
    }

    let hex_secret: String = secret.iter().map(|b| format!("{b:02x}")).collect();
    let sd = shamir::SecretData::with_secret(&hex_secret, k);

    let mut shares = Vec::with_capacity(n as usize);
    for i in 1..=n {
        let share_data = sd.get_share(i).map_err(|e| {
            SharingError::Operation(format!("failed to get share {i}: {e:?}"))
        })?;
        shares.push(Share {
            index: i,
            data: share_data,
        });
    }
    Ok(shares)
}

/// Reconstructs the original secret from `shares` given the `threshold`.
///
/// Returns an error if the shares are insufficient or invalid.
pub fn reconstruct(shares: &[Share], threshold: u8) -> Result<Vec<u8>, SharingError> {
    let share_vecs: Vec<Vec<u8>> = shares.iter().map(|s| s.data.clone()).collect();
    let hex_secret = shamir::SecretData::recover_secret(threshold, share_vecs)
        .ok_or(SharingError::Recovery)?;

    hex_decode(&hex_secret).map_err(|_| SharingError::Recovery)
}

fn hex_decode(hex: &str) -> Result<Vec<u8>, ()> {
    if hex.len() % 2 != 0 {
        return Err(());
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|_| ()))
        .collect()
}
