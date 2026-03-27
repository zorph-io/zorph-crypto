use thiserror::Error;

#[derive(Debug, Error)]
pub enum SharingError {
    #[error("sharing operation failed: {0}")]
    Operation(String),
    #[error("recovery failed: insufficient or invalid shares")]
    Recovery,
}

#[derive(Clone, Debug)]
pub struct Share {
    pub index: u8,
    pub data: Vec<u8>,
}

// splits the secret into n shares, any k of them are enough to reconstruct
pub fn split(secret: &[u8], k: u8, n: u8) -> Result<Vec<Share>, SharingError> {
    let secret_str = std::str::from_utf8(secret)
        .map_err(|e| SharingError::Operation(format!("secret must be valid UTF-8: {e}")))?;

    let sd = shamir::SecretData::with_secret(secret_str, k);

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

pub fn reconstruct(shares: &[Share], threshold: u8) -> Result<Vec<u8>, SharingError> {
    let share_vecs: Vec<Vec<u8>> = shares.iter().map(|s| s.data.clone()).collect();
    let result = shamir::SecretData::recover_secret(threshold, share_vecs)
        .ok_or(SharingError::Recovery)?;
    Ok(result.into_bytes())
}
