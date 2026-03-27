//! BLAKE3 hashing, MACs, and streaming hasher.
//!
//! All operations use BLAKE3. Hash comparisons are constant-time
//! via the [`subtle`] crate to prevent timing side-channels.

use subtle::ConstantTimeEq;

/// Computes the BLAKE3 hash of `data`, returning a 32-byte digest.
pub fn hash(data: &[u8]) -> [u8; 32] {
    blake3::hash(data).into()
}

/// Computes the BLAKE3 hash of `data`, returning a hex-encoded string.
pub fn hash_hex(data: &[u8]) -> String {
    blake3::hash(data).to_hex().to_string()
}

/// Verifies that the BLAKE3 hash of `data` matches `expected` (constant-time).
pub fn verify(data: &[u8], expected: &[u8; 32]) -> bool {
    let actual = hash(data);
    actual.ct_eq(expected).into()
}

/// Computes a BLAKE3 keyed hash (MAC) of `data`.
///
/// Use for authentication, commitments, and integrity binding.
/// `key` must be exactly 32 bytes.
pub fn mac(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
    blake3::keyed_hash(key, data).into()
}

/// Verifies a BLAKE3 keyed hash (MAC) against `expected` (constant-time).
pub fn verify_mac(key: &[u8; 32], data: &[u8], expected: &[u8; 32]) -> bool {
    let actual = mac(key, data);
    actual.ct_eq(expected).into()
}

/// Streaming BLAKE3 hasher for data that doesn't fit in memory.
///
/// Call [`update`](Hasher::update) incrementally, then [`finalize`](Hasher::finalize).
pub struct Hasher {
    inner: blake3::Hasher,
}

impl Hasher {
    /// Creates a new streaming hasher.
    pub fn new() -> Self {
        Self { inner: blake3::Hasher::new() }
    }

    /// Feeds `data` into the hasher. Can be called multiple times.
    pub fn update(&mut self, data: &[u8]) -> &mut Self {
        self.inner.update(data);
        self
    }

    /// Finalizes the hash computation and returns a 32-byte digest.
    pub fn finalize(&self) -> [u8; 32] {
        self.inner.finalize().into()
    }

    /// Finalizes the hash computation and returns a hex-encoded string.
    pub fn finalize_hex(&self) -> String {
        self.inner.finalize().to_hex().to_string()
    }
}

impl Default for Hasher {
    fn default() -> Self {
        Self::new()
    }
}
