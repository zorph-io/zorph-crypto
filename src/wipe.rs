//! Secure memory wiping via [`zeroize`].
//!
//! Provides explicit wipe functions and a [`SecureBuffer`] wrapper
//! that automatically zeroes its contents on drop.

use zeroize::Zeroize;

/// Overwrites a byte slice with zeroes.
pub fn wipe(data: &mut [u8]) {
    data.zeroize();
}

/// Overwrites a [`Vec<u8>`] with zeroes and sets its length to zero.
pub fn wipe_vec(data: &mut Vec<u8>) {
    data.zeroize();
}

/// Overwrites a fixed-size byte array with zeroes.
pub fn wipe_array<const N: usize>(data: &mut [u8; N]) {
    data.zeroize();
}

/// A byte buffer that is zeroed on drop.
///
/// Use for holding sensitive data (keys, plaintexts) that must not linger in memory.
#[derive(Clone)]
pub struct SecureBuffer {
    inner: Vec<u8>,
}

impl SecureBuffer {
    /// Creates a new [`SecureBuffer`] taking ownership of the given vector.
    pub fn new(data: Vec<u8>) -> Self {
        Self { inner: data }
    }

    /// Creates a new [`SecureBuffer`] by copying the given slice.
    pub fn from_slice(data: &[u8]) -> Self {
        Self {
            inner: data.to_vec(),
        }
    }

    /// Returns a reference to the underlying bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.inner
    }

    /// Returns a mutable reference to the underlying bytes.
    pub fn as_mut_bytes(&mut self) -> &mut [u8] {
        &mut self.inner
    }

    /// Returns the number of bytes in the buffer.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns `true` if the buffer contains no bytes.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl Drop for SecureBuffer {
    fn drop(&mut self) {
        self.inner.zeroize();
    }
}

impl AsRef<[u8]> for SecureBuffer {
    fn as_ref(&self) -> &[u8] {
        &self.inner
    }
}

impl AsMut<[u8]> for SecureBuffer {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.inner
    }
}

impl From<Vec<u8>> for SecureBuffer {
    fn from(data: Vec<u8>) -> Self {
        Self { inner: data }
    }
}

impl From<String> for SecureBuffer {
    fn from(s: String) -> Self {
        Self { inner: s.into_bytes() }
    }
}

impl From<&[u8]> for SecureBuffer {
    fn from(data: &[u8]) -> Self {
        Self { inner: data.to_vec() }
    }
}
