use zeroize::Zeroize;

pub fn wipe(data: &mut [u8]) {
    data.zeroize();
}

pub fn wipe_vec(data: &mut Vec<u8>) {
    data.zeroize();
}

pub fn wipe_array<const N: usize>(data: &mut [u8; N]) {
    data.zeroize();
}

// wrapper over Vec<u8> — zeroed on drop, for sensitive data
#[derive(Clone)]
pub struct SecureBuffer {
    inner: Vec<u8>,
}

impl SecureBuffer {
    pub fn new(data: Vec<u8>) -> Self {
        Self { inner: data }
    }

    pub fn from_slice(data: &[u8]) -> Self {
        Self {
            inner: data.to_vec(),
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.inner
    }

    pub fn as_mut_bytes(&mut self) -> &mut [u8] {
        &mut self.inner
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

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
