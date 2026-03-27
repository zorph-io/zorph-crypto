use subtle::ConstantTimeEq;

pub fn hash(data: &[u8]) -> [u8; 32] {
    blake3::hash(data).into()
}

pub fn hash_hex(data: &[u8]) -> String {
    blake3::hash(data).to_hex().to_string()
}

// constant-time comparison to prevent timing leaks
pub fn verify(data: &[u8], expected: &[u8; 32]) -> bool {
    let actual = hash(data);
    actual.ct_eq(expected).into()
}

// keyed hash (MAC) — use for authentication, commitments, integrity binding.
// key must be exactly 32 bytes.
pub fn mac(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
    blake3::keyed_hash(key, data).into()
}

pub fn verify_mac(key: &[u8; 32], data: &[u8], expected: &[u8; 32]) -> bool {
    let actual = mac(key, data);
    actual.ct_eq(expected).into()
}

// streaming hasher for large data — call update() as many times as needed, then finalize()
pub struct Hasher {
    inner: blake3::Hasher,
}

impl Hasher {
    pub fn new() -> Self {
        Self { inner: blake3::Hasher::new() }
    }

    pub fn update(&mut self, data: &[u8]) -> &mut Self {
        self.inner.update(data);
        self
    }

    pub fn finalize(&self) -> [u8; 32] {
        self.inner.finalize().into()
    }

    pub fn finalize_hex(&self) -> String {
        self.inner.finalize().to_hex().to_string()
    }
}

impl Default for Hasher {
    fn default() -> Self {
        Self::new()
    }
}
