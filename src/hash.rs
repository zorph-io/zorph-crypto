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
