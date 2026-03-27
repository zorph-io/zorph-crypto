use zorph_crypto::hash::{hash, hash_hex, verify};

#[test]
fn hash_deterministic() {
    let h1 = hash(b"hello");
    let h2 = hash(b"hello");
    assert_eq!(h1, h2);
}

#[test]
fn hash_different_inputs() {
    assert_ne!(hash(b"a"), hash(b"b"));
}

#[test]
fn hash_hex_length() {
    let hex = hash_hex(b"test");
    assert_eq!(hex.len(), 64);
}

#[test]
fn verify_correct_hash() {
    let data = b"zorph transaction data";
    let h = hash(data);
    assert!(verify(data, &h));
}

#[test]
fn verify_wrong_hash() {
    let h = hash(b"original");
    assert!(!verify(b"tampered", &h));
}
