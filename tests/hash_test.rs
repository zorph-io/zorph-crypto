use zorph_crypto::hash::{hash, hash_hex, verify, mac, verify_mac, Hasher};

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

#[test]
fn hash_empty_input() {
    let h = hash(b"");
    assert_eq!(h.len(), 32);
    assert_ne!(h, [0u8; 32]);
}

#[test]
fn hash_large_input() {
    let data = vec![0xABu8; 1024 * 1024]; // 1MB
    let h = hash(&data);
    assert!(verify(&data, &h));
}

// streaming hasher

#[test]
fn hasher_single_update_matches_hash() {
    let data = b"streaming test data";
    let expected = hash(data);

    let mut hasher = Hasher::new();
    hasher.update(data);
    assert_eq!(hasher.finalize(), expected);
}

#[test]
fn hasher_multiple_updates_matches_hash() {
    let full = b"hello world";
    let expected = hash(full);

    let mut hasher = Hasher::new();
    hasher.update(b"hello ");
    hasher.update(b"world");
    assert_eq!(hasher.finalize(), expected);
}

#[test]
fn hasher_finalize_hex() {
    let data = b"hex test";
    let expected = hash_hex(data);

    let mut hasher = Hasher::new();
    hasher.update(data);
    assert_eq!(hasher.finalize_hex(), expected);
}

#[test]
fn hasher_large_chunked() {
    let data = vec![0xCDu8; 256 * 1024]; // 256KB
    let expected = hash(&data);

    let mut hasher = Hasher::new();
    for chunk in data.chunks(4096) {
        hasher.update(chunk);
    }
    assert_eq!(hasher.finalize(), expected);
}

#[test]
fn hasher_chained_updates() {
    let expected = hash(b"abc");
    let result = Hasher::new().update(b"a").update(b"b").update(b"c").finalize();
    assert_eq!(result, expected);
}

// BLAKE3 MAC (keyed hash)

#[test]
fn mac_deterministic() {
    let key = [0x42u8; 32];
    let m1 = mac(&key, b"data");
    let m2 = mac(&key, b"data");
    assert_eq!(m1, m2);
}

#[test]
fn mac_different_keys_differ() {
    let k1 = [0x01u8; 32];
    let k2 = [0x02u8; 32];
    assert_ne!(mac(&k1, b"data"), mac(&k2, b"data"));
}

#[test]
fn mac_different_data_differ() {
    let key = [0x42u8; 32];
    assert_ne!(mac(&key, b"a"), mac(&key, b"b"));
}

#[test]
fn verify_mac_correct() {
    let key = [0x42u8; 32];
    let tag = mac(&key, b"payload");
    assert!(verify_mac(&key, b"payload", &tag));
}

#[test]
fn verify_mac_wrong_data() {
    let key = [0x42u8; 32];
    let tag = mac(&key, b"original");
    assert!(!verify_mac(&key, b"tampered", &tag));
}

#[test]
fn verify_mac_wrong_key() {
    let k1 = [0x01u8; 32];
    let k2 = [0x02u8; 32];
    let tag = mac(&k1, b"data");
    assert!(!verify_mac(&k2, b"data", &tag));
}

#[test]
fn mac_differs_from_hash() {
    let key = [0x42u8; 32];
    let data = b"same input";
    // keyed hash and plain hash should produce different outputs
    assert_ne!(mac(&key, data), hash(data));
}
