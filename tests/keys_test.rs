use zorph_crypto::keys::{
    derive_key, derive_key_with_params, derive_subkey,
    SecretKey, generate_recovery, from_recovery,
    random_bytes, random_bytes_vec, Argon2Params,
};

#[test]
fn derive_key_deterministic() {
    let k1 = derive_key(b"password", b"saltsalt").unwrap();
    let k2 = derive_key(b"password", b"saltsalt").unwrap();
    assert_eq!(k1, k2);
}

#[test]
fn derive_key_different_passwords() {
    let k1 = derive_key(b"password1", b"saltsalt").unwrap();
    let k2 = derive_key(b"password2", b"saltsalt").unwrap();
    assert_ne!(k1, k2);
}

#[test]
fn secret_key_wrapper() {
    let sk = SecretKey::from_password(b"pass", b"saltsalt").unwrap();
    assert_eq!(sk.as_bytes().len(), 32);
}

#[test]
fn recovery_phrase_roundtrip() {
    let words = generate_recovery();
    assert_eq!(words.len(), 24);
    let key = from_recovery(&words).unwrap();
    assert_eq!(key.len(), 32);

    let key2 = from_recovery(&words).unwrap();
    assert_eq!(key, key2);
}

#[test]
fn recovery_phrase_wrong_word_count() {
    let words: Vec<String> = vec!["abandon".into(); 12];
    assert!(from_recovery(&words).is_err());
}

#[test]
fn recovery_phrase_unknown_word() {
    let mut words: Vec<String> = vec!["abandon".into(); 24];
    words[0] = "zzzznotaword".into();
    assert!(from_recovery(&words).is_err());
}

#[test]
fn recovery_phrases_are_unique() {
    let w1 = generate_recovery();
    let w2 = generate_recovery();
    assert_ne!(w1, w2);
}

// derive_subkey

#[test]
fn derive_subkey_deterministic() {
    let secret = b"shared secret material";
    let k1 = derive_subkey(secret, "zorph-crypto file-key v1");
    let k2 = derive_subkey(secret, "zorph-crypto file-key v1");
    assert_eq!(k1, k2);
}

#[test]
fn derive_subkey_different_contexts() {
    let secret = b"same secret";
    let k1 = derive_subkey(secret, "zorph-crypto encryption-key");
    let k2 = derive_subkey(secret, "zorph-crypto mac-key");
    assert_ne!(k1, k2);
}

#[test]
fn derive_subkey_different_secrets() {
    let k1 = derive_subkey(b"secret-a", "same context");
    let k2 = derive_subkey(b"secret-b", "same context");
    assert_ne!(k1, k2);
}

// configurable Argon2 params

#[test]
fn derive_key_interactive_params() {
    let k = derive_key_with_params(b"password", b"saltsalt", Argon2Params::INTERACTIVE).unwrap();
    assert_eq!(k.len(), 32);
    assert_ne!(k, [0u8; 32]);
}

#[test]
fn derive_key_server_matches_default() {
    let k1 = derive_key(b"password", b"saltsalt").unwrap();
    let k2 = derive_key_with_params(b"password", b"saltsalt", Argon2Params::SERVER).unwrap();
    assert_eq!(k1, k2);
}

#[test]
fn derive_key_different_params_different_keys() {
    let k1 = derive_key_with_params(b"password", b"saltsalt", Argon2Params::SERVER).unwrap();
    let k2 = derive_key_with_params(b"password", b"saltsalt", Argon2Params::INTERACTIVE).unwrap();
    assert_ne!(k1, k2);
}

#[test]
fn derive_key_custom_params() {
    let params = Argon2Params { memory_kib: 8192, iterations: 1, parallelism: 1 };
    let k = derive_key_with_params(b"pass", b"saltsalt", params).unwrap();
    assert_eq!(k.len(), 32);
}

// random bytes

#[test]
fn random_bytes_32() {
    let a: [u8; 32] = random_bytes();
    let b: [u8; 32] = random_bytes();
    assert_ne!(a, b);
    assert_eq!(a.len(), 32);
}

#[test]
fn random_bytes_16() {
    let a: [u8; 16] = random_bytes();
    assert_eq!(a.len(), 16);
}

#[test]
fn random_bytes_vec_length() {
    let v = random_bytes_vec(64);
    assert_eq!(v.len(), 64);
}

#[test]
fn random_bytes_vec_not_zero() {
    let v = random_bytes_vec(32);
    // statistically impossible for 32 random bytes to all be zero
    assert!(v.iter().any(|&b| b != 0));
}
