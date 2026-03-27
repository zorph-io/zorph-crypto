use zorph_crypto::keys::{derive_key, derive_subkey, SecretKey, generate_recovery, from_recovery};

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
