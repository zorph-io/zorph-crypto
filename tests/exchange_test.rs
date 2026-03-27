use zorph_crypto::exchange::{
    generate_keypair, diffie_hellman,
    public_key_to_bytes, public_key_from_bytes,
    derive_key,
};

#[test]
fn key_exchange_shared_secret() {
    let (secret_a, public_a) = generate_keypair();
    let (secret_b, public_b) = generate_keypair();

    let shared_a = diffie_hellman(secret_a, &public_b);
    let shared_b = diffie_hellman(secret_b, &public_a);

    assert_eq!(shared_a.as_bytes(), shared_b.as_bytes());
}

#[test]
fn public_key_serialization_roundtrip() {
    let (_secret, public) = generate_keypair();
    let bytes = public_key_to_bytes(&public);
    let restored = public_key_from_bytes(bytes);
    assert_eq!(public_key_to_bytes(&restored), bytes);
}

#[test]
fn derive_key_from_shared_secret() {
    let (secret_a, _public_a) = generate_keypair();
    let (_secret_b, public_b) = generate_keypair();

    let shared = diffie_hellman(secret_a, &public_b);
    let key = derive_key(&shared, "zorph-crypto test-key v1");
    assert_eq!(key.len(), 32);
    assert_ne!(key, [0u8; 32]);
}

#[test]
fn derive_key_different_contexts_differ() {
    let (secret_a, _public_a) = generate_keypair();
    let (_secret_b, public_b) = generate_keypair();

    let shared = diffie_hellman(secret_a, &public_b);
    let k1 = derive_key(&shared, "context-1");
    let k2 = derive_key(&shared, "context-2");
    assert_ne!(k1, k2);
}

#[test]
fn different_keypairs_different_secrets() {
    let (secret_a, _public_a) = generate_keypair();
    let (_secret_b, public_b) = generate_keypair();
    let (_secret_c, public_c) = generate_keypair();

    let shared_ab = diffie_hellman(secret_a, &public_b);
    let (secret_a2, _) = generate_keypair();
    let shared_ac = diffie_hellman(secret_a2, &public_c);
    assert_ne!(shared_ab.as_bytes(), shared_ac.as_bytes());
}
