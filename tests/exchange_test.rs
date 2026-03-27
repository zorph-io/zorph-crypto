use zorph_crypto::exchange::{generate_keypair, diffie_hellman};

#[test]
fn key_exchange_shared_secret() {
    let (secret_a, public_a) = generate_keypair();
    let (secret_b, public_b) = generate_keypair();

    let shared_a = diffie_hellman(secret_a, &public_b);
    let shared_b = diffie_hellman(secret_b, &public_a);

    assert_eq!(shared_a.as_bytes(), shared_b.as_bytes());
}
