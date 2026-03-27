use zorph_crypto::sign::{generate_keypair, sign, verify};

#[test]
fn sign_verify_roundtrip() {
    let (secret, public) = generate_keypair();
    let message = b"zorph transaction";
    let sig = sign(&secret, message);
    assert!(verify(&public, message, &sig).is_ok());
}

#[test]
fn verify_wrong_message_fails() {
    let (secret, public) = generate_keypair();
    let sig = sign(&secret, b"original");
    assert!(verify(&public, b"tampered", &sig).is_err());
}
