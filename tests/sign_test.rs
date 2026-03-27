use zorph_crypto::sign::{
    generate_keypair, sign, verify,
    signing_key_to_bytes, signing_key_from_bytes,
    verifying_key_to_bytes, verifying_key_from_bytes,
    signature_to_bytes, signature_from_bytes,
};

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

#[test]
fn verify_wrong_key_fails() {
    let (sk, _pk) = generate_keypair();
    let (_sk2, pk2) = generate_keypair();
    let sig = sign(&sk, b"message");
    assert!(verify(&pk2, b"message", &sig).is_err());
}

#[test]
fn signing_key_serialization_roundtrip() {
    let (sk, _pk) = generate_keypair();
    let bytes = signing_key_to_bytes(&sk);
    let sk2 = signing_key_from_bytes(&bytes);
    assert_eq!(sk.to_bytes(), sk2.to_bytes());
}

#[test]
fn verifying_key_serialization_roundtrip() {
    let (_sk, pk) = generate_keypair();
    let bytes = verifying_key_to_bytes(&pk);
    let pk2 = verifying_key_from_bytes(&bytes).unwrap();
    assert_eq!(pk, pk2);
}

#[test]
fn signature_serialization_roundtrip() {
    let (sk, pk) = generate_keypair();
    let msg = b"roundtrip test";
    let sig = sign(&sk, msg);
    let bytes = signature_to_bytes(&sig);
    let sig2 = signature_from_bytes(&bytes);
    assert!(verify(&pk, msg, &sig2).is_ok());
}

#[test]
fn sign_with_restored_key() {
    let (sk, pk) = generate_keypair();
    let bytes = signing_key_to_bytes(&sk);
    let sk2 = signing_key_from_bytes(&bytes);
    let sig = sign(&sk2, b"restored signing");
    assert!(verify(&pk, b"restored signing", &sig).is_ok());
}

#[test]
fn verifying_key_from_invalid_bytes_fails() {
    // Ed25519 y-coordinates must be < p = 2^255 - 19.
    // 0xEE..EE (all bytes 0xEE) with high bit set is outside the field.
    let mut bad = [0xEEu8; 32];
    bad[31] = 0xFF; // force high bit — invalid compressed point
    assert!(verifying_key_from_bytes(&bad).is_err());
}

#[test]
fn sign_empty_message() {
    let (sk, pk) = generate_keypair();
    let sig = sign(&sk, b"");
    assert!(verify(&pk, b"", &sig).is_ok());
}

#[test]
fn sign_large_message() {
    let (sk, pk) = generate_keypair();
    let msg = vec![0xABu8; 64 * 1024];
    let sig = sign(&sk, &msg);
    assert!(verify(&pk, &msg, &sig).is_ok());
}
