use zorph_crypto::pqc::{
    generate_signing_keypair, hybrid_sign, hybrid_verify,
    generate_exchange_keypair, hybrid_exchange_initiate, hybrid_exchange_respond,
    HybridSigningKey, HybridVerifyingKey, HybridSignature, HybridExchangeMessage,
    generate_stateless_keypair, stateless_sign, stateless_verify,
    StatelessSigningKey, StatelessVerifyingKey, StatelessSignature,
};

#[test]
fn hybrid_sign_verify_roundtrip() {
    let (sk, vk) = generate_signing_keypair();
    let msg = b"quantum-safe transaction";
    let sig = hybrid_sign(&sk, msg).unwrap();
    assert!(hybrid_verify(&vk, msg, &sig).is_ok());
}

#[test]
fn hybrid_verify_wrong_message_fails() {
    let (sk, vk) = generate_signing_keypair();
    let sig = hybrid_sign(&sk, b"original").unwrap();
    assert!(hybrid_verify(&vk, b"tampered", &sig).is_err());
}

#[test]
fn hybrid_verify_wrong_key_fails() {
    let (sk, _vk) = generate_signing_keypair();
    let (_sk2, vk2) = generate_signing_keypair();
    let sig = hybrid_sign(&sk, b"message").unwrap();
    assert!(hybrid_verify(&vk2, b"message", &sig).is_err());
}

#[test]
fn hybrid_key_exchange() {
    let responder = generate_exchange_keypair();
    let (msg, initiator_secret) = hybrid_exchange_initiate(
        &responder.x25519_public,
        &responder.mlkem_ek,
    );
    let responder_secret = hybrid_exchange_respond(
        &msg,
        responder.x25519_secret,
        &responder.mlkem_dk,
    );
    assert_eq!(initiator_secret.derive_key(), responder_secret.derive_key());
}

#[test]
fn signing_key_serialization_roundtrip() {
    let (sk, vk) = generate_signing_keypair();
    let bytes = sk.to_bytes();
    assert_eq!(bytes.len(), 64);

    let sk2 = HybridSigningKey::from_bytes(&bytes).unwrap();

    let msg = b"roundtrip test";
    let sig = hybrid_sign(&sk2, msg).unwrap();
    assert!(hybrid_verify(&vk, msg, &sig).is_ok());
}

#[test]
fn verifying_key_serialization_roundtrip() {
    let (_sk, vk) = generate_signing_keypair();
    let bytes = vk.to_bytes();
    assert!(bytes.len() > 32);

    let vk2 = HybridVerifyingKey::from_bytes(&bytes).unwrap();
    assert_eq!(vk.classical.as_bytes(), vk2.classical.as_bytes());
    assert_eq!(vk.pqc.encode(), vk2.pqc.encode());
}

#[test]
fn signature_serialization_roundtrip() {
    let (sk, vk) = generate_signing_keypair();
    let msg = b"serialize this signature";
    let sig = hybrid_sign(&sk, msg).unwrap();

    let bytes = sig.to_bytes();
    assert!(bytes.len() > 64);

    let sig2 = HybridSignature::from_bytes(&bytes).unwrap();
    assert!(hybrid_verify(&vk, msg, &sig2).is_ok());
}

#[test]
fn exchange_message_serialization_roundtrip() {
    let responder = generate_exchange_keypair();
    let (msg, _secret) = hybrid_exchange_initiate(
        &responder.x25519_public,
        &responder.mlkem_ek,
    );

    let bytes = msg.to_bytes();
    assert!(bytes.len() > 32);

    let msg2 = HybridExchangeMessage::from_bytes(&bytes).unwrap();
    assert_eq!(msg.x25519_public.as_bytes(), msg2.x25519_public.as_bytes());
}

#[test]
fn exchange_public_key_serde() {
    let responder = generate_exchange_keypair();
    let pub_key = responder.public_key();

    let json = serde_json::to_string(&pub_key).unwrap();
    let pub_key2: zorph_crypto::pqc::HybridExchangePublicKey =
        serde_json::from_str(&json).unwrap();

    assert_eq!(pub_key.x25519().as_bytes(), pub_key2.x25519().as_bytes());
    assert!(pub_key2.mlkem().is_ok());
}

#[test]
fn signing_key_from_bytes_wrong_length() {
    assert!(HybridSigningKey::from_bytes(&[0u8; 32]).is_err());
    assert!(HybridSigningKey::from_bytes(&[0u8; 128]).is_err());
}

#[test]
fn verifying_key_from_bytes_too_short() {
    assert!(HybridVerifyingKey::from_bytes(&[0u8; 10]).is_err());
}

#[test]
fn signature_from_bytes_too_short() {
    assert!(HybridSignature::from_bytes(&[0u8; 32]).is_err());
}

#[test]
fn slh_dsa_sign_verify_roundtrip() {
    let (sk, vk) = generate_stateless_keypair();
    let msg = b"conservative quantum-safe signature";
    let sig = stateless_sign(&sk, msg).unwrap();
    assert!(stateless_verify(&vk, msg, &sig).is_ok());
}

#[test]
fn slh_dsa_verify_wrong_message_fails() {
    let (sk, vk) = generate_stateless_keypair();
    let sig = stateless_sign(&sk, b"original").unwrap();
    assert!(stateless_verify(&vk, b"tampered", &sig).is_err());
}

#[test]
fn slh_dsa_verify_wrong_key_fails() {
    let (sk, _vk) = generate_stateless_keypair();
    let (_sk2, vk2) = generate_stateless_keypair();
    let sig = stateless_sign(&sk, b"msg").unwrap();
    assert!(stateless_verify(&vk2, b"msg", &sig).is_err());
}

#[test]
fn slh_dsa_serialization_roundtrip() {
    let (sk, vk) = generate_stateless_keypair();
    let msg = b"serialize slh-dsa";

    let sk_bytes = sk.to_bytes();
    let sk2 = StatelessSigningKey::from_bytes(&sk_bytes).unwrap();
    let sig = stateless_sign(&sk2, msg).unwrap();
    assert!(stateless_verify(&vk, msg, &sig).is_ok());

    let vk_bytes = vk.to_bytes();
    let vk2 = StatelessVerifyingKey::from_bytes(&vk_bytes).unwrap();
    assert!(stateless_verify(&vk2, msg, &sig).is_ok());

    let sig_bytes = sig.to_bytes();
    let sig2 = StatelessSignature::from_bytes(&sig_bytes).unwrap();
    assert!(stateless_verify(&vk, msg, &sig2).is_ok());
}

#[test]
fn slh_dsa_signature_is_large() {
    let (sk, _vk) = generate_stateless_keypair();
    let sig = stateless_sign(&sk, b"test").unwrap();
    let sig_bytes = sig.to_bytes();
    assert!(sig_bytes.len() > 1000, "SLH-DSA sig should be large: {} bytes", sig_bytes.len());
}
