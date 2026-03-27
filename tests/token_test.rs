use zorph_crypto::sign;
use zorph_crypto::token::{
    create_signed_token, generate_api_key, generate_token, verify_signed_token, SignedToken,
};

#[test]
fn generate_token_is_64_hex() {
    let t = generate_token();
    assert_eq!(t.len(), 64);
    assert!(t.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn generate_api_key_has_prefix() {
    let k = generate_api_key();
    assert!(k.starts_with("zrph_"));
    assert_eq!(k.len(), 5 + 64);
}

#[test]
fn tokens_are_unique() {
    let a = generate_token();
    let b = generate_token();
    assert_ne!(a, b);
}

#[test]
fn signed_token_roundtrip() {
    let (sk, vk) = sign::generate_keypair();
    let payload = b"hello world";
    let expires = 9999999999u64; // far future

    let token = create_signed_token(&sk, payload, expires);
    let recovered = verify_signed_token(&vk, &token, 1000000000).unwrap();
    assert_eq!(recovered, payload);
}

#[test]
fn signed_token_no_expiry() {
    let (sk, vk) = sign::generate_keypair();
    let token = create_signed_token(&sk, b"data", 0);
    // expires_at = 0 means no expiry, should pass at any time
    let result = verify_signed_token(&vk, &token, u64::MAX);
    assert!(result.is_ok());
}

#[test]
fn signed_token_expired() {
    let (sk, vk) = sign::generate_keypair();
    let token = create_signed_token(&sk, b"data", 1000);
    let result = verify_signed_token(&vk, &token, 2000);
    assert!(result.is_err());
}

#[test]
fn signed_token_wrong_key() {
    let (sk, _) = sign::generate_keypair();
    let (_, other_vk) = sign::generate_keypair();
    let token = create_signed_token(&sk, b"data", 0);
    let result = verify_signed_token(&other_vk, &token, 0);
    assert!(result.is_err());
}

#[test]
fn signed_token_tampered_payload() {
    let (sk, vk) = sign::generate_keypair();
    let mut token = create_signed_token(&sk, b"original", 0);
    token.payload = b"tampered".to_vec();
    let result = verify_signed_token(&vk, &token, 0);
    assert!(result.is_err());
}

#[test]
fn signed_token_binary_roundtrip() {
    let (sk, vk) = sign::generate_keypair();
    let token = create_signed_token(&sk, b"binary test", 5000);
    let bytes = token.to_bytes();
    let restored = SignedToken::from_bytes(&bytes).unwrap();
    let payload = verify_signed_token(&vk, &restored, 1000).unwrap();
    assert_eq!(payload, b"binary test");
}

#[test]
fn signed_token_serde_roundtrip() {
    let (sk, vk) = sign::generate_keypair();
    let token = create_signed_token(&sk, b"serde", 0);
    let json = serde_json::to_string(&token).unwrap();
    let restored: SignedToken = serde_json::from_str(&json).unwrap();
    let payload = verify_signed_token(&vk, &restored, 0).unwrap();
    assert_eq!(payload, b"serde");
}
