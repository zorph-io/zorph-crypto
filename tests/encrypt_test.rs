use zorph_crypto::encrypt::{
    encrypt, decrypt, seal, open, seal_aad, open_aad,
    envelope_seal, envelope_open, envelope_seal_aad, envelope_open_aad,
    Cipher, StreamSealer, StreamOpener,
};

#[test]
fn encrypt_decrypt_roundtrip() {
    let key = [0x42u8; 32];
    let plaintext = b"hello zorph";
    let ciphertext = encrypt(&key, plaintext).unwrap();
    let decrypted = decrypt(&key, &ciphertext).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn decrypt_wrong_key_fails() {
    let key = [0x42u8; 32];
    let wrong_key = [0x00u8; 32];
    let ciphertext = encrypt(&key, b"secret").unwrap();
    assert!(decrypt(&wrong_key, &ciphertext).is_err());
}

#[test]
fn decrypt_too_short_fails() {
    let key = [0x42u8; 32];
    assert!(decrypt(&key, &[0u8; 5]).is_err());
}

#[test]
fn seal_open_aes() {
    let key = [0x42u8; 32];
    let plaintext = b"sealed with AES";
    let ct = seal(&key, plaintext, Cipher::Aes256Gcm).unwrap();
    assert_eq!(ct[0], 0x01);
    let pt = open(&key, &ct).unwrap();
    assert_eq!(pt, plaintext);
}

#[test]
fn seal_open_chacha() {
    let key = [0x42u8; 32];
    let plaintext = b"sealed with ChaCha20";
    let ct = seal(&key, plaintext, Cipher::ChaCha20Poly1305).unwrap();
    assert_eq!(ct[0], 0x02);
    let pt = open(&key, &ct).unwrap();
    assert_eq!(pt, plaintext);
}

#[test]
fn open_wrong_key_fails() {
    let key = [0x42u8; 32];
    let wrong = [0x00u8; 32];
    let ct = seal(&key, b"secret", Cipher::ChaCha20Poly1305).unwrap();
    assert!(open(&wrong, &ct).is_err());
}

#[test]
fn open_invalid_tag_fails() {
    let key = [0x42u8; 32];
    let mut ct = seal(&key, b"data", Cipher::Aes256Gcm).unwrap();
    ct[0] = 0xFF;
    assert!(open(&key, &ct).is_err());
}

// AAD

#[test]
fn seal_open_aad_roundtrip() {
    let key = [0x42u8; 32];
    let plaintext = b"secret data";
    let aad = b"file_id:abc123";
    let ct = seal_aad(&key, plaintext, aad, Cipher::Aes256Gcm).unwrap();
    let pt = open_aad(&key, &ct, aad).unwrap();
    assert_eq!(pt, plaintext);
}

#[test]
fn seal_open_aad_chacha() {
    let key = [0x42u8; 32];
    let plaintext = b"secret data";
    let aad = b"version:7";
    let ct = seal_aad(&key, plaintext, aad, Cipher::ChaCha20Poly1305).unwrap();
    let pt = open_aad(&key, &ct, aad).unwrap();
    assert_eq!(pt, plaintext);
}

#[test]
fn open_aad_wrong_aad_fails() {
    let key = [0x42u8; 32];
    let ct = seal_aad(&key, b"data", b"correct_context", Cipher::Aes256Gcm).unwrap();
    assert!(open_aad(&key, &ct, b"wrong_context").is_err());
}

#[test]
fn open_aad_missing_aad_fails() {
    let key = [0x42u8; 32];
    let ct = seal_aad(&key, b"data", b"has_aad", Cipher::Aes256Gcm).unwrap();
    // trying to decrypt without AAD — should fail
    assert!(open(&key, &ct).is_err());
}

#[test]
fn seal_without_aad_open_without_aad() {
    let key = [0x42u8; 32];
    // seal without AAD via seal_aad with empty AAD = equivalent to seal
    let ct = seal_aad(&key, b"data", &[], Cipher::Aes256Gcm).unwrap();
    let pt = open(&key, &ct).unwrap();
    assert_eq!(pt, b"data");
}

// Streaming

#[test]
fn stream_roundtrip_aes() {
    let key = [0x42u8; 32];
    let chunks: Vec<&[u8]> = vec![b"chunk one", b"chunk two", b"chunk three"];

    let (mut sealer, header) = StreamSealer::new(&key, Cipher::Aes256Gcm);
    let encrypted: Vec<Vec<u8>> = chunks
        .iter()
        .map(|c| sealer.seal_chunk(c).unwrap())
        .collect();

    let mut opener = StreamOpener::new(&key, &header).unwrap();
    for (i, ct) in encrypted.iter().enumerate() {
        let pt = opener.open_chunk(ct).unwrap();
        assert_eq!(pt, chunks[i]);
    }
}

#[test]
fn stream_roundtrip_chacha() {
    let key = [0x42u8; 32];
    let chunks: Vec<&[u8]> = vec![b"alpha", b"beta", b"gamma"];

    let (mut sealer, header) = StreamSealer::new(&key, Cipher::ChaCha20Poly1305);
    let encrypted: Vec<Vec<u8>> = chunks
        .iter()
        .map(|c| sealer.seal_chunk(c).unwrap())
        .collect();

    let mut opener = StreamOpener::new(&key, &header).unwrap();
    for (i, ct) in encrypted.iter().enumerate() {
        let pt = opener.open_chunk(ct).unwrap();
        assert_eq!(pt, chunks[i]);
    }
}

#[test]
fn stream_wrong_key_fails() {
    let key = [0x42u8; 32];
    let wrong = [0x00u8; 32];

    let (mut sealer, header) = StreamSealer::new(&key, Cipher::Aes256Gcm);
    let ct = sealer.seal_chunk(b"secret").unwrap();

    let mut opener = StreamOpener::new(&wrong, &header).unwrap();
    assert!(opener.open_chunk(&ct).is_err());
}

#[test]
fn stream_chunks_not_reorderable() {
    let key = [0x42u8; 32];

    let (mut sealer, header) = StreamSealer::new(&key, Cipher::Aes256Gcm);
    let _ct0 = sealer.seal_chunk(b"first").unwrap();
    let ct1 = sealer.seal_chunk(b"second").unwrap();

    // trying to decrypt out of order — nonce won't match
    let mut opener = StreamOpener::new(&key, &header).unwrap();
    assert!(opener.open_chunk(&ct1).is_err()); // expects nonce counter=0, but ct1 was encrypted with counter=1
}

#[test]
fn stream_header_too_short() {
    let key = [0x42u8; 32];
    assert!(StreamOpener::new(&key, &[0x01]).is_err());
}

#[test]
fn stream_header_invalid_tag() {
    let key = [0x42u8; 32];
    assert!(StreamOpener::new(&key, &[0xFF, 0, 0, 0, 0, 0, 0, 0, 0]).is_err());
}

#[test]
fn stream_large_data() {
    let key = [0x42u8; 32];
    let chunk = vec![0xABu8; 64 * 1024]; // 64KB

    let (mut sealer, header) = StreamSealer::new(&key, Cipher::Aes256Gcm);
    let ct = sealer.seal_chunk(&chunk).unwrap();

    let mut opener = StreamOpener::new(&key, &header).unwrap();
    let pt = opener.open_chunk(&ct).unwrap();
    assert_eq!(pt, chunk);
}

// Envelope encryption (DEK/KEK)

#[test]
fn envelope_roundtrip_aes() {
    let kek = [0x42u8; 32];
    let plaintext = b"envelope secret";
    let ct = envelope_seal(&kek, plaintext, Cipher::Aes256Gcm).unwrap();
    let pt = envelope_open(&kek, &ct).unwrap();
    assert_eq!(pt, plaintext);
}

#[test]
fn envelope_roundtrip_chacha() {
    let kek = [0x42u8; 32];
    let plaintext = b"envelope chacha secret";
    let ct = envelope_seal(&kek, plaintext, Cipher::ChaCha20Poly1305).unwrap();
    let pt = envelope_open(&kek, &ct).unwrap();
    assert_eq!(pt, plaintext);
}

#[test]
fn envelope_wrong_kek_fails() {
    let kek = [0x42u8; 32];
    let wrong = [0x00u8; 32];
    let ct = envelope_seal(&kek, b"secret", Cipher::Aes256Gcm).unwrap();
    assert!(envelope_open(&wrong, &ct).is_err());
}

#[test]
fn envelope_tampered_ciphertext_fails() {
    let kek = [0x42u8; 32];
    let mut ct = envelope_seal(&kek, b"secret", Cipher::Aes256Gcm).unwrap();
    // tamper with the encrypted data portion — breaks the BLAKE3 binding
    let last = ct.len() - 1;
    ct[last] ^= 0xFF;
    assert!(envelope_open(&kek, &ct).is_err());
}

#[test]
fn envelope_aad_roundtrip() {
    let kek = [0x42u8; 32];
    let plaintext = b"envelope aad data";
    let aad = b"file_id:xyz";
    let ct = envelope_seal_aad(&kek, plaintext, aad, Cipher::Aes256Gcm).unwrap();
    let pt = envelope_open_aad(&kek, &ct, aad).unwrap();
    assert_eq!(pt, plaintext);
}

#[test]
fn envelope_aad_wrong_aad_fails() {
    let kek = [0x42u8; 32];
    let ct = envelope_seal_aad(&kek, b"data", b"correct", Cipher::Aes256Gcm).unwrap();
    assert!(envelope_open_aad(&kek, &ct, b"wrong").is_err());
}

#[test]
fn envelope_too_short_fails() {
    let kek = [0x42u8; 32];
    assert!(envelope_open(&kek, &[0u8; 3]).is_err());
}
