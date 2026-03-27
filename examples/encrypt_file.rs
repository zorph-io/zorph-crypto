use zorph_crypto::encrypt::{seal, open, seal_aad, open_aad, Cipher};

fn main() {
    let key = [0x42u8; 32];

    // basic seal/open — cipher auto-detected on open
    let ciphertext = seal(&key, b"secret document", Cipher::Aes256Gcm).unwrap();
    println!("Sealed: {} bytes (AES-256-GCM)", ciphertext.len());

    let plaintext = open(&key, &ciphertext).unwrap();
    println!("Opened: {}", String::from_utf8_lossy(&plaintext));

    // with AAD — binds ciphertext to metadata (e.g. file_id)
    let aad = b"file_id:abc123,version:1";
    let ct = seal_aad(&key, b"bound to context", aad, Cipher::ChaCha20Poly1305).unwrap();
    let pt = open_aad(&key, &ct, aad).unwrap();
    println!("AAD round-trip: {}", String::from_utf8_lossy(&pt));

    // wrong AAD fails
    assert!(open_aad(&key, &ct, b"wrong_context").is_err());
    println!("Wrong AAD correctly rejected");
}
