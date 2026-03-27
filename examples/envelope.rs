use zorph_crypto::encrypt::{envelope_seal, envelope_open, Cipher};
use zorph_crypto::keys::random_bytes;

fn main() {
    // master key (in production: derived from password via Argon2id)
    let master_key: [u8; 32] = random_bytes();
    println!("Master key: {:02x?}", &master_key[..8]);

    // envelope encryption: random DEK encrypts data, KEK wraps the DEK
    let document = b"confidential financial report Q4 2025";
    let encrypted = envelope_seal(&master_key, document, Cipher::Aes256Gcm).unwrap();
    println!("Envelope sealed: {} bytes (includes wrapped DEK + ciphertext)", encrypted.len());

    // decrypt — DEK is unwrapped, then used to decrypt data
    let decrypted = envelope_open(&master_key, &encrypted).unwrap();
    println!("Decrypted: {}", String::from_utf8_lossy(&decrypted));

    // tamper detection — BLAKE3 binds wrapped DEK to ciphertext
    let mut tampered = encrypted.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0xFF;
    assert!(envelope_open(&master_key, &tampered).is_err());
    println!("Tamper detected correctly");
}
