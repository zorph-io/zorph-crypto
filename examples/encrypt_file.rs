use zorph_crypto::encrypt::{encrypt, decrypt};

fn main() {
    let key = [0x42u8; 32];
    let plaintext = b"This is a secret message";

    let ciphertext = encrypt(&key, plaintext).expect("encryption failed");
    println!("Encrypted: {} bytes", ciphertext.len());

    let decrypted = decrypt(&key, &ciphertext).expect("decryption failed");
    println!("Decrypted: {}", String::from_utf8_lossy(&decrypted));
}
