use argon2::{Argon2, Algorithm, Params, Version};
use rand::RngCore;
use thiserror::Error;
use zeroize::Zeroize;

#[derive(Debug, Error)]
pub enum KeyError {
    #[error("key derivation failed: {0}")]
    Derivation(String),
    #[error("invalid recovery phrase: {0}")]
    InvalidRecovery(String),
}

// Argon2id: 64MB memory, 3 iterations, 4 threads -> 32-byte key
pub fn derive_key(password: &[u8], salt: &[u8]) -> Result<[u8; 32], KeyError> {
    let params = Params::new(65536, 3, 4, Some(32))
        .map_err(|e| KeyError::Derivation(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password, salt, &mut key)
        .map_err(|e| KeyError::Derivation(e.to_string()))?;
    Ok(key)
}

// BIP39 English, 2048 words — embedded at compile time
const WORDLIST: &[&str] = &include!("wordlist.txt");

// 256 bits of entropy -> 24 words (+ 8-bit checksum = 264 bits = 24 x 11)
pub fn generate_recovery() -> Vec<String> {
    let mut entropy = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut entropy);

    let words = entropy_to_words(&entropy);
    entropy.zeroize();
    words
}

// 24 words -> 32-byte key with checksum verification
pub fn from_recovery(words: &[String]) -> Result<[u8; 32], KeyError> {
    if words.len() != 24 {
        return Err(KeyError::InvalidRecovery(format!(
            "expected 24 words, got {}",
            words.len()
        )));
    }

    let mut bits = Vec::with_capacity(264);
    for word in words {
        let idx = WORDLIST
            .iter()
            .position(|w| *w == word.as_str())
            .ok_or_else(|| {
                KeyError::InvalidRecovery(format!("unknown word: {word}"))
            })?;
        for bit in (0..11).rev() {
            bits.push((idx >> bit) & 1);
        }
    }

    // first 256 bits — entropy, last 8 — checksum
    let mut key = [0u8; 32];
    for i in 0..32 {
        let mut byte = 0u8;
        for bit in 0..8 {
            byte |= (bits[i * 8 + bit] as u8) << (7 - bit);
        }
        key[i] = byte;
    }

    let checksum_byte = sha256_first_byte(&key);
    let mut recovered_checksum = 0u8;
    for bit in 0..8 {
        recovered_checksum |= (bits[256 + bit] as u8) << (7 - bit);
    }
    if checksum_byte != recovered_checksum {
        return Err(KeyError::InvalidRecovery("checksum mismatch".into()));
    }

    Ok(key)
}

fn entropy_to_words(entropy: &[u8; 32]) -> Vec<String> {
    let checksum = sha256_first_byte(entropy);

    let mut bits = Vec::with_capacity(264);
    for byte in entropy.iter() {
        for bit in (0..8).rev() {
            bits.push((byte >> bit) & 1);
        }
    }
    for bit in (0..8).rev() {
        bits.push((checksum >> bit) & 1);
    }

    bits.chunks(11)
        .map(|chunk| {
            let idx: usize = chunk.iter().fold(0, |acc, &b| (acc << 1) | b as usize);
            WORDLIST[idx].to_string()
        })
        .collect()
}

// BIP39 uses SHA-256, we use BLAKE3 for consistency within Zorph
fn sha256_first_byte(data: &[u8]) -> u8 {
    let h = blake3::hash(data);
    h.as_bytes()[0]
}

// BLAKE3 KDF — derives a subkey from a secret with domain separation
// context must be a unique string per use case,
// e.g. "zorph-crypto file-encryption-key v1"
pub fn derive_subkey(ikm: &[u8], context: &str) -> [u8; 32] {
    blake3::derive_key(context, ikm)
}

// Zeroed on drop — so the key doesn't linger in memory
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct SecretKey(pub [u8; 32]);

impl SecretKey {
    pub fn from_password(password: &[u8], salt: &[u8]) -> Result<Self, KeyError> {
        derive_key(password, salt).map(SecretKey)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}
