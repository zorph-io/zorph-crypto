use argon2::{Argon2, Algorithm, Params, Version, PasswordHasher, PasswordVerifier};
use argon2::password_hash::SaltString;
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

// Argon2id parameters — pick based on deployment target
#[derive(Debug, Clone, Copy)]
pub struct Argon2Params {
    pub memory_kib: u32,   // memory cost in KiB
    pub iterations: u32,   // time cost
    pub parallelism: u32,  // thread count
}

impl Argon2Params {
    // server-side: 64MB, 3 iterations, 4 threads — good baseline for backend services
    pub const SERVER: Self = Self { memory_kib: 65536, iterations: 3, parallelism: 4 };
    // interactive: 19MB, 2 iterations, 1 thread — responsive on laptops/mobile
    pub const INTERACTIVE: Self = Self { memory_kib: 19456, iterations: 2, parallelism: 1 };
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self::SERVER
    }
}

// Argon2id with SERVER preset (64MB, 3 iterations, 4 threads) -> 32-byte key
pub fn derive_key(password: &[u8], salt: &[u8]) -> Result<[u8; 32], KeyError> {
    derive_key_with_params(password, salt, Argon2Params::SERVER)
}

pub fn derive_key_with_params(
    password: &[u8],
    salt: &[u8],
    kdf_params: Argon2Params,
) -> Result<[u8; 32], KeyError> {
    let params = Params::new(kdf_params.memory_kib, kdf_params.iterations, kdf_params.parallelism, Some(32))
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

// cryptographically secure random bytes from OS RNG
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    buf
}

pub fn random_bytes_vec(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    buf
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

// Password hashing — Argon2id in standard PHC string format.
// Use for storing/verifying passwords, not for key derivation.

/// Hash a password for storage. Returns a PHC-format string
/// (e.g. `$argon2id$v=19$m=65536,t=3,p=4$salt$hash`).
pub fn hash_password(password: &[u8]) -> Result<String, KeyError> {
    hash_password_with_params(password, Argon2Params::SERVER)
}

pub fn hash_password_with_params(
    password: &[u8],
    kdf_params: Argon2Params,
) -> Result<String, KeyError> {
    let params = Params::new(
        kdf_params.memory_kib,
        kdf_params.iterations,
        kdf_params.parallelism,
        Some(32),
    )
    .map_err(|e| KeyError::Derivation(e.to_string()))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let salt = SaltString::generate(&mut rand::rngs::OsRng);

    let hash = argon2
        .hash_password(password, &salt)
        .map_err(|e| KeyError::Derivation(e.to_string()))?;

    Ok(hash.to_string())
}

/// Verify a password against a PHC-format hash string (constant-time).
pub fn verify_password(password: &[u8], hash_str: &str) -> Result<bool, KeyError> {
    let hash = argon2::PasswordHash::new(hash_str)
        .map_err(|e| KeyError::Derivation(e.to_string()))?;

    // params are embedded in the hash — Argon2::default() delegates to them
    let argon2 = Argon2::default();
    Ok(argon2.verify_password(password, &hash).is_ok())
}
