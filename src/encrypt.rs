use aes_gcm::{
    aead::{Aead, KeyInit, OsRng, Payload},
    Aes256Gcm, AeadCore, Nonce,
};
use chacha20poly1305::ChaCha20Poly1305;
use rand::RngCore;
use thiserror::Error;
use zeroize::Zeroize;

#[derive(Debug, Error)]
pub enum EncryptError {
    #[error("encryption failed")]
    Encrypt,
    #[error("decryption failed")]
    Decrypt,
    #[error("invalid ciphertext: too short")]
    TooShort,
    #[error("nonce counter overflow")]
    NonceOverflow,
    #[error("invalid stream header")]
    InvalidHeader,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cipher {
    Aes256Gcm,
    ChaCha20Poly1305,
}

const NONCE_LEN: usize = 12;
const TAG_AES: u8 = 0x01;
const TAG_CHACHA: u8 = 0x02;
const NONCE_PREFIX_LEN: usize = 8;
const STREAM_HEADER_LEN: usize = 1 + NONCE_PREFIX_LEN;

// Legacy API — AES-256-GCM only, format: nonce(12) || ciphertext

pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, EncryptError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| EncryptError::Encrypt)?;
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| EncryptError::Encrypt)?;

    let mut output = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

pub fn decrypt(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>, EncryptError> {
    if data.len() < NONCE_LEN {
        return Err(EncryptError::TooShort);
    }
    let (nonce_bytes, ciphertext) = data.split_at(NONCE_LEN);
    let nonce = Nonce::from_slice(nonce_bytes);
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| EncryptError::Decrypt)?;
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| EncryptError::Decrypt)
}

// seal/open — cipher selection, format: tag(1) || nonce(12) || ciphertext
// open() detects cipher from the first byte

pub fn seal(key: &[u8; 32], plaintext: &[u8], cipher: Cipher) -> Result<Vec<u8>, EncryptError> {
    seal_aad(key, plaintext, &[], cipher)
}

pub fn open(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>, EncryptError> {
    open_aad(key, data, &[])
}

// AAD variants — bind ciphertext to metadata (file_id, version, etc.)
// without AAD the ciphertext can be moved from one context to another

pub fn seal_aad(
    key: &[u8; 32],
    plaintext: &[u8],
    aad: &[u8],
    cipher: Cipher,
) -> Result<Vec<u8>, EncryptError> {
    let payload = Payload { msg: plaintext, aad };
    match cipher {
        Cipher::Aes256Gcm => {
            let c = Aes256Gcm::new_from_slice(key).map_err(|_| EncryptError::Encrypt)?;
            let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
            let ct = c
                .encrypt(&nonce, payload)
                .map_err(|_| EncryptError::Encrypt)?;
            let mut out = Vec::with_capacity(1 + NONCE_LEN + ct.len());
            out.push(TAG_AES);
            out.extend_from_slice(&nonce);
            out.extend_from_slice(&ct);
            Ok(out)
        }
        Cipher::ChaCha20Poly1305 => {
            let c =
                ChaCha20Poly1305::new_from_slice(key).map_err(|_| EncryptError::Encrypt)?;
            let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
            let ct = c
                .encrypt(&nonce, payload)
                .map_err(|_| EncryptError::Encrypt)?;
            let mut out = Vec::with_capacity(1 + NONCE_LEN + ct.len());
            out.push(TAG_CHACHA);
            out.extend_from_slice(&nonce);
            out.extend_from_slice(&ct);
            Ok(out)
        }
    }
}

pub fn open_aad(key: &[u8; 32], data: &[u8], aad: &[u8]) -> Result<Vec<u8>, EncryptError> {
    if data.len() < 1 + NONCE_LEN {
        return Err(EncryptError::TooShort);
    }
    let tag = data[0];
    let nonce_bytes = &data[1..1 + NONCE_LEN];
    let ciphertext = &data[1 + NONCE_LEN..];
    let payload = Payload { msg: ciphertext, aad };

    match tag {
        TAG_AES => {
            let nonce = Nonce::from_slice(nonce_bytes);
            let cipher =
                Aes256Gcm::new_from_slice(key).map_err(|_| EncryptError::Decrypt)?;
            cipher
                .decrypt(nonce, payload)
                .map_err(|_| EncryptError::Decrypt)
        }
        TAG_CHACHA => {
            let nonce = chacha20poly1305::Nonce::from_slice(nonce_bytes);
            let cipher =
                ChaCha20Poly1305::new_from_slice(key).map_err(|_| EncryptError::Decrypt)?;
            cipher
                .decrypt(nonce, payload)
                .map_err(|_| EncryptError::Decrypt)
        }
        _ => Err(EncryptError::Decrypt),
    }
}

// Streaming encryption — for files that don't fit in memory.
// Each chunk is encrypted with a separate nonce = prefix(8 random) || counter(4 BE).
// Header: tag(1) || nonce_prefix(8). Caller is responsible for chunk framing.

pub struct StreamSealer {
    key: [u8; 32],
    nonce_prefix: [u8; NONCE_PREFIX_LEN],
    counter: u32,
    cipher: Cipher,
}

impl StreamSealer {
    // returns (sealer, header_bytes) — header must be written first
    pub fn new(key: &[u8; 32], cipher: Cipher) -> (Self, Vec<u8>) {
        let mut nonce_prefix = [0u8; NONCE_PREFIX_LEN];
        rand::rngs::OsRng.fill_bytes(&mut nonce_prefix);

        let tag = match cipher {
            Cipher::Aes256Gcm => TAG_AES,
            Cipher::ChaCha20Poly1305 => TAG_CHACHA,
        };

        let mut header = Vec::with_capacity(STREAM_HEADER_LEN);
        header.push(tag);
        header.extend_from_slice(&nonce_prefix);

        (
            Self {
                key: *key,
                nonce_prefix,
                counter: 0,
                cipher,
            },
            header,
        )
    }

    // encrypts one chunk, output = ciphertext + 16 bytes AEAD tag
    pub fn seal_chunk(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, EncryptError> {
        let nonce = self.next_nonce()?;
        let nonce_ref = Nonce::from_slice(&nonce);

        match self.cipher {
            Cipher::Aes256Gcm => {
                let c = Aes256Gcm::new_from_slice(&self.key)
                    .map_err(|_| EncryptError::Encrypt)?;
                c.encrypt(nonce_ref, plaintext.as_ref())
                    .map_err(|_| EncryptError::Encrypt)
            }
            Cipher::ChaCha20Poly1305 => {
                let c = ChaCha20Poly1305::new_from_slice(&self.key)
                    .map_err(|_| EncryptError::Encrypt)?;
                c.encrypt(chacha20poly1305::Nonce::from_slice(&nonce), plaintext.as_ref())
                    .map_err(|_| EncryptError::Encrypt)
            }
        }
    }

    fn next_nonce(&mut self) -> Result<[u8; NONCE_LEN], EncryptError> {
        if self.counter == u32::MAX {
            return Err(EncryptError::NonceOverflow);
        }
        let mut nonce = [0u8; NONCE_LEN];
        nonce[..NONCE_PREFIX_LEN].copy_from_slice(&self.nonce_prefix);
        nonce[NONCE_PREFIX_LEN..].copy_from_slice(&self.counter.to_be_bytes());
        self.counter += 1;
        Ok(nonce)
    }
}

impl Drop for StreamSealer {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

pub struct StreamOpener {
    key: [u8; 32],
    nonce_prefix: [u8; NONCE_PREFIX_LEN],
    counter: u32,
    cipher: Cipher,
}

impl StreamOpener {
    // parses header (9 bytes), determines cipher and nonce prefix
    pub fn new(key: &[u8; 32], header: &[u8]) -> Result<Self, EncryptError> {
        if header.len() < STREAM_HEADER_LEN {
            return Err(EncryptError::InvalidHeader);
        }
        let cipher = match header[0] {
            TAG_AES => Cipher::Aes256Gcm,
            TAG_CHACHA => Cipher::ChaCha20Poly1305,
            _ => return Err(EncryptError::InvalidHeader),
        };
        let mut nonce_prefix = [0u8; NONCE_PREFIX_LEN];
        nonce_prefix.copy_from_slice(&header[1..STREAM_HEADER_LEN]);

        Ok(Self {
            key: *key,
            nonce_prefix,
            counter: 0,
            cipher,
        })
    }

    pub fn open_chunk(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, EncryptError> {
        let nonce = self.next_nonce()?;
        let nonce_ref = Nonce::from_slice(&nonce);

        match self.cipher {
            Cipher::Aes256Gcm => {
                let c = Aes256Gcm::new_from_slice(&self.key)
                    .map_err(|_| EncryptError::Decrypt)?;
                c.decrypt(nonce_ref, ciphertext.as_ref())
                    .map_err(|_| EncryptError::Decrypt)
            }
            Cipher::ChaCha20Poly1305 => {
                let c = ChaCha20Poly1305::new_from_slice(&self.key)
                    .map_err(|_| EncryptError::Decrypt)?;
                c.decrypt(chacha20poly1305::Nonce::from_slice(&nonce), ciphertext.as_ref())
                    .map_err(|_| EncryptError::Decrypt)
            }
        }
    }

    fn next_nonce(&mut self) -> Result<[u8; NONCE_LEN], EncryptError> {
        if self.counter == u32::MAX {
            return Err(EncryptError::NonceOverflow);
        }
        let mut nonce = [0u8; NONCE_LEN];
        nonce[..NONCE_PREFIX_LEN].copy_from_slice(&self.nonce_prefix);
        nonce[NONCE_PREFIX_LEN..].copy_from_slice(&self.counter.to_be_bytes());
        self.counter += 1;
        Ok(nonce)
    }
}

impl Drop for StreamOpener {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

// Envelope encryption (DEK/KEK pattern).
// Generate random DEK, encrypt data with it, wrap DEK with KEK.
// Format: wrapped_dek_len(4 LE) || wrapped_dek || encrypted_data
// The wrapped DEK includes AAD binding it to the encrypted payload (BLAKE3 hash of ciphertext).

pub fn envelope_seal(
    kek: &[u8; 32],
    plaintext: &[u8],
    cipher: Cipher,
) -> Result<Vec<u8>, EncryptError> {
    envelope_seal_aad(kek, plaintext, &[], cipher)
}

pub fn envelope_open(kek: &[u8; 32], data: &[u8]) -> Result<Vec<u8>, EncryptError> {
    envelope_open_aad(kek, data, &[])
}

pub fn envelope_seal_aad(
    kek: &[u8; 32],
    plaintext: &[u8],
    aad: &[u8],
    cipher: Cipher,
) -> Result<Vec<u8>, EncryptError> {
    // 1. random DEK
    let mut dek = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut dek);

    // 2. encrypt data with DEK
    let encrypted_data = seal_aad(&dek, plaintext, aad, cipher)?;

    // 3. wrap DEK with KEK — AAD = blake3(encrypted_data) to bind them together
    let binding = blake3::hash(&encrypted_data);
    let wrapped_dek = seal_aad(kek, &dek, binding.as_bytes(), cipher)?;

    dek.zeroize();

    // 4. assemble: wrapped_dek_len(4 LE) || wrapped_dek || encrypted_data
    let wdk_len = (wrapped_dek.len() as u32).to_le_bytes();
    let mut out = Vec::with_capacity(4 + wrapped_dek.len() + encrypted_data.len());
    out.extend_from_slice(&wdk_len);
    out.extend_from_slice(&wrapped_dek);
    out.extend_from_slice(&encrypted_data);
    Ok(out)
}

pub fn envelope_open_aad(
    kek: &[u8; 32],
    data: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, EncryptError> {
    if data.len() < 4 {
        return Err(EncryptError::TooShort);
    }

    // 1. parse wrapped_dek_len
    let wdk_len = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
    if data.len() < 4 + wdk_len {
        return Err(EncryptError::TooShort);
    }

    let wrapped_dek = &data[4..4 + wdk_len];
    let encrypted_data = &data[4 + wdk_len..];

    // 2. unwrap DEK — AAD = blake3(encrypted_data) verifies binding
    let binding = blake3::hash(encrypted_data);
    let dek_bytes = open_aad(kek, wrapped_dek, binding.as_bytes())?;

    if dek_bytes.len() != 32 {
        return Err(EncryptError::Decrypt);
    }
    let mut dek = [0u8; 32];
    dek.copy_from_slice(&dek_bytes);

    // 3. decrypt data with DEK
    let plaintext = open_aad(&dek, encrypted_data, aad)?;

    dek.zeroize();
    Ok(plaintext)
}
