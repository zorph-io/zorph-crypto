//! Cryptographic primitives for the Zorph platform.
//!
//! This crate provides a unified set of cryptographic building blocks:
//! symmetric encryption, key derivation, digital signatures, secret sharing,
//! zero-knowledge proofs, post-quantum cryptography, and secure memory handling.
//!
//! All hash operations use BLAKE3 unless an external standard requires otherwise.
//! All random bytes come from the OS CSPRNG via [`rand::rngs::OsRng`].

/// Symmetric encryption: AES-256-GCM, ChaCha20-Poly1305, streaming, and envelope encryption.
pub mod encrypt;
/// Key derivation (Argon2id), BIP39 recovery phrases, and secure key wrappers.
pub mod keys;
/// Ed25519 digital signatures.
pub mod sign;
/// BLAKE3 hashing, MACs, and streaming hasher.
pub mod hash;
/// Threshold multisig: m-of-n Ed25519 signature verification.
pub mod multisig;
/// Shamir's Secret Sharing over GF(256).
pub mod sharing;
/// X25519 Diffie-Hellman key exchange.
pub mod exchange;
/// Hybrid post-quantum cryptography: Ed25519 + ML-DSA-65, X25519 + ML-KEM-768, SLH-DSA.
pub mod pqc;
/// AMD SEV-SNP attestation report and certificate chain verification.
pub mod attest;
/// Zero-knowledge primitives: commitments, Merkle trees, and proof envelopes.
pub mod zk;
/// Secure memory wiping via zeroize.
pub mod wipe;
/// Token generation and Ed25519-signed tokens with expiry.
pub mod token;
