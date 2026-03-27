//! X25519 Diffie-Hellman key exchange.
//!
//! Provides ephemeral key generation, shared secret computation,
//! and BLAKE3-based symmetric key derivation from the shared secret.

use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};
use rand::rngs::OsRng;

/// Generates an ephemeral X25519 keypair.
///
/// The [`EphemeralSecret`] is consumed on use and cannot be reused or serialized.
pub fn generate_keypair() -> (EphemeralSecret, PublicKey) {
    let secret = EphemeralSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    (secret, public)
}

/// Computes the X25519 shared secret from our ephemeral secret and their public key.
///
/// Consumes `secret` — it cannot be reused after this call.
pub fn diffie_hellman(secret: EphemeralSecret, their_public: &PublicKey) -> SharedSecret {
    secret.diffie_hellman(their_public)
}

/// Serializes a [`PublicKey`] to its 32-byte Montgomery form.
pub fn public_key_to_bytes(key: &PublicKey) -> [u8; 32] {
    key.to_bytes()
}

/// Deserializes a [`PublicKey`] from 32 bytes in Montgomery form.
pub fn public_key_from_bytes(bytes: [u8; 32]) -> PublicKey {
    PublicKey::from(bytes)
}

/// Derives a 32-byte symmetric key from the shared secret using BLAKE3 KDF.
///
/// `context` provides domain separation (e.g. `"zorph file-transfer v1"`).
pub fn derive_key(shared: &SharedSecret, context: &str) -> [u8; 32] {
    blake3::derive_key(context, shared.as_bytes())
}
