use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};
use rand::rngs::OsRng;

pub fn generate_keypair() -> (EphemeralSecret, PublicKey) {
    let secret = EphemeralSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    (secret, public)
}

pub fn diffie_hellman(secret: EphemeralSecret, their_public: &PublicKey) -> SharedSecret {
    secret.diffie_hellman(their_public)
}

pub fn public_key_to_bytes(key: &PublicKey) -> [u8; 32] {
    key.to_bytes()
}

pub fn public_key_from_bytes(bytes: [u8; 32]) -> PublicKey {
    PublicKey::from(bytes)
}

// derives a 32-byte symmetric key from the shared secret using BLAKE3 KDF
pub fn derive_key(shared: &SharedSecret, context: &str) -> [u8; 32] {
    blake3::derive_key(context, shared.as_bytes())
}
