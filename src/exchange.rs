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
