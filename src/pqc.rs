//! Hybrid post-quantum cryptography.
//!
//! All operations combine a classical and a post-quantum algorithm simultaneously —
//! an attacker must break **both** to compromise security.
//!
//! - **Signatures:** Ed25519 + ML-DSA-65 (FIPS 204).
//! - **Key exchange:** X25519 + ML-KEM-768 (FIPS 203).
//! - **Hash-based signatures:** SLH-DSA / SPHINCS+ (FIPS 205) — the most conservative
//!   PQC option, relying only on hash function strength. Trade-off: ~17 KB signatures.

use ed25519_dalek::{
    Signer as Ed25519Signer, Verifier as Ed25519Verifier,
    SigningKey as Ed25519SigningKey, VerifyingKey as Ed25519VerifyingKey,
    Signature as Ed25519Signature,
};
use ml_dsa::{
    MlDsa65,
    signature::{Keypair, Signer as MlDsaSigner, Verifier as MlDsaVerifier},
    KeyGen,
};
use ml_kem::{
    MlKem768,
    kem::{Decapsulate, Encapsulate, Kem, KeyExport},
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};
use zeroize::Zeroize;

/// Returns a `rand_core 0.10` RNG backed by `getrandom::SysRng`.
///
/// PQC crates use `rand_core 0.10` (via `getrandom`),
/// while classical crates use `rand_core 0.6` (via `rand`).
fn pqc_rng() -> getrandom::rand_core::UnwrapErr<getrandom::SysRng> {
    getrandom::rand_core::UnwrapErr(getrandom::SysRng)
}

/// Errors returned by hybrid PQC operations.
#[derive(Debug, Error)]
pub enum PqcError {
    #[error("hybrid signature verification failed")]
    SignatureVerification,
    #[error("ML-DSA signing failed: {0}")]
    MlDsaSign(String),
    #[error("deserialization failed: {0}")]
    Deserialize(String),
}

// ===========================================================================
// Hybrid signatures: Ed25519 + ML-DSA-65
// ===========================================================================

/// Combined Ed25519 + ML-DSA-65 signing key.
pub struct HybridSigningKey {
    pub classical: Ed25519SigningKey,
    pub pqc: ml_dsa::SigningKey<MlDsa65>,
}

impl HybridSigningKey {
    /// Serializes as `ed25519_seed(32) || mldsa_seed(32)` = 64 bytes.
    ///
    /// Uses seeds instead of expanded keys (~4 KB) for compact storage.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        out.extend_from_slice(&self.classical.to_bytes());
        out.extend_from_slice(&self.pqc.to_seed());
        out
    }

    /// Deserializes from 64 bytes (`ed25519_seed || mldsa_seed`).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PqcError> {
        if bytes.len() != 64 {
            return Err(PqcError::Deserialize(format!(
                "HybridSigningKey: expected 64 bytes, got {}",
                bytes.len()
            )));
        }
        let ed_bytes: [u8; 32] = bytes[..32]
            .try_into()
            .map_err(|_| PqcError::Deserialize("invalid ed25519 seed".into()))?;
        let classical = Ed25519SigningKey::from_bytes(&ed_bytes);

        let mldsa_seed: [u8; 32] = bytes[32..64]
            .try_into()
            .map_err(|_| PqcError::Deserialize("invalid mldsa seed".into()))?;
        let pqc = <MlDsa65 as KeyGen>::from_seed(&mldsa_seed.into());

        Ok(Self { classical, pqc })
    }
}

impl Serialize for HybridSigningKey {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.to_bytes())
    }
}

impl<'de> Deserialize<'de> for HybridSigningKey {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        Self::from_bytes(&bytes).map_err(serde::de::Error::custom)
    }
}

/// Combined Ed25519 + ML-DSA-65 verifying key.
pub struct HybridVerifyingKey {
    pub classical: Ed25519VerifyingKey,
    pub pqc: ml_dsa::VerifyingKey<MlDsa65>,
}

impl HybridVerifyingKey {
    /// Serializes as `ed25519_vk(32) || mldsa_vk(encoded)`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let pqc_encoded = self.pqc.encode();
        let pqc_bytes: &[u8] = pqc_encoded.as_ref();
        let mut out = Vec::with_capacity(32 + pqc_bytes.len());
        out.extend_from_slice(self.classical.as_bytes());
        out.extend_from_slice(pqc_bytes);
        out
    }

    /// Deserializes from `ed25519_vk(32) || mldsa_vk(variable)`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PqcError> {
        if bytes.len() < 33 {
            return Err(PqcError::Deserialize("HybridVerifyingKey: too short".into()));
        }
        let ed_bytes: [u8; 32] = bytes[..32]
            .try_into()
            .map_err(|_| PqcError::Deserialize("invalid ed25519 vk".into()))?;
        let classical = Ed25519VerifyingKey::from_bytes(&ed_bytes)
            .map_err(|e| PqcError::Deserialize(format!("invalid ed25519 vk: {e}")))?;

        let pqc_bytes = &bytes[32..];
        let pqc_encoded = pqc_bytes
            .try_into()
            .map_err(|_| PqcError::Deserialize("invalid mldsa vk length".into()))?;
        let pqc = ml_dsa::VerifyingKey::<MlDsa65>::decode(&pqc_encoded);

        Ok(Self { classical, pqc })
    }
}

impl Serialize for HybridVerifyingKey {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.to_bytes())
    }
}

impl<'de> Deserialize<'de> for HybridVerifyingKey {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        Self::from_bytes(&bytes).map_err(serde::de::Error::custom)
    }
}

/// Combined Ed25519 + ML-DSA-65 signature.
pub struct HybridSignature {
    pub classical: Ed25519Signature,
    pub pqc: ml_dsa::Signature<MlDsa65>,
}

impl HybridSignature {
    /// Serializes as `ed25519_sig(64) || mldsa_sig(encoded)`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let pqc_encoded = self.pqc.encode();
        let pqc_bytes: &[u8] = pqc_encoded.as_ref();
        let mut out = Vec::with_capacity(64 + pqc_bytes.len());
        out.extend_from_slice(&self.classical.to_bytes());
        out.extend_from_slice(pqc_bytes);
        out
    }

    /// Deserializes from `ed25519_sig(64) || mldsa_sig(variable)`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PqcError> {
        if bytes.len() < 65 {
            return Err(PqcError::Deserialize("HybridSignature: too short".into()));
        }
        let ed_bytes: [u8; 64] = bytes[..64]
            .try_into()
            .map_err(|_| PqcError::Deserialize("invalid ed25519 sig".into()))?;
        let classical = Ed25519Signature::from_bytes(&ed_bytes);

        let pqc = ml_dsa::Signature::<MlDsa65>::try_from(&bytes[64..])
            .map_err(|e| PqcError::Deserialize(format!("invalid mldsa sig: {e}")))?;

        Ok(Self { classical, pqc })
    }
}

impl Serialize for HybridSignature {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.to_bytes())
    }
}

impl<'de> Deserialize<'de> for HybridSignature {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        Self::from_bytes(&bytes).map_err(serde::de::Error::custom)
    }
}

/// Generates a hybrid Ed25519 + ML-DSA-65 signing/verifying keypair.
pub fn generate_signing_keypair() -> (HybridSigningKey, HybridVerifyingKey) {
    let classical = Ed25519SigningKey::generate(&mut OsRng);
    let classical_vk = classical.verifying_key();

    let mut rng = pqc_rng();
    let pqc_sk = MlDsa65::key_gen(&mut rng);
    let pqc_vk = pqc_sk.verifying_key().clone();

    (
        HybridSigningKey {
            classical,
            pqc: pqc_sk,
        },
        HybridVerifyingKey {
            classical: classical_vk,
            pqc: pqc_vk,
        },
    )
}

/// Signs `message` with both Ed25519 and ML-DSA-65.
///
/// Both signatures must pass verification — if either is invalid, the whole thing is rejected.
pub fn hybrid_sign(key: &HybridSigningKey, message: &[u8]) -> Result<HybridSignature, PqcError> {
    let classical = key.classical.sign(message);
    let pqc = key
        .pqc
        .try_sign(message)
        .map_err(|e| PqcError::MlDsaSign(e.to_string()))?;

    Ok(HybridSignature { classical, pqc })
}

/// Verifies both the Ed25519 and ML-DSA-65 signatures.
///
/// Fails if either signature is invalid.
pub fn hybrid_verify(
    key: &HybridVerifyingKey,
    message: &[u8],
    sig: &HybridSignature,
) -> Result<(), PqcError> {
    key.classical
        .verify(message, &sig.classical)
        .map_err(|_| PqcError::SignatureVerification)?;
    key.pqc
        .verify(message, &sig.pqc)
        .map_err(|_| PqcError::SignatureVerification)?;
    Ok(())
}

// ===========================================================================
// Hybrid key exchange: X25519 + ML-KEM-768
// ===========================================================================

/// Combined shared secret from X25519 (32 bytes) and ML-KEM-768 (32 bytes).
///
/// Call [`derive_key`](Self::derive_key) to combine both halves into a single
/// 32-byte key via BLAKE3 KDF.
pub struct HybridSharedSecret {
    data: [u8; 64],
}

impl HybridSharedSecret {
    /// Returns the raw 64-byte combined secret (X25519 || ML-KEM).
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.data
    }

    /// Derives a single 32-byte key from both halves via BLAKE3 KDF.
    pub fn derive_key(&self) -> [u8; 32] {
        blake3::derive_key("zorph-crypto hybrid-shared-secret v1", &self.data)
    }
}

impl Drop for HybridSharedSecret {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

/// Message sent from the initiator to the responder during hybrid key exchange.
pub struct HybridExchangeMessage {
    /// Initiator's ephemeral X25519 public key.
    pub x25519_public: X25519PublicKey,
    /// ML-KEM-768 ciphertext encapsulating the PQC shared secret.
    pub mlkem_ciphertext: ml_kem::Ciphertext<MlKem768>,
}

impl HybridExchangeMessage {
    /// Serializes as `x25519_pk(32) || mlkem_ciphertext(variable)`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let ct_bytes: &[u8] = self.mlkem_ciphertext.as_ref();
        let mut out = Vec::with_capacity(32 + ct_bytes.len());
        out.extend_from_slice(self.x25519_public.as_bytes());
        out.extend_from_slice(ct_bytes);
        out
    }

    /// Deserializes from `x25519_pk(32) || mlkem_ciphertext`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PqcError> {
        if bytes.len() < 33 {
            return Err(PqcError::Deserialize(
                "HybridExchangeMessage: too short".into(),
            ));
        }
        let x25519_bytes: [u8; 32] = bytes[..32]
            .try_into()
            .map_err(|_| PqcError::Deserialize("invalid x25519 pk".into()))?;
        let x25519_public = X25519PublicKey::from(x25519_bytes);

        let mlkem_ciphertext = bytes[32..]
            .try_into()
            .map_err(|_| PqcError::Deserialize("invalid mlkem ciphertext length".into()))?;

        Ok(Self {
            x25519_public,
            mlkem_ciphertext,
        })
    }
}

impl Serialize for HybridExchangeMessage {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.to_bytes())
    }
}

impl<'de> Deserialize<'de> for HybridExchangeMessage {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        Self::from_bytes(&bytes).map_err(serde::de::Error::custom)
    }
}

/// Ephemeral hybrid keypair for key exchange.
///
/// [`EphemeralSecret`] is non-serializable by design — generate a fresh one per exchange.
pub struct HybridExchangeKeypair {
    pub x25519_secret: EphemeralSecret,
    pub x25519_public: X25519PublicKey,
    pub mlkem_dk: ml_kem::DecapsulationKey<MlKem768>,
    pub mlkem_ek: ml_kem::EncapsulationKey<MlKem768>,
}

/// Serializable public half of a [`HybridExchangeKeypair`].
#[derive(Serialize, Deserialize)]
pub struct HybridExchangePublicKey {
    x25519: [u8; 32],
    mlkem: Vec<u8>,
}

impl HybridExchangeKeypair {
    /// Extracts the serializable public key.
    pub fn public_key(&self) -> HybridExchangePublicKey {
        let ek_bytes = self.mlkem_ek.to_bytes();
        let mlkem_bytes: Vec<u8> = AsRef::<[u8]>::as_ref(&ek_bytes).to_vec();
        HybridExchangePublicKey {
            x25519: *self.x25519_public.as_bytes(),
            mlkem: mlkem_bytes,
        }
    }
}

impl HybridExchangePublicKey {
    /// Returns the X25519 public key.
    pub fn x25519(&self) -> X25519PublicKey {
        X25519PublicKey::from(self.x25519)
    }

    /// Parses the ML-KEM-768 encapsulation key.
    pub fn mlkem(&self) -> Result<ml_kem::EncapsulationKey<MlKem768>, PqcError> {
        let key_bytes = self
            .mlkem
            .as_slice()
            .try_into()
            .map_err(|_| PqcError::Deserialize("invalid mlkem ek length".into()))?;
        ml_kem::EncapsulationKey::<MlKem768>::new(&key_bytes)
            .map_err(|_| PqcError::Deserialize("invalid mlkem ek".into()))
    }
}

/// Generates an ephemeral hybrid X25519 + ML-KEM-768 keypair.
pub fn generate_exchange_keypair() -> HybridExchangeKeypair {
    let x25519_secret = EphemeralSecret::random_from_rng(OsRng);
    let x25519_public = X25519PublicKey::from(&x25519_secret);

    let mut rng = pqc_rng();
    let (mlkem_dk, mlkem_ek) = MlKem768::generate_keypair_from_rng(&mut rng);

    HybridExchangeKeypair {
        x25519_secret,
        x25519_public,
        mlkem_dk,
        mlkem_ek,
    }
}

/// Initiates a hybrid key exchange.
///
/// Performs X25519 DH and ML-KEM encapsulation against the responder's public keys,
/// returning the exchange message (to send) and the derived shared secret.
pub fn hybrid_exchange_initiate(
    their_x25519: &X25519PublicKey,
    their_mlkem: &ml_kem::EncapsulationKey<MlKem768>,
) -> (HybridExchangeMessage, HybridSharedSecret) {
    let x25519_secret = EphemeralSecret::random_from_rng(OsRng);
    let x25519_public = X25519PublicKey::from(&x25519_secret);
    let x25519_shared = x25519_secret.diffie_hellman(their_x25519);

    let mut rng = pqc_rng();
    let (mlkem_ct, mlkem_shared) = their_mlkem.encapsulate_with_rng(&mut rng);

    let mut combined = [0u8; 64];
    combined[..32].copy_from_slice(x25519_shared.as_bytes());
    let mlkem_bytes: &[u8] = mlkem_shared.as_ref();
    combined[32..].copy_from_slice(mlkem_bytes);

    (
        HybridExchangeMessage {
            x25519_public,
            mlkem_ciphertext: mlkem_ct,
        },
        HybridSharedSecret { data: combined },
    )
}

/// Completes a hybrid key exchange on the responder side.
///
/// Derives the same shared secret from the initiator's exchange message.
pub fn hybrid_exchange_respond(
    msg: &HybridExchangeMessage,
    x25519_secret: EphemeralSecret,
    mlkem_dk: &ml_kem::DecapsulationKey<MlKem768>,
) -> HybridSharedSecret {
    let x25519_shared = x25519_secret.diffie_hellman(&msg.x25519_public);
    let mlkem_shared = mlkem_dk.decapsulate(&msg.mlkem_ciphertext);

    let mut combined = [0u8; 64];
    combined[..32].copy_from_slice(x25519_shared.as_bytes());
    let mlkem_bytes: &[u8] = mlkem_shared.as_ref();
    combined[32..].copy_from_slice(mlkem_bytes);

    HybridSharedSecret { data: combined }
}

// ===========================================================================
// SLH-DSA (SPHINCS+) — hash-based signatures, FIPS 205
// ===========================================================================

use slh_dsa::{
    Shake128f as SlhDsaShake128f,
    SigningKey as SlhDsaSigningKey,
    VerifyingKey as SlhDsaVerifyingKey,
    Signature as SlhDsaSignature,
};

/// SLH-DSA (SPHINCS+) signing key — SHAKE-128f parameter set.
///
/// Hash-based signatures whose security relies only on hash function strength.
/// Most conservative PQC option; trade-off is ~17 KB signatures.
pub struct StatelessSigningKey {
    inner: SlhDsaSigningKey<SlhDsaShake128f>,
}

/// SLH-DSA (SPHINCS+) verifying key.
pub struct StatelessVerifyingKey {
    inner: SlhDsaVerifyingKey<SlhDsaShake128f>,
}

/// SLH-DSA (SPHINCS+) signature (~17 KB).
pub struct StatelessSignature {
    inner: SlhDsaSignature<SlhDsaShake128f>,
}

/// Generates an SLH-DSA signing/verifying keypair.
pub fn generate_stateless_keypair() -> (StatelessSigningKey, StatelessVerifyingKey) {
    let mut rng = pqc_rng();
    let sk = SlhDsaSigningKey::<SlhDsaShake128f>::new(&mut rng);
    let vk: &SlhDsaVerifyingKey<SlhDsaShake128f> = sk.as_ref();
    let vk_clone = vk.clone();
    (
        StatelessSigningKey { inner: sk },
        StatelessVerifyingKey { inner: vk_clone },
    )
}

/// Signs `message` with SLH-DSA.
pub fn stateless_sign(
    key: &StatelessSigningKey,
    message: &[u8],
) -> Result<StatelessSignature, PqcError> {
    let sig = key
        .inner
        .try_sign(message)
        .map_err(|e| PqcError::MlDsaSign(format!("SLH-DSA: {e}")))?;
    Ok(StatelessSignature { inner: sig })
}

/// Verifies an SLH-DSA signature.
pub fn stateless_verify(
    key: &StatelessVerifyingKey,
    message: &[u8],
    sig: &StatelessSignature,
) -> Result<(), PqcError> {
    key.inner
        .verify(message, &sig.inner)
        .map_err(|_| PqcError::SignatureVerification)
}

impl StatelessSigningKey {
    /// Serializes the signing key to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_vec()
    }

    /// Deserializes a signing key from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PqcError> {
        let inner = SlhDsaSigningKey::<SlhDsaShake128f>::try_from(bytes)
            .map_err(|e| PqcError::Deserialize(format!("SLH-DSA sk: {e}")))?;
        Ok(Self { inner })
    }
}

impl StatelessVerifyingKey {
    /// Serializes the verifying key to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_vec()
    }

    /// Deserializes a verifying key from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PqcError> {
        let inner = SlhDsaVerifyingKey::<SlhDsaShake128f>::try_from(bytes)
            .map_err(|e| PqcError::Deserialize(format!("SLH-DSA vk: {e}")))?;
        Ok(Self { inner })
    }
}

impl StatelessSignature {
    /// Serializes the signature to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_vec()
    }

    /// Deserializes a signature from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PqcError> {
        let inner = SlhDsaSignature::<SlhDsaShake128f>::try_from(bytes)
            .map_err(|e| PqcError::Deserialize(format!("SLH-DSA sig: {e}")))?;
        Ok(Self { inner })
    }
}

impl Serialize for StatelessSigningKey {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.to_bytes())
    }
}

impl<'de> Deserialize<'de> for StatelessSigningKey {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        Self::from_bytes(&bytes).map_err(serde::de::Error::custom)
    }
}

impl Serialize for StatelessVerifyingKey {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.to_bytes())
    }
}

impl<'de> Deserialize<'de> for StatelessVerifyingKey {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        Self::from_bytes(&bytes).map_err(serde::de::Error::custom)
    }
}

impl Serialize for StatelessSignature {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.to_bytes())
    }
}

impl<'de> Deserialize<'de> for StatelessSignature {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        Self::from_bytes(&bytes).map_err(serde::de::Error::custom)
    }
}
