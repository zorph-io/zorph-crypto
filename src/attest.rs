// AMD SEV-SNP attestation report verification + certificate chain.
// Full chain: AMD Root Key (ARK) -> ASK -> VCEK -> attestation report.

use ecdsa::signature::Verifier;
use p384::ecdsa::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AttestError {
    #[error("attestation signature verification failed")]
    SignatureInvalid,
    #[error("measurement mismatch: expected {expected}, got {got}")]
    MeasurementMismatch { expected: String, got: String },
    #[error("report version unsupported: {0}")]
    UnsupportedVersion(u32),
    #[error("deserialization failed: {0}")]
    Deserialize(String),
    #[error("VCEK public key invalid: {0}")]
    InvalidVcek(String),
    #[error("certificate chain invalid: {0}")]
    CertChainInvalid(String),
}

// SEV-SNP attestation report v2
// measurement — hash of enclave code, report_data — client nonce (anti-replay)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationReport {
    pub version: u32,
    pub guest_svn: u32,
    pub policy: u64,
    pub measurement: Vec<u8>,
    pub report_data: Vec<u8>,
    pub signed_data: Vec<u8>,
    pub signature: Vec<u8>,
}

// VCEK — per-chip key, signed by the AMD chain (ARK -> ASK -> VCEK)
#[derive(Debug, Clone)]
pub struct VcekPublicKey {
    inner: VerifyingKey,
}

impl VcekPublicKey {
    pub fn from_sec1_bytes(bytes: &[u8]) -> Result<Self, AttestError> {
        let inner = VerifyingKey::from_sec1_bytes(bytes)
            .map_err(|e| AttestError::InvalidVcek(e.to_string()))?;
        Ok(Self { inner })
    }

    pub fn from_public_key_der(der: &[u8]) -> Result<Self, AttestError> {
        let inner = VerifyingKey::from_sec1_bytes(der)
            .map_err(|e| AttestError::InvalidVcek(e.to_string()))?;
        Ok(Self { inner })
    }
}

// 1. version must be 2
// 2. ECDSA-P384 signature from VCEK
// 3. measurement matches expected value (constant-time)
pub fn verify_attestation(
    report: &AttestationReport,
    vcek: &VcekPublicKey,
    expected_measurement: &[u8; 48],
) -> Result<(), AttestError> {
    if report.version != 2 {
        return Err(AttestError::UnsupportedVersion(report.version));
    }

    let signature = Signature::from_der(&report.signature)
        .map_err(|_| AttestError::SignatureInvalid)?;

    vcek.inner
        .verify(&report.signed_data, &signature)
        .map_err(|_| AttestError::SignatureInvalid)?;

    use subtle::ConstantTimeEq;
    if !bool::from(report.measurement.as_slice().ct_eq(expected_measurement.as_slice())) {
        return Err(AttestError::MeasurementMismatch {
            expected: hex::encode(expected_measurement),
            got: hex::encode(&report.measurement),
        });
    }

    Ok(())
}

// verifies nonce in report_data — replay attack protection
pub fn verify_report_nonce(
    report: &AttestationReport,
    expected_nonce: &[u8; 64],
) -> bool {
    use subtle::ConstantTimeEq;
    report.report_data.as_slice().ct_eq(expected_nonce.as_slice()).into()
}

// Full AMD certificate chain verification: ARK -> ASK -> VCEK.
// Input: three DER-encoded X.509 certificates.
// Returns VCEK public key ready for verify_attestation().
pub fn verify_cert_chain(
    ark_der: &[u8],
    ask_der: &[u8],
    vcek_der: &[u8],
) -> Result<VcekPublicKey, AttestError> {
    use x509_cert::Certificate;
    use x509_cert::der::Decode;

    let ark = Certificate::from_der(ark_der)
        .map_err(|e| AttestError::CertChainInvalid(format!("ARK: {e}")))?;
    let ask = Certificate::from_der(ask_der)
        .map_err(|e| AttestError::CertChainInvalid(format!("ASK: {e}")))?;
    let vcek = Certificate::from_der(vcek_der)
        .map_err(|e| AttestError::CertChainInvalid(format!("VCEK: {e}")))?;

    // ARK — self-signed root
    verify_x509_p384(&ark, &ark)?;
    // ASK signed by ARK
    verify_x509_p384(&ask, &ark)?;
    // VCEK signed by ASK
    verify_x509_p384(&vcek, &ask)?;

    let vcek_pk = vcek
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes();
    VcekPublicKey::from_sec1_bytes(vcek_pk)
}

// verifies ECDSA-P384 signature of an X.509 certificate using the issuer's key
fn verify_x509_p384(
    cert: &x509_cert::Certificate,
    issuer: &x509_cert::Certificate,
) -> Result<(), AttestError> {
    use x509_cert::der::Encode;

    let tbs_bytes = cert
        .tbs_certificate
        .to_der()
        .map_err(|e| AttestError::CertChainInvalid(format!("TBS encode: {e}")))?;

    let sig_bytes = cert.signature.raw_bytes();
    let signature = Signature::from_der(sig_bytes)
        .map_err(|_| AttestError::SignatureInvalid)?;

    let issuer_pk = issuer
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes();
    let vk = VerifyingKey::from_sec1_bytes(issuer_pk)
        .map_err(|e| AttestError::CertChainInvalid(format!("issuer key: {e}")))?;

    vk.verify(&tbs_bytes, &signature)
        .map_err(|_| AttestError::SignatureInvalid)
}

mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}
