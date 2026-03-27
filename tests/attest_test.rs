use zorph_crypto::attest::{
    AttestationReport, VcekPublicKey, verify_attestation, verify_report_nonce, verify_cert_chain,
};

use p384::ecdsa::{SigningKey, signature::{Signer, SignatureEncoding}};

fn make_test_report() -> (AttestationReport, VcekPublicKey, [u8; 48]) {
    let sk = SigningKey::random(&mut rand::rngs::OsRng);
    let vk = *sk.verifying_key();

    let measurement = [0xABu8; 48];
    let report_data = vec![0xCDu8; 64];

    let mut signed_data = Vec::new();
    signed_data.extend_from_slice(&2u32.to_le_bytes());
    signed_data.extend_from_slice(&1u32.to_le_bytes());
    signed_data.extend_from_slice(&0u64.to_le_bytes());
    signed_data.extend_from_slice(&measurement);
    signed_data.extend_from_slice(&report_data);

    let signature: p384::ecdsa::DerSignature = sk.sign(&signed_data);

    let report = AttestationReport {
        version: 2,
        guest_svn: 1,
        policy: 0,
        measurement: measurement.to_vec(),
        report_data,
        signed_data,
        signature: signature.to_vec(),
    };

    let vcek = VcekPublicKey::from_sec1_bytes(&vk.to_encoded_point(false).as_bytes()).unwrap();

    (report, vcek, measurement)
}

#[test]
fn verify_valid_attestation() {
    let (report, vcek, measurement) = make_test_report();
    assert!(verify_attestation(&report, &vcek, &measurement).is_ok());
}

#[test]
fn verify_wrong_measurement_fails() {
    let (report, vcek, _measurement) = make_test_report();
    let wrong = [0x00u8; 48];
    let result = verify_attestation(&report, &vcek, &wrong);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("mismatch"));
}

#[test]
fn verify_wrong_version_fails() {
    let (mut report, vcek, measurement) = make_test_report();
    report.version = 1;
    assert!(verify_attestation(&report, &vcek, &measurement).is_err());
}

#[test]
fn verify_tampered_data_fails() {
    let (mut report, vcek, measurement) = make_test_report();
    report.signed_data[0] ^= 0xFF;
    assert!(verify_attestation(&report, &vcek, &measurement).is_err());
}

#[test]
fn verify_wrong_vcek_fails() {
    let (report, _vcek, measurement) = make_test_report();
    let sk2 = SigningKey::random(&mut rand::rngs::OsRng);
    let vk2 = *sk2.verifying_key();
    let vcek2 = VcekPublicKey::from_sec1_bytes(&vk2.to_encoded_point(false).as_bytes()).unwrap();
    assert!(verify_attestation(&report, &vcek2, &measurement).is_err());
}

#[test]
fn verify_report_nonce_matches() {
    let (mut report, _, _) = make_test_report();
    let nonce = [0xCDu8; 64];
    report.report_data = nonce.to_vec();
    assert!(verify_report_nonce(&report, &nonce));
}

#[test]
fn verify_report_nonce_mismatch() {
    let (report, _, _) = make_test_report();
    let wrong_nonce = [0x00u8; 64];
    assert!(!verify_report_nonce(&report, &wrong_nonce));
}

// cert chain (ARK → ASK → VCEK)

fn make_cert_chain() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    use rcgen::{CertificateParams, KeyPair, IsCa, BasicConstraints};

    let ark_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
    let mut ark_params = CertificateParams::new(vec!["AMD ARK".into()]).unwrap();
    ark_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ark_cert = ark_params.self_signed(&ark_key).unwrap();

    let ask_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
    let mut ask_params = CertificateParams::new(vec!["AMD ASK".into()]).unwrap();
    ask_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ask_cert = ask_params.signed_by(&ask_key, &ark_cert, &ark_key).unwrap();

    let vcek_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
    let vcek_params = CertificateParams::new(vec!["AMD VCEK".into()]).unwrap();
    let vcek_cert = vcek_params.signed_by(&vcek_key, &ask_cert, &ask_key).unwrap();

    (
        ark_cert.der().to_vec(),
        ask_cert.der().to_vec(),
        vcek_cert.der().to_vec(),
    )
}

#[test]
fn cert_chain_valid() {
    let (ark, ask, vcek) = make_cert_chain();
    let result = verify_cert_chain(&ark, &ask, &vcek);
    assert!(result.is_ok());
}

#[test]
fn cert_chain_wrong_ark_fails() {
    let (_ark, ask, vcek) = make_cert_chain();

    // different ARK — chain won't verify
    let fake_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
    let mut fake_params = rcgen::CertificateParams::new(vec!["FAKE ARK".into()]).unwrap();
    fake_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let fake_ark_cert = fake_params.self_signed(&fake_key).unwrap();
    let fake_ark = fake_ark_cert.der().to_vec();

    assert!(verify_cert_chain(&fake_ark, &ask, &vcek).is_err());
}

#[test]
fn cert_chain_swapped_ask_vcek_fails() {
    let (ark, ask, vcek) = make_cert_chain();
    // swapped ASK and VCEK — signatures won't match
    assert!(verify_cert_chain(&ark, &vcek, &ask).is_err());
}

#[test]
fn cert_chain_invalid_der_fails() {
    let (ark, ask, _vcek) = make_cert_chain();
    assert!(verify_cert_chain(&ark, &ask, b"not a certificate").is_err());
}
