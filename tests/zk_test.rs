use zorph_crypto::zk::{
    commit, verify_commitment,
    merkle_root, merkle_prove, merkle_verify,
    ProofEnvelope, ProofKind,
};

#[test]
fn commitment_roundtrip() {
    let data = b"secret value";
    let (commitment, opening) = commit(data);
    assert!(verify_commitment(&commitment, &opening).is_ok());
}

#[test]
fn commitment_wrong_value_fails() {
    let (commitment, mut opening) = commit(b"original");
    opening.value = b"tampered".to_vec();
    assert!(verify_commitment(&commitment, &opening).is_err());
}

#[test]
fn commitment_wrong_nonce_fails() {
    let (commitment, mut opening) = commit(b"data");
    opening.nonce[0] ^= 0xFF;
    assert!(verify_commitment(&commitment, &opening).is_err());
}

#[test]
fn two_commitments_are_different() {
    let (c1, _) = commit(b"same data");
    let (c2, _) = commit(b"same data");
    assert_ne!(c1.hash, c2.hash);
}

#[test]
fn merkle_root_single_leaf() {
    let leaf = blake3::hash(b"only leaf").into();
    let root = merkle_root(&[leaf]);
    assert_eq!(root, leaf);
}

#[test]
fn merkle_root_deterministic() {
    let leaves: Vec<[u8; 32]> = (0..4u8)
        .map(|i| blake3::hash(&[i]).into())
        .collect();
    let r1 = merkle_root(&leaves);
    let r2 = merkle_root(&leaves);
    assert_eq!(r1, r2);
}

#[test]
fn merkle_root_changes_with_data() {
    let leaves_a: Vec<[u8; 32]> = (0..4u8)
        .map(|i| blake3::hash(&[i]).into())
        .collect();
    let leaves_b: Vec<[u8; 32]> = (10..14u8)
        .map(|i| blake3::hash(&[i]).into())
        .collect();
    assert_ne!(merkle_root(&leaves_a), merkle_root(&leaves_b));
}

#[test]
fn merkle_proof_verify_all_leaves() {
    let leaves: Vec<[u8; 32]> = (0..8u8)
        .map(|i| blake3::hash(&[i]).into())
        .collect();

    for i in 0..leaves.len() {
        let proof = merkle_prove(&leaves, i).unwrap();
        assert_eq!(proof.leaf, leaves[i]);
        assert_eq!(proof.root, merkle_root(&leaves));
        assert!(merkle_verify(&proof).is_ok());
    }
}

#[test]
fn merkle_proof_odd_number_of_leaves() {
    let leaves: Vec<[u8; 32]> = (0..5u8)
        .map(|i| blake3::hash(&[i]).into())
        .collect();

    for i in 0..leaves.len() {
        let proof = merkle_prove(&leaves, i).unwrap();
        assert!(merkle_verify(&proof).is_ok());
    }
}

#[test]
fn merkle_proof_tampered_leaf_fails() {
    let leaves: Vec<[u8; 32]> = (0..4u8)
        .map(|i| blake3::hash(&[i]).into())
        .collect();
    let mut proof = merkle_prove(&leaves, 0).unwrap();
    proof.leaf[0] ^= 0xFF;
    assert!(merkle_verify(&proof).is_err());
}

#[test]
fn merkle_prove_out_of_bounds() {
    let leaves: Vec<[u8; 32]> = vec![blake3::hash(b"a").into()];
    assert!(merkle_prove(&leaves, 1).is_err());
}

#[test]
fn proof_envelope_verify_signature() {
    use ed25519_dalek::{Signer, SigningKey};

    let sk = SigningKey::generate(&mut rand::rngs::OsRng);
    let vk = sk.verifying_key();

    let mut envelope = ProofEnvelope {
        kind: ProofKind::FileIntegrity,
        timestamp: 1700000000,
        statement_hash: blake3::hash(b"file content").into(),
        proof_data: vec![1, 2, 3],
        signature: vec![],
        prover_key: vk.to_bytes(),
    };

    let msg = envelope.signed_message();
    let sig = sk.sign(&msg);
    envelope.signature = sig.to_bytes().to_vec();

    assert!(envelope.verify_signature().is_ok());
}

#[test]
fn proof_envelope_tampered_fails() {
    use ed25519_dalek::{Signer, SigningKey};

    let sk = SigningKey::generate(&mut rand::rngs::OsRng);
    let vk = sk.verifying_key();

    let mut envelope = ProofEnvelope {
        kind: ProofKind::Deletion,
        timestamp: 1700000000,
        statement_hash: blake3::hash(b"deleted file").into(),
        proof_data: vec![],
        signature: vec![],
        prover_key: vk.to_bytes(),
    };

    let msg = envelope.signed_message();
    let sig = sk.sign(&msg);
    envelope.signature = sig.to_bytes().to_vec();

    envelope.statement_hash[0] ^= 0xFF;
    assert!(envelope.verify_signature().is_err());
}

#[test]
fn proof_envelope_wrong_key_fails() {
    use ed25519_dalek::{Signer, SigningKey};

    let sk = SigningKey::generate(&mut rand::rngs::OsRng);
    let sk2 = SigningKey::generate(&mut rand::rngs::OsRng);

    let mut envelope = ProofEnvelope {
        kind: ProofKind::Approval,
        timestamp: 1700000000,
        statement_hash: [0u8; 32],
        proof_data: vec![],
        signature: vec![],
        prover_key: sk2.verifying_key().to_bytes(),
    };

    let msg = envelope.signed_message();
    let sig = sk.sign(&msg);
    envelope.signature = sig.to_bytes().to_vec();

    assert!(envelope.verify_signature().is_err());
}

#[test]
fn proof_envelope_serialization() {
    let envelope = ProofEnvelope {
        kind: ProofKind::Computation,
        timestamp: 1700000000,
        statement_hash: [0xAA; 32],
        proof_data: vec![1, 2, 3, 4, 5],
        signature: vec![0; 64],
        prover_key: [0xBB; 32],
    };

    let json = serde_json::to_string(&envelope).unwrap();
    let deserialized: ProofEnvelope = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.kind, ProofKind::Computation);
    assert_eq!(deserialized.timestamp, 1700000000);
}
