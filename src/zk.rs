// ZK primitives: commitments, Merkle trees, proof envelope wrapper.
// Verification lives here (open-source lib), proof generation is in the closed-source code.
// Proofs are verifiable without contacting Zorph. Even if Zorph disappears.

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ZkError {
    #[error("commitment verification failed")]
    CommitmentMismatch,
    #[error("merkle proof verification failed")]
    MerkleProofInvalid,
    #[error("proof verification failed: {0}")]
    ProofInvalid(String),
    #[error("invalid proof data: {0}")]
    InvalidData(String),
}

// Commitments: commit(value) -> (hash, opening), verify(hash, opening) -> ok/err
// hash = BLAKE3(nonce || value)

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Commitment {
    pub hash: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitmentOpening {
    pub nonce: [u8; 32],
    pub value: Vec<u8>,
}

pub fn commit(value: &[u8]) -> (Commitment, CommitmentOpening) {
    let mut nonce = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);

    let hash = compute_commitment(&nonce, value);

    (
        Commitment { hash },
        CommitmentOpening {
            nonce,
            value: value.to_vec(),
        },
    )
}

pub fn verify_commitment(commitment: &Commitment, opening: &CommitmentOpening) -> Result<(), ZkError> {
    let expected = compute_commitment(&opening.nonce, &opening.value);
    use subtle::ConstantTimeEq;
    if bool::from(commitment.hash.as_slice().ct_eq(expected.as_slice())) {
        Ok(())
    } else {
        Err(ZkError::CommitmentMismatch)
    }
}

fn compute_commitment(nonce: &[u8; 32], value: &[u8]) -> [u8; 32] {
    blake3::keyed_hash(nonce, value).into()
}

// Merkle tree on BLAKE3
// proves that a leaf (file hash) belongs to the set without revealing the others

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    pub leaf: [u8; 32],
    pub path: Vec<MerkleNode>,
    pub root: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleNode {
    pub hash: [u8; 32],
    pub is_left: bool,
}

pub fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    if leaves.len() == 1 {
        return leaves[0];
    }

    let mut current: Vec<[u8; 32]> = leaves.to_vec();

    while current.len() > 1 {
        let mut next = Vec::with_capacity((current.len() + 1) / 2);
        for chunk in current.chunks(2) {
            if chunk.len() == 2 {
                next.push(hash_pair(&chunk[0], &chunk[1]));
            } else {
                // odd leaf — duplicate it so the tree is always balanced.
                // prevents cross-tree root collisions.
                next.push(hash_pair(&chunk[0], &chunk[0]));
            }
        }
        current = next;
    }

    current[0]
}

pub fn merkle_prove(leaves: &[[u8; 32]], index: usize) -> Result<MerkleProof, ZkError> {
    if index >= leaves.len() {
        return Err(ZkError::InvalidData(format!(
            "index {index} out of range ({})",
            leaves.len()
        )));
    }
    if leaves.len() == 1 {
        return Ok(MerkleProof {
            leaf: leaves[0],
            path: vec![],
            root: leaves[0],
        });
    }

    let mut path = Vec::new();
    let mut current: Vec<[u8; 32]> = leaves.to_vec();
    let mut idx = index;

    while current.len() > 1 {
        let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };

        if sibling_idx < current.len() {
            path.push(MerkleNode {
                hash: current[sibling_idx],
                is_left: idx % 2 == 1,
            });
        } else {
            // odd leaf — sibling is itself (duplication)
            path.push(MerkleNode {
                hash: current[idx],
                is_left: false,
            });
        }

        let mut next = Vec::with_capacity((current.len() + 1) / 2);
        for chunk in current.chunks(2) {
            if chunk.len() == 2 {
                next.push(hash_pair(&chunk[0], &chunk[1]));
            } else {
                next.push(hash_pair(&chunk[0], &chunk[0]));
            }
        }
        current = next;
        idx /= 2;
    }

    Ok(MerkleProof {
        leaf: leaves[index],
        path,
        root: current[0],
    })
}

pub fn merkle_verify(proof: &MerkleProof) -> Result<(), ZkError> {
    let mut current = proof.leaf;

    for node in &proof.path {
        if node.is_left {
            current = hash_pair(&node.hash, &current);
        } else {
            current = hash_pair(&current, &node.hash);
        }
    }

    if current == proof.root {
        Ok(())
    } else {
        Err(ZkError::MerkleProofInvalid)
    }
}

fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

// ProofEnvelope — container for any type of proof
// signed with the enclave's Ed25519 key (prover_key is verified via SEV-SNP attestation)

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProofKind {
    FileIntegrity,
    Approval,
    Computation,
    Deletion,
    SearchCompleteness,
    AccessLog,
    Enclave,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofEnvelope {
    pub kind: ProofKind,
    pub timestamp: u64,
    pub statement_hash: [u8; 32],
    pub proof_data: Vec<u8>,
    pub signature: Vec<u8>,
    pub prover_key: [u8; 32],
}

impl ProofEnvelope {
    // signature covers: kind || timestamp || statement_hash || proof_data
    pub fn signed_message(&self) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.push(self.kind as u8);
        msg.extend_from_slice(&self.timestamp.to_le_bytes());
        msg.extend_from_slice(&self.statement_hash);
        msg.extend_from_slice(&self.proof_data);
        msg
    }

    pub fn verify_signature(&self) -> Result<(), ZkError> {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        let vk = VerifyingKey::from_bytes(&self.prover_key)
            .map_err(|e| ZkError::ProofInvalid(format!("invalid prover key: {e}")))?;

        let sig_bytes: [u8; 64] = self
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| ZkError::ProofInvalid("invalid signature length".into()))?;
        let sig = Signature::from_bytes(&sig_bytes);

        let msg = self.signed_message();
        vk.verify(&msg, &sig)
            .map_err(|_| ZkError::ProofInvalid("signature verification failed".into()))
    }
}
