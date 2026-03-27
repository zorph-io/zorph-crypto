//! Zero-knowledge primitives: commitments, Merkle trees, and proof envelopes.
//!
//! Verification lives here (open-source); proof generation is in the closed-source enclave code.
//! All proofs are independently verifiable without contacting Zorph.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors returned by ZK operations.
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

// ---------------------------------------------------------------------------
// Commitments: commit(value) -> (hash, opening), verify(hash, opening) -> ok/err
// hash = BLAKE3(nonce || value)
// ---------------------------------------------------------------------------

/// A hiding commitment — the BLAKE3 hash of a nonce-prefixed value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Commitment {
    pub hash: [u8; 32],
}

/// The opening (witness) for a [`Commitment`]: the random nonce and the original value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitmentOpening {
    pub nonce: [u8; 32],
    pub value: Vec<u8>,
}

/// Creates a new commitment to `value`.
///
/// Returns the commitment and the opening needed to reveal it later.
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

/// Verifies a commitment against its opening (constant-time comparison).
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

// ---------------------------------------------------------------------------
// Merkle tree (BLAKE3)
// ---------------------------------------------------------------------------

/// A Merkle inclusion proof for a single leaf.
///
/// Proves that `leaf` is part of the tree with the given `root`
/// without revealing any other leaves.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    /// The leaf hash being proved.
    pub leaf: [u8; 32],
    /// Sibling hashes along the path from leaf to root.
    pub path: Vec<MerkleNode>,
    /// The Merkle root.
    pub root: [u8; 32],
}

/// A sibling node in a [`MerkleProof`] path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleNode {
    /// The sibling's hash.
    pub hash: [u8; 32],
    /// `true` if this sibling is the left child (i.e., the proved node is on the right).
    pub is_left: bool,
}

/// Computes the Merkle root of the given leaf hashes.
///
/// Odd layers duplicate the last leaf to keep the tree balanced.
/// Returns `[0u8; 32]` for an empty slice.
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
                // odd leaf — duplicate to keep the tree balanced
                next.push(hash_pair(&chunk[0], &chunk[0]));
            }
        }
        current = next;
    }

    current[0]
}

/// Generates a Merkle inclusion proof for the leaf at `index`.
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

/// Verifies a Merkle inclusion proof by recomputing the root from the leaf and path.
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

// ---------------------------------------------------------------------------
// Proof envelope
// ---------------------------------------------------------------------------

/// The type of proof carried by a [`ProofEnvelope`].
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

/// A signed proof container.
///
/// Wraps any type of proof with an Ed25519 signature from the enclave's key.
/// The `prover_key` is verified via SEV-SNP attestation.
///
/// Signature covers: `kind(1) || timestamp(8 LE) || statement_hash(32) || proof_data`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofEnvelope {
    /// What this proof attests to.
    pub kind: ProofKind,
    /// Unix timestamp (seconds) when the proof was created.
    pub timestamp: u64,
    /// BLAKE3 hash of the statement being proved.
    pub statement_hash: [u8; 32],
    /// Opaque proof payload (interpretation depends on `kind`).
    pub proof_data: Vec<u8>,
    /// Ed25519 signature over the canonical message.
    pub signature: Vec<u8>,
    /// Ed25519 public key of the prover (verified via attestation).
    pub prover_key: [u8; 32],
}

impl ProofEnvelope {
    /// Builds the canonical message covered by the signature.
    ///
    /// Format: `kind(1) || timestamp(8 LE) || statement_hash(32) || proof_data`.
    pub fn signed_message(&self) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.push(self.kind as u8);
        msg.extend_from_slice(&self.timestamp.to_le_bytes());
        msg.extend_from_slice(&self.statement_hash);
        msg.extend_from_slice(&self.proof_data);
        msg
    }

    /// Verifies the Ed25519 signature against `prover_key`.
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
