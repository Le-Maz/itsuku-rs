//! This module abstracts the environment parameters required for both the PoW search
//! (solving) and validation (verifying).
//!
//! By using the [`SearchParams`] trait, core logic can remain agnostic of whether it is
//! operating on a complete memory/Merkle tree dataset or a partial one.

use crate::{
    challenge_id::ChallengeId,
    config::Config,
    memory::{Memory, PartialMemory, verifier_memory::VerifierMemory},
    merkle_tree::{MerkleTree, PartialMerkleTree, verifier_merkle_tree::VerifierMerkleTree},
};

/// Defines the requirements for parameters used in the PoW search or verification process.
///
/// This trait allows core logic to remain agnostic of whether it is running on a full
/// dataset (during solving) or a partial dataset (during verification).
pub trait SearchParams: Copy {
    /// The specific implementation of partial memory access (Full or Sparse).
    type MemoryType: PartialMemory;
    /// The specific implementation of partial Merkle tree access (Full or Sparse).
    type MerkleTreeType: PartialMerkleTree;

    /// Returns the protocol configuration settings.
    fn config(&self) -> &Config;
    /// Returns the unique challenge ID for the current PoW task.
    fn challenge_id(&self) -> &ChallengeId;
    /// Returns a reference to the memory provider.
    fn memory(&self) -> &Self::MemoryType;
    /// Returns a reference to the Merkle tree provider.
    fn merkle_tree(&self) -> &Self::MerkleTreeType;
}

/// Helper struct to pass immutable search parameters to workers during the solving phase.
///
/// This implementation uses the full [`Memory`] and [`MerkleTree`] structures.
#[derive(Clone, Copy)]
pub struct SolverSearchParams<'a> {
    /// The protocol configuration.
    pub config: &'a Config,
    /// The specific challenge being solved.
    pub challenge_id: &'a ChallengeId,
    /// The full memory dataset.
    pub memory: &'a Memory,
    /// The complete Merkle tree commitment.
    pub merkle_tree: &'a MerkleTree,
}

impl<'a> SearchParams for SolverSearchParams<'a> {
    type MemoryType = Memory;
    type MerkleTreeType = MerkleTree;

    fn config(&self) -> &Config {
        self.config
    }
    fn challenge_id(&self) -> &ChallengeId {
        self.challenge_id
    }
    fn memory(&self) -> &Self::MemoryType {
        self.memory
    }
    fn merkle_tree(&self) -> &Self::MerkleTreeType {
        self.merkle_tree
    }
}

/// Parameters provided to the verifier to validate a specific proof.
///
/// This implementation uses sparse representations ([`VerifierMemory`] and [`VerifierMerkleTree`]).
#[derive(Clone, Copy)]
pub struct VerifierSearchParams<'a> {
    /// The protocol configuration used for validation.
    pub config: &'a Config,
    /// The challenge ID associated with the proof.
    pub challenge_id: &'a ChallengeId,
    /// The sparse memory containing only revealed elements.
    pub memory: &'a VerifierMemory,
    /// The sparse Merkle tree containing only revealed nodes/paths.
    pub merkle_tree: &'a VerifierMerkleTree,
}

impl<'a> SearchParams for VerifierSearchParams<'a> {
    type MemoryType = VerifierMemory;
    type MerkleTreeType = VerifierMerkleTree;

    fn config(&self) -> &Config {
        self.config
    }
    fn challenge_id(&self) -> &ChallengeId {
        self.challenge_id
    }
    fn memory(&self) -> &Self::MemoryType {
        self.memory
    }
    fn merkle_tree(&self) -> &Self::MerkleTreeType {
        self.merkle_tree
    }
}
