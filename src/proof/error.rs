//! This module defines errors that can occur during proof verification.

use std::fmt::{Display, Formatter};

/// Specific errors that can occur during proof verification.
///
/// These errors cover all structural, cryptographic, and consistency
/// failures that can arise when validating an Itsuku proof.
#[derive(Debug)]
pub enum VerificationError {
    /// The number of antecedents supplied for a memory element is not valid
    /// for the current configuration.
    ///
    /// *For example:*  
    /// - A base-chunk element must have exactly 1 antecedent.  
    /// - A compressed element must have exactly `antecedent_count` antecedents.
    InvalidAntecedentCount(usize),

    /// A required Merkle opening for a leaf index referenced in the path
    /// is missing from the proof.
    MissingOpeningForLeaf(usize),

    /// The Merkle leaf hash computed from a reconstructed memory element does
    /// not match the hash provided in the Merkle opening.
    LeafHashMismatch(usize),

    /// A computed Merkle intermediate node hash does not match the hash
    /// provided in the opening.
    IntermediateHashMismatch(usize),

    /// The reconstructed Merkle tree does not contain the root node.  
    /// This indicates an incomplete or malformed opening.
    MissingMerkleRoot,

    /// The structure of the Merkle opening does not represent a valid path
    /// from the required leaves to the root.
    MalformedProofPath,

    /// During Omega recomputation, the verifier encountered a memory leaf that
    /// was *not* included in the proof’s antecedent set.
    UnprovenLeafInPath,

    /// The recomputed Omega hash does not satisfy the difficulty requirement
    /// (insufficient leading zero bits).
    DifficultyNotMet,

    /// A memory element needed to reconstruct part of the path is missing in
    /// the antecedent set.
    RequiredElementMissing(usize),

    /// A Merkle child node required to verify a parent hash is missing from the
    /// opening.
    MissingChildNode(usize),
}

impl Display for VerificationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            VerificationError::InvalidAntecedentCount(count) => {
                write!(f, "Invalid antecedent count: {}", count)
            }
            VerificationError::MissingOpeningForLeaf(idx) => {
                write!(f, "Missing Merkle opening for required leaf index: {}", idx)
            }
            VerificationError::LeafHashMismatch(idx) => {
                write!(f, "Computed leaf hash mismatch for index: {}", idx)
            }
            VerificationError::IntermediateHashMismatch(idx) => {
                write!(f, "Computed intermediate hash mismatch for index: {}", idx)
            }
            VerificationError::MissingMerkleRoot => write!(f, "Missing Merkle Root hash (Phi)"),
            VerificationError::MalformedProofPath => write!(
                f,
                "The Merkle path structure in the proof opening is malformed"
            ),
            VerificationError::UnprovenLeafInPath => write!(
                f,
                "Recalculated path includes leaves not provided in the proof"
            ),
            VerificationError::DifficultyNotMet => {
                write!(f, "Proof difficulty not met (insufficient leading zeros)")
            }
            VerificationError::RequiredElementMissing(idx) => {
                write!(f, "Required memory element missing at index: {}", idx)
            }
            VerificationError::MissingChildNode(idx) => write!(
                f,
                "Missing child node required to verify parent hash at index: {}",
                idx
            ),
        }
    }
}
