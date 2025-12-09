//! This module defines the core **configuration parameters** for the Itsuku Proof-of-Work (PoW) scheme.
//!
//! The `Config` struct holds all constants that define the memory requirements,
//! the structure of the memory dependency graph, and the required cryptographic difficulty.
//! These parameters ensure deterministic behavior across the prover (searcher) and the verifier.

use clap::Args;
use serde::{Deserialize, Serialize};

/// # Configuration Parameters
///
/// Holds the essential parameters that define the **memory hard function** and the
/// **Proof-of-Work (PoW)** difficulty for the Itsuku scheme.
///
/// These values collectively determine the total memory size, the computational cost of
/// reconstructing memory elements, and the required effort for finding a valid proof.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Args)]
pub struct Config {
    /// The size of a single memory chunk (in elements which are 64 bytes each)
    ///
    /// See [`crate::memory::Element`]
    pub chunk_size: usize,
    /// The total number of memory chunks used for the proof
    pub chunk_count: usize,
    /// The number of antecedent elements required to compute a single compressed memory element
    pub antecedent_count: usize,
    /// The required number of leading zeros in the Omega hash
    pub difficulty_bits: usize,
    /// The number of tree paths used for a single proof
    pub search_length: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chunk_size: 1 << 15,
            chunk_count: 1 << 10,
            difficulty_bits: 24,
            antecedent_count: 4,
            search_length: 9,
        }
    }
}
