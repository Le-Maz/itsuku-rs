//! This module defines the `Proof` structure and the core algorithms for searching and
//! verifying solutions.
//!
//! The Itsuku Proof-of-Work (PoW) scheme requires finding a nonce N such that a
//! computationally expensive hash chain called Omega produces a hash with a specific
//! number of leading zeros. This demonstrates that the prover has spent significant
//! memory and time resources.
//!
//! The module handles:
//! * Search: Parallelized nonce search to find a valid nonce.
//! * Construction: Building the compact proof object containing the nonce, Merkle
//!   opening, and antecedents.
//! * Verification: Reconstructing the partial memory and Merkle path to efficiently
//!   validate the proof.

use std::collections::BTreeMap;

use blake3::Hasher;
use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::{
    challenge_id::ChallengeId,
    config::Config,
    endianness::{Endian, EndiannessTag, NativeEndian},
    memory::{Element, PartialMemory},
    proof::search_params::SearchParams,
};

pub mod error;
pub mod search_params;
pub mod solve;
pub mod verify;

/// A cryptographic Proof-of-Work (PoW) solution for the Itsuku scheme.
///
/// A `Proof` consists of a successful nonce, a set of leaf antecedents needed to
/// rebuild memory elements, and a Merkle tree opening containing the hashes that
/// authenticate those elements. Proof size is small (around 11 KiB for the default
/// parameters described in Section 4 of the specification).
#[derive(Debug, Serialize, Deserialize)]
pub struct Proof {
    /// Configuration of the algorithm's parameters used to generate this proof.
    config: Config,
    /// Challenge identifier (I) unique to this PoW instance.
    challenge_id: ChallengeId,
    /// The nonce (N) that satisfied the difficulty requirement.
    nonce: u64,
    /// A map from leaf index to the list of `Element`s required to compute
    /// the leaf's memory value (its antecedents).
    ///
    /// The keys are the indices of the leaves selected by the random walk.
    /// The values are the antecedent elements. These are stored using `NativeEndian`
    /// for serialization simplicity, but are transmuted to the correct endianness
    /// during verification based on `endianness`.
    leaf_antecedents: BTreeMap<usize, Vec<Element<NativeEndian>>>,
    /// A map from Merkle node index to its hash.
    ///
    /// This provides the collective opening (Z) (Merkle tree proof) of the selected
    /// leaves and their antecedents, allowing the verifier to authenticate the
    /// memory values used in the proof without holding the entire dataset.
    tree_opening: BTreeMap<usize, Bytes>,
    /// Endianness of the solver (prover).
    ///
    /// This tag ensures that the verifier interprets the byte order of the proof
    /// correctly, regardless of their own system's architecture.
    #[serde(default)]
    endianness: EndiannessTag,
}

impl Proof {
    /// Calculates the final Omega hash for a given nonce based on the memory's structure
    /// and the challenge (I).
    ///
    /// This function implements the core hash chain process:
    /// 1.  Init: Y0 = H(N || Phi || I)
    /// 2.  Chain: For j = 1 .. L:
    ///     * i_{j-1} = Y_{j-1} mod T (Select random leaf)
    ///     * Yj = H(Y_{j-1} || (X[i_{j-1}] XOR I)) (Hash current path value with selected element)
    /// 3.  Finalize: Combine path hashes to form Omega.
    ///
    /// The hash function H is made challenge-specific to thwart precomputation attacks like Dinur-Nadler.
    ///
    /// ## Arguments
    /// * `params`: Configuration and data access.
    /// * `hasher`: A mutable Blake2b512 hasher instance to reuse.
    /// * `selected_leaves`: Output vector to store the indices of the memory elements accessed.
    /// * `path`: Output vector to store the intermediate hash chain values (Yj).
    /// * `memory_size`: The total number of elements in memory (T).
    /// * `nonce`: The nonce (N) to be included in the hash chain.
    ///
    /// ## Returns
    /// The final Omega hash as a 64-byte array.
    fn calculate_omega<S: SearchParams>(
        params: &S,
        root_hash: &[u8],
        hasher: &mut Hasher,
        selected_leaves: &mut Vec<usize>,
        path: &mut Vec<[u8; 64]>,
        memory_size: usize,
        nonce: u64,
    ) -> [u8; 64] {
        let mut hash_output = [0; 64];

        selected_leaves.clear();
        path.clear();

        // Step 4: Calculate the first path hash (Y0)
        // Y0 = HS(N || Phi || I)
        hasher.update(&S::SolverEndian::u64_to_bytes(nonce));
        hasher.update(root_hash);
        hasher.update(&params.challenge_id().bytes);
        hasher.finalize_xof().fill(&mut hash_output);
        path.push(hash_output);
        hasher.reset();
        let challenge_element: Element<S::SolverEndian> = params.challenge_id().bytes.into();

        // Step 5: Iterative hash chain (1 <= j <= L)
        for _ in 1..=params.config().search_length {
            let prev_hash = path.last().unwrap();

            // Determine the next memory element index: i_j-1 = Y_j-1 mod T
            let index = (S::SolverEndian::u64_from_bytes(prev_hash.first_chunk().unwrap())
                as usize)
                % memory_size;
            selected_leaves.push(index);

            // Fetch the element, XOR it with the challenge_id for anti-precomputation
            // Itsuku uses X_I[i_j-1] XOR I
            let mut element = params
                .memory()
                .get_element(index)
                .expect("Required element must exist");
            element ^= &challenge_element;

            // Calculate the next path hash (Yj): Yj = HS(Y_j-1 || X_I[i_j-1] XOR I)
            hasher.update(prev_hash);
            hasher.update(S::SolverEndian::simd_to_bytes(element.data).as_array());

            hasher.finalize_xof().fill(&mut hash_output);
            path.push(hash_output);
            hasher.reset();
        }

        // Step 6: Calculate Omega (Ω)
        // Back sweep over intermediate hashes in reverse order: Omega = HS(Y_L || ... || Y_1-L mod 2 XOR I)
        // Note: The specific back sweep formula described in the paper is approximated here by combining
        // path hashes in reverse order followed by an XORed hash of the initial path hash (Y0).

        // Combine all intermediate path hashes (h_L, h_{L-1}, ..., h_1) in reverse order
        for h in path.iter().skip(1).rev() {
            hasher.update(h);
        }

        // Element(0) - XOR of the initial path hash (h_0)
        {
            let first = path.first().unwrap();
            let mut element = Element::<S::SolverEndian>::from(*first);
            element ^= &challenge_element;
            hasher.update(&S::SolverEndian::simd_to_bytes(element.data).to_array());
        }

        hasher.finalize_xof().fill(&mut hash_output);
        hasher.reset();
        hash_output
    }

    /// Counts the number of leading zero bits in a byte array.
    #[inline]
    fn leading_zeros<const N: usize>(array: [u8; N]) -> usize {
        let mut counter = 0;
        for byte in array {
            if byte == 0 {
                counter += 8;
            } else {
                counter += byte.leading_zeros() as usize;
                break;
            }
        }
        counter
    }
}

#[cfg(test)]
mod tests;
