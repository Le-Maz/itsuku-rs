//! This module implements the [`Proof::verify`] function for the Itsuku PoW scheme.
//!
//! Verification allows us to confirm a proof's validity using only a
//! fraction of the memory (partial memory) and the Merkle path (opening)
//! provided in the proof object.

use std::collections::BTreeMap;

use crate::endianness::{BigEndian, Endian, EndiannessTag, LittleEndian, NativeEndian};
use crate::memory::Element;
use crate::memory::{Memory, verifier_memory::VerifierMemory};
use crate::merkle_tree::verifier_merkle_tree::VerifierMerkleTree;
use crate::merkle_tree::{MerkleTree, PartialMerkleTree};
use crate::proof::Proof;
use crate::proof::error::VerificationError;
use crate::proof::search_params::VerifierSearchParams;
use blake3::Hasher;
use bytes::Bytes;

impl Proof {
    /// Validates the proof against the challenge and protocol configuration.
    ///
    /// Returns `Ok(())` if the nonce, memory elements, and Merkle path are
    /// cryptographically sound and meet the difficulty target.
    pub fn verify(&self) -> Result<(), VerificationError> {
        match self.endianness {
            EndiannessTag::Little => self.verify_inner::<LittleEndian>(),
            EndiannessTag::Big => self.verify_inner::<BigEndian>(),
        }
    }

    /// Internal verification logic specialized by endianness.
    pub(crate) fn verify_inner<E: Endian>(&self) -> Result<(), VerificationError> {
        let config = &self.config;
        let challenge_id = &self.challenge_id;
        let challenge_element = challenge_id.bytes.into();
        let node_size = MerkleTree::<E>::calculate_node_size(config);
        let memory_size = config.chunk_count * config.chunk_size;

        // Transmute stored antecedents back to the specific Endian type E.
        let leaf_antecedents: &BTreeMap<usize, Vec<Element<E>>> = unsafe {
            std::mem::transmute::<
                &BTreeMap<usize, Vec<Element<NativeEndian>>>,
                &BTreeMap<usize, Vec<Element<E>>>,
            >(&self.leaf_antecedents)
        };

        // Step 1: Reconstruct required memory elements
        // We only rebuild the parts of memory needed to verify the specific leaves touched by the proof path.
        let mut partial_memory = VerifierMemory::default();
        for (index, antacedents) in leaf_antecedents.iter() {
            match antacedents.len() {
                1 => {
                    // Base element (chunk 0) is provided directly
                    partial_memory.insert(*index, antacedents[0]);
                }
                n if n == config.antecedent_count => {
                    // Compressed element (chunk > 0) is recomputed from its antecedents
                    let element = Memory::compress(antacedents, *index as u64, &challenge_element);
                    partial_memory.insert(*index, element);
                }
                n => {
                    // Invalid antecedent count
                    return Err(VerificationError::InvalidAntecedentCount(n));
                }
            }
        }

        // Step 2: Rebuild Merkle path and verify against tree opening (Z)
        let mut merkle_nodes = VerifierMerkleTree::default(); // Stores verified/provided hashes

        // A. Verify the hashes of the selected leaves X[i_j]
        for (leaf_index, element) in partial_memory.iter() {
            let node_index = memory_size - 1 + leaf_index;
            let mut leaf_hash = vec![0u8; node_size];

            // Compute leaf hash: H_M^I(e)=H_M(e||I)
            MerkleTree::compute_leaf_hash(challenge_id, element, &mut leaf_hash);

            // Check if the computed leaf hash matches the provided opening hash
            let Some(opened_hash) = self.tree_opening.get(&node_index) else {
                return Err(VerificationError::MissingOpeningForLeaf(*leaf_index));
            };
            if opened_hash.as_ref() != leaf_hash.as_slice() {
                return Err(VerificationError::LeafHashMismatch(*leaf_index));
            }
            // Store the verified leaf hash
            merkle_nodes.insert(node_index, Bytes::from(leaf_hash));
        }

        // B. Rebuild and verify intermediate nodes up to the root (Phi)
        for (&node_index, opened_hash) in self.tree_opening.iter().rev() {
            if merkle_nodes.contains_key(node_index) {
                continue; // Leaf already verified in step A
            }

            let (left_index, right_index) = MerkleTree::<E>::children_of(node_index);

            // Attempt to get children from verified/stored nodes OR from the opening itself
            let left_child = merkle_nodes.get_node(left_index).or_else(|| {
                self.tree_opening
                    .get(&left_index)
                    .map(|bytes| bytes.as_ref())
            });
            let right_child = merkle_nodes.get_node(right_index).or_else(|| {
                self.tree_opening
                    .get(&right_index)
                    .map(|bytes| bytes.as_ref())
            });

            if left_child.is_none() && right_child.is_none() {
                // This node is not a parent of any verified leaf and is not part of the path from a verified leaf to the root.
                // We simply store the provided hash for potential future use (e.g., if it's a root/partial tree node)
                merkle_nodes.insert(node_index, opened_hash.clone());
                continue;
            }

            // At least one child is present, so we must be able to verify this parent hash.
            let Some(left_child) = left_child else {
                return Err(VerificationError::MissingChildNode(left_index));
            };
            let Some(right_child) = right_child else {
                return Err(VerificationError::MissingChildNode(right_index));
            };

            // Compute intermediate hash: B[i]=H_M^I(B[2i+1]||B[2i+2])
            let compute_hash =
                MerkleTree::<E>::compute_intermediate_hash(challenge_id, left_child, right_child);
            let mut computed_hash = vec![0u8; node_size];
            compute_hash(&mut computed_hash);

            // Check if the computed intermediate hash matches the opened hash
            if computed_hash.as_slice() != opened_hash.as_ref() {
                return Err(VerificationError::IntermediateHashMismatch(node_index));
            }
            // Store the verified intermediate hash
            merkle_nodes.insert(node_index, opened_hash.clone());
        }

        // Final check: The root hash (Phi) must be present
        let Some(root_hash) = merkle_nodes.get_node(0) else {
            return Err(VerificationError::MissingMerkleRoot);
        };

        // Step 3: Verify Omega hash
        let mut hasher = Hasher::new();
        let mut path: Vec<[u8; 64]> = Vec::with_capacity(config.search_length + 1);
        let mut selected_leaves = Vec::with_capacity(config.search_length);

        // Recalculate Omega using the partial data and the discovered root hash.
        let omega = Self::calculate_omega(
            &VerifierSearchParams {
                config,
                challenge_id,
                // Use the reconstructed memory and verified Merkle nodes as partial data sources
                memory: &partial_memory,
                merkle_tree: &merkle_nodes,
            },
            root_hash.as_ref(),
            &mut hasher,
            &mut selected_leaves,
            &mut path,
            memory_size,
            self.nonce,
        );

        // Check 3.1: Ensure the recalculated path matches the leaves provided in the proof
        // We check if *any* of the selected leaves is NOT present in the proven antecedents.
        if selected_leaves
            .iter()
            .any(|leaf| !self.leaf_antecedents.contains_key(leaf))
        {
            return Err(VerificationError::UnprovenLeafInPath);
        }

        // Check 3.2: Check difficulty (d)
        if Self::leading_zeros(omega) < config.difficulty_bits {
            return Err(VerificationError::DifficultyNotMet);
        }

        // If all checks pass, the proof is valid.
        Ok(())
    }
}
