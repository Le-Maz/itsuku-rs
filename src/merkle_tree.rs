//! This module implements the Merkle Tree used to commit to the memory contents.
//!
//! The Merkle Tree serves as a cryptographic commitment to the entire memory array.
//! It allows the prover to demonstrate that they have correctly computed specific elements
//! without revealing the entire dataset.
//!
//! Unlike standard Merkle trees, the node size here is dynamic, calculated based on
//! security parameters to ensure a specific cost for time-memory trade-off attacks.

use std::{collections::BTreeMap, marker::PhantomData, ops::Range};

use blake2::{
    Blake2bVar,
    digest::{Update, VariableOutput},
};
use bytes::Bytes;

use crate::{
    challenge_id::ChallengeId,
    config::Config,
    endianness::Endian,
    memory::{Element, Memory},
};

/// A constant representing the computational cost multiplier for memory.
const MEMORY_COST_CX: f64 = 1.0;

/// A Merkle Tree implementation tailored for the Itsuku PoW scheme.
///
/// It stores the entire tree in a flat byte vector for efficiency.
/// The tree is a complete binary tree where leaves correspond to memory elements.
pub struct MerkleTree<E: Endian> {
    config: Config,
    /// The size of each node in bytes (dynamic based on config).
    node_size: usize,
    /// Flat storage for all tree nodes (leaves and intermediate nodes).
    nodes: Vec<u8>,
    _marker: PhantomData<E>,
}

impl<E: Endian> MerkleTree<E> {
    /// Calculates the required size (in bytes) for Merkle Tree nodes.
    ///
    /// The size is determined dynamically to ensure that the cost of storing the tree
    /// or recomputing nodes balances against the difficulty of the PoW.
    pub fn calculate_node_size(config: &Config) -> usize {
        let search_length = config.search_length as f64;
        let difficulty = config.difficulty_bits as f64;

        let log_operand = MEMORY_COST_CX * search_length + (search_length * 0.5).ceil();
        let log_value = (1.0 + log_operand).log2();
        ((difficulty + log_value + 6.0) * 0.125).ceil() as usize
    }

    /// Allocates a new, empty Merkle Tree based on the provided configuration.
    ///
    /// The total size is calculated to hold 2N - 1 nodes, where N is the number of memory elements.
    pub fn new(config: Config) -> Self {
        let node_size = Self::calculate_node_size(&config);

        let nodes_count = 2 * config.chunk_count * config.chunk_size - 1;
        let total_bytes = nodes_count * node_size;

        let nodes = vec![0u8; total_bytes];

        Self {
            config,
            node_size,
            nodes,
            _marker: PhantomData,
        }
    }

    /// Converts a node index into a byte range for the underlying flat storage.
    #[inline]
    fn translate_index(&self, index: usize) -> Range<usize> {
        let start = index * self.node_size;
        let end = start + self.node_size;
        start..end
    }

    /// Retrieves a reference to the node data at the specified index.
    #[inline]
    pub fn get_node(&self, index: usize) -> Option<&[u8]> {
        let range = self.translate_index(index);
        self.nodes.get(range)
    }

    /// Retrieves a mutable reference to the node data at the specified index.
    #[inline]
    pub fn get_node_mut(&mut self, index: usize) -> Option<&mut [u8]> {
        let range = self.translate_index(index);
        self.nodes.get_mut(range)
    }

    /// Computes the hash for a leaf node (a memory element).
    pub fn compute_leaf_hash(
        challenge_id: &ChallengeId,
        element: &Element<E>,
        node_size: usize,
        output: &mut [u8],
    ) {
        let mut hasher = Blake2bVar::new(node_size).unwrap();

        hasher.update(&E::simd_to_bytes(element.data).to_array());
        hasher.update(&challenge_id.bytes);

        hasher.finalize_variable(output).unwrap();
    }

    /// Populates all leaf nodes of the tree by hashing the elements of the Memory array.
    ///
    /// In the flat array representation, leaves are stored starting at index `total_elements - 1`.
    pub fn compute_leaf_hashes(&mut self, challenge_id: &ChallengeId, memory: &Memory<E>) {
        let element_count = self.config.chunk_count * self.config.chunk_size;
        let node_size = self.node_size;

        // Leaves start at index element_count - 1
        let first_leaf = element_count - 1;

        for i in 0..element_count {
            let node_index = first_leaf + i;
            let element = memory.get(i).unwrap();
            let node = self.get_node_mut(node_index).unwrap();
            Self::compute_leaf_hash(challenge_id, element, node_size, node);
        }
    }

    /// Creates a closure to compute the hash of an intermediate node.
    ///
    /// This function returns a closure to allow the caller to handle the output buffer
    /// (e.g., writing directly into the tree storage).
    pub fn compute_intermediate_hash(
        challenge_id: &ChallengeId,
        left: &[u8],
        right: &[u8],
        node_size: usize,
    ) -> impl FnOnce(&mut [u8]) + use<E> {
        let mut hasher = Blake2bVar::new(node_size).unwrap();

        hasher.update(left);
        hasher.update(right);
        hasher.update(&challenge_id.bytes);

        |output| hasher.finalize_variable(output).unwrap()
    }

    /// Returns the indices of the left and right children for a given parent index.
    pub fn children_of(index: usize) -> (usize, usize) {
        let left_index = 2 * index + 1;
        let right_index = 2 * index + 2;
        (left_index, right_index)
    }

    /// Computes all intermediate nodes up to the root.
    ///
    /// This function iterates backwards from the last non-leaf node to the root (index 0),
    /// hashing the children to produce the parent. `compute_leaf_hashes` must be called first.
    pub fn compute_intermediate_nodes(&mut self, challenge_id: &ChallengeId) {
        let total_elements = self.config.chunk_count * self.config.chunk_size;

        // Iterate in reverse from the last parent node down to the root
        for parent_index in (0..total_elements - 1).rev() {
            let (left_index, right_index) = Self::children_of(parent_index);

            let left_node = self.get_node(left_index).unwrap();
            let right_node = self.get_node(right_index).unwrap();

            let compute_hash = Self::compute_intermediate_hash(
                challenge_id,
                left_node,
                right_node,
                self.node_size,
            );

            let parent_node = self.get_node_mut(parent_index).unwrap();
            compute_hash(parent_node);
        }
    }

    /// Traces the Merkle path (authentication path) for a given node index.
    ///
    /// This function collects the node itself, its sibling, and recursively the siblings
    /// of all ancestors up to the root. This set of nodes allows a verifier to reconstruct
    /// the root hash starting from the leaf.
    pub fn trace_node(&self, index: usize, nodes: &mut BTreeMap<usize, Bytes>) {
        if let Some(node) = self.get_node(index) {
            nodes.insert(index, Bytes::copy_from_slice(node));
        }
        if index == 0 {
            return;
        }

        let sibling_index = if index.is_multiple_of(2) {
            index - 1
        } else {
            index + 1
        };
        if let Some(node) = self.get_node(sibling_index) {
            nodes.insert(sibling_index, Bytes::copy_from_slice(node));
        }

        let parent_index = (index - 1) / 2;
        Self::trace_node(self, parent_index, nodes);
    }
}

#[cfg(test)]
mod tests;
