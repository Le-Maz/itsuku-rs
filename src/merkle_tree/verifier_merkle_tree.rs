//! This module provides [`VerifierMerkleTree`], a structure that stores only the 
//! Merkle tree nodes necessary to verify a proof.

use std::{collections::HashMap, marker::PhantomData, ops::Range};
use crate::{endianness::Endian, merkle_tree::PartialMerkleTree};

/// A memory-efficient Merkle tree storage for the verifier.
/// 
/// Instead of storing a full tree, it stores a flat byte vector of revealed hashes 
/// and a mapping that points specific node indices to ranges within that vector.
pub struct VerifierMerkleTree<E: Endian> {
    /// Flat storage for all revealed node hashes.
    bytes: Vec<u8>,
    /// Maps a Merkle tree node index to its corresponding byte range in `bytes`.
    mapping: HashMap<usize, Range<usize>>,
    _marker: PhantomData<E>,
}

impl<E: Endian> Default for VerifierMerkleTree<E> {
    /// Creates an empty [`VerifierMerkleTree`].
    fn default() -> Self {
        Self {
            bytes: Default::default(),
            mapping: Default::default(),
            _marker: PhantomData,
        }
    }
}

impl<E: Endian> VerifierMerkleTree<E> {
    /// Inserts a revealed node hash into the partial tree.
    /// 
    /// This appends the `leaf_hash` to the internal buffer and records its location 
    /// associated with the `node_index`.
    pub fn insert(&mut self, node_index: usize, leaf_hash: bytes::Bytes) {
        let bytes_len = self.bytes.len();
        let range = bytes_len..(bytes_len + leaf_hash.len());
        self.bytes.extend_from_slice(&leaf_hash);
        self.mapping.insert(node_index, range);
    }

    /// Checks if a specific node index is present in the partial tree.
    pub fn contains_key(&self, node_index: usize) -> bool {
        self.mapping.contains_key(&node_index)
    }
}

impl<E: Endian> PartialMerkleTree<E> for VerifierMerkleTree<E> {
    /// Retrieves a reference to the hash of a node at a given index, if available.
    fn get_node(&self, index: usize) -> Option<&[u8]> {
        let range = self.mapping.get(&index)?.clone();
        self.bytes.get(range)
    }
}
