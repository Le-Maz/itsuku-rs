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

const MEMORY_COST_CX: f64 = 1.0;

pub struct MerkleTree<E: Endian> {
    config: Config,
    node_size: usize,
    nodes: Vec<u8>,
    _marker: PhantomData<E>,
}

impl<E: Endian> MerkleTree<E> {
    pub fn calculate_node_size(config: &Config) -> usize {
        let search_length = config.search_length as f64;
        let difficulty = config.difficulty_bits as f64;

        let log_operand = MEMORY_COST_CX * search_length + (search_length * 0.5).ceil();
        let log_value = (1.0 + log_operand).log2();
        ((difficulty + log_value + 6.0) * 0.125).ceil() as usize
    }

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

    #[inline]
    fn translate_index(&self, index: usize) -> Range<usize> {
        let start = index * self.node_size;
        let end = start + self.node_size;
        start..end
    }

    #[inline]
    pub fn get_node(&self, index: usize) -> Option<&[u8]> {
        let range = self.translate_index(index);
        self.nodes.get(range)
    }

    #[inline]
    pub fn get_node_mut(&mut self, index: usize) -> Option<&mut [u8]> {
        let range = self.translate_index(index);
        self.nodes.get_mut(range)
    }

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

    pub fn children_of(index: usize) -> (usize, usize) {
        let left_index = 2 * index + 1;
        let right_index = 2 * index + 2;
        (left_index, right_index)
    }

    pub fn compute_intermediate_nodes(&mut self, challenge_id: &ChallengeId) {
        let total_elements = self.config.chunk_count * self.config.chunk_size;

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
