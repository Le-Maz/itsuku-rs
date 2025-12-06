use std::{ops::Range, simd::ToBytes};

use blake2::{
    Blake2bVar,
    digest::{Update, VariableOutput},
};

use crate::{challenge_id::ChallengeId, config::Config, memory::Memory};

const MEMORY_COST_CX: f64 = 1.0;
const NODES_PER_FRAGMENT: usize = 1024;

pub struct MerkleTree {
    config: Config,
    node_size: usize,
    fragments: Vec<Vec<u8>>,
}

impl MerkleTree {
    fn calculate_node_size(config: &Config) -> usize {
        let search_length = config.search_length as f64;
        let difficulty = config.difficulty_bits as f64;

        let log_operand = MEMORY_COST_CX * search_length + (search_length * 0.5).ceil();
        let log_value = (1.0 + log_operand).log2();
        ((difficulty + log_value + 6.0) * 0.125).ceil() as usize
    }

    pub fn new(config: Config) -> Self {
        let node_size = Self::calculate_node_size(&config);
        let nodes_count = 2 * config.chunk_count * config.chunk_size - 1;
        let fragments_count = nodes_count.div_ceil(NODES_PER_FRAGMENT);

        let mut fragments = Vec::with_capacity(fragments_count);
        for _ in 0..fragments_count {
            let fragment = vec![0; node_size * NODES_PER_FRAGMENT];
            fragments.push(fragment);
        }

        Self {
            config,
            node_size,
            fragments,
        }
    }

    #[inline]
    fn translate_index(&self, index: usize) -> (usize, Range<usize>) {
        let fragment = index / NODES_PER_FRAGMENT;
        let start = (index % NODES_PER_FRAGMENT) * self.node_size;
        let end = start + self.node_size;
        (fragment, start..end)
    }

    #[inline]
    pub fn get_node(&self, index: usize) -> Option<&[u8]> {
        let (fragment, range) = self.translate_index(index);
        self.fragments.get(fragment)?.get(range)
    }

    #[inline]
    pub fn get_node_mut(&mut self, index: usize) -> Option<&mut [u8]> {
        let (fragment, range) = self.translate_index(index);
        self.fragments.get_mut(fragment)?.get_mut(range)
    }

    pub fn compute_leaf_hashes(&mut self, challenge_id: &ChallengeId, memory: &Memory) {
        let element_count = self.config.chunk_count * self.config.chunk_size;

        for element_index in 0..element_count {
            let mut hasher = Blake2bVar::new(self.node_size).unwrap();
            let element = memory.get(element_index).unwrap();
            hasher.update(&element.data.to_le_bytes().to_array());
            hasher.update(challenge_id.bytes.as_slice());

            let node_index = element_index + element_count - 1;
            let node = self.get_node_mut(node_index).unwrap();
            hasher.finalize_variable(node).unwrap();
        }
    }

    pub fn compute_intermediate_nodes(&mut self, challenge_id: &ChallengeId) {
        let total_elements = self.config.chunk_count * self.config.chunk_size;

        for parent_index in (0..total_elements - 1).rev() {
            let mut hasher = Blake2bVar::new(self.node_size).unwrap();
            let left = self.get_node(2 * parent_index + 1).unwrap();
            let right = self.get_node(2 * parent_index + 2).unwrap();

            hasher.update(left);
            hasher.update(right);
            hasher.update(&challenge_id.bytes);

            let parent_node = self.get_node_mut(parent_index).unwrap();
            hasher.finalize_variable(parent_node).unwrap();
        }
    }
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use super::*;
    use crate::{challenge_id::ChallengeId, config::Config, memory::Memory};

    const EXPECTED_ROOT_HASH: &[u8] = &hex!("681965c4ab"); // from C output

    fn build_test_challenge() -> ChallengeId {
        let mut bytes = [0u8; 64];
        for i in 0..64 {
            bytes[i] = i as u8;
        }
        ChallengeId {
            bytes: bytes.to_vec(),
        }
    }

    #[test]
    fn rust_merkle_root_matches_c() {
        // 1) Create config matching C test
        let mut config = Config::default();
        config.chunk_count = 2;
        config.chunk_size = 8;

        let challenge_id = build_test_challenge();

        // 2) Build memory
        let mut memory = Memory::new(config);
        memory.build_all_chunks(&challenge_id);

        // 3) Build Merkle tree
        let mut tree = MerkleTree::new(config);

        // Compute leaf hashes and intermediate nodes
        tree.compute_leaf_hashes(&challenge_id, &memory);
        tree.compute_intermediate_nodes(&challenge_id);
        for i in 0..tree.config.chunk_count * tree.config.chunk_size * 2 - 1 {
            println!("Node [{}]: {:02x?}", i, tree.get_node(i).unwrap());
        }

        // 4) Get root hash
        let root_hash = tree.get_node(0).unwrap();

        // 5) Compare with C output (only first 5 bytes)
        assert_eq!(&root_hash[..5], EXPECTED_ROOT_HASH);
    }
}
