use std::simd::ToBytes;

use blake2::{Blake2b512, Digest};

use crate::{
    challenge_id::ChallengeId,
    config::Config,
    memory::{Element, Memory},
    merkle_tree::MerkleTree,
};

#[derive(Debug)]
pub struct Proof {
    nonce: u64,
}

impl Proof {
    pub fn search(
        config: Config,
        challenge_id: &ChallengeId,
        memory: &Memory,
        merkle_tree: &MerkleTree,
    ) -> Self {
        let root_hash = merkle_tree.get_node(0).unwrap().to_vec();
        let memory_size = (config.chunk_count * config.chunk_size) as u64;
        let mut path: Vec<[u8; 64]> = Vec::with_capacity(config.search_length + 1);
        let mut hasher = Blake2b512::new();

        // Step 3 - init
        let mut nonce: u64 = 0;
        loop {
            // Step 4
            {
                hasher.update(nonce.to_le_bytes());
                hasher.update(root_hash.as_slice());
                hasher.update(challenge_id.bytes.as_slice());
                path.push(hasher.finalize_reset().into());
            }

            // Step 5
            for _ in 1..=config.search_length {
                let prev_hash = path.last().unwrap();
                let index = u64::from_le_bytes(*prev_hash.first_chunk().unwrap()) % memory_size;
                let mut element = *memory.get(index as usize).unwrap();
                element ^= challenge_id.bytes.as_slice();

                hasher.update(prev_hash);
                hasher.update(element.data.to_le_bytes());
                path.push(hasher.finalize_reset().into());
            }

            // Step 6
            for hash in path.iter().skip(1).rev() {
                hasher.update(hash);
            }
            {
                let hash = path.first().unwrap();
                let mut element = Element::from(*hash);
                element ^= challenge_id.bytes.as_slice();
                hasher.update(element.data.to_le_bytes());
            }
            let omega_hash = hasher.finalize_reset().into();

            // Step 7
            if Self::leading_zeros(omega_hash) >= config.difficulty_bits {
                return Self { nonce };
            }

            path.clear();
            // Step 3 - loop
            nonce += 1;
        }
    }

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

    pub fn nonce(&self) -> u64 {
        self.nonce
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        challenge_id::ChallengeId, config::Config, memory::Memory, merkle_tree::MerkleTree,
        proof::Proof,
    };

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
    fn solves() {
        // 1) Create config matching C test
        let mut config = Config::default();
        config.chunk_count = 16;
        config.chunk_size = 128;
        config.difficulty_bits = 16;

        let challenge_id = build_test_challenge();

        // 2) Build memory
        let mut memory = Memory::new(config);
        memory.build_all_chunks(&challenge_id);

        // 3) Build Merkle tree
        let mut merkle_tree = MerkleTree::new(config);

        // Compute leaf hashes and intermediate nodes
        merkle_tree.compute_leaf_hashes(&challenge_id, &memory);
        merkle_tree.compute_intermediate_nodes(&challenge_id);

        let proof = Proof::search(config, &challenge_id, &memory, &merkle_tree);
        println!("{:#?}", proof);
    }
}
