use std::{
    simd::ToBytes,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};

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

#[derive(Clone, Copy)]
struct SearchParams<'a> {
    config: Config,
    challenge_id: &'a ChallengeId,
    memory: &'a Memory,
    root_hash: &'a [u8],
}

impl Proof {
    pub fn search(
        config: Config,
        challenge_id: &ChallengeId,
        memory: &Memory,
        merkle_tree: &MerkleTree,
    ) -> Self {
        let root_hash = merkle_tree.get_node(0).unwrap().to_vec();

        let stop_flag = AtomicBool::new(false);
        let winner_nonce = AtomicU64::new(0);

        let threads = num_cpus::get();
        let chunk = u64::MAX / threads as u64;

        std::thread::scope(|scope| {
            for thread in 0..threads {
                let start = thread as u64 * chunk;
                let end = if thread == threads - 1 {
                    u64::MAX
                } else {
                    (thread as u64 + 1) * chunk
                };

                let root_hash = &root_hash;
                let stop_flag = &stop_flag;
                let winner_nonce = &winner_nonce;
                let params = SearchParams {
                    config,
                    challenge_id,
                    memory,
                    root_hash,
                };

                scope.spawn(move || {
                    Self::search_worker(params, start, end, stop_flag, winner_nonce)
                });
            }
        });
        Proof {
            nonce: winner_nonce.load(Ordering::Relaxed),
        }
    }

    fn search_worker(
        params: SearchParams,
        start: u64,
        end: u64,
        stop_flag: &AtomicBool,
        winner_nonce: &AtomicU64,
    ) {
        let mut hasher = Blake2b512::new();
        let mut path: Vec<[u8; 64]> = Vec::with_capacity(params.config.search_length + 1);
        let memory_size = (params.config.chunk_count * params.config.chunk_size) as u64;

        for nonce in start..=end {
            // If another thread found a solution, exit
            if stop_flag.load(Ordering::Relaxed) {
                return;
            }

            // ---- step 4 ----
            hasher.update(nonce.to_le_bytes());
            hasher.update(&params.root_hash);
            hasher.update(&params.challenge_id.bytes);
            path.push(hasher.finalize_reset().into());

            // ---- step 5 ----
            for _ in 1..=params.config.search_length {
                let prev_hash = path.last().unwrap();

                let index = u64::from_le_bytes(*prev_hash.first_chunk().unwrap()) % memory_size;

                let mut element = *params.memory.get(index as usize).unwrap();
                element ^= params.challenge_id.bytes.as_slice();

                hasher.update(prev_hash);
                hasher.update(element.data.to_le_bytes());
                path.push(hasher.finalize_reset().into());
            }

            // ---- step 6: omega ----
            // Combine path hashes
            for h in path.iter().skip(1).rev() {
                hasher.update(h);
            }

            {
                // element(0)
                let first = path.first().unwrap();
                let mut el = Element::from(*first);
                el ^= params.challenge_id.bytes.as_slice();
                hasher.update(el.data.to_le_bytes());
            }

            let omega: [u8; 64] = hasher.finalize_reset().into();

            if Self::leading_zeros(omega) >= params.config.difficulty_bits {
                winner_nonce.store(nonce, Ordering::SeqCst);
                stop_flag.store(true, Ordering::SeqCst);
                return;
            }

            path.clear();
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
