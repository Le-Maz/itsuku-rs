use std::{
    collections::BTreeMap,
    fmt::{Display, Formatter},
    simd::ToBytes,
    sync::OnceLock,
};

use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use blake2::{Blake2b512, Digest};
use bytes::Bytes;

use crate::{
    challenge_id::ChallengeId,
    config::Config,
    memory::{Element, Memory},
    merkle_tree::MerkleTree,
};

#[derive(Debug)]
pub struct Proof {
    nonce: u64,
    leaf_antecedents: BTreeMap<usize, Vec<Element>>,
    tree_opening: BTreeMap<usize, Bytes>,
}

impl Display for Proof {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "(proof")?;

        // nonce
        writeln!(f, "  (nonce {})", self.nonce)?;

        // leaf antecedents
        writeln!(f, "  (leaf_antecedents")?;
        for (leaf_idx, elems) in &self.leaf_antecedents {
            write!(f, "    ({leaf_idx} (")?;
            for elem in elems {
                write!(f, "\"{}\" ", elem.to_base64())?;
            }
            writeln!(f, "))")?;
        }
        writeln!(f, "  )")?;

        // tree opening
        writeln!(f, "  (tree_opening")?;
        for (node_idx, bytes) in &self.tree_opening {
            let b64 = BASE64_URL_SAFE_NO_PAD.encode(bytes);
            writeln!(f, "    ({node_idx} \"{b64}\")")?;
        }
        writeln!(f, "  )")?;

        write!(f, ")")
    }
}

#[derive(Clone, Copy)]
struct SearchParams<'a> {
    config: Config,
    challenge_id: &'a ChallengeId,
    memory: &'a Memory,
    merkle_tree: &'a MerkleTree,
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

        let proof_slot = OnceLock::new();

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
                let proof_slot = &proof_slot;
                let params = SearchParams {
                    config,
                    challenge_id,
                    memory,
                    merkle_tree,
                    root_hash,
                };

                scope.spawn(move || Self::search_worker(params, start, end, proof_slot));
            }
        });
        proof_slot.into_inner().unwrap()
    }

    fn search_worker(params: SearchParams, start: u64, end: u64, proof_slot: &OnceLock<Proof>) {
        let mut hasher = Blake2b512::new();
        let mut selected_leaves = Vec::with_capacity(params.config.search_length);
        let mut path: Vec<[u8; 64]> = Vec::with_capacity(params.config.search_length + 1);
        let memory_size = params.config.chunk_count * params.config.chunk_size;

        for nonce in start..=end {
            // If another thread found a solution, exit
            if proof_slot.get().is_some() {
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

                // Might need to be replaced with modulo of the whole hash
                let index =
                    (u64::from_le_bytes(*prev_hash.first_chunk().unwrap()) as usize) % memory_size;
                selected_leaves.push(index);

                let mut element = *params.memory.get(index).unwrap();
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

            // ---- step 7: check difficulty ----
            if Self::leading_zeros(omega) < params.config.difficulty_bits {
                selected_leaves.clear();
                path.clear();
                continue;
            }

            // ---- step 8: construct proof ----
            let mut tree_opening = BTreeMap::new();
            let mut leaf_antecedents = BTreeMap::new();
            for &leaf_index in &selected_leaves {
                let node_index = memory_size + leaf_index;
                leaf_antecedents.insert(leaf_index, params.memory.trace_element(leaf_index));
                params.merkle_tree.trace_node(node_index, &mut tree_opening);
            }
            let proof = Proof {
                nonce,
                leaf_antecedents,
                tree_opening,
            };
            proof_slot.set(proof).ok();
            return;
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
        config.chunk_size = 64;
        config.difficulty_bits = 8;

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
        println!("{}", proof);
    }
}
