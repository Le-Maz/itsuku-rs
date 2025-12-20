//! This module implements the [`Proof::search`] function for the Itsuku PoW scheme.
//!
//! The solving process involves a multi-threaded search for a nonce N that,
//! when combined with the memory commitment and challenge ID, satisfies the
//! network difficulty requirements through a specific hash chain.

use crate::proof::Proof;
use crate::proof::search_params::SolverSearchParams;
use blake3::Hasher;
use std::collections::BTreeMap;
use std::hint::unlikely;
use std::sync::OnceLock;

impl Proof {
    /// Initiates a multi-threaded search for a valid nonce.
    ///
    /// Iterates over nonces until one produces an Omega hash with at least d
    /// leading zeros, as defined in the configuration.
    pub fn search<>(params: SolverSearchParams) -> Self {
        let root_hash = params.merkle_tree.get_node(0).unwrap().to_vec();
        let proof_slot = OnceLock::new();
        let threads = crate::NUM_CPUS.min(params.config.jobs);
        let chunk = u64::MAX / threads as u64;
        let root_hash_ref = &root_hash;

        if threads <= 1 {
            Self::search_worker(&params, root_hash_ref, 0, u64::MAX, &proof_slot);
            return proof_slot.into_inner().expect("Search failed");
        }

        std::thread::scope(|scope| {
            for thread in 0..threads {
                let start = thread as u64 * chunk;
                let end = if thread == threads - 1 {
                    u64::MAX
                } else {
                    (thread as u64 + 1) * chunk - 1
                };
                let proof_slot_ref = &proof_slot;

                scope.spawn(move || {
                    Self::search_worker(&params, root_hash_ref, start, end, proof_slot_ref)
                });
            }
        });

        proof_slot.into_inner().expect("Search failed")
    }

    /// The core worker function for nonce searching within a specific range.
    fn search_worker<>(
        params: &SolverSearchParams,
        root_hash: &[u8],
        start: u64,
        end: u64,
        proof_slot: &OnceLock<Proof>,
    ) {
        let mut hasher = Hasher::new();
        let mut selected_leaves = Vec::with_capacity(params.config.search_length);
        let mut path = Vec::with_capacity(params.config.search_length + 1);
        let memory_size = params.config.chunk_count * params.config.chunk_size;

        for nonce in start..=end {
            if unlikely(proof_slot.get().is_some()) {
                return;
            }

            let omega = Self::calculate_omega(
                params,
                root_hash,
                &mut hasher,
                &mut selected_leaves,
                &mut path,
                memory_size,
                nonce,
            );

            if unlikely(Self::leading_zeros(omega) < params.config.difficulty_bits) {
                continue;
            }

            // Construction of Merkle opening and antecedents
            let mut tree_opening = BTreeMap::new();
            let mut leaf_antecedents = BTreeMap::new();
            for &leaf_index in &selected_leaves {
                let node_index = memory_size - 1 + leaf_index;
                leaf_antecedents.insert(leaf_index, params.memory.trace_element(leaf_index));
                params.merkle_tree.trace_node(node_index, &mut tree_opening);
            }

            let proof = Proof {
                config: *params.config,
                challenge_id: params.challenge_id.clone(),
                nonce,
                leaf_antecedents,
                tree_opening,
            };

            proof_slot.set(proof).ok();
            return;
        }
    }
}
