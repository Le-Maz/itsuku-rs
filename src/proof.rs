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

use std::{
    collections::{BTreeMap, HashMap},
    marker::PhantomData,
    sync::OnceLock,
};

use blake3::Hasher;
use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::{
    challenge_id::ChallengeId,
    config::Config,
    endianness::{BigEndian, Endian, EndiannessTag, LittleEndian, NativeEndian},
    memory::{Element, Memory, PartialMemory},
    merkle_tree::{MerkleTree, PartialMerkleTree},
    proof::error::VerificationError,
};

pub mod error;

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

/// Helper struct to pass immutable search parameters to workers.
///
/// This abstracts over the concrete implementations of memory and Merkle tree access,
/// allowing the core logic to work with both full datasets (during search) and partial/reconstructed
/// datasets (during verification).
#[derive(Clone, Copy)]
struct SearchParams<
    'a,
    E: Endian,
    MemoryType: PartialMemory<E>,
    MerkleTreeType: PartialMerkleTree<E>,
> {
    config: Config,
    challenge_id: &'a ChallengeId,
    challenge_element: &'a Element<E>,
    memory: &'a MemoryType,
    merkle_tree: &'a MerkleTreeType,
    root_hash: &'a [u8],
    _marker: PhantomData<E>,
}

impl Proof {
    /// Initiates a multi-threaded nonce search for a valid proof that meets the difficulty requirement.
    ///
    /// The search iterates over nonces, calculating an Omega hash for each, until one
    /// satisfies the configured number of leading zero bits (d).
    /// The parallel implementation uses threading to allow available computing power to
    /// contribute easily to the search.
    ///
    /// ## Arguments
    /// * `config`: The PoW configuration.
    /// * `challenge_id`: The challenge identifier (I).
    /// * `memory`: The pre-computed memory array (X).
    /// * `merkle_tree`: The Merkle tree built over the memory.
    ///
    /// ## Returns
    /// The first valid `Proof` found.
    pub fn search<E: Endian>(
        config: Config,
        challenge_id: &ChallengeId,
        memory: &Memory<E>,
        merkle_tree: &MerkleTree<E>,
    ) -> Self {
        let root_hash = merkle_tree.get_node(0).unwrap().to_vec();

        // Used to safely store the first proof found by any thread.
        let proof_slot = OnceLock::new();

        let threads = num_cpus::get();
        // Divide the full u64::MAX range into chunks for each thread.
        let chunk = u64::MAX / threads as u64;
        let challenge_element = challenge_id.bytes.into();

        std::thread::scope(|scope| {
            for thread in 0..threads {
                let start = thread as u64 * chunk;
                let end = if thread == threads - 1 {
                    u64::MAX // Last thread takes the remainder
                } else {
                    (thread as u64 + 1) * chunk - 1
                };

                // Create shared/borrowed references for the parameters
                let root_hash = &root_hash;
                let proof_slot = &proof_slot;
                let params = SearchParams {
                    config,
                    challenge_id,
                    challenge_element: &challenge_element,
                    memory,
                    merkle_tree,
                    root_hash,
                    _marker: PhantomData::<E>,
                };

                scope.spawn(move || Self::search_worker(params, start, end, proof_slot));
            }
        });

        proof_slot
            .into_inner()
            .expect("Proof search failed to find a solution.")
    }

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
    fn calculate_omega<E: Endian>(
        params: &SearchParams<'_, E, impl PartialMemory<E>, impl PartialMerkleTree<E>>,
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
        hasher.update(&E::u64_to_bytes(nonce));
        hasher.update(params.root_hash);
        hasher.update(&params.challenge_id.bytes);
        hasher.finalize_xof().fill(&mut hash_output);
        path.push(hash_output);
        hasher.reset();

        // Step 5: Iterative hash chain (1 <= j <= L)
        for _ in 1..=params.config.search_length {
            let prev_hash = path.last().unwrap();

            // Determine the next memory element index: i_j-1 = Y_j-1 mod T
            let index =
                (E::u64_from_bytes(prev_hash.first_chunk().unwrap()) as usize) % memory_size;
            selected_leaves.push(index);

            // Fetch the element, XOR it with the challenge_id for anti-precomputation
            // Itsuku uses X_I[i_j-1] XOR I
            let mut element = params
                .memory
                .get_element(index)
                .expect("Required element must exist");
            element ^= params.challenge_element;

            // Calculate the next path hash (Yj): Yj = HS(Y_j-1 || X_I[i_j-1] XOR I)
            hasher.update(prev_hash);
            hasher.update(E::simd_to_bytes(element.data).as_array());

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
            let mut element = Element::<E>::from(*first);
            element ^= params.challenge_element;
            hasher.update(&E::simd_to_bytes(element.data).to_array());
        }

        hasher.finalize_xof().fill(&mut hash_output);
        hasher.reset();
        hash_output
    }

    /// The worker function executed by each thread to search a range of nonces.
    fn search_worker<E: Endian>(
        params: SearchParams<E, Memory<E>, MerkleTree<E>>,
        start: u64,
        end: u64,
        proof_slot: &OnceLock<Proof>,
    ) {
        let mut hasher = Hasher::new();
        let mut selected_leaves = Vec::with_capacity(params.config.search_length);
        // Path length is L (search_length) + 1 (for Y0)
        let mut path: Vec<[u8; 64]> = Vec::with_capacity(params.config.search_length + 1);
        let memory_size = params.config.chunk_count * params.config.chunk_size;

        for nonce in start..=end {
            // Check if another thread has already found and set a solution
            if proof_slot.get().is_some() {
                return;
            }

            let omega = Self::calculate_omega::<E>(
                &params,
                &mut hasher,
                &mut selected_leaves,
                &mut path,
                memory_size,
                nonce,
            );

            // Step 7: Check difficulty
            // If Omega has at least **d** leading binary zeros, the PoW search ends (Section 4).
            if Self::leading_zeros(omega) < params.config.difficulty_bits {
                // Not enough leading zeros, try next nonce
                continue;
            }

            // Step 8: Construct and store the proof
            let mut tree_opening = BTreeMap::new();
            let mut leaf_antecedents = BTreeMap::new();
            for &leaf_index in &selected_leaves {
                let node_index = memory_size - 1 + leaf_index;
                // Collect one-level antecedents of the needed array elements
                let antecedents = params.memory.trace_element(leaf_index);
                // Convert to NativeEndian for storage (Element data layout is identical)
                // This unsafe cast is valid because Element is repr(transparent) over Simd<u64>
                // and PhantomData is zero-sized.
                let stored_antecedents = unsafe {
                    std::mem::transmute::<Vec<Element<E>>, Vec<Element<NativeEndian>>>(antecedents)
                };
                leaf_antecedents.insert(leaf_index, stored_antecedents);

                // Collect all Merkle tree nodes needed for the opening path
                params.merkle_tree.trace_node(node_index, &mut tree_opening);
            }

            let proof = Proof {
                config: params.config,
                challenge_id: params.challenge_id.clone(),
                nonce,
                leaf_antecedents,
                tree_opening,
                endianness: E::kind(),
            };

            // Attempt to set the proof. Only the first successful call will succeed.
            proof_slot.set(proof).ok();
            return;
        }
    }

    /// Counts the number of leading zero bits in a byte array.
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

    /// Verifies the PoW proof against the challenge (I) and configuration.
    ///
    /// This method switches based on the proof's `endianness` tag to invoke the
    /// correct verification logic (`verify_inner`), ensuring that proofs generated
    /// on Big Endian systems can be verified on Little Endian systems and vice versa.
    ///
    /// ## Returns
    /// `Ok(())` if the proof is valid, or a `VerificationError` otherwise.
    pub fn verify(&self) -> Result<(), VerificationError> {
        match self.endianness {
            EndiannessTag::Little => self.verify_inner::<LittleEndian>(),
            EndiannessTag::Big => self.verify_inner::<BigEndian>(),
        }
    }

    /// The generic verification logic parameterized by the solver's Endianness `E`.
    fn verify_inner<E: Endian>(&self) -> Result<(), VerificationError> {
        let config = &self.config;
        let challenge_id = &self.challenge_id;
        let challenge_element = challenge_id.bytes.into();
        let node_size = MerkleTree::<E>::calculate_node_size(config);
        let memory_size = config.chunk_count * config.chunk_size;

        // Transmute stored antecedents back to the specific Endian type E.
        let leaf_antecedents = unsafe {
            std::mem::transmute::<
                &BTreeMap<usize, Vec<Element<NativeEndian>>>,
                &BTreeMap<usize, Vec<Element<E>>>,
            >(&self.leaf_antecedents)
        };

        // Step 1: Reconstruct required memory elements
        // We only rebuild the parts of memory needed to verify the specific leaves touched by the proof path.
        let mut partial_memory = HashMap::new();
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
        let mut merkle_nodes = HashMap::new(); // Stores verified/provided hashes

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
            if merkle_nodes.contains_key(&node_index) {
                continue; // Leaf already verified in step A
            }

            let (left_index, right_index) = MerkleTree::<E>::children_of(node_index);

            // Attempt to get children from verified/stored nodes OR from the opening itself
            let left_child = merkle_nodes
                .get(&left_index)
                .or_else(|| self.tree_opening.get(&left_index));
            let right_child = merkle_nodes
                .get(&right_index)
                .or_else(|| self.tree_opening.get(&right_index));

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
        let Some(root_hash) = merkle_nodes.get(&0) else {
            return Err(VerificationError::MissingMerkleRoot);
        };

        // Step 3: Verify Omega hash
        let mut hasher = Hasher::new();
        let mut path: Vec<[u8; 64]> = Vec::with_capacity(config.search_length + 1);
        let mut selected_leaves = Vec::with_capacity(config.search_length);

        // Recalculate Omega using the partial data and the discovered root hash.
        let omega = Self::calculate_omega::<E>(
            &SearchParams {
                config: *config,
                challenge_id,
                challenge_element: &challenge_id.bytes.into(),
                // Use the reconstructed memory and verified Merkle nodes as partial data sources
                memory: &partial_memory,
                merkle_tree: &merkle_nodes,
                root_hash: root_hash.as_ref(),
                _marker: PhantomData::<E>,
            },
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

#[cfg(test)]
mod tests;
