use std::{
    collections::{BTreeMap, HashMap},
    fmt::{Display, Formatter},
    simd::ToBytes,
    sync::OnceLock,
};

use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use blake2::{Blake2b512, Digest};
use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::{
    challenge_id::ChallengeId,
    config::Config,
    memory::{Element, Memory},
    merkle_tree::MerkleTree,
};

/// A cryptographic **Proof-of-Work (PoW)** solution for the Itsuku scheme.
///
/// A `Proof` consists of a successful nonce, a set of leaf antecedents
/// required to reconstruct the memory elements for the path, and the
/// Merkle tree opening (hashes) needed to verify the selected leaves. The proof
/// size is typically small (around 11 KiB for Itsuku's preferred parameters, Section 4).
#[derive(Debug, Serialize, Deserialize)]
pub struct Proof {
    /// Configuration of the algorithm's parameters
    config: Config,
    /// Challenge identifier (I)
    challenge_id: ChallengeId,
    /// The nonce (N) that satisfied the difficulty (d) requirement.
    nonce: u64,
    /// A map from leaf index to the list of `Element`s required to compute
    /// the leaf's memory value (its antecedents).
    leaf_antecedents: BTreeMap<usize, Vec<Element>>,
    /// A map from Merkle node index to its hash, providing the collective opening
    /// (Z) (Merkle tree proof) of the selected leaves and their antecedents.
    tree_opening: BTreeMap<usize, Bytes>,
}

impl Display for Proof {
    /// Formats the Proof into an S-expression-like string for human-readable
    /// or simple serialization output.
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "(proof")?;

        // nonce
        writeln!(f, "  (nonce {})", self.nonce)?;

        // leaf antecedents
        writeln!(f, "  (leaf_antecedents")?;
        for (leaf_idx, elems) in &self.leaf_antecedents {
            // Write elements as Base64-encoded strings
            write!(f, "    ({leaf_idx} (")?;
            for elem in elems {
                // Assuming Element has a to_base64 method
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

/// Helper struct to pass immutable search parameters to workers, abstracting
/// over the concrete implementations of memory and Merkle tree access.
#[derive(Clone, Copy)]
struct SearchParams<'a, MemoryType: PartialMemory, MerkleTreeType: PartialMerkleTree> {
    config: Config,
    challenge_id: &'a ChallengeId,
    memory: &'a MemoryType,
    merkle_tree: &'a MerkleTreeType,
    root_hash: &'a [u8],
}

impl Proof {
    /// Initiates a multi-threaded search for a valid proof that meets the difficulty requirement.
    ///
    /// The search iterates over nonces, calculating an Omega hash for each, until one
    /// satisfies the configured number of leading zero bits (d).
    /// The parallel implementation uses threading to allow available computing power to
    /// contribute easily to mining, making the scheme more progress free (Section 3.7, 4).
    ///
    /// ## Arguments
    /// * `config`: The PoW configuration.
    /// * `challenge_id`: The challenge identifier (I).
    /// * `memory`: The pre-computed memory array (X).
    /// * `merkle_tree`: The Merkle tree built over the memory.
    ///
    /// ## Returns
    /// The first valid `Proof` found.
    pub fn search(
        config: Config,
        challenge_id: &ChallengeId,
        memory: &Memory,
        merkle_tree: &MerkleTree,
    ) -> Self {
        let root_hash = merkle_tree.get_node(0).unwrap().to_vec();

        // Used to safely store the first proof found by any thread.
        let proof_slot = OnceLock::new();

        let threads = num_cpus::get();
        // Divide the full u64::MAX range into chunks for each thread.
        let chunk = u64::MAX / threads as u64;

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
                    memory,
                    merkle_tree,
                    root_hash,
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
    /// This function implements the core hash chain process (analogous to MTP-Argon2 steps 4, 5, and Itsuku steps 4, 5, 6).
    /// The hash function H is made challenge-specific to thwart precomputation attacks like Dinur-Nadler (Section 3.4, 4).
    ///
    /// ## Arguments
    /// * `params`: Configuration and data access.
    /// * `hasher`: A mutable Blake2b512 hasher instance to reuse.
    /// * `selected_leaves`: Output vector to store the indices of the memory elements accessed (I).
    /// * `path`: Output vector to store the intermediate hash chain values (Yj).
    /// * `memory_size`: The total number of elements in memory (T).
    /// * `nonce`: The nonce (N) to be included in the hash chain.
    ///
    /// ## Returns
    /// The final Omega hash as a 64-byte array.
    fn calculate_omega(
        params: &SearchParams<'_, impl PartialMemory, impl PartialMerkleTree>,
        hasher: &mut Blake2b512,
        selected_leaves: &mut Vec<usize>,
        path: &mut Vec<[u8; 64]>,
        memory_size: usize,
        nonce: u64,
    ) -> [u8; 64] {
        selected_leaves.clear();
        path.clear();

        // Step 4: Calculate the first path hash (Y0)
        // Y0 = HS(N || Phi || I)
        hasher.update(nonce.to_le_bytes());
        hasher.update(params.root_hash);
        hasher.update(&params.challenge_id.bytes);
        path.push(hasher.finalize_reset().into());

        // Step 5: Iterative hash chain (1 <= j <= L)
        for _ in 1..=params.config.search_length {
            let prev_hash = path.last().unwrap();

            // Determine the next memory element index: i_j-1 = Y_j-1 mod T
            let index =
                (u64::from_le_bytes(*prev_hash.first_chunk().unwrap()) as usize) % memory_size;
            selected_leaves.push(index);

            // Fetch the element, XOR it with the challenge_id for anti-precomputation
            // Itsuku uses X_I[i_j-1] XOR I
            let mut element = params
                .memory
                .get_element(index)
                .expect("Required element must exist");
            element ^= params.challenge_id.bytes.as_slice();

            // Calculate the next path hash (Yj): Yj = HS(Y_j-1 || X_I[i_j-1] XOR I)
            hasher.update(prev_hash);
            hasher.update(element.data.to_le_bytes());
            path.push(hasher.finalize_reset().into());
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
            let mut el = Element::from(*first);
            el ^= params.challenge_id.bytes.as_slice();
            hasher.update(el.data.to_le_bytes());
        }

        let omega: [u8; 64] = hasher.finalize_reset().into();
        omega
    }

    /// The worker function executed by each thread to search a range of nonces.
    fn search_worker(
        params: SearchParams<Memory, MerkleTree>,
        start: u64,
        end: u64,
        proof_slot: &OnceLock<Proof>,
    ) {
        let mut hasher = Blake2b512::new();
        let mut selected_leaves = Vec::with_capacity(params.config.search_length);
        // Path length is L (search_length) + 1 (for Y0)
        let mut path: Vec<[u8; 64]> = Vec::with_capacity(params.config.search_length + 1);
        let memory_size = params.config.chunk_count * params.config.chunk_size;

        for nonce in start..=end {
            // Check if another thread has already found and set a solution
            if proof_slot.get().is_some() {
                return;
            }

            let omega = Self::calculate_omega(
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
                leaf_antecedents.insert(leaf_index, params.memory.trace_element(leaf_index));
                // Collect all Merkle tree nodes needed for the opening path
                params.merkle_tree.trace_node(node_index, &mut tree_opening);
            }

            let proof = Proof {
                config: params.config,
                challenge_id: params.challenge_id.clone(),
                nonce,
                leaf_antecedents,
                tree_opening,
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
    /// ## Returns
    /// `Ok(())` if the proof is valid, or a `VerificationError` otherwise.
    pub fn verify(&self) -> Result<(), VerificationError> {
        let config = &self.config;
        let challenge_id = &self.challenge_id;
        let node_size = MerkleTree::calculate_node_size(config);
        let memory_size = config.chunk_count * config.chunk_size;

        // Step 1: Reconstruct required memory elements
        let mut partial_memory = HashMap::new();
        for (index, antacedents) in self.leaf_antecedents.iter() {
            match antacedents.len() {
                1 => {
                    // Base element (chunk 0) is provided directly
                    partial_memory.insert(*index, antacedents[0]);
                }
                n if n == config.antecedent_count => {
                    // Compressed element (chunk > 0) is recomputed from its antecedents
                    let element = Memory::compress(antacedents, *index as u64, challenge_id);
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
            MerkleTree::compute_leaf_hash(challenge_id, element, node_size, &mut leaf_hash);

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

            let (left_index, right_index) = MerkleTree::children_of(node_index);

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
            let compute_hash = MerkleTree::compute_intermediate_hash(
                challenge_id,
                left_child,
                right_child,
                node_size,
            );
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
        let mut hasher = Blake2b512::new();
        let mut path: Vec<[u8; 64]> = Vec::with_capacity(config.search_length + 1);
        let mut selected_leaves = Vec::with_capacity(config.search_length);

        let omega = Self::calculate_omega(
            &SearchParams {
                config: *config,
                challenge_id,
                // Use the reconstructed memory and verified Merkle nodes as partial data sources
                memory: &partial_memory,
                merkle_tree: &merkle_nodes,
                root_hash: root_hash.as_ref(),
            },
            &mut hasher,
            &mut selected_leaves,
            &mut path,
            memory_size,
            self.nonce,
        );

        // Check 3.1: Ensure the recalculated path (I) matches the leaves provided in the proof
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

/// Specific errors that can occur during Proof-of-Work verification.
#[derive(Debug)]
pub enum VerificationError {
    InvalidAntecedentCount(usize),
    MissingOpeningForLeaf(usize),
    LeafHashMismatch(usize),
    IntermediateHashMismatch(usize),
    MissingMerkleRoot,
    MalformedProofPath,
    UnprovenLeafInPath,
    DifficultyNotMet,
    RequiredElementMissing(usize),
    MissingChildNode(usize),
}

impl Display for VerificationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            VerificationError::InvalidAntecedentCount(count) => {
                write!(f, "Invalid antecedent count: {}", count)
            }
            VerificationError::MissingOpeningForLeaf(idx) => {
                write!(f, "Missing Merkle opening for required leaf index: {}", idx)
            }
            VerificationError::LeafHashMismatch(idx) => {
                write!(f, "Computed leaf hash mismatch for index: {}", idx)
            }
            VerificationError::IntermediateHashMismatch(idx) => {
                write!(f, "Computed intermediate hash mismatch for index: {}", idx)
            }
            VerificationError::MissingMerkleRoot => write!(f, "Missing Merkle Root hash (Phi)"),
            VerificationError::MalformedProofPath => write!(
                f,
                "The Merkle path structure in the proof opening is malformed"
            ),
            VerificationError::UnprovenLeafInPath => write!(
                f,
                "Recalculated path includes leaves not provided in the proof"
            ),
            VerificationError::DifficultyNotMet => {
                write!(f, "Proof difficulty not met (insufficient leading zeros)")
            }
            VerificationError::RequiredElementMissing(idx) => {
                write!(f, "Required memory element missing at index: {}", idx)
            }
            VerificationError::MissingChildNode(idx) => write!(
                f,
                "Missing child node required to verify parent hash at index: {}",
                idx
            ),
        }
    }
}

/// Trait representing memory access required for hash computation.
/// Used to abstract between the full `Memory` (searcher) and the reconstructed partial memory (verifier).
trait PartialMemory: Send + Sync {
    /// Gets the element at the given index.
    fn get_element(&self, index: usize) -> Option<Element>;
}

impl PartialMemory for Memory {
    /// Accesses the full memory array X.
    fn get_element(&self, index: usize) -> Option<Element> {
        self.get(index).copied()
    }
}

impl PartialMemory for HashMap<usize, Element> {
    /// Accesses the partial memory reconstructed from antecedents during verification.
    fn get_element(&self, index: usize) -> Option<Element> {
        self.get(&index).copied()
    }
}

/// Trait representing Merkle node access required during verification.
/// Used to abstract between the full `MerkleTree` (searcher) and the map of opened nodes (verifier).
pub trait PartialMerkleTree: Send + Sync {
    /// Gets the Merkle node hash at the given index.
    fn get_node(&self, index: usize) -> Option<&[u8]>;
}

impl PartialMerkleTree for MerkleTree {
    /// Accesses the Merkle node in the full tree structure.
    fn get_node(&self, index: usize) -> Option<&[u8]> {
        self.get_node(index)
    }
}

impl PartialMerkleTree for HashMap<usize, Bytes> {
    /// Accesses the provided or reconstructed Merkle node in the opening.
    fn get_node(&self, index: usize) -> Option<&[u8]> {
        self.get(&index).map(|node| node.as_ref())
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
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = i as u8;
        }
        ChallengeId {
            bytes: bytes.to_vec(),
        }
    }

    #[test]
    fn solves_and_verifies() {
        // 1) Create config matching C test
        let config = Config {
            chunk_count: 16,
            chunk_size: 64,
            difficulty_bits: 8,
            ..Config::default()
        };

        let challenge_id = build_test_challenge();

        // 2) Build memory
        let mut memory = Memory::new(config);
        memory.build_all_chunks(&challenge_id);

        // 3) Build Merkle tree
        let mut merkle_tree = MerkleTree::new(config);

        // Compute leaf hashes and intermediate nodes
        merkle_tree.compute_leaf_hashes(&challenge_id, &memory);
        merkle_tree.compute_intermediate_nodes(&challenge_id);

        // 4) Search for the proof
        let proof = Proof::search(config, &challenge_id, &memory, &merkle_tree);

        // 5) Verify the proof
        assert!(proof.verify().is_ok(), "Proof failed verification");
    }
}
