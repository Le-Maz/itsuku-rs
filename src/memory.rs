//! This module defines the memory structure and operations for the Itsuku Proof-of-Work.
//!
//! It handles the allocation of the large memory array, the definition of individual
//! 64-byte `Element`s using SIMD for performance, and the core "compression" function
//! used to populate the memory and generate proofs.

use std::{
    collections::HashMap,
    fmt::{Debug, Display},
    marker::PhantomData,
    ops::{AddAssign, BitXorAssign},
    simd::{Simd, ToBytes},
    str::FromStr,
};

use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use blake3::Hasher;
use bytemuck::checked::cast_slice_mut;
use serde_with::{DeserializeFromStr, SerializeDisplay};

use crate::{
    calculate_argon2_index, calculate_phi_variant_index, challenge_id::ChallengeId, config::Config,
    endianness::Endian,
};

/// The size of a single memory element in bytes (64 bytes / 512 bits).
pub const ELEMENT_SIZE: usize = 64;
/// The number of 64-bit lanes in a SIMD vector (8 lanes).
const LANES: usize = ELEMENT_SIZE / 8;

/// A single unit of data within the Proof-of-Work memory.
///
/// Each `Element` consists of 64 bytes of data, represented internally as a SIMD vector
/// of `u64` integers. This allows for efficient parallel arithmetic operations (XOR, ADD)
/// required by the mixing function.
#[derive(SerializeDisplay, DeserializeFromStr)]
#[repr(transparent)]
pub struct Element<E: Endian> {
    /// The underlying SIMD data.
    pub data: Simd<u64, LANES>,
    /// Marker to handle the generic Endian type without consuming space.
    _marker: PhantomData<E>,
}

impl<E: Endian> Debug for Element<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Element")
            .field("data", &self.data)
            .field("_marker", &self._marker)
            .finish()
    }
}

impl<E: Endian> Copy for Element<E> {}
impl<E: Endian> Clone for Element<E> {
    #[inline]
    fn clone(&self) -> Self {
        *self
    }
}

impl<E: Endian> PartialEq for Element<E> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.data == other.data
    }
}
impl<E: Endian> Eq for Element<E> {}

impl<E: Endian> Display for Element<E> {
    /// Formats the element as a lowercase hex string representing its little-endian byte sequence.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let bytes: [u8; ELEMENT_SIZE] = self.data.to_le_bytes().to_array();
        for byte in &bytes {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

impl<E: Endian> FromStr for Element<E> {
    type Err = String;

    /// Parses an Element from a hex string.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != ELEMENT_SIZE * 2 {
            return Err(format!(
                "Invalid length: expected {} hex characters, got {}",
                ELEMENT_SIZE * 2,
                s.len()
            ));
        }

        let mut bytes = [0u8; ELEMENT_SIZE];
        for i in 0..ELEMENT_SIZE {
            let byte_str = &s[i * 2..i * 2 + 2];
            bytes[i] =
                u8::from_str_radix(byte_str, 16).map_err(|e| format!("Invalid hex: {}", e))?;
        }

        let simd_u8 = Simd::from_array(bytes);
        let simd_u64 = Simd::from_le_bytes(simd_u8);

        Ok(Self {
            data: simd_u64,
            _marker: PhantomData,
        })
    }
}

impl<E: Endian> From<[u8; ELEMENT_SIZE]> for Element<E> {
    #[inline]
    fn from(value: [u8; ELEMENT_SIZE]) -> Self {
        let simd_bytes = Simd::from_array(value);
        Self {
            data: E::simd_from_bytes(simd_bytes),
            _marker: PhantomData,
        }
    }
}

impl<E: Endian> Element<E> {
    /// Returns a new Element with all bits set to zero.
    #[inline]
    const fn zero() -> Self {
        Self {
            data: Simd::from_array([0; LANES]),
            _marker: PhantomData,
        }
    }

    /// Convert Element to a URL-safe Base64 string of its 64-byte little-endian encoding.
    ///
    /// This is primarily used for compact serialization in proofs.
    pub fn to_base64(&self) -> String {
        let bytes: [u8; ELEMENT_SIZE] = self.data.to_le_bytes().to_array();
        BASE64_URL_SAFE_NO_PAD.encode(bytes)
    }
}

impl<E: Endian> BitXorAssign<&Self> for Element<E> {
    /// Performs a bitwise XOR assignment (`^=`) between two elements using SIMD.
    #[inline]
    fn bitxor_assign(&mut self, rhs: &Self) {
        self.data ^= rhs.data;
    }
}

impl<E: Endian> AddAssign<&Self> for Element<E> {
    /// Performs a wrapping addition assignment (`+=`) between two elements using SIMD.
    #[inline]
    fn add_assign(&mut self, rhs: &Self) {
        self.data += rhs.data;
    }
}

/// The main memory structure for the PoW scheme.
///
/// It represents the directed acyclic graph (DAG) of data that must be computed and stored.
/// The memory is divided into "chunks" to facilitate efficient parallel construction.
///
///
pub struct Memory<E: Endian> {
    config: Config,
    chunks: Vec<Vec<Element<E>>>,
}

impl<E: Endian> Memory<E> {
    /// Allocates the memory structure based on the provided configuration.
    ///
    /// Memory is initialized to zero and organized into `config.chunk_count` chunks,
    /// each containing `config.chunk_size` elements.
    pub fn new(config: Config) -> Self {
        let mut chunks = Vec::with_capacity(config.chunk_count);
        for _ in 0..config.chunk_count {
            let chunk = vec![Element::zero(); config.chunk_size];
            chunks.push(chunk);
        }
        Self { config, chunks }
    }

    /// Retrieves a reference to the element at the specified global index.
    #[inline]
    pub fn get(&self, index: usize) -> Option<&Element<E>> {
        let chunk = index / self.config.chunk_size;
        let element = index % self.config.chunk_size;
        self.chunks.get(chunk)?.get(element)
    }

    /// Retrieves a mutable reference to the element at the specified global index.
    #[inline]
    pub fn get_mut(&mut self, index: usize) -> Option<&mut Element<E>> {
        let chunk = index / self.config.chunk_size;
        let element = index % self.config.chunk_size;
        self.chunks.get_mut(chunk)?.get_mut(element)
    }

    /// Calculates the indices of antecedent elements required to compute a specific element.
    ///
    /// This implements the dependency graph logic. The indices are derived pseudo-randomly
    /// based on the content of the *previous* element in the sequence, making the graph
    /// data-dependent.
    ///
    /// The results are written directly into the provided `index_buffer` to avoid allocation.
    pub fn get_antecedent_indices(
        config: &Config,
        chunk: &[Element<E>],
        element_index: usize,
        index_buffer: &mut [usize],
    ) {
        let antecedent_count = config.antecedent_count;
        assert!(element_index >= antecedent_count);
        assert_eq!(index_buffer.len(), antecedent_count);

        // This logic is driven by the element *before* the current one
        let prev = &chunk[element_index - 1];
        let prev_bytes: [u8; ELEMENT_SIZE] = E::simd_to_bytes(prev.data).to_array();

        // Use the first 4 bytes of the previous element as a seed
        let mut seed_4 = [0u8; 4];
        seed_4.copy_from_slice(&prev_bytes[0..4]);

        // Calculate a base index using Argon2-like indexing logic
        let argon2_index = calculate_argon2_index(seed_4, element_index);

        let element_count = config.chunk_size;

        for (variant, index_slot) in index_buffer.iter_mut().enumerate() {
            // Apply phi variant indexing to diversify dependencies
            let idx = calculate_phi_variant_index(element_index, argon2_index, variant);
            let idx_mod = idx % element_count;

            *index_slot = idx_mod;
        }
    }

    /// The core compression function (Phi).
    ///
    /// This function takes a set of antecedent elements and compresses them into a single
    /// new element. The process involves:
    /// 1. Summing even-indexed antecedents.
    /// 2. Summing odd-indexed antecedents.
    /// 3. Applying perturbations using the `global_element_index` and `challenge_id`.
    /// 4. Hashing the result using Blake2b to produce the final element.
    pub fn compress(
        antecedents: &[Element<E>],
        global_element_index: u64,
        challenge_element: &Element<E>,
    ) -> Element<E> {
        // 1. Calculate Sum Even
        let mut sum_even = Element::zero();
        let even_count = antecedents.len().div_ceil(2);
        for k in 0..even_count {
            sum_even += &antecedents[2 * k];
        }

        // Apply XOR modification with global index
        let mut sum_even_mut = sum_even;
        let sum_even_array = sum_even_mut.data.as_mut_array();
        sum_even_array[0] ^= global_element_index;

        // 2. Calculate Sum Odd
        let mut sum_odd = Element::zero();
        let odd_count = antecedents.len() / 2;
        for k in 0..odd_count {
            sum_odd += &antecedents[2 * k + 1];
        }

        // Apply XOR modification with challenge bytes
        let mut sum_odd_mut = sum_odd;
        sum_odd_mut ^= challenge_element;

        // 3. Variable-length Blake2b Hash
        let mut hasher = Hasher::new();
        hasher.update(&E::simd_to_bytes(sum_even_mut.data).to_array());
        hasher.update(&E::simd_to_bytes(sum_odd_mut.data).to_array());

        let mut output = Element::zero();
        let output_bytes = output.data.as_mut_array();
        let output_slice = cast_slice_mut(output_bytes);
        hasher.finalize_xof().fill(output_slice);

        output
    }

    /// Populates a single memory chunk.
    ///
    /// This process has two stages:
    /// 1. **Initialization**: The first `antecedent_count` elements are generated directly
    ///    from the chunk index and challenge ID via hashing.
    /// 2. **Iterative Construction**: The remaining elements are generated by compressing
    ///    antecedent elements found using `get_antecedent_indices`.
    pub fn build_chunk(
        config: &Config,
        chunk_index: usize,
        chunk: &mut [Element<E>],
        challenge_id: &ChallengeId,
        challenge_element: &Element<E>,
    ) {
        // Initialize first n elements (allocation-free)
        for (element_index, element) in chunk.iter_mut().enumerate() {
            let mut hasher = Hasher::new();
            hasher.update(&E::u64_to_bytes(element_index as u64));
            hasher.update(&E::u64_to_bytes(chunk_index as u64));
            hasher.update(&challenge_id.bytes);
            let output = element.data.as_mut_array().as_mut_slice();
            hasher.finalize_xof().fill(cast_slice_mut(output));
        }

        // Allocate the reusable index buffer once for the whole chunk
        let mut index_buffer = vec![0; config.antecedent_count];
        let mut antecedents = Vec::with_capacity(config.antecedent_count);
        let antecedent_count = config.antecedent_count;
        let element_count = config.chunk_size;

        for element_index in antecedent_count..element_count {
            // 1. Calculate and store Antecedent Indices into the reusable buffer
            Self::get_antecedent_indices(config, chunk, element_index, &mut index_buffer);

            // 2. Retrieve Antecedent Elements
            let antedecent_iter = index_buffer.iter().map(|&idx| chunk[idx % element_count]);
            antecedents.extend(antedecent_iter);

            // 3. Perform Compression
            let global_element_index = (chunk_index as u64)
                .wrapping_mul(config.chunk_size as u64)
                .wrapping_add(element_index as u64);
            let new_element =
                Self::compress(&antecedents, global_element_index, &challenge_element);
            antecedents.clear();

            // Write the result back into the chunk
            chunk[element_index] = new_element;
        }
    }

    /// Builds the entire memory structure in parallel.
    ///
    /// Splits the work of building chunks across all available CPU threads.
    pub fn build_all_chunks(&mut self, challenge_id: &ChallengeId) {
        std::thread::scope(|scope| {
            let config = self.config;
            let threads = num_cpus::get().min(config.jobs);
            let chunks_per_thread = config.chunk_count.div_ceil(threads);
            let challenge_element = challenge_id.bytes.into();
            for (thread, chunks_to_build) in self.chunks.chunks_mut(chunks_per_thread).enumerate() {
                scope.spawn(move || {
                    for (chunk_index, chunk) in chunks_to_build.iter_mut().enumerate() {
                        let chunk_index = thread * chunks_per_thread + chunk_index;
                        Self::build_chunk(
                            &config,
                            chunk_index,
                            chunk,
                            challenge_id,
                            &challenge_element,
                        );
                    }
                });
            }
        });
    }

    /// Traces and retrieves the antecedent elements for a given leaf index.
    ///
    /// This is used during proof generation to gather the data required for the verifier
    /// to reconstruct a specific memory element.
    ///
    /// * If the element is a base element (start of a chunk), it returns just itself.
    /// * Otherwise, it recalculates indices and returns the full list of parents.
    pub fn trace_element(&self, leaf_index: usize) -> Vec<Element<E>> {
        let antecedent_count = self.config.antecedent_count;

        let chunk_index = leaf_index / self.config.chunk_size;
        let chunk = &self.chunks[chunk_index];

        let element_index = leaf_index % self.config.chunk_size;

        // Case 1: A base element — it has no antecedents by definition.
        if element_index < antecedent_count {
            // Just return the element itself as the "trace" of size 1.
            return vec![chunk[element_index]];
        }

        // Case 2: Compute the antecedents exactly like the compression function
        let mut indices = vec![0; antecedent_count];
        Self::get_antecedent_indices(&self.config, chunk, element_index, &mut indices);
        indices.into_iter().map(|idx| chunk[idx]).collect()
    }
}

/// Trait representing memory access required for hash computation.
/// Used to abstract between the full `Memory` (searcher) and the reconstructed partial memory (verifier).
pub trait PartialMemory<E: Endian>: Send + Sync {
    /// Gets the element at the given index.
    fn get_element(&self, index: usize) -> Option<Element<E>>;
}

impl<E: Endian> PartialMemory<E> for Memory<E> {
    /// Accesses the full memory array X.
    fn get_element(&self, index: usize) -> Option<Element<E>> {
        self.get(index).copied()
    }
}

impl<E: Endian> PartialMemory<E> for HashMap<usize, Element<E>> {
    /// Accesses the partial memory reconstructed from antecedents during verification.
    fn get_element(&self, index: usize) -> Option<Element<E>> {
        self.get(&index).copied()
    }
}

#[cfg(test)]
mod tests;
