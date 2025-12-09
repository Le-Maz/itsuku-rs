use std::{
    fmt::{Debug, Display},
    marker::PhantomData,
    ops::{AddAssign, BitXorAssign},
    simd::{Simd, ToBytes},
    str::FromStr,
};

use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use blake2::{
    Blake2bVar,
    digest::{Update, VariableOutput},
};
use bytemuck::checked::cast_slice_mut;
use serde_with::{DeserializeFromStr, SerializeDisplay};

use crate::{
    calculate_argon2_index, calculate_phi_variant_index, challenge_id::ChallengeId, config::Config,
    endianness::Endian,
};

const ELEMENT_SIZE: usize = 64;
const LANES: usize = ELEMENT_SIZE / 8;

#[derive(SerializeDisplay, DeserializeFromStr)]
#[repr(transparent)]
pub struct Element<E: Endian> {
    pub data: Simd<u64, LANES>,
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
    #[inline]
    const fn zero() -> Self {
        Self {
            data: Simd::from_array([0; LANES]),
            _marker: PhantomData,
        }
    }

    /// Convert Element → base64 of its 64-byte little-endian encoding.
    pub fn to_base64(&self) -> String {
        let bytes: [u8; ELEMENT_SIZE] = self.data.to_le_bytes().to_array();
        BASE64_URL_SAFE_NO_PAD.encode(bytes)
    }
}

impl<E: Endian> BitXorAssign<&Self> for Element<E> {
    #[inline]
    fn bitxor_assign(&mut self, rhs: &Self) {
        self.data ^= rhs.data;
    }
}

impl<E: Endian> BitXorAssign<&[u8]> for Element<E> {
    #[inline]
    fn bitxor_assign(&mut self, rhs: &[u8]) {
        let rhs_simd_u8 = Simd::load_or_default(rhs);
        let rhs_simd_u64 = E::simd_from_bytes(rhs_simd_u8);
        self.data ^= rhs_simd_u64;
    }
}

impl<E: Endian> AddAssign<&Self> for Element<E> {
    #[inline]
    fn add_assign(&mut self, rhs: &Self) {
        self.data += rhs.data;
    }
}

pub struct Memory<E: Endian> {
    config: Config,
    chunks: Vec<Vec<Element<E>>>,
}

impl<E: Endian> Memory<E> {
    pub fn new(config: Config) -> Self {
        let mut chunks = Vec::with_capacity(config.chunk_count);
        for _ in 0..config.chunk_count {
            let chunk = vec![Element::zero(); config.chunk_size];
            chunks.push(chunk);
        }
        Self { config, chunks }
    }

    #[inline]
    pub fn get(&self, index: usize) -> Option<&Element<E>> {
        let chunk = index / self.config.chunk_size;
        let element = index % self.config.chunk_size;
        self.chunks.get(chunk)?.get(element)
    }

    #[inline]
    pub fn get_mut(&mut self, index: usize) -> Option<&mut Element<E>> {
        let chunk = index / self.config.chunk_size;
        let element = index % self.config.chunk_size;
        self.chunks.get_mut(chunk)?.get_mut(element)
    }

    /// Calculates the antecedent indices for a given element index
    /// and writes them directly into the provided mutable slice of usize.
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

        let mut seed_4 = [0u8; 4];
        seed_4.copy_from_slice(&prev_bytes[0..4]);
        let argon2_index = calculate_argon2_index(seed_4, element_index);

        let element_count = config.chunk_size;

        for (variant, index_slot) in index_buffer.iter_mut().enumerate() {
            let idx = calculate_phi_variant_index(element_index, argon2_index, variant);
            let idx_mod = idx % element_count;

            *index_slot = idx_mod;
        }
    }

    /// The core compression function, decoupled from memory access.
    /// It computes a new Element given its antecedent Elements.
    pub fn compress(
        antecedents: &[Element<E>],
        global_element_index: u64,
        challenge_id: &ChallengeId,
    ) -> Element<E> {
        // 1. Calculate Sum Even
        let mut sum_even = Element::zero();
        let even_count = antecedents.len().div_ceil(2);
        for k in 0..even_count {
            sum_even += &antecedents[2 * k];
        }

        // Apply XOR modification
        let mut sum_even_mut = sum_even;
        let sum_even_array = sum_even_mut.data.as_mut_array();
        sum_even_array[0] ^= global_element_index;

        // 2. Calculate Sum Odd
        let mut sum_odd = Element::zero();
        let odd_count = antecedents.len() / 2;
        for k in 0..odd_count {
            sum_odd += &antecedents[2 * k + 1];
        }

        // Apply XOR modification
        let mut sum_odd_mut = sum_odd;
        sum_odd_mut ^= challenge_id.bytes.as_slice();

        // 3. Variable-length Blake2b
        let mut hasher = Blake2bVar::new(ELEMENT_SIZE).unwrap();
        hasher.update(&E::simd_to_bytes(sum_even_mut.data).to_array());
        hasher.update(&E::simd_to_bytes(sum_odd_mut.data).to_array());

        let mut output = Element::zero();
        let output_bytes = output.data.as_mut_array();
        let output_slice = cast_slice_mut(output_bytes);
        hasher.finalize_variable(output_slice).unwrap();

        output
    }

    pub fn build_chunk(
        config: &Config,
        chunk_index: usize,
        chunk: &mut [Element<E>],
        challenge_id: &ChallengeId,
    ) {
        // Initialize first n elements (allocation-free)
        for (element_index, element) in chunk.iter_mut().enumerate() {
            let mut hasher = Blake2bVar::new(ELEMENT_SIZE).unwrap();
            hasher.update(&E::u64_to_bytes(element_index as u64));
            hasher.update(&E::u64_to_bytes(chunk_index as u64));
            hasher.update(&challenge_id.bytes);
            let output = element.data.as_mut_array().as_mut_slice();
            hasher.finalize_variable(cast_slice_mut(output)).unwrap();
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
            let new_element = Self::compress(&antecedents, global_element_index, challenge_id);
            antecedents.clear();

            // Write the result back into the chunk
            chunk[element_index] = new_element;
        }
    }

    pub fn build_all_chunks(&mut self, challenge_id: &ChallengeId) {
        std::thread::scope(|scope| {
            let threads = num_cpus::get();
            let chunks_per_thread = self.config.chunk_count.div_ceil(threads);
            let config = self.config;
            for (thread, chunks_to_build) in self.chunks.chunks_mut(chunks_per_thread).enumerate() {
                scope.spawn(move || {
                    for (chunk_index, chunk) in chunks_to_build.iter_mut().enumerate() {
                        let chunk_index = thread * chunks_per_thread + chunk_index;
                        Self::build_chunk(&config, chunk_index, chunk, challenge_id);
                    }
                });
            }
        });
    }

    /// Traces the element's antecedents
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

#[cfg(test)]
mod tests;
