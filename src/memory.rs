use std::{
    ops::{AddAssign, BitXorAssign},
    simd::{Simd, ToBytes},
};

use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use blake2::{
    Blake2bVar,
    digest::{Update, VariableOutput},
};
use bytemuck::checked::cast_slice_mut;

use crate::{
    calculate_argon2_index, calculate_phi_variant_index, challenge_id::ChallengeId, config::Config,
};

const ELEMENT_SIZE: usize = 64;
const LANES: usize = ELEMENT_SIZE / 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Element {
    pub data: Simd<u64, LANES>,
}

impl From<[u8; 64]> for Element {
    #[inline]
    fn from(value: [u8; 64]) -> Self {
        let simd_bytes = Simd::from_array(value);
        Self {
            data: Simd::from_le_bytes(simd_bytes),
        }
    }
}

impl Element {
    #[inline]
    const fn zero() -> Self {
        Self {
            data: Simd::from_array([0; LANES]),
        }
    }

    /// Convert Element → base64 of its 64-byte little-endian encoding.
    pub fn to_base64(&self) -> String {
        let bytes: [u8; 64] = self.data.to_le_bytes().to_array();
        BASE64_URL_SAFE_NO_PAD.encode(&bytes)
    }
}

impl BitXorAssign<&Self> for Element {
    #[inline]
    fn bitxor_assign(&mut self, rhs: &Self) {
        self.data ^= rhs.data;
    }
}

impl BitXorAssign<&[u8]> for Element {
    #[inline]
    fn bitxor_assign(&mut self, rhs: &[u8]) {
        let rhs_simd_u8 = Simd::load_or_default(rhs);
        let rhs_simd_u64 = Simd::from_le_bytes(rhs_simd_u8);
        self.data ^= rhs_simd_u64;
    }
}

impl AddAssign<&Self> for Element {
    #[inline]
    fn add_assign(&mut self, rhs: &Self) {
        self.data += rhs.data;
    }
}

pub struct Memory {
    config: Config,
    chunks: Vec<Vec<Element>>,
}

impl Memory {
    pub fn new(config: Config) -> Self {
        let mut chunks = Vec::with_capacity(config.chunk_count);
        for _ in 0..config.chunk_count {
            let chunk = vec![Element::zero(); config.chunk_size];
            chunks.push(chunk);
        }
        Self { config, chunks }
    }

    #[inline]
    pub fn get(&self, index: usize) -> Option<&Element> {
        let chunk = index / self.config.chunk_size;
        let element = index % self.config.chunk_size;
        self.chunks.get(chunk)?.get(element)
    }

    #[inline]
    pub fn get_mut(&mut self, index: usize) -> Option<&mut Element> {
        let chunk = index / self.config.chunk_size;
        let element = index % self.config.chunk_size;
        self.chunks.get_mut(chunk)?.get_mut(element)
    }

    fn compression_function(
        config: &Config,
        chunk_index: usize,
        chunk: &mut Vec<Element>,
        element_index: usize,
        challenge_id: &ChallengeId,
    ) {
        assert!(element_index >= config.antecedent_count);

        let prev = &chunk[element_index - 1];
        let prev_bytes: [u8; ELEMENT_SIZE] = prev.data.to_le_bytes().to_array();

        let mut seed_4 = [0u8; 4];
        seed_4.copy_from_slice(&prev_bytes[0..4]);

        let argon2_index = calculate_argon2_index(seed_4, element_index);
        let mut antecedents: Vec<usize> = Vec::with_capacity(config.antecedent_count);
        for k in 0..config.antecedent_count {
            antecedents.push(calculate_phi_variant_index(element_index, argon2_index, k));
        }

        let element_count = config.chunk_size;

        let mut sum_even = Element::zero();
        let even_count = (antecedents.len() + 1) / 2;
        for k in 0..even_count {
            let idx = antecedents[2 * k] % element_count;
            sum_even += &chunk[idx];
        }

        let global_element_index = (chunk_index as u64)
            .wrapping_mul(config.chunk_size as u64)
            .wrapping_add(element_index as u64);
        let sum_even_array = sum_even.data.as_mut_array();
        sum_even_array[0] ^= global_element_index;

        let mut sum_odd = Element::zero();
        let odd_count = antecedents.len() / 2;
        for k in 0..odd_count {
            let idx = antecedents[2 * k + 1] % element_count;
            sum_odd += &chunk[idx];
        }
        sum_odd ^= challenge_id.bytes.as_slice();

        // ---- Variable-length Blake2b ----
        let mut hasher = Blake2bVar::new(ELEMENT_SIZE).unwrap();
        hasher.update(&sum_even.data.to_le_bytes().to_array());
        hasher.update(&sum_odd.data.to_le_bytes().to_array());

        let output = chunk[element_index].data.as_mut_array().as_mut_slice();
        hasher.finalize_variable(cast_slice_mut(output)).unwrap();
    }

    pub fn build_chunk(
        config: &Config,
        chunk_index: usize,
        chunk: &mut Vec<Element>,
        challenge_id: &ChallengeId,
    ) {
        // Initialize first n elements
        for element_index in 0..config.antecedent_count {
            let mut hasher = Blake2bVar::new(ELEMENT_SIZE).unwrap();
            hasher.update(&element_index.to_le_bytes());
            hasher.update(&chunk_index.to_le_bytes());
            hasher.update(&challenge_id.bytes);
            let output = chunk[element_index].data.as_mut_array().as_mut_slice();
            hasher.finalize_variable(cast_slice_mut(output)).unwrap();
        }

        for element_index in config.antecedent_count..config.chunk_size {
            Self::compression_function(config, chunk_index, chunk, element_index, challenge_id);
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

    pub fn trace_element(&self, leaf_index: usize) -> Vec<Element> {
        let chunk_index = leaf_index / self.config.chunk_size;
        let chunk = &self.chunks[chunk_index];

        let element_index = leaf_index % self.config.chunk_size;

        // Case 1: A base element — it has no antecedents by definition.
        if element_index < self.config.antecedent_count {
            return vec![chunk[element_index]];
        }

        // Case 2: Compute the antecedents exactly like the compression function
        let prev = &chunk[element_index - 1];
        let prev_bytes: [u8; ELEMENT_SIZE] = prev.data.to_le_bytes().to_array();

        let mut seed_4 = [0u8; 4];
        seed_4.copy_from_slice(&prev_bytes[0..4]);

        let argon2_index = calculate_argon2_index(seed_4, element_index);

        let mut trace = Vec::with_capacity(self.config.antecedent_count);
        let element_count = self.config.chunk_size;

        for antecedent in 0..self.config.antecedent_count {
            let idx = calculate_phi_variant_index(element_index, argon2_index, antecedent);
            let idx_mod = idx % element_count;
            trace.push(chunk[idx_mod]);
        }

        trace
    }
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use super::*;

    const LANES: usize = ELEMENT_SIZE.div_ceil(8);

    #[test]
    fn element_zero_is_correct() {
        let z = Element::zero();
        assert_eq!(z.data.to_array(), [0u64; LANES]);
    }

    #[test]
    fn xor_of_identical_elements_is_zero() {
        let mut el1 = Element::zero();
        for (i, lane) in el1.data.as_mut_array().iter_mut().enumerate() {
            *lane = (i as u64) * 0x1234_5678_ABCD_EF01u64;
        }

        let el2 = el1;

        let mut x = el1;
        x ^= &el2;

        assert_eq!(x, Element::zero());
    }

    #[test]
    fn xor_matches_scalar_xor() {
        let mut el1 = Element::zero();
        let mut el2 = Element::zero();

        for (i, lane) in el1.data.as_mut_array().iter_mut().enumerate() {
            *lane = (i as u64).wrapping_mul(0xFFEEDDCCBBAA9988);
        }
        for (i, lane) in el2.data.as_mut_array().iter_mut().enumerate() {
            *lane = (i as u64).wrapping_mul(0x1122334455667788);
        }

        let mut simd_res = el1;
        simd_res ^= &el2;

        let mut scalar_res = [0u64; LANES];
        for i in 0..LANES {
            scalar_res[i] = el1.data[i] ^ el2.data[i];
        }

        assert_eq!(simd_res.data.to_array(), scalar_res);
    }

    #[test]
    fn add_matches_scalar_add() {
        let mut el1 = Element::zero();
        let mut el2 = Element::zero();

        for (i, lane) in el1.data.as_mut_array().iter_mut().enumerate() {
            *lane = (i as u64).wrapping_mul(0x1111111111111111);
        }
        for (i, lane) in el2.data.as_mut_array().iter_mut().enumerate() {
            *lane = (i as u64).wrapping_mul(0x2222222222222222);
        }

        let mut simd_res = el1;
        simd_res += &el2;

        let mut scalar_res = [0u64; LANES];
        for i in 0..LANES {
            scalar_res[i] = el1.data[i].wrapping_add(el2.data[i]);
        }

        assert_eq!(simd_res.data.to_array(), scalar_res);
    }

    #[test]
    fn xor_with_slice_matches_scalar() {
        let mut el = Element::zero();

        // Fill the SIMD element with a known pattern
        for (i, lane) in el.data.as_mut_array().iter_mut().enumerate() {
            *lane = 0x0102030405060708u64.wrapping_mul(i as u64 + 1);
        }

        // Construct a 64-byte slice we XOR with
        let mut array = [0u8; ELEMENT_SIZE];
        for i in 0..ELEMENT_SIZE {
            array[i] = (i as u8).wrapping_mul(7).wrapping_add(3);
        }

        // Compute expected result with scalar operations
        let mut expected = [0u64; LANES];
        for lane in 0..LANES {
            let mut word_bytes = [0u8; 8];
            word_bytes.copy_from_slice(&array[lane * 8..lane * 8 + 8]);
            let rhs_word = u64::from_le_bytes(word_bytes);
            expected[lane] = el.data[lane] ^ rhs_word;
        }

        // Apply SIMD XOR
        let mut simd_el = el;
        simd_el ^= array.as_slice();

        assert_eq!(simd_el.data.to_array(), expected);
    }

    #[test]
    fn lane_count_is_correct() {
        // Static sanity check: 64 bytes should produce exactly 8 lanes of u64
        assert_eq!(LANES * 8, ELEMENT_SIZE);
    }

    #[test]
    fn compare_with_c_reference_output() {
        use crate::{challenge_id::ChallengeId, config::Config, memory::Memory};

        // ---- Input identical to the C program ----

        let mut challenge_bytes = [0u8; 64];
        for i in 0..64 {
            challenge_bytes[i] = i as u8;
        }

        let challenge_id = ChallengeId {
            bytes: challenge_bytes.into(),
        };

        let mut config = Config::default();
        config.chunk_count = 2;
        config.chunk_size = 8;

        let mut memory = Memory::new(config);

        memory.build_all_chunks(&challenge_id);

        // ---- Expected output from C reference ----

        const EXPECTED: [[u8; 64]; 8] = [
            hex!(
                "3b1da82003c6c8749ed080b4ad02043638f158ca52e8f19b15bebfd15ecb92b436fcb9ceef092b5f6f8b722fecec6fe0ed5f7beb3ab855b42edbd306ddc7b297"
            ),
            hex!(
                "cb87b2a8628b61bf35cb4b67faa7d03bc0272e2c3210b584014ee23ee2c48d9209bf7ec5383ae9ed419dab2e8317cfc966b46f49288d4f470ddf64955c4a1389"
            ),
            hex!(
                "7f3c7902197eda4bf7682cc2c3c7a2b3ef37936fd4ee8a6d36c089592c764703d23b62619f153449fbc5f2ca84eec38cee6ebf786fcbfccb3db22adb5254d5ed"
            ),
            hex!(
                "0132ee4240bc64733517790a4406ed1b4a42698f40133ae2f9f65e4dac06605f81de400843b74498d3052af58649f6eaaa12a443954d0aefddef52c4764d53c7"
            ),
            hex!(
                "870d931c871173138163f54134c150876679e63a0c434075d3f474b669799a8b952426862531b5892063718b7b0445bb9ee671d45df6572e02410707e2675f41"
            ),
            hex!(
                "97e2a1af68abf9658a6b731da7815f320cd363835fbbaab87129e3c699692d71dde4146571fe340ee978e9bffd12119cea847ed5999ca332d2ab43cd971d963d"
            ),
            hex!(
                "2b6d8d0afcab11115d7ec82b020b7fac8421862b6412020aa67361f25cd305cf5e3610129d0ac6ab7d5cda519bc2eee80dd48d144bb59f91cae8b189c98828d0"
            ),
            hex!(
                "6e3f7633fe74120bcbea86e34dfa49d6a939d06f29945175015e4b312ec41e47d2b12a9cf00ce5f80da94d029c42f79426723071b49a568338964d42e3aff578"
            ),
        ];

        // ---- Compare ----

        for i in 0..8 {
            let rust_el = memory.get(i).unwrap();
            let rust_bytes = rust_el.data.to_le_bytes().to_array();

            assert_eq!(
                rust_bytes, EXPECTED[i],
                "Mismatch at element {}:\nRust: {:02x?}\nC:    {:02x?}",
                i, rust_bytes, EXPECTED[i]
            );
        }
    }
}
