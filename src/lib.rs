#![doc = include_str!("../README.md")]
#![feature(portable_simd, likely_unlikely)]
#![warn(missing_docs)]

use std::sync::LazyLock;

pub mod challenge_id;
pub mod config;
pub mod endianness;
pub mod memory;
pub mod merkle_tree;
pub mod proof;

static NUM_CPUS: LazyLock<usize> = LazyLock::new(|| {
    #[cfg(not(target_family = "wasm"))]
    {
        num_cpus::get()
    }
    #[cfg(target_family = "wasm")]
    {
        1
    }
});

/// Computes argon2 index from a given seed and original index.
/// RFC 9106, Section 3.4.2
#[inline]
fn calculate_argon2_index(seed_bytes: [u8; 4], original_index: usize) -> usize {
    let seed_integer_value: u64 = u32::from_le_bytes(seed_bytes) as u64;

    let x = (seed_integer_value.wrapping_mul(seed_integer_value)) >> 32;
    let y = ((original_index as u64).wrapping_mul(x)) >> 32;
    let z = (original_index as u64).wrapping_sub(1).wrapping_sub(y);
    z as usize
}

/// Computes the phi variant index based on the original index, argon2 index,
/// and the variant identifier.
#[inline]
fn calculate_phi_variant_index(
    original_index: usize,
    argon2_index: usize,
    variant_identifier: usize,
) -> usize {
    match variant_identifier % 12 {
        0 => original_index - 1,
        1 => argon2_index,
        2 => (argon2_index + original_index) / 2,
        3 => (original_index * 7) / 8,
        4 => (argon2_index + 3 * original_index) / 4,
        5 => (3 * argon2_index + original_index) / 4,
        6 => argon2_index / 2,
        7 => original_index / 2,
        8 => argon2_index / 4,
        9 => original_index / 4,
        10 => (7 * argon2_index) / 8,
        11 => (7 * original_index) / 8,
        _ => unreachable!(),
    }
}
