#![feature(portable_simd)]
#[cfg(not(target_endian = "little"))]
compile_error!("This library only supports little-endian systems");

pub mod challenge_id;
pub mod config;
pub mod memory;
pub mod merkle_tree;
pub mod proof;

// Helper: compute argon2 index from first 4 bytes of previous element
fn calculate_argon2_index(seed_bytes: [u8; 4], original_index: usize) -> usize {
    let seed_integer_value: u64 = u32::from_le_bytes(seed_bytes) as u64;

    // mirror the C arithmetic (shift right 32)
    let temporary_x = (seed_integer_value.wrapping_mul(seed_integer_value)) >> 32;
    let temporary_y = (((original_index as u64).wrapping_sub(1)).wrapping_mul(temporary_x)) >> 32;
    let computed_z_index = (original_index as u64)
        .wrapping_sub(1)
        .wrapping_sub(temporary_y);
    computed_z_index as usize
}

// Helper: compute phi variant index
fn calculate_phi_variant_index(
    original_index: usize,
    argon2_index: usize,
    variant_identifier: usize,
) -> usize {
    match variant_identifier {
        0 => original_index - 1,
        1 => argon2_index,
        2 => (argon2_index + original_index) / 2,
        3 => (original_index * 7) / 8,
        4 => (argon2_index + 3 * original_index) / 4,
        5 => (3 * argon2_index + original_index) / 4,
        _ => original_index - 1,
    }
}
