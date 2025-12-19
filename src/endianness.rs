//! This module provides abstractions for handling endianness-specific operations.
//!
//! It defines the `Endian` trait, which unifies operations for converting between
//! raw byte arrays (e.g., from network packets or hashes) and computational types
//! (like `u64` or SIMD vectors), respecting the chosen byte order.
//!
//! This allows the core proof-of-work logic to remain generic (`<E: Endian>`) while
//! enabling cross-platform verification (e.g., generating a proof on a Big Endian machine
//! and verifying it on a Little Endian one).

use std::simd::{Simd, ToBytes};

use serde::{Deserialize, Serialize};

/// A trait representing a specific byte order (endianness) strategy.
///
/// This trait acts as a compile-time strategy pattern. Implementing structs (`LittleEndian`,
/// `BigEndian`, `NativeEndian`) provide specific implementations for converting data
/// to and from that byte order.
///
/// It must be `Send + Sync + 'static` to be used safely in multi-threaded contexts (like `Proof::search`).
pub trait Endian: Copy + Send + Sync + 'static {
    /// Returns the runtime tag (`EndiannessTag`) corresponding to this generic type.
    ///
    /// This is useful for storing the endianness used to generate a proof in the proof struct itself.
    fn kind() -> EndiannessTag;

    /// Reads a `u64` from a 8-byte array using this endianness.
    fn u64_from_bytes(bytes: &[u8; 8]) -> u64;

    /// Writes a `u64` into an 8-byte array using this endianness.
    fn u64_to_bytes(x: u64) -> [u8; 8];

    /// Converts a 64-byte SIMD vector of `u8` (raw bytes) into a SIMD vector of `u64` (integers)
    /// using this endianness.
    ///
    /// This is critical for efficient memory element processing where 64 bytes are treated as
    /// 8 lanes of 64-bit integers.
    fn simd_from_bytes(bytes: Simd<u8, 64>) -> Simd<u64, 8>;

    /// Converts a SIMD vector of `u64` (integers) back into a 64-byte SIMD vector of `u8` (raw bytes)
    /// using this endianness.
    fn simd_to_bytes(x: Simd<u64, 8>) -> Simd<u8, 64>;
}

/// A runtime enum tag identifying the byte order.
///
/// This is used in the `Proof` struct to indicate which endianness was used during the
/// search process, allowing the verifier to switch to the correct verification strategy.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum EndiannessTag {
    /// Least Significant Byte (LSB) first.
    Little,
    /// Most Significant Byte (MSB) first.
    Big,
}

impl Default for EndiannessTag {
    /// Detects the native endianness of the current system at runtime.
    #[inline]
    fn default() -> Self {
        const TEST: u16 = 1;
        // If the byte representation of 1u16 is identical to the little-endian representation,
        // then the system is little-endian.
        if TEST.to_le_bytes() == TEST.to_ne_bytes() {
            EndiannessTag::Little
        } else {
            EndiannessTag::Big
        }
    }
}

/// Strategy for the system's native byte order.
///
/// Using this variant allows for the most efficient operations (no byte swapping) on the host machine.
#[derive(Debug, Clone, Copy)]
pub struct NativeEndian;

/// Strategy for Little Endian byte order (LSB first).
#[derive(Debug, Clone, Copy)]
pub struct LittleEndian;

/// Strategy for Big Endian byte order (MSB first).
#[derive(Debug, Clone, Copy)]
pub struct BigEndian;

impl Endian for NativeEndian {
    #[inline]
    fn u64_from_bytes(b: &[u8; 8]) -> u64 {
        u64::from_ne_bytes(*b)
    }

    #[inline]
    fn u64_to_bytes(x: u64) -> [u8; 8] {
        x.to_ne_bytes()
    }

    #[inline]
    fn simd_from_bytes(bytes: Simd<u8, 64>) -> Simd<u64, 8> {
        Simd::from_ne_bytes(bytes)
    }

    #[inline]
    fn simd_to_bytes(x: Simd<u64, 8>) -> Simd<u8, 64> {
        x.to_ne_bytes()
    }

    #[inline]
    fn kind() -> EndiannessTag {
        EndiannessTag::default()
    }
}

impl Endian for LittleEndian {
    #[inline]
    fn u64_from_bytes(b: &[u8; 8]) -> u64 {
        u64::from_le_bytes(*b)
    }

    #[inline]
    fn u64_to_bytes(x: u64) -> [u8; 8] {
        x.to_le_bytes()
    }

    #[inline]
    fn simd_from_bytes(bytes: Simd<u8, 64>) -> Simd<u64, 8> {
        Simd::from_le_bytes(bytes)
    }

    #[inline]
    fn simd_to_bytes(x: Simd<u64, 8>) -> Simd<u8, 64> {
        x.to_le_bytes()
    }

    #[inline]
    fn kind() -> EndiannessTag {
        EndiannessTag::Little
    }
}

impl Endian for BigEndian {
    #[inline]
    fn u64_from_bytes(b: &[u8; 8]) -> u64 {
        u64::from_be_bytes(*b)
    }

    #[inline]
    fn u64_to_bytes(x: u64) -> [u8; 8] {
        x.to_be_bytes()
    }

    #[inline]
    fn simd_from_bytes(bytes: Simd<u8, 64>) -> Simd<u64, 8> {
        Simd::from_be_bytes(bytes)
    }

    #[inline]
    fn simd_to_bytes(x: Simd<u64, 8>) -> Simd<u8, 64> {
        x.to_be_bytes()
    }

    #[inline]
    fn kind() -> EndiannessTag {
        EndiannessTag::Big
    }
}
