use std::simd::{Simd, ToBytes};

use serde::{Deserialize, Serialize};

pub trait Endian: Send + Sync + 'static {
    fn u64_from_bytes(bytes: &[u8; 8]) -> u64;
    fn u64_to_bytes(x: u64) -> [u8; 8];
    fn simd_from_bytes(bytes: Simd<u8, 64>) -> Simd<u64, 8>;
    fn simd_to_bytes(x: Simd<u64, 8>) -> Simd<u8, 64>;
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum EndiannessTag {
    Little,
    Big,
}

impl Default for EndiannessTag {
    #[inline]
    fn default() -> Self {
        const TEST: u16 = 1;
        if TEST.to_le_bytes() == TEST.to_ne_bytes() {
            EndiannessTag::Little
        } else {
            EndiannessTag::Big
        }
    }
}

pub struct NativeEndian;
pub struct LittleEndian;
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
}
