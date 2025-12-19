//! This module provides the [`VerifierMemory`] structure, which is a sparse representation 
//! of the memory array. 
//! 
//! During verification, the entire memory dataset is not available; instead, only the 
//! elements revealed as part of the proof are stored and indexed.

use std::collections::HashMap;

use crate::{
    endianness::Endian,
    memory::{Element, PartialMemory},
};

/// A sparse representation of memory used by the verifier.
/// 
/// Unlike the full `Memory` struct used by the solver, `VerifierMemory` only contains
/// the specific memory elements revealed in a proof, indexed by their original positions.
pub struct VerifierMemory<E: Endian> {
    /// Internal storage mapping original memory indices to their revealed [`Element`] data.
    data: HashMap<usize, Element<E>>,
}

impl<E: Endian> Default for VerifierMemory<E> {
    /// Creates an empty [`VerifierMemory`] instance with no pre-allocated elements.
    fn default() -> Self {
        Self {
            data: Default::default(),
        }
    }
}

impl<E: Endian> VerifierMemory<E> {
    /// Inserts a memory element at the specified index.
    /// 
    /// Returns the previous element at that index, if any.
    pub fn insert(&mut self, k: usize, v: Element<E>) -> Option<Element<E>> {
        self.data.insert(k, v)
    }

    /// Returns an iterator over the memory elements present in this partial memory.
    pub fn iter(&self) -> std::collections::hash_map::Iter<'_, usize, Element<E>> {
        self.data.iter()
    }
}

impl<E: Endian> PartialMemory<E> for VerifierMemory<E> {
    /// Retrieves an element from the sparse memory if it exists.
    /// 
    /// Returns `Some(Element)` if the index was revealed in the proof, otherwise `None`.
    fn get_element(&self, index: usize) -> Option<Element<E>> {
        self.data.get(&index).copied()
    }
}
