use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Config {
    pub chunk_size: usize,
    pub chunk_count: usize,
    pub antecedent_count: usize,
    pub difficulty_bits: usize,
    pub search_length: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chunk_size: 1 << 15,
            chunk_count: 1 << 10,
            difficulty_bits: 24,
            antecedent_count: 4,
            search_length: 9,
        }
    }
}
