use hex_literal::hex;

use super::*;
use crate::{challenge_id::ChallengeId, config::Config, endianness::LittleEndian, memory::Memory};

const EXPECTED_ROOT_HASH: &[u8] = &hex!("bf8dbfafcc");

fn build_test_challenge() -> ChallengeId {
    let mut bytes = [0u8; 64];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = i as u8;
    }
    ChallengeId { bytes }
}

#[test]
fn merkle_root_matches_golden() {
    let config = Config {
        chunk_count: 2,
        chunk_size: 8,
        ..Config::default()
    };

    let challenge_id = build_test_challenge();

    let mut memory = Memory::<LittleEndian>::new(config);
    memory.build_all_chunks(&challenge_id);

    let mut tree = MerkleTree::new(config);

    tree.compute_leaf_hashes(&challenge_id, &memory);
    tree.compute_intermediate_nodes(&challenge_id);

    let root_hash = tree.get_node(0).unwrap();
    assert_eq!(&root_hash[..5], EXPECTED_ROOT_HASH);
}
