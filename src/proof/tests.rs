use crate::{
    challenge_id::ChallengeId,
    config::Config,
    memory::Memory,
    merkle_tree::MerkleTree,
    proof::{Proof, search_params::SolverSearchParams},
};

fn build_test_challenge() -> ChallengeId {
    let mut bytes = [0u8; 64];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = i as u8;
    }
    ChallengeId { bytes }
}

#[test]
fn solves_and_verifies() {
    // 1) Create config matching C test
    let config = Config {
        chunk_count: 16,
        chunk_size: 64,
        difficulty_bits: 8,
        ..Config::default()
    };

    let challenge_id = build_test_challenge();

    // 2) Build memory
    let mut memory = Memory::new(config);
    memory.build_all_chunks(&challenge_id);

    // 3) Build Merkle tree
    let mut merkle_tree = MerkleTree::new(config);

    // Compute leaf hashes and intermediate nodes
    merkle_tree.compute_leaf_hashes(&challenge_id, &memory);
    merkle_tree.compute_intermediate_nodes(&challenge_id);

    // 4) Search for the proof
    let proof = Proof::search(SolverSearchParams {
        config: &config,
        challenge_id: &challenge_id,
        memory: &memory,
        merkle_tree: &merkle_tree,
    });

    // 5) Verify the proof
    assert!(proof.verify().is_ok(), "Proof failed verification");
}
