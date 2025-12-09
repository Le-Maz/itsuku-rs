use crate::{
    challenge_id::ChallengeId,
    config::Config,
    endianness::{BigEndian, Endian, LittleEndian, NativeEndian},
    memory::Memory,
    merkle_tree::MerkleTree,
    proof::Proof,
};

fn build_test_challenge() -> ChallengeId {
    let mut bytes = [0u8; 64];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = i as u8;
    }
    ChallengeId {
        bytes: bytes.to_vec(),
    }
}

fn solves_and_verifies<E: Endian>() -> Proof {
    // 1) Create config matching C test
    let config = Config {
        chunk_count: 16,
        chunk_size: 64,
        difficulty_bits: 8,
        ..Config::default()
    };

    let challenge_id = build_test_challenge();

    // 2) Build memory
    let mut memory = Memory::<E>::new(config);
    memory.build_all_chunks(&challenge_id);

    // 3) Build Merkle tree
    let mut merkle_tree = MerkleTree::new(config);

    // Compute leaf hashes and intermediate nodes
    merkle_tree.compute_leaf_hashes(&challenge_id, &memory);
    merkle_tree.compute_intermediate_nodes(&challenge_id);

    // 4) Search for the proof
    let proof = Proof::search(config, &challenge_id, &memory, &merkle_tree);

    // 5) Verify the proof
    assert!(proof.verify().is_ok(), "Proof failed verification");

    proof
}

#[test]
fn prove_and_verify_native_endian() {
    solves_and_verifies::<NativeEndian>();
}

#[test]
fn prove_and_verify_little_endian() {
    solves_and_verifies::<LittleEndian>();
}

#[test]
fn prove_and_verify_big_endian() {
    solves_and_verifies::<BigEndian>();
}

#[test]
fn proof_inner_fails_on_diffferent_endianness() {
    let proof_le = solves_and_verifies::<LittleEndian>();
    let proof_be = solves_and_verifies::<BigEndian>();

    // Verify that a little-endian proof fails verification when interpreted as big-endian
    assert!(
        proof_le.verify_inner::<BigEndian>().is_err(),
        "Little-endian proof incorrectly verified as big-endian"
    );

    // Verify that a big-endian proof fails verification when interpreted as little-endian
    assert!(
        proof_be.verify_inner::<LittleEndian>().is_err(),
        "Big-endian proof incorrectly verified as little-endian"
    );
}
