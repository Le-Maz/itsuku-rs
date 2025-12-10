use crate::{config::Config, endianness::LittleEndian, memory::Memory};
use hex_literal::hex;

use super::*;

const LANES: usize = ELEMENT_SIZE.div_ceil(8);

#[test]
fn element_zero_is_correct() {
    let z = Element::<LittleEndian>::zero();
    assert_eq!(z.data.to_array(), [0u64; LANES]);
}

#[test]
fn xor_of_identical_elements_is_zero() {
    let mut el1 = Element::<LittleEndian>::zero();
    for (i, lane) in el1.data.as_mut_array().iter_mut().enumerate() {
        *lane = (i as u64) * 0x1234_5678_ABCD_EF01u64;
    }

    let el2 = el1;

    let mut x = el1;
    x ^= &el2;

    assert_eq!(x, Element::<LittleEndian>::zero());
}

#[test]
fn xor_matches_scalar_xor() {
    let mut el1 = Element::<LittleEndian>::zero();
    let mut el2 = Element::<LittleEndian>::zero();

    for (i, lane) in el1.data.as_mut_array().iter_mut().enumerate() {
        *lane = (i as u64).wrapping_mul(0xFFEEDDCCBBAA9988);
    }
    for (i, lane) in el2.data.as_mut_array().iter_mut().enumerate() {
        *lane = (i as u64).wrapping_mul(0x1122334455667788);
    }

    let mut simd_res = el1;
    simd_res ^= &el2;

    let mut scalar_res = [0u64; LANES];
    for (i, res_part) in scalar_res.iter_mut().enumerate() {
        *res_part = el1.data[i] ^ el2.data[i];
    }

    assert_eq!(simd_res.data.to_array(), scalar_res);
}

#[test]
fn add_matches_scalar_add() {
    let mut el1 = Element::<LittleEndian>::zero();
    let mut el2 = Element::<LittleEndian>::zero();

    for (i, lane) in el1.data.as_mut_array().iter_mut().enumerate() {
        *lane = (i as u64).wrapping_mul(0x1111111111111111);
    }
    for (i, lane) in el2.data.as_mut_array().iter_mut().enumerate() {
        *lane = (i as u64).wrapping_mul(0x2222222222222222);
    }

    let mut simd_res = el1;
    simd_res += &el2;

    let mut scalar_res = [0u64; LANES];

    for (i, res_part) in scalar_res.iter_mut().enumerate() {
        *res_part = el1.data[i].wrapping_add(el2.data[i]);
    }

    assert_eq!(simd_res.data.to_array(), scalar_res);
}

#[test]
fn lane_count_is_correct() {
    // Static sanity check: 64 bytes should produce exactly 8 lanes of u64
    assert_eq!(LANES * 8, ELEMENT_SIZE);
}

fn build_test_challenge() -> ChallengeId {
    let mut bytes = [0u8; 64];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = i as u8;
    }
    ChallengeId { bytes }
}

#[test]
fn compare_with_goldens() {
    let config = Config {
        chunk_count: 2,
        chunk_size: 8,
        ..Config::default()
    };

    let challenge_id = build_test_challenge();

    let mut memory = Memory::<LittleEndian>::new(config);

    memory.build_all_chunks(&challenge_id);

    const EXPECTED: [[u8; 64]; 8] = [
        hex!(
            "bfaa820cbe6ba0089574cb3542d412b63bf2a67b18db2b1fec01e05d67e61a494a29b467e31f762bc0ed6d0563fdc7f24e5033619d92a2dc9dde37285146009a"
        ),
        hex!(
            "822680f5c9010d753a5d4f43eda2388c39de635ac16721c6995d2221166c2fc52b5fb644ee00f1e6e57ec49ff8f8f823aa4c3174ab159aa7620978abd915ca6f"
        ),
        hex!(
            "b5839565fcddfa90e2427cbcd625027816a8e611c863451b27efc10bcfd5d89296e32753e6e6a134f74ce760b3513f0670177499fde4cbfc3b426b18f5adb288"
        ),
        hex!(
            "7733af4af5a7031dc58cee6eeb3c838c1d1f06ae7c2722e5f8c4a423aa4ad720c260ee411a781617f2767d4000d57b98d790882195152c2e50f34d4dab7b8ceb"
        ),
        hex!(
            "93587dc15a1820e6a9062f897d9ace19548976af2eaf7bb33d90772d08d5091eeb104678626ec4e85f09a23f0e0d8ac5fc873b1f0884d0817265ac8ee7ff497f"
        ),
        hex!(
            "ff69dd0d69d9f902d10e18b6502a58c3f7e56278cf8207c29b22eb0753efb3e08c4d19aa82817ffbc9edb6e58581b167135a4dcbbb702114725803dc4000bc20"
        ),
        hex!(
            "ea0fa5b63f76f023c623c11316febe695ce9d2d8eee1d2135574a65b88713b5d269a63f2ea6bf2560b5f01b3e8109033ea6587dfb1d9be05a5056cb8a482e19b"
        ),
        hex!(
            "db09868d506fb8d3d42fbf2fa1cc4749e4be5e6328af7afe58954f156cc54e83d1b5670ad0838472f5c5d107d730e0153c3fe2090e1d31760c5487422813540b"
        ),
    ];

    for (i, &expected) in EXPECTED.iter().enumerate() {
        let rust_el = memory.get(i).unwrap();
        let rust_bytes = rust_el.data.to_le_bytes().to_array();

        assert_eq!(
            rust_bytes, expected,
            "Mismatch at element {}:\nGot: {:02x?}\nExpected:    {:02x?}",
            i, rust_bytes, expected
        );
    }
}

#[test]
fn test_trace_element_reproducibility() {
    let config = Config {
        chunk_count: 2,
        chunk_size: 8,
        antecedent_count: 4,
        ..Config::default()
    };

    let challenge_id = build_test_challenge();

    let mut memory = Memory::<LittleEndian>::new(config);
    memory.build_all_chunks(&challenge_id);

    // Iterate over ALL elements and verify that tracing and recomputing works
    let total_elements = config.chunk_count * config.chunk_size;
    let antecedent_count = config.antecedent_count;
    let chunk_size = config.chunk_size;

    for global_index in antecedent_count..total_elements {
        // 1. Trace antecedents
        let antecedents = memory.trace_element(global_index);

        if global_index % chunk_size < antecedent_count {
            assert_eq!(antecedents.len(), 1);
            continue;
        }

        // trace_element for a compressed element should return exactly antecedent_count elements.
        assert_eq!(
            antecedents.len(),
            antecedent_count,
            "Trace length is incorrect for element index {}",
            global_index
        );

        // 2. Re-compute the element using the traced antecedents
        let challenge_element = challenge_id.bytes.into();
        let recomputed_element =
            Memory::compress(&antecedents, global_index as u64, &challenge_element);

        // 3. Assert that the recomputed element matches the original element
        let original_element = memory.get(global_index).unwrap();

        assert_eq!(original_element, &recomputed_element);
    }
}
