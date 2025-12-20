use crate::{config::Config, memory::Memory};

use super::*;

const LANES: usize = ELEMENT_SIZE.div_ceil(8);

#[test]
fn element_zero_is_correct() {
    let z = Element::zero();
    assert_eq!(z.data.to_array(), [0u64; LANES]);
}

#[test]
fn xor_of_identical_elements_is_zero() {
    let mut el1 = Element::zero();
    for (i, lane) in el1.data.as_mut_array().iter_mut().enumerate() {
        *lane = (i as u64) * 0x1234_5678_ABCD_EF01u64;
    }

    let el2 = el1;

    let mut x = el1;
    x ^= &el2;

    assert_eq!(x, Element::zero());
}

#[test]
fn xor_matches_scalar_xor() {
    let mut el1 = Element::zero();
    let mut el2 = Element::zero();

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
    let mut el1 = Element::zero();
    let mut el2 = Element::zero();

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

    let mut memory = Memory::new(config);

    memory.build_all_chunks(&challenge_id);

    let expected: [[u8; 64]; 8] = [
        *BASE64_URL_SAFE_NO_PAD.decode("v6qCDL5roAiVdMs1QtQStjvypnsY2ysf7AHgXWfmGklKKbRn4x92K8DtbQVj_cfyTlAzYZ2Sotyd3jcoUUYAmg").unwrap().first_chunk().unwrap(),
        *BASE64_URL_SAFE_NO_PAD.decode("giaA9ckBDXU6XU9D7aI4jDneY1rBZyHGmV0iIRZsL8UrX7ZE7gDx5uV-xJ_4-PgjqkwxdKsVmqdiCXir2RXKbw").unwrap().first_chunk().unwrap(),
        *BASE64_URL_SAFE_NO_PAD.decode("tYOVZfzd-pDiQny81iUCeBao5hHIY0UbJ-_BC8_V2JKW4ydT5uahNPdM52CzUT8GcBd0mf3ky_w7QmsY9a2yiA").unwrap().first_chunk().unwrap(),
        *BASE64_URL_SAFE_NO_PAD.decode("dzOvSvWnAx3FjO5u6zyDjB0fBq58JyLl-MSkI6pK1yDCYO5BGngWF_J2fUAA1XuY15CIIZUVLC5Q801Nq3uM6w").unwrap().first_chunk().unwrap(),
        *BASE64_URL_SAFE_NO_PAD.decode("oedFfANdjlevrQGiwjJ6tv5edwLq98oIezn1ShR6avRKQqcm0EjoBfk_AGQ9GgYugd4W6jYV51vr3ePMiZbS5Q").unwrap().first_chunk().unwrap(),
        *BASE64_URL_SAFE_NO_PAD.decode("LUmosI1g7ebVb_9hR2xx3d36ELOeWkrChKVmMwFhNTWrg5I0_iIOUXzR5yG91X84FWTvp4dKlkP-Jg2nXaZwvw").unwrap().first_chunk().unwrap(),
        *BASE64_URL_SAFE_NO_PAD.decode("xJjD9fm5FZpV5YtjhtiKZPYUT2aP53clkGc9ChFrYWuizZLbsZzw_-wmIrHiaejnoJGASjm84VLFg7BE41LTCA").unwrap().first_chunk().unwrap(),
        *BASE64_URL_SAFE_NO_PAD.decode("O7BOFvOQexReDBaF8zVH-PFl05sFaRHwV2s3QdPzhnxZwBBZWLeQ3eBYllsFLgfNqAPh4ytcBdGYksqoQyiOew").unwrap().first_chunk().unwrap(),
    ];

    for (i, &expected) in expected.iter().enumerate() {
        let rust_el = memory.get(i).unwrap();
        let rust_bytes = rust_el.data.to_le_bytes().to_array();

        assert_eq!(
            rust_bytes,
            expected,
            "Mismatch at element {}:\nGot: {}\nExpected: {}",
            i,
            BASE64_URL_SAFE_NO_PAD.encode(rust_bytes),
            BASE64_URL_SAFE_NO_PAD.encode(expected)
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

    let mut memory = Memory::new(config);
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
