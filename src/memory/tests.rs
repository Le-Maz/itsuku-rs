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
fn xor_with_slice_matches_scalar() {
    let mut el = Element::<LittleEndian>::zero();

    // Fill the SIMD element with a known pattern
    for (i, lane) in el.data.as_mut_array().iter_mut().enumerate() {
        *lane = 0x0102030405060708u64.wrapping_mul(i as u64 + 1);
    }

    // Construct a 64-byte slice we XOR with
    let mut array = [0u8; ELEMENT_SIZE];
    for (i, part) in array.iter_mut().enumerate() {
        *part = (i as u8).wrapping_mul(7).wrapping_add(3);
    }

    // Compute expected result with scalar operations
    let mut expected = [0u64; LANES];
    for lane in 0..LANES {
        let mut word_bytes = [0u8; 8];
        word_bytes.copy_from_slice(&array[lane * 8..lane * 8 + 8]);
        let rhs_word = u64::from_le_bytes(word_bytes);
        expected[lane] = el.data[lane] ^ rhs_word;
    }

    // Apply SIMD XOR
    let mut simd_el = el;
    simd_el ^= array.as_slice();

    assert_eq!(simd_el.data.to_array(), expected);
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
    ChallengeId {
        bytes: bytes.to_vec(),
    }
}

#[test]
fn compare_with_c_reference_output() {
    let config = Config {
        chunk_count: 2,
        chunk_size: 8,
        ..Config::default()
    };

    let challenge_id = build_test_challenge();

    let mut memory = Memory::<LittleEndian>::new(config);

    memory.build_all_chunks(&challenge_id);

    // ---- Expected output from C reference ----

    const EXPECTED: [[u8; 64]; 8] = [
        hex!(
            "3b1da82003c6c8749ed080b4ad02043638f158ca52e8f19b15bebfd15ecb92b436fcb9ceef092b5f6f8b722fecec6fe0ed5f7beb3ab855b42edbd306ddc7b297"
        ),
        hex!(
            "cb87b2a8628b61bf35cb4b67faa7d03bc0272e2c3210b584014ee23ee2c48d9209bf7ec5383ae9ed419dab2e8317cfc966b46f49288d4f470ddf64955c4a1389"
        ),
        hex!(
            "7f3c7902197eda4bf7682cc2c3c7a2b3ef37936fd4ee8a6d36c089592c764703d23b62619f153449fbc5f2ca84eec38cee6ebf786fcbfccb3db22adb5254d5ed"
        ),
        hex!(
            "0132ee4240bc64733517790a4406ed1b4a42698f40133ae2f9f65e4dac06605f81de400843b74498d3052af58649f6eaaa12a443954d0aefddef52c4764d53c7"
        ),
        hex!(
            "870d931c871173138163f54134c150876679e63a0c434075d3f474b669799a8b952426862531b5892063718b7b0445bb9ee671d45df6572e02410707e2675f41"
        ),
        hex!(
            "97e2a1af68abf9658a6b731da7815f320cd363835fbbaab87129e3c699692d71dde4146571fe340ee978e9bffd12119cea847ed5999ca332d2ab43cd971d963d"
        ),
        hex!(
            "2b6d8d0afcab11115d7ec82b020b7fac8421862b6412020aa67361f25cd305cf5e3610129d0ac6ab7d5cda519bc2eee80dd48d144bb59f91cae8b189c98828d0"
        ),
        hex!(
            "6e3f7633fe74120bcbea86e34dfa49d6a939d06f29945175015e4b312ec41e47d2b12a9cf00ce5f80da94d029c42f79426723071b49a568338964d42e3aff578"
        ),
    ];

    for (i, &expected) in EXPECTED.iter().enumerate() {
        let rust_el = memory.get(i).unwrap();
        let rust_bytes = rust_el.data.to_le_bytes().to_array();

        assert_eq!(
            rust_bytes, expected,
            "Mismatch at element {}:\nRust: {:02x?}\nC:    {:02x?}",
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
        let recomputed_element = Memory::compress(&antecedents, global_index as u64, &challenge_id);

        // 3. Assert that the recomputed element matches the original element
        let original_element = memory.get(global_index).unwrap();

        assert_eq!(original_element, &recomputed_element);
    }
}
