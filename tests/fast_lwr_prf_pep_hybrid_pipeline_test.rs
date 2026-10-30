#![cfg(feature = "fast-prf-tfhe-private-input")]

use pq_libpep::algebra::ring::{PolyRq, Q};
use pq_libpep::core::fast_lwr_prf::{
    FastLwrPrf, FastLwrPrfParameters, FastLwrPrfSecretKey,
};
use pq_libpep::core::fast_lwr_prf_pep_ks128_e16_pipeline::{
    output_symbols_for_bytes, setup_pep_lwr_prf,
};
use pq_libpep::core::fast_lwr_prf_pep_hybrid_pipeline::{
    HybridPepRecipient, HybridPepSource, HybridPepTranscryptor,
    PreparedHybridPepRequest,
};
use pq_libpep::core::id_encoding::string_to_id;
use pq_libpep::core::rlwe::KeyGenResult;
use pq_libpep::core::rlwe_pke::encrypt_poly;
use pq_libpep::core::rlwe_pre::generate_rekey;
#[cfg(feature = "experimental-linear-reshuffle")]
use pq_libpep::core::params::prf_modulus_chain;
#[cfg(feature = "experimental-linear-reshuffle")]
use pq_libpep::core::reshuffle::derive_invertible_reshuffle_factor;
#[cfg(feature = "experimental-linear-reshuffle")]
use pq_libpep::core::rlwr_prf::{RlwrPrf, RlwrPrfBase};
use rand::{rngs::OsRng, rngs::StdRng, RngCore, SeedableRng};

const TARGET_BYTES: usize = 32;
const PAYLOAD_RING_N: usize = 64;
const RLWE_REKEY_BASE_BITS: usize = 4;
const TOY_ITEM_LIMIT: usize = 4 * 1024 * 1024;

fn pack_symbols_for_test(
    parameters: FastLwrPrfParameters,
    symbols: &[u64],
    output_len_bytes: usize,
) -> Vec<u8> {
    let bits_per_symbol =
        parameters.output_modulus.trailing_zeros() as usize;
    let required_bits = output_len_bytes * 8;

    assert!(symbols.len() * bits_per_symbol >= required_bits);

    let mut out = vec![0u8; output_len_bytes];
    let mut bit_index = 0usize;

    for &symbol in symbols {
        assert!(symbol < parameters.output_modulus);

        for bit_pos in (0..bits_per_symbol).rev() {
            if bit_index == required_bits {
                return out;
            }

            out[bit_index / 8] |=
                (((symbol >> bit_pos) & 1) as u8)
                    << (7 - bit_index % 8);

            bit_index += 1;
        }
    }

    out
}

fn assert_hybrid_result(
    parameters: FastLwrPrfParameters,
    id: &[u8],
    reference: &FastLwrPrf,
    recipient: &HybridPepRecipient,
    response_wire: &[u8],
    transaction_id: &[u8; 16],
    batch_id: &[u8; 16],
    target_bytes: usize,
    expected_payload: &[u64],
) {
    let result = recipient
        .open_response_wire(
            response_wire,
            transaction_id,
            batch_id,
            target_bytes,
        )
        .expect("recipient validates and decrypts hybrid response");

    let symbol_count =
        output_symbols_for_bytes(parameters, target_bytes).unwrap();

    let expected_symbols =
        reference.evaluate_many(id, symbol_count);

    let expected_pseudonym = pack_symbols_for_test(
        parameters,
        &expected_symbols,
        target_bytes,
    );

    assert_eq!(
        result.pseudonym.len(),
        target_bytes,
        "pseudonym has the requested byte length",
    );

    assert_eq!(
        result.pseudonym,
        expected_pseudonym,
        "TFHE output matches the cleartext LWR-PRF reference",
    );

    assert_eq!(
        result.payload_coefficients.len(),
        PAYLOAD_RING_N,
        "RLWE payload returns exactly n application coefficients",
    );

    assert_eq!(
        result.payload_coefficients,
        expected_payload,
        "RLWE PRE preserves the application payload",
    );

    assert_eq!(
        result.transaction_id,
        *transaction_id,
        "response is bound to the expected transaction",
    );

    assert_eq!(
        result.batch_id,
        *batch_id,
        "response is bound to the expected PRF batch",
    );
}

fn run_hybrid_transaction<R: RngCore>(
    parameters: FastLwrPrfParameters,
    rng: &mut R,
) {
    let id = string_to_id("patient-001");

    let prf_key =
        FastLwrPrfSecretKey::generate(parameters, rng).unwrap();

    let reference = FastLwrPrf::new(prf_key.clone());

    // Centralized setup is intentional for this experimental test.
    // It does not establish distributed n-PEP key generation.
    let (tfhe_source, tfhe_recipient, tfhe_evaluator) =
        setup_pep_lwr_prf(parameters, &prf_key)
            .expect("TFHE setup");

    let alice = KeyGenResult::keygen(rng, PAYLOAD_RING_N);
    let bob = KeyGenResult::keygen(rng, PAYLOAD_RING_N);

    let expected_payload = (0..PAYLOAD_RING_N)
        .map(|i| ((i * 7 + 3) % 17) as u64)
        .collect::<Vec<_>>();

    let payload_plain =
        PolyRq::from_coeffs(
            &expected_payload,
            PAYLOAD_RING_N,
            Q,
        );

    let payload_ciphertext_a =
        encrypt_poly(
            rng,
            &alice.pk,
            &payload_plain,
            PAYLOAD_RING_N,
        );

    let rekey_ab =
        generate_rekey(
            rng,
            &alice.sk,
            &bob.pk,
            RLWE_REKEY_BASE_BITS,
        );

    let source = HybridPepSource::new(tfhe_source);

    let transcryptor = HybridPepTranscryptor::new(
        tfhe_evaluator,
        rekey_ab,
        bob.pk,
        RLWE_REKEY_BASE_BITS,
    )
    .expect("hybrid transcryptor setup");

    let recipient =
        HybridPepRecipient::new(
            tfhe_recipient,
            bob.sk,
            PAYLOAD_RING_N,
        )
        .expect("hybrid recipient setup");

    let request = source
        .prepare_request(
            &id,
            &payload_ciphertext_a,
            TARGET_BYTES,
        )
        .expect("source prepares hybrid request");

    assert_eq!(
        &request.wire_bytes()[..4],
        b"HPRQ",
        "request uses the expected envelope magic",
    );

    assert_eq!(
        request.wire_bytes()[4],
        1,
        "request wire version is explicit",
    );

    let transaction_id = request.transaction_id();
    let batch_id = request.batch_id();

    // The outer batch tag must agree with the embedded indexed PLPI inputs.
    let mut wrong_batch_wire = request.wire_bytes().to_vec();
    wrong_batch_wire[21] ^= 0x01;

    let batch_error = transcryptor
        .process_request_wire(&wrong_batch_wire, rng)
        .expect_err("modified batch tag must be rejected");

    assert!(
        batch_error
            .to_string()
            .contains("mixed batch ID or invalid index order"),
        "wrong-batch rejection should identify the binding failure: {batch_error}",
    );

    let response_wire = transcryptor
        .process_request_wire(request.wire_bytes(), rng)
        .expect(
            "transcryptor evaluates TFHE and rekeys/rerandomizes RLWE",
        );

    let wrong_transaction = [0xA5u8; 16];

    let tx_error = recipient
        .open_response_wire(
            &response_wire,
            &wrong_transaction,
            &batch_id,
            TARGET_BYTES,
        )
        .expect_err(
            "response for a different transaction must be rejected",
        );

    assert!(
        tx_error
            .to_string()
            .contains("transaction or batch ID"),
        "transaction mismatch should be diagnosed: {tx_error}",
    );

    assert_hybrid_result(
        parameters,
        &id,
        &reference,
        &recipient,
        &response_wire,
        &transaction_id,
        &batch_id,
        TARGET_BYTES,
        &expected_payload,
    );
}

struct ToyFixture {
    transcryptor: HybridPepTranscryptor,
    recipient: HybridPepRecipient,
    request: PreparedHybridPepRequest,
    rng: StdRng,
    transaction_id: [u8; 16],
    batch_id: [u8; 16],
    target_bytes: usize,
    expected_pseudonym: Vec<u8>,
    expected_payload: Vec<u64>,
}

fn make_toy_fixture(target_bytes: usize) -> ToyFixture {
    let mut rng =
        StdRng::seed_from_u64(
            0x4859_4252_4944_0001 ^ target_bytes as u64,
        );

    let parameters = FastLwrPrfParameters {
        lwr_dimension: 8,
        ring_dimension: 64,
        output_modulus: 4,
    };

    let id = string_to_id("patient-001");

    let prf_key =
        FastLwrPrfSecretKey::generate(parameters, &mut rng)
            .unwrap();

    let reference = FastLwrPrf::new(prf_key.clone());

    let (tfhe_source, tfhe_recipient, tfhe_evaluator) =
        setup_pep_lwr_prf(parameters, &prf_key)
            .expect("toy TFHE setup");

    let alice = KeyGenResult::keygen(&mut rng, PAYLOAD_RING_N);
    let bob = KeyGenResult::keygen(&mut rng, PAYLOAD_RING_N);

    let expected_payload = (0..PAYLOAD_RING_N)
        .map(|i| ((i * 7 + 3) % 17) as u64)
        .collect::<Vec<_>>();

    let payload_plain =
        PolyRq::from_coeffs(
            &expected_payload,
            PAYLOAD_RING_N,
            Q,
        );

    let payload_ciphertext_a =
        encrypt_poly(
            &mut rng,
            &alice.pk,
            &payload_plain,
            PAYLOAD_RING_N,
        );

    let rekey_ab =
        generate_rekey(
            &mut rng,
            &alice.sk,
            &bob.pk,
            RLWE_REKEY_BASE_BITS,
        );

    let source = HybridPepSource::new(tfhe_source);

    let transcryptor = HybridPepTranscryptor::new(
        tfhe_evaluator,
        rekey_ab,
        bob.pk,
        RLWE_REKEY_BASE_BITS,
    )
    .expect("toy hybrid transcryptor setup");

    let recipient =
        HybridPepRecipient::new(
            tfhe_recipient,
            bob.sk,
            PAYLOAD_RING_N,
        )
        .expect("toy hybrid recipient setup");

    let request = source
        .prepare_request(
            &id,
            &payload_ciphertext_a,
            target_bytes,
        )
        .expect("toy source prepares request");

    let transaction_id = request.transaction_id();
    let batch_id = request.batch_id();

    let symbol_count =
        output_symbols_for_bytes(parameters, target_bytes).unwrap();

    let expected_symbols =
        reference.evaluate_many(&id, symbol_count);

    let expected_pseudonym = pack_symbols_for_test(
        parameters,
        &expected_symbols,
        target_bytes,
    );

    ToyFixture {
        transcryptor,
        recipient,
        request,
        rng,
        transaction_id,
        batch_id,
        target_bytes,
        expected_pseudonym,
        expected_payload,
    }
}

fn expect_request_error(
    fixture: &mut ToyFixture,
    wire: &[u8],
    expected_fragment: &str,
) {
    let error = fixture
        .transcryptor
        .process_request_wire(wire, &mut fixture.rng)
        .expect_err("malformed request must be rejected");

    assert!(
        error.to_string().contains(expected_fragment),
        "expected request error containing {expected_fragment:?}, got: {error}",
    );
}

fn expect_response_error(
    fixture: &ToyFixture,
    wire: &[u8],
    expected_fragment: &str,
) {
    let error = fixture
        .recipient
        .open_response_wire(
            wire,
            &fixture.transaction_id,
            &fixture.batch_id,
            fixture.target_bytes,
        )
        .expect_err("malformed response must be rejected");

    assert!(
        error.to_string().contains(expected_fragment),
        "expected response error containing {expected_fragment:?}, got: {error}",
    );
}

fn item_ranges(
    frame: &[u8],
    count_offset: usize,
    first_length_offset: usize,
) -> Vec<std::ops::Range<usize>> {
    let count = u32::from_le_bytes(
        frame[count_offset..count_offset + 4]
            .try_into()
            .unwrap(),
    ) as usize;

    let mut cursor = first_length_offset;
    let mut ranges = Vec::with_capacity(count);

    for _ in 0..count {
        let len = u32::from_le_bytes(
            frame[cursor..cursor + 4]
                .try_into()
                .unwrap(),
        ) as usize;

        cursor += 4;

        ranges.push(cursor..cursor + len);
        cursor += len;

        assert!(
            cursor <= frame.len(),
            "test helper parsed an item outside the frame",
        );
    }

    ranges
}

fn swap_first_two_items(frame: &mut [u8]) {
    let ranges = item_ranges(frame, 41, 45);

    assert!(
        ranges.len() >= 2,
        "test fixture must contain at least two slots",
    );

    assert_eq!(
        ranges[0].len(),
        ranges[1].len(),
        "fixed-size ciphertext wires should have equal lengths",
    );

    let first = frame[ranges[0].clone()].to_vec();
    let second = frame[ranges[1].clone()].to_vec();

    frame[ranges[0].clone()].copy_from_slice(&second);
    frame[ranges[1].clone()].copy_from_slice(&first);
}

fn payload_offset(frame: &[u8]) -> usize {
    let ranges = item_ranges(frame, 41, 45);

    ranges
        .last()
        .map(|range| range.end)
        .expect("at least one PRF slot")
}

#[test]
fn toy_hybrid_transaction_round_trip_binds_pseudonym_and_payload() {
    let parameters = FastLwrPrfParameters {
        lwr_dimension: 8,
        ring_dimension: 64,
        output_modulus: 4,
    };

    let mut rng =
        StdRng::seed_from_u64(0x4859_4252_4944_0001);

    run_hybrid_transaction(parameters, &mut rng);
}

#[test]
fn hybrid_request_rejects_corrupt_headers_slots_and_rlwe_encoding() {
    // Two bytes keep malformed-input checks cheap and give multiple slots.
    let mut fixture = make_toy_fixture(2);
    let original = fixture.request.wire_bytes().to_vec();

    assert_eq!(
        u32::from_le_bytes(original[41..45].try_into().unwrap()),
        8,
        "p=4 uses two bits per symbol, so two bytes require eight slots",
    );

    let mut bad = original.clone();
    bad[0] ^= 0xFF;
    expect_request_error(
        &mut fixture,
        &bad,
        "invalid hybrid request magic",
    );

    let mut bad = original.clone();
    bad[4] = 2;
    expect_request_error(
        &mut fixture,
        &bad,
        "unsupported hybrid request version",
    );

    let mut bad = original.clone();
    bad.pop();
    expect_request_error(
        &mut fixture,
        &bad,
        "truncated hybrid wire frame",
    );

    let mut bad = original.clone();
    bad.push(0);
    expect_request_error(
        &mut fixture,
        &bad,
        "trailing bytes after hybrid wire frame",
    );

    let mut bad = original.clone();
    bad[21] ^= 0x01;
    expect_request_error(
        &mut fixture,
        &bad,
        "mixed batch ID or invalid index order",
    );

    let mut bad = original.clone();
    bad[41..45].copy_from_slice(&1u32.to_le_bytes());
    expect_request_error(
        &mut fixture,
        &bad,
        "wrong number of PRF input slots",
    );

    let mut bad = original.clone();
    bad[45..49].copy_from_slice(
        &((TOY_ITEM_LIMIT + 1) as u32).to_le_bytes(),
    );
    expect_request_error(
        &mut fixture,
        &bad,
        "exceeds maximum allowed length",
    );

    // PLPI v1: input-wire batch ID starts at +45;
    // the slot index starts at +61.
    let input_ranges = item_ranges(&original, 41, 45);
    let first_input = input_ranges[0].start;

    let mut bad = original.clone();
    bad[first_input + 45] ^= 0x01;
    expect_request_error(
        &mut fixture,
        &bad,
        "mixed batch ID or invalid index order",
    );

    let mut bad = original.clone();
    bad[first_input + 61..first_input + 69]
        .copy_from_slice(&2u64.to_le_bytes());
    expect_request_error(
        &mut fixture,
        &bad,
        "mixed batch ID or invalid index order",
    );

    let mut bad = original.clone();
    bad[first_input..first_input + 4].copy_from_slice(b"NOPE");
    expect_request_error(
        &mut fixture,
        &bad,
        "invalid or truncated PLPI input envelope",
    );

    let mut bad = original.clone();
    bad[first_input + 4] = 2;
    expect_request_error(
        &mut fixture,
        &bad,
        "invalid or truncated PLPI input envelope",
    );

    // PLPI v1 block count is at +69; the first GLWE coefficient
    // count is at +73. The complete batch is validated before PBS.
    let mut bad = original.clone();
    bad[first_input + 69..first_input + 73]
        .copy_from_slice(&0u32.to_le_bytes());
    expect_request_error(
        &mut fixture,
        &bad,
        "invalid GLWE block count",
    );

    let mut bad = original.clone();
    bad[first_input + 73..first_input + 81]
        .copy_from_slice(&0u64.to_le_bytes());
    expect_request_error(
        &mut fixture,
        &bad,
        "wire GLWE has an invalid coefficient count",
    );

    let mut bad = original.clone();
    swap_first_two_items(&mut bad);
    expect_request_error(
        &mut fixture,
        &bad,
        "mixed batch ID or invalid index order",
    );

    // RLWE tail begins after the input items.
    // The wire carries n coefficients, not PolyRq's internal n+1.
    let rlwe_offset = payload_offset(&original);

    let mut bad = original.clone();
    bad[rlwe_offset..rlwe_offset + 4]
        .copy_from_slice(
            &((PAYLOAD_RING_N + 1) as u32).to_le_bytes(),
        );
    expect_request_error(
        &mut fixture,
        &bad,
        "parameters do not match the configured key",
    );

    let mut bad = original.clone();

    let modulus = u64::from_le_bytes(
        bad[rlwe_offset + 4..rlwe_offset + 12]
            .try_into()
            .unwrap(),
    );

    // n(4) + q(8) + u count(4) = first u coefficient at +16.
    bad[rlwe_offset + 16..rlwe_offset + 24]
        .copy_from_slice(&modulus.to_le_bytes());

    expect_request_error(
        &mut fixture,
        &bad,
        "u coefficient is outside the modulus",
    );
}

#[test]
fn hybrid_response_rejects_corrupt_headers_count_order_and_rlwe_encoding() {
    let mut fixture = make_toy_fixture(2);

    let response = fixture
        .transcryptor
        .process_request_wire(
            fixture.request.wire_bytes(),
            &mut fixture.rng,
        )
        .expect("valid toy request produces a response");

    // Verify the unmodified response before mutation tests.
    let valid = fixture
        .recipient
        .open_response_wire(
            &response,
            &fixture.transaction_id,
            &fixture.batch_id,
            fixture.target_bytes,
        )
        .expect("valid toy response should decrypt");

    assert_eq!(valid.pseudonym, fixture.expected_pseudonym);
    assert_eq!(
        valid.payload_coefficients,
        fixture.expected_payload,
    );

    let mut bad = response.clone();
    bad[0] ^= 0xFF;
    expect_response_error(
        &fixture,
        &bad,
        "invalid hybrid response magic",
    );

    let mut bad = response.clone();
    bad[4] = 2;
    expect_response_error(
        &fixture,
        &bad,
        "unsupported hybrid response version",
    );

    let mut bad = response.clone();
    bad.pop();
    expect_response_error(
        &fixture,
        &bad,
        "truncated hybrid wire frame",
    );

    let mut bad = response.clone();
    bad.push(0);
    expect_response_error(
        &fixture,
        &bad,
        "trailing bytes after hybrid wire frame",
    );

    let mut bad = response.clone();
    bad[41..45].copy_from_slice(&1u32.to_le_bytes());
    expect_response_error(
        &fixture,
        &bad,
        "wrong number of PRF output slots",
    );

    let response_ranges = item_ranges(&response, 41, 45);
    let first_output = response_ranges[0].start;

    let mut bad = response.clone();
    bad[first_output..first_output + 4].copy_from_slice(b"NOPE");
    expect_response_error(
        &fixture,
        &bad,
        "invalid output wire magic",
    );

    let mut bad = response.clone();
    bad[first_output + 4] = 2;
    expect_response_error(
        &fixture,
        &bad,
        "unsupported output wire version",
    );

    let mut bad = response.clone();
    // PLPO v1 output index: +77..+85.
    bad[first_output + 77..first_output + 85]
        .copy_from_slice(&0u64.to_le_bytes());
    expect_response_error(
        &fixture,
        &bad,
        "invalid zero slot",
    );

    let mut bad = response.clone();
    swap_first_two_items(&mut bad);
    expect_response_error(
        &fixture,
        &bad,
        "contiguous one-based indices",
    );

    let mut bad = response.clone();
    let rlwe_offset = payload_offset(&response);

    let modulus = u64::from_le_bytes(
        bad[rlwe_offset + 4..rlwe_offset + 12]
            .try_into()
            .unwrap(),
    );

    bad[rlwe_offset + 16..rlwe_offset + 24]
        .copy_from_slice(&modulus.to_le_bytes());

    expect_response_error(
        &fixture,
        &bad,
        "u coefficient is outside the modulus",
    );

    let wrong_len_error = fixture
        .recipient
        .open_response_wire(
            &response,
            &fixture.transaction_id,
            &fixture.batch_id,
            fixture.target_bytes + 1,
        )
        .expect_err(
            "recipient must reject unexpected pseudonym length",
        );

    assert!(
        wrong_len_error
            .to_string()
            .contains("pseudonym length does not match"),
        "wrong pseudonym length should be diagnosed: {wrong_len_error}",
    );
}

#[test]
#[ignore = "paper LWR parameters; 52-symbol TFHE request/response plus RLWE PRE"]
fn paper_hybrid_transaction_round_trip_binds_32_byte_pseudonym_and_payload() {
    let mut rng = OsRng;
    run_hybrid_transaction(
        FastLwrPrfParameters::paper_default(),
        &mut rng,
    );
}

#[test]
#[cfg(feature = "experimental-linear-reshuffle")]
fn toy_hybrid_domain_transition_reshuffles_rekeys_and_rerandomizes() {
    // TFHE's ring parameter stays toy-sized and independent of the RLWE ring.
    // RLWE and the RLWR-derived reshuffling factor both use N=256.
    const RLWR_RLWE_N: usize = 256;
    const PLAINTEXT_P: u64 = 17;
    const PSEUDONYM_BYTES: usize = 2;

    let mut rng = StdRng::seed_from_u64(0xA2B3_C4D5_1020_3040);

    let fast_parameters = FastLwrPrfParameters {
        lwr_dimension: 8,
        ring_dimension: 64,
        output_modulus: 4,
    };
    let id = string_to_id("patient-001");

    // Independent TFHE PRF branch: patient ID -> 2-byte toy pseudonym.
    let fast_key = FastLwrPrfSecretKey::generate(fast_parameters, &mut rng)
        .expect("generate TFHE LWR PRF key");
    let fast_reference = FastLwrPrf::new(fast_key.clone());
    let (tfhe_source, tfhe_recipient, tfhe_evaluator) =
        setup_pep_lwr_prf(fast_parameters, &fast_key)
            .expect("setup TFHE pseudonymization branch");

    // Existing Ring-LWR/BPR12 PRF: its 256-bit input is used to derive
    // domain factors in R_17. The polynomial degree is also 256 to match RLWE.
    let moduli = prf_modulus_chain();
    let highest_modulus = *moduli.last().expect("non-empty modulus chain");
    let leaf_count = 1usize << (moduli.len() - 1);
    assert_eq!(leaf_count, 256, "32-byte IDs produce 256 input bits");

    let base = RlwrPrfBase::sample(
        &mut rng,
        RLWR_RLWE_N,
        highest_modulus,
        leaf_count,
    );
    let domain_prf = RlwrPrf::new(base, moduli);

    let factor_a = derive_invertible_reshuffle_factor(
        &domain_prf,
        "hospital-A",
        RLWR_RLWE_N,
        Q,
    )
    .expect("derive invertible domain-A factor");
    let factor_b = derive_invertible_reshuffle_factor(
        &domain_prf,
        "hospital-B",
        RLWR_RLWE_N,
        Q,
    )
    .expect("derive invertible domain-B factor");

    // Verify that the domain factors really have inverses in R_17.
    let identity_a = factor_a
        .factor_mod_p
        .mul_negacyclic(&factor_a.inverse_mod_p);
    assert_eq!(identity_a.coefficients()[0], 1);
    assert!(identity_a.coefficients()[1..RLWR_RLWE_N]
        .iter()
        .all(|&coefficient| coefficient == 0));

    let identity_b = factor_b
        .factor_mod_p
        .mul_negacyclic(&factor_b.inverse_mod_p);
    assert_eq!(identity_b.coefficients()[0], 1);
    assert!(identity_b.coefficients()[1..RLWR_RLWE_N]
        .iter()
        .all(|&coefficient| coefficient == 0));

    // Logical message M lives in R_17. For this transition test, the
    // source encrypts M*g_A; after the transition, B should obtain M*g_B.
    let original_coefficients: Vec<u64> = (0..RLWR_RLWE_N)
        .map(|i| ((i * 7 + 3) as u64) % PLAINTEXT_P)
        .collect();
    let original_mod_p = PolyRq::from_coeffs(
        &original_coefficients,
        RLWR_RLWE_N,
        PLAINTEXT_P,
    );
    let source_representation_mod_p = original_mod_p
        .mul_negacyclic(&factor_a.factor_mod_p);
    let expected_target_mod_p = original_mod_p
        .mul_negacyclic(&factor_b.factor_mod_p);

    // encrypt_poly expects coefficients represented modulo Q and applies
    // Delta=floor(Q/17) internally. Copy the canonical 0..16 plaintext reps
    // into R_Q; do not pre-scale them here.
    let source_representation_q = PolyRq::from_coeffs(
        &source_representation_mod_p.coefficients()[..RLWR_RLWE_N],
        RLWR_RLWE_N,
        Q,
    );

    let alice = KeyGenResult::keygen(&mut rng, RLWR_RLWE_N);
    let bob = KeyGenResult::keygen(&mut rng, RLWR_RLWE_N);
    let ciphertext_a = encrypt_poly(
        &mut rng,
        &alice.pk,
        &source_representation_q,
        RLWR_RLWE_N,
    );
    let rekey_ab = generate_rekey(
        &mut rng,
        &alice.sk,
        &bob.pk,
        RLWE_REKEY_BASE_BITS,
    );

    let transcryptor = HybridPepTranscryptor::new_with_domain_transition(
        tfhe_evaluator,
        rekey_ab,
        bob.pk,
        RLWE_REKEY_BASE_BITS,
        &domain_prf,
        "hospital-A",
        "hospital-B",
    )
    .expect("initialize RLWR reshuffle + RLWE PRE transcryptor");

    let recipient = HybridPepRecipient::new(
        tfhe_recipient,
        bob.sk,
        RLWR_RLWE_N,
    )
    .expect("initialize recipient with matching RLWE ring dimension");
    let source = HybridPepSource::new(tfhe_source);

    let request = source
        .prepare_request(&id, &ciphertext_a, PSEUDONYM_BYTES)
        .expect("prepare request carrying independent TFHE and RLWE branches");
    let transaction_id = request.transaction_id();
    let batch_id = request.batch_id();

    let response = transcryptor
        .process_request_wire(request.wire_bytes(), &mut rng)
        .expect("apply reshuffling, rekeying and rerandomization");

    let result = recipient
        .open_response_wire(
            &response,
            &transaction_id,
            &batch_id,
            PSEUDONYM_BYTES,
        )
        .expect("recipient validates and decrypts the response");

    // The key functional integration property: M*g_A -> M*g_B.
    assert_eq!(
        result.payload_coefficients,
        expected_target_mod_p.coefficients()[..RLWR_RLWE_N].to_vec(),
        "RLWE payload must transform from the source-domain encoding to the target-domain encoding",
    );

    // Independently check the TFHE pseudonym result against the cleartext PRF.
    let symbol_count =
        output_symbols_for_bytes(fast_parameters, PSEUDONYM_BYTES).unwrap();
    let expected_symbols = fast_reference.evaluate_many(&id, symbol_count);
    let expected_pseudonym = pack_symbols_for_test(
        fast_parameters,
        &expected_symbols,
        PSEUDONYM_BYTES,
    );
    assert_eq!(
        result.pseudonym,
        expected_pseudonym,
        "TFHE pseudonym must still match its own cleartext reference",
    );
    assert_eq!(result.transaction_id, transaction_id);
    assert_eq!(result.batch_id, batch_id);
}

#[test]
fn hybrid_rejects_complete_foreign_batch_and_foreign_source() {
    let mut f = make_toy_fixture(2);
    let response = f.transcryptor.process_request_wire(f.request.wire_bytes(), &mut f.rng).unwrap();
    // All PLPO items are changed coherently: old consistency-only checks accepted this.
    let ranges = item_ranges(&response, 41, 45);
    let mut foreign = response.clone();
    for range in &ranges { foreign[range.start + 61] ^= 1; }
    expect_response_error(&f, &foreign, "output batch does not match pending request");
    let source: [u8; 16] = response[ranges[0].start + 29..ranges[0].start + 45].try_into().unwrap();
    f.recipient.open_response_wire_in_context(&response, &f.transaction_id,
        &f.batch_id, f.target_bytes, &source).unwrap();
    let mut foreign = response.clone();
    for range in &ranges { foreign[range.start + 29] ^= 1; }
    assert!(f.recipient.open_response_wire_in_context(&foreign, &f.transaction_id,
        &f.batch_id, f.target_bytes, &source).is_err());
}
