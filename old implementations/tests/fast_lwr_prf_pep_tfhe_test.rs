use pq_libpep::core::fast_lwr_prf::{FastLwrPrf, FastLwrPrfParameters, FastLwrPrfSecretKey};
use pq_libpep::core::fast_lwr_prf_pep_tfhe::{output_symbols_for_bytes, setup_pep_lwr_prf};
use std::time::Instant;

fn small_fixture() -> (FastLwrPrfParameters, FastLwrPrfSecretKey) {
    let parameters = FastLwrPrfParameters {
        lwr_dimension: 8,
        ring_dimension: 64,
        output_modulus: 4,
    };
    let key = FastLwrPrfSecretKey::from_bits(parameters, vec![1, 0, 1, 1, 0, 1, 0, 1])
        .expect("valid toy PRF key");
    (parameters, key)
}

#[test]
fn pep_private_input_one_pbs_matches_cleartext_reference_for_multiple_slots() {
    // Functional-only toy parameters; never use these parameters for security.
    let (parameters, prf_key) = small_fixture();
    let reference = FastLwrPrf::new(prf_key.clone());
    let (source, recipient, evaluator) =
        setup_pep_lwr_prf(parameters, &prf_key).expect("generate test contexts");

    let identifier = b"pqpep-private-input-fast-path";
    let count = 4;
    let encrypted_inputs = source
        .encrypt_inputs(identifier, count)
        .expect("source encrypts H(identifier, slot)");
    let encrypted_outputs = evaluator
        .evaluate_many(&encrypted_inputs)
        .expect("transcryptor evaluates encrypted slots");
    let actual = recipient
        .decrypt_many_outputs(&encrypted_outputs)
        .expect("recipient decrypts outputs")
        .into_iter()
        .map(u64::from)
        .collect::<Vec<_>>();
    let expected = reference.evaluate_many(identifier, count);
    assert_eq!(actual, expected);

    // Single-slot API is exactly the first indexed component H(x,1).
    let one_input = source.encrypt_input(identifier, 1).unwrap();
    let one_output = evaluator.evaluate(&one_input).unwrap();
    assert_eq!(
        recipient.decrypt_output(&one_output).unwrap() as u64,
        reference.evaluate(identifier)
    );
}

#[test]
fn pep_private_input_byte_output_has_expected_slot_count_and_packs_correctly() {
    let parameters = FastLwrPrfParameters {
        lwr_dimension: 2,
        ring_dimension: 64,
        output_modulus: 4,
    };
    let prf_key = FastLwrPrfSecretKey::from_bits(parameters, vec![1, 0]).unwrap();
    let reference = FastLwrPrf::new(prf_key.clone());
    let (source, recipient, evaluator) = setup_pep_lwr_prf(parameters, &prf_key).unwrap();

    assert_eq!(output_symbols_for_bytes(parameters, 1).unwrap(), 4);
    let identifier = b"toy-id";
    let encrypted_inputs = source
        .encrypt_inputs_for_output_bytes(identifier, 1)
        .unwrap();
    let encrypted_outputs = evaluator
        .evaluate_outputs_for_bytes(&encrypted_inputs, 1)
        .unwrap();
    let actual = recipient
        .decrypt_outputs_to_bytes(&encrypted_outputs, 1)
        .unwrap();

    let reference_symbols = reference
        .evaluate_many(identifier, 4)
        .into_iter()
        .map(|x| x as u8)
        .collect::<Vec<_>>();
    let expected = recipient
        .pack_symbols_to_bytes(&reference_symbols, 1)
        .unwrap();
    assert_eq!(actual, expected);
    assert_eq!(actual.len(), 1);
}

#[test]
fn pep_private_input_rejects_zero_output_index_and_incomplete_bytes() {
    let (parameters, prf_key) = small_fixture();
    let (source, _recipient, evaluator) = setup_pep_lwr_prf(parameters, &prf_key).unwrap();
    assert!(source.encrypt_input(b"id", 0).is_err());

    let incomplete = source.encrypt_inputs(b"id", 2).unwrap();
    assert!(evaluator
        .evaluate_outputs_for_bytes(&incomplete, 1)
        .is_err());
}

#[test]
fn paper_parameters_need_103_slots_for_64_bytes() {
    assert_eq!(
        output_symbols_for_bytes(FastLwrPrfParameters::paper_default(), 64).unwrap(),
        103
    );
}

#[test]
#[ignore = "paper-size TFHE parameters; explicit release benchmark"]
fn paper_default_private_input_prf_produces_64_byte_pseudonym() {
    let total = Instant::now();
    let parameters = FastLwrPrfParameters::paper_default();
    let mut rng = rand::rngs::OsRng;

    let t = Instant::now();
    let prf_key = FastLwrPrfSecretKey::generate(parameters, &mut rng).unwrap();
    eprintln!("[BENCH] PRF key generation: {:.3?}", t.elapsed());

    let reference = FastLwrPrf::new(prf_key.clone());
    let identifier = b"pqpep-paper-parameters-private-input-test";

    let t = Instant::now();
    let (source, recipient, evaluator) =
        setup_pep_lwr_prf(parameters, &prf_key).unwrap();
    eprintln!("[BENCH] PEP setup + bootstrapping key: {:.3?}", t.elapsed());

    let t = Instant::now();
    let encrypted_inputs = source
        .encrypt_inputs_for_output_bytes(identifier, 64)
        .expect("encrypt all 103 indexed hash vectors");
    assert_eq!(encrypted_inputs.len(), 103);
    eprintln!("[BENCH] Encrypt 103 inputs: {:.3?}", t.elapsed());

    let t = Instant::now();
    let encrypted_outputs = evaluator
        .evaluate_outputs_for_bytes(&encrypted_inputs, 64)
        .expect("evaluate all output slots");
    eprintln!("[BENCH] Evaluate 103 slots: {:.3?}", t.elapsed());

    let t = Instant::now();
    let actual_symbols = recipient
        .decrypt_many_outputs(&encrypted_outputs)
        .expect("recipient decrypts output symbols");
    eprintln!("[BENCH] Decrypt output symbols: {:.3?}", t.elapsed());

    let t = Instant::now();
    let expected_symbols = reference
        .evaluate_many(identifier, 103)
        .into_iter()
        .map(|symbol| symbol as u8)
        .collect::<Vec<_>>();
    eprintln!("[BENCH] Cleartext reference: {:.3?}", t.elapsed());

    let mismatches = actual_symbols
        .iter()
        .zip(expected_symbols.iter())
        .enumerate()
        .filter_map(|(i, (actual, expected))| {
            (actual != expected).then_some((i + 1, *actual, *expected))
        })
        .collect::<Vec<_>>();

    assert!(
        mismatches.is_empty(),
        "PRF symbol mismatches (slot, actual, expected): {mismatches:?}"
    );

    let t = Instant::now();
    let actual = recipient
        .pack_symbols_to_bytes(&actual_symbols, 64)
        .expect("pack encrypted PRF output");
    let expected = recipient
        .pack_symbols_to_bytes(&expected_symbols, 64)
        .expect("pack cleartext reference output");
    assert_eq!(actual, expected);
    eprintln!("[BENCH] Pack and compare output: {:.3?}", t.elapsed());

    eprintln!("[BENCH] TOTAL: {:.3?}", total.elapsed());
}