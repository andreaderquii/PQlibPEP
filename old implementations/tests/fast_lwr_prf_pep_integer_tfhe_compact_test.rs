#![cfg(feature = "fast-prf-tfhe-private-input")]

use std::time::Instant;

use pq_libpep::core::fast_lwr_prf::{
    FastLwrPrf,
    FastLwrPrfParameters,
    FastLwrPrfSecretKey,
};
use pq_libpep::core::fast_lwr_prf_pep_integer_tfhe_compact::{
    output_symbols_for_bytes,
    pack_symbols_to_bytes,
    setup_pep_integer_tfhe_compact,
};

fn small_fixture() -> (FastLwrPrfParameters, FastLwrPrfSecretKey) {
    let parameters = FastLwrPrfParameters {
        lwr_dimension: 8,
        ring_dimension: 64,
        output_modulus: 4,
    };

    let key = FastLwrPrfSecretKey::from_bits(
        parameters,
        vec![1, 0, 1, 1, 0, 1, 0, 1],
    )
    .expect("valid toy key");

    (parameters, key)
}

/// Test funzionale con parametri toy e controlli degli indici.
#[test]
fn compact_input_integer_fhe_matches_cleartext_and_recipient_key() {
    let (parameters, prf_key) = small_fixture();
    let reference = FastLwrPrf::new(prf_key.clone());

    let t = Instant::now();
    let (source, recipient, evaluator) =
        setup_pep_integer_tfhe_compact(&prf_key)
            .expect("create source, recipient, and evaluator contexts");
    eprintln!("[COMPACT] setup: {:.2?}", t.elapsed());

    let identifier = b"compact-private-input-pep-test";

    assert_eq!(output_symbols_for_bytes(parameters, 1).unwrap(), 4);

    let expected_symbols = reference
        .evaluate_many(identifier, 4)
        .into_iter()
        .map(|x| x as u8)
        .collect::<Vec<_>>();

    let t = Instant::now();
    let encrypted_inputs = source
        .encrypt_inputs_for_output_bytes(identifier, 1)
        .expect("compact-encrypt indexed input vectors");
    eprintln!("[COMPACT] compact input encryption x4: {:.2?}", t.elapsed());

    assert_eq!(encrypted_inputs.len(), 4);
    assert!(
        encrypted_inputs
            .iter()
            .all(|input| input.coefficient_count() == parameters.lwr_dimension)
    );

    let t = Instant::now();
    let encrypted_outputs = evaluator
        .evaluate_outputs_for_bytes(&encrypted_inputs, 1)
        .expect("evaluate PRF homomorphically and key-switch outputs");
    eprintln!("[COMPACT] evaluate + key switch x4: {:.2?}", t.elapsed());

    let t = Instant::now();
    let actual_symbols = recipient
        .decrypt_many_outputs(&encrypted_outputs)
        .expect("recipient decrypts outputs");

    let actual_bytes = recipient
        .decrypt_outputs_to_bytes(&encrypted_outputs, 1)
        .expect("recipient packs output byte");

    eprintln!(
        "[COMPACT] recipient decryption + byte packing: {:.2?}",
        t.elapsed()
    );

    assert_eq!(actual_symbols, expected_symbols);

    let expected_bytes =
        pack_symbols_to_bytes(parameters, &expected_symbols, 1).unwrap();

    assert_eq!(actual_bytes, expected_bytes);
    assert_eq!(actual_bytes.len(), 1);

    // Output indices are one-based and the byte must contain all four symbols.
    assert!(source.encrypt_input(b"x", 0).is_err());

    assert!(
        evaluator
            .evaluate_outputs_for_bytes(&encrypted_inputs[..2], 1)
            .is_err()
    );

    let slot_two = source.encrypt_input(b"id", 2).unwrap();
    assert!(evaluator.evaluate_many(&[slot_two]).is_err());
}

/// Paper-parameter single-symbol test.
/// Uses fresh keys and checks slot 77 against the cleartext PRF reference.
#[test]
#[ignore = "paper LWR parameters and default TFHE integer keys; run explicitly in release mode"]
fn paper_parameters_compact_integer_fhe_slot_77_matches_cleartext() {
    let parameters = FastLwrPrfParameters::paper_default();
    let mut rng = rand::rngs::OsRng;

    let prf_key =
        FastLwrPrfSecretKey::generate(parameters, &mut rng).unwrap();

    let reference = FastLwrPrf::new(prf_key.clone());
    let identifier = b"pqpep-paper-parameters-compact-private-input-test";
    let index = 77u64;

    let expected = reference
        .evaluate_many(identifier, index as usize)[index as usize - 1]
        as u8;

    let t = Instant::now();
    let (source, recipient, evaluator) =
        setup_pep_integer_tfhe_compact(&prf_key)
            .expect("create source, recipient, and evaluator contexts");
    eprintln!("[COMPACT-PAPER] setup: {:.3?}", t.elapsed());

    let t = Instant::now();
    let input = source
        .encrypt_input(identifier, index)
        .expect("encrypt slot 77");
    eprintln!("[COMPACT-PAPER] encrypt slot 77: {:.3?}", t.elapsed());

    let t = Instant::now();
    let output = evaluator
        .evaluate(&input)
        .expect("homomorphically evaluate slot 77");
    eprintln!(
        "[COMPACT-PAPER] evaluate + key switch slot 77: {:.3?}",
        t.elapsed()
    );

    let actual = recipient
        .decrypt_output(&output)
        .expect("recipient decrypts slot 77");

    eprintln!("[COMPACT-PAPER] actual={actual}, expected={expected}");
    assert_eq!(actual, expected);
}

/// Full 64-byte end-to-end test: 103 symbols with paper LWR parameters.
/// Run this only after the single-slot test succeeds.
#[test]
#[ignore = "paper parameters and 103 integer-FHE evaluations; run explicitly after the single-slot test"]
fn paper_parameters_compact_integer_fhe_produces_64_byte_pseudonym() {
    let total = Instant::now();
    let parameters = FastLwrPrfParameters::paper_default();
    let mut rng = rand::rngs::OsRng;

    let prf_key =
        FastLwrPrfSecretKey::generate(parameters, &mut rng).unwrap();

    let reference = FastLwrPrf::new(prf_key.clone());
    let identifier = b"pqpep-paper-parameters-compact-private-input-test";

    let t = Instant::now();
    let (source, recipient, evaluator) =
        setup_pep_integer_tfhe_compact(&prf_key)
            .expect("create source, recipient, and evaluator contexts");
    eprintln!("[COMPACT-PAPER] setup: {:.3?}", t.elapsed());

    let t = Instant::now();
    let encrypted_inputs = source
        .encrypt_inputs_for_output_bytes(identifier, 64)
        .expect("encrypt the 103 indexed hash vectors");

    assert_eq!(encrypted_inputs.len(), 103);

    eprintln!(
        "[COMPACT-PAPER] encrypt 103 input vectors: {:.3?}",
        t.elapsed()
    );

    let t = Instant::now();
    let encrypted_outputs = evaluator
        .evaluate_outputs_for_bytes(&encrypted_inputs, 64)
        .expect("evaluate all 103 PRF symbols homomorphically");

    eprintln!(
        "[COMPACT-PAPER] evaluate + key switch 103 symbols: {:.3?}",
        t.elapsed()
    );

    let expected_symbols = reference
        .evaluate_many(identifier, 103)
        .into_iter()
        .map(|symbol| symbol as u8)
        .collect::<Vec<_>>();

    let actual_symbols = recipient
        .decrypt_many_outputs(&encrypted_outputs)
        .expect("recipient decrypts all symbols");

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
        "symbol mismatches (slot, actual, expected): {mismatches:?}"
    );

    let actual_bytes = recipient
        .decrypt_outputs_to_bytes(&encrypted_outputs, 64)
        .unwrap();

    let expected_bytes =
        pack_symbols_to_bytes(parameters, &expected_symbols, 64).unwrap();

    assert_eq!(actual_bytes, expected_bytes);
    assert_eq!(actual_bytes.len(), 64);

    eprintln!("[COMPACT-PAPER] total: {:.3?}", total.elapsed());
}