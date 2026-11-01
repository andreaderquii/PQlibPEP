#![cfg(feature = "fast-prf-tfhe-private-input")]

//! Validation suite for the experimental KS128/E16 packed private-input LWR PRF.
//!
//! Fast tests use toy parameters and check API/functional properties. They are
//! not security tests. The ignored paper-parameter test checks three different
//! identifiers under one freshly generated PRF key/context and requires 52
//! symbols / 32 bytes per identifier.

use std::time::Instant;

use pq_libpep::core::fast_lwr_prf::{
    FastLwrPrf,
    FastLwrPrfParameters,
    FastLwrPrfSecretKey,
};
use pq_libpep::core::fast_lwr_prf_pep_tfhe_ks128_exp16_packed::{
    output_symbols_for_bytes,
    setup_pep_lwr_prf,
};

fn toy_fixture() -> (FastLwrPrfParameters, FastLwrPrfSecretKey) {
    let parameters = FastLwrPrfParameters {
        lwr_dimension: 8,
        ring_dimension: 64,
        output_modulus: 4,
    };
    let key = FastLwrPrfSecretKey::from_bits(
        parameters,
        vec![1, 0, 1, 1, 0, 1, 0, 1],
    )
    .expect("valid toy LWR key");
    (parameters, key)
}

#[test]
fn toy_matrix_checks_multiple_ids_slots_randomness_and_byte_packing() {
    let (parameters, prf_key) = toy_fixture();
    let reference = FastLwrPrf::new(prf_key.clone());
    let (source, recipient, evaluator) =
        setup_pep_lwr_prf(parameters, &prf_key).expect("create toy PEP contexts");

    let identifiers: Vec<(&str, Vec<u8>)> = vec![
        ("empty", vec![]),
        ("one-byte", vec![0xA5]),
        ("ascii", b"ordinary-ascii-identifier".to_vec()),
        ("binary", vec![0x00, 0xFF, 0x80, 0x7F, 0x00, 0x42]),
        ("long-256", (0u16..=255).map(|x| x as u8).collect()),
    ];

    for (label, identifier) in &identifiers {
        let count = 8usize;
        let encrypted_inputs = source
            .encrypt_inputs(identifier, count)
            .expect("encrypt indexed hash vectors");
        assert_eq!(encrypted_inputs.len(), count, "{label}: input count");
        assert!(encrypted_inputs.iter().all(|input| input.glwe_ciphertexts().len() == 1),
            "{label}: paper-style packed vectors should use one GLWE block for this fixture");
        let encrypted_outputs = evaluator
            .evaluate_many(&encrypted_inputs)
            .expect("evaluate encrypted-input PRF");
        assert_eq!(encrypted_outputs.len(), count, "{label}: output count");

        let actual = recipient
            .decrypt_many_outputs(&encrypted_outputs)
            .expect("recipient decrypts symbols");
        let expected = reference
            .evaluate_many(identifier, count)
            .into_iter()
            .map(|x| x as u8)
            .collect::<Vec<_>>();
        assert_eq!(actual, expected, "{label}: symbol mismatch");
        assert!(actual.iter().all(|&s| (s as u64) < parameters.output_modulus));
        eprintln!("[VALIDATION/TOY] {label}: {count} symbols matched");
    }

    // An arbitrary one-based slot must match the same indexed component of the
    // cleartext PRF, not merely slot 1 or a sequential batch.
    let identifier = b"arbitrary-slot-test";
    let slot = 17u64;
    let encrypted_input = source.encrypt_input(identifier, slot).unwrap();
    let encrypted_output = evaluator.evaluate(&encrypted_input).unwrap();
    assert_eq!(encrypted_output.output_index(), slot);
    let actual = recipient.decrypt_output(&encrypted_output).unwrap();
    let expected = reference.evaluate_many(identifier, slot as usize)[slot as usize - 1] as u8;
    assert_eq!(actual, expected, "arbitrary indexed slot mismatch");

    // Re-encrypting the same indexed input should use fresh randomness. This is
    // a sanity check on ciphertext refresh, not a cryptographic security proof.
    let first = source.encrypt_input(b"same-plaintext", 3).unwrap();
    let second = source.encrypt_input(b"same-plaintext", 3).unwrap();
    assert_ne!(
        first.glwe_ciphertexts()[0].as_ref(),
        second.glwe_ciphertexts()[0].as_ref(),
        "fresh encryptions of the same vector should not be byte-identical"
    );

    // Byte packing using toy p=4 (2 bits/symbol): 3 bytes require 12 symbols.
    let byte_len = 3usize;
    let required = output_symbols_for_bytes(parameters, byte_len).unwrap();
    assert_eq!(required, 12);
    let inputs = source.encrypt_inputs_for_output_bytes(b"binary\0ID", byte_len).unwrap();
    let outputs = evaluator.evaluate_outputs_for_bytes(&inputs, byte_len).unwrap();
    let actual_bytes = recipient.decrypt_outputs_to_bytes(&outputs, byte_len).unwrap();
    let expected_symbols = reference
        .evaluate_many(b"binary\0ID", required)
        .into_iter()
        .map(|x| x as u8)
        .collect::<Vec<_>>();
    let expected_bytes = recipient.pack_symbols_to_bytes(&expected_symbols, byte_len).unwrap();
    assert_eq!(actual_bytes, expected_bytes, "byte packing mismatch");
    assert_eq!(actual_bytes.len(), byte_len);
}

#[test]
fn toy_api_rejects_invalid_indices_lengths_and_parameter_mismatch() {
    let (parameters_a, key_a) = toy_fixture();
    let (source_a, recipient_a, evaluator_a) =
        setup_pep_lwr_prf(parameters_a, &key_a).expect("context A");

    assert!(source_a.encrypt_input(b"id", 0).is_err(), "index 0 must be rejected");
    assert!(source_a.encrypt_inputs(b"id", 0).unwrap().is_empty());
    assert!(evaluator_a.evaluate_many(&[]).unwrap().is_empty());

    let one = source_a.encrypt_input(b"id", 1).unwrap();
    let three = source_a.encrypt_input(b"id", 3).unwrap();
    assert!(evaluator_a.evaluate_many(&[one, three]).is_err(),
        "batch evaluation must reject gaps in one-based indices");

    let three_inputs = source_a.encrypt_inputs(b"id", 3).unwrap();
    assert!(evaluator_a.evaluate_outputs_for_bytes(&three_inputs, 1).is_err(),
        "one byte at p=4 requires four symbols, not three");

    assert!(recipient_a.pack_symbols_to_bytes(&[1, 2, 3], 4).is_err(),
        "insufficient symbols must be rejected");
    assert!(recipient_a.pack_symbols_to_bytes(&[0, 1, 2, 4], 1).is_err(),
        "symbols outside Z_p must be rejected");
    assert_eq!(output_symbols_for_bytes(parameters_a, 0).unwrap(), 0);
    assert!(output_symbols_for_bytes(parameters_a, usize::MAX).is_err(),
        "byte-count overflow must be rejected");

    // A ciphertext created by a different parameter context should fail closed.
    // The API currently checks parameter metadata; it does not yet carry explicit
    // context/key IDs, which remains a pre-integration hardening item.
    let parameters_b = FastLwrPrfParameters {
        lwr_dimension: 4,
        ring_dimension: 64,
        output_modulus: 4,
    };
    let key_b = FastLwrPrfSecretKey::from_bits(parameters_b, vec![1, 0, 1, 1]).unwrap();
    let (_source_b, _recipient_b, evaluator_b) =
        setup_pep_lwr_prf(parameters_b, &key_b).expect("context B");
    let foreign_input = source_a.encrypt_input(b"foreign-context", 1).unwrap();
    assert!(evaluator_b.evaluate(&foreign_input).is_err(),
        "evaluation under incompatible parameters must fail closed");
}

#[test]
fn paper_parameter_byte_target_uses_52_symbols_for_32_bytes() {
    let parameters = FastLwrPrfParameters::paper_default();
    assert_eq!(parameters.lwr_dimension, 445);
    assert_eq!(parameters.ring_dimension, 2048);
    assert_eq!(parameters.output_modulus, 32);
    assert_eq!(output_symbols_for_bytes(parameters, 32).unwrap(), 52);
    assert_eq!(output_symbols_for_bytes(parameters, 64).unwrap(), 103);
    assert_eq!(output_symbols_for_bytes(parameters, 0).unwrap(), 0);
}

/// Slow integration stress test: reuse one freshly generated PRF/evaluation
/// context but encrypt each identifier afresh. It tests different input values
/// under one key/context, as expected for a PRF interface. Expect roughly 2–3
/// minutes depending on the machine. This does not replace a security audit.
#[test]
#[ignore = "paper parameters; 3 identifiers x 52 symbols; run explicitly in release mode"]
fn paper_parameters_three_identifiers_each_match_32_byte_reference() {
    let parameters = FastLwrPrfParameters::paper_default();
    let mut rng = rand::rngs::OsRng;
    let prf_key = FastLwrPrfSecretKey::generate(parameters, &mut rng).unwrap();
    let reference = FastLwrPrf::new(prf_key.clone());

    let identifiers: Vec<(&str, Vec<u8>)> = vec![
        ("empty", vec![]),
        ("binary", vec![0x00, 0xFF, 0x80, 0x7F, 0x00, 0x42, 0xA5]),
        ("long-256", (0u16..=255).map(|x| x as u8).collect()),
    ];
    let count = output_symbols_for_bytes(parameters, 32).unwrap();
    assert_eq!(count, 52);

    let overall = Instant::now();
    let (source, recipient, evaluator) =
        setup_pep_lwr_prf(parameters, &prf_key).expect("paper-size PEP contexts");
    eprintln!("[VALIDATION/PAPER] setup: {:.3?}", overall.elapsed());

    for (label, identifier) in &identifiers {
        let started = Instant::now();
        let inputs = source
            .encrypt_inputs_for_output_bytes(identifier, 32)
            .expect("encrypt 52 indexed hash vectors");
        assert_eq!(inputs.len(), 52);
        assert!(inputs.iter().all(|input| input.glwe_ciphertexts().len() == 1));

        let outputs = evaluator
            .evaluate_outputs_for_bytes(&inputs, 32)
            .expect("evaluate 52 symbols homomorphically");
        let actual_symbols = recipient.decrypt_many_outputs(&outputs).unwrap();
        let expected_symbols = reference
            .evaluate_many(identifier, 52)
            .into_iter()
            .map(|x| x as u8)
            .collect::<Vec<_>>();
        assert_eq!(actual_symbols, expected_symbols,
            "{label}: one or more of 52 PRF symbols differ");

        let actual_bytes = recipient.decrypt_outputs_to_bytes(&outputs, 32).unwrap();
        let expected_bytes = recipient.pack_symbols_to_bytes(&expected_symbols, 32).unwrap();
        assert_eq!(actual_bytes, expected_bytes, "{label}: packed 32-byte output differs");
        assert_eq!(actual_bytes.len(), 32);
        eprintln!("[VALIDATION/PAPER] {label}: 52 symbols matched in {:.3?}", started.elapsed());
    }
    eprintln!("[VALIDATION/PAPER] all identifiers passed; total {:.3?}", overall.elapsed());
}
