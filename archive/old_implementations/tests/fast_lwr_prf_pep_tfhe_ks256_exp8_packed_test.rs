#![cfg(feature = "fast-prf-tfhe-private-input")]

use std::time::Instant;

use pq_libpep::core::fast_lwr_prf::{
    FastLwrPrf,
    FastLwrPrfParameters,
    FastLwrPrfSecretKey,
};
use pq_libpep::core::fast_lwr_prf_pep_tfhe_ks256_exp8_packed::{
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
fn ks256_exp8_packed_toy_inputs_match_cleartext_and_recipient_key() {
    let (parameters, prf_key) = toy_fixture();
    let reference = FastLwrPrf::new(prf_key.clone());
    let (source, recipient, evaluator) =
        setup_pep_lwr_prf(parameters, &prf_key).expect("create experimental PEP contexts");
    let identifier = b"ks256-exp8-toy-test";
    let count = 4usize;

    let encrypted_inputs = source
        .encrypt_inputs(identifier, count)
        .expect("encrypt indexed hash vectors");
    assert!(encrypted_inputs.iter().all(|input| input.glwe_ciphertexts().len() == 1));
    let encrypted_outputs = evaluator
        .evaluate_many(&encrypted_inputs)
        .expect("evaluate encrypted-input LWR PRF");
    let actual = recipient
        .decrypt_many_outputs(&encrypted_outputs)
        .expect("recipient decrypts output symbols");
    let expected = reference
        .evaluate_many(identifier, count)
        .into_iter()
        .map(|x| x as u8)
        .collect::<Vec<_>>();
    assert_eq!(actual, expected);
    assert_eq!(output_symbols_for_bytes(parameters, 1).unwrap(), 4);
}

#[test]
#[ignore = "paper parameters; one slot only, run after toy test and expect slow setup"]
fn paper_parameters_ks256_exp8_packed_slot_77_matches_cleartext() {
    let parameters = FastLwrPrfParameters::paper_default();
    let mut rng = rand::rngs::OsRng;
    let prf_key = FastLwrPrfSecretKey::generate(parameters, &mut rng).unwrap();
    let reference = FastLwrPrf::new(prf_key.clone());
    let identifier = b"pqpep-paper-ks256-exp8-slot-test";
    let index = 77u64;
    let expected = reference.evaluate_many(identifier, index as usize)[index as usize - 1] as u8;

    let t = Instant::now();
    let (source, recipient, evaluator) =
        setup_pep_lwr_prf(parameters, &prf_key).expect("create paper-size PEP contexts");
    eprintln!("[KS256/E8] setup: {:.3?}", t.elapsed());

    let t = Instant::now();
    let encrypted_input = source.encrypt_input(identifier, index).unwrap();
    eprintln!("[KS256/E8] encrypt slot {index}: {:.3?}", t.elapsed());

    let t = Instant::now();
    let encrypted_output = evaluator.evaluate(&encrypted_input).unwrap();
    eprintln!("[KS256/E8] evaluate + key switch + PBS: {:.3?}", t.elapsed());

    let actual = recipient.decrypt_output(&encrypted_output).unwrap();
    eprintln!("[KS256/E8] actual={actual}, expected={expected}");
    assert_eq!(actual, expected);
}

#[test]
#[ignore = "paper parameters and 52 PBS evaluations; run explicitly after the slot-77 test"]
fn paper_parameters_ks256_exp8_packed_produces_32_byte_pseudonym() {
    let parameters = FastLwrPrfParameters::paper_default();
    let mut rng = rand::rngs::OsRng;
    let prf_key = FastLwrPrfSecretKey::generate(parameters, &mut rng).unwrap();
    let reference = FastLwrPrf::new(prf_key.clone());
    let identifier = b"pqpep-paper-ks256-exp8-32-byte-test";

    // p = 32 gives 5 bits per PRF symbol. For 32 bytes we need ceil(256/5) = 52 symbols.
    let expected_count = output_symbols_for_bytes(parameters, 32).unwrap();
    assert_eq!(expected_count, 52);

    let total = Instant::now();
    let (source, recipient, evaluator) =
        setup_pep_lwr_prf(parameters, &prf_key).expect("create paper-size PEP contexts");
    eprintln!("[KS256/E8-PACKED-32B] setup: {:.3?}", total.elapsed());

    let t = Instant::now();
    let inputs = source
        .encrypt_inputs_for_output_bytes(identifier, 32)
        .expect("encrypt 52 input vectors");
    assert_eq!(inputs.len(), 52);
    assert!(inputs.iter().all(|input| input.glwe_ciphertexts().len() == 1),
        "paper hash vector should be packed into one GLWE ciphertext per symbol");
    let input_payload_bytes: usize = inputs.iter()
        .map(|input| input.glwe_ciphertexts().iter()
            .map(|ct| ct.as_ref().len() * std::mem::size_of::<u128>())
            .sum::<usize>())
        .sum();
    eprintln!("[KS256/E8-PACKED-32B] input ciphertext payload: {:.3} MiB (coefficient bytes only)",
        input_payload_bytes as f64 / (1024.0 * 1024.0));
    eprintln!("[KS256/E8-PACKED-32B] encrypt 52 input vectors: {:.3?}", t.elapsed());

    let t = Instant::now();
    let outputs = evaluator
        .evaluate_outputs_for_bytes(&inputs, 32)
        .expect("evaluate all 52 symbols");
    assert_eq!(outputs.len(), 52);
    let output_payload_bytes: usize = outputs.iter()
        .map(|output| output.lwe_ciphertext().as_ref().len() * std::mem::size_of::<u128>())
        .sum();
    eprintln!("[KS256/E8-PACKED-32B] output ciphertext payload: {:.3} MiB (coefficient bytes only)",
        output_payload_bytes as f64 / (1024.0 * 1024.0));
    eprintln!("[KS256/E8-PACKED-32B] evaluate 52 symbols: {:.3?}", t.elapsed());

    let t = Instant::now();
    let actual = recipient.decrypt_many_outputs(&outputs).unwrap();
    eprintln!("[KS256/E8-PACKED-32B] decrypt 52 symbols: {:.3?}", t.elapsed());

    let expected = reference
        .evaluate_many(identifier, expected_count)
        .into_iter()
        .map(|x| x as u8)
        .collect::<Vec<_>>();
    let mismatches = actual.iter().zip(&expected).enumerate()
        .filter_map(|(i, (a, e))| (a != e).then_some((i + 1, *a, *e)))
        .collect::<Vec<_>>();
    assert!(mismatches.is_empty(), "mismatches (slot, actual, expected): {mismatches:?}");

    let actual_bytes = recipient.decrypt_outputs_to_bytes(&outputs, 32).unwrap();
    let expected_bytes = recipient.pack_symbols_to_bytes(&expected, 32).unwrap();
    assert_eq!(actual_bytes, expected_bytes);
    assert_eq!(actual_bytes.len(), 32);
    eprintln!("[KS256/E8-PACKED-32B] total: {:.3?}", total.elapsed());
}
