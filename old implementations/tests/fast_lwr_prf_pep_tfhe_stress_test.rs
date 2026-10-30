#![cfg(feature = "fast-prf-tfhe-private-input")]

//! Paper-parameter stress test for the blockwise LWR-PRF PEP adapter.
//!
//! This test intentionally evaluates several different identifiers under a
//! freshly generated PRF key and fresh encryption randomness. It compares all
//! 103 symbols and the final 64-byte output with the cleartext reference.
//! Run explicitly in release mode because each identifier uses 103 PBS calls.

use pq_libpep::core::fast_lwr_prf::{
    FastLwrPrf,
    FastLwrPrfParameters,
    FastLwrPrfSecretKey,
};
use pq_libpep::core::fast_lwr_prf_pep_tfhe::{
    output_symbols_for_bytes,
    setup_pep_lwr_prf,
};

#[test]
#[ignore = "paper-parameter stress test: multiple identifiers x 103 PBS each"]
fn paper_parameters_match_cleartext_for_multiple_identifiers() {
    let parameters = FastLwrPrfParameters::paper_default();
    let mut rng = rand::rngs::OsRng;
    let prf_key = FastLwrPrfSecretKey::generate(parameters, &mut rng)
        .expect("generate a fresh PRF key for this test run");
    let reference = FastLwrPrf::new(prf_key.clone());
    let (source, recipient, evaluator) = setup_pep_lwr_prf(parameters, &prf_key)
        .expect("create fresh PEP contexts");

    let long_identifier = vec![b'X'; 256];
    let cases: [(&str, &[u8]); 5] = [
        ("empty", b""),
        ("one-byte", b"x"),
        ("ordinary-ascii", b"student-2026-identifier-12345"),
        ("binary", b"\x00\xff\x10\x80\x7f"),
        ("long-256-byte", long_identifier.as_slice()),
    ];

    let expected_slots = output_symbols_for_bytes(parameters, 64)
        .expect("valid output size");
    assert_eq!(expected_slots, 103);

    for (case_name, identifier) in cases {
        let expected_symbols = reference
            .evaluate_many(identifier, expected_slots)
            .into_iter()
            .map(|symbol| symbol as u8)
            .collect::<Vec<_>>();

        let encrypted_inputs = source
            .encrypt_inputs_for_output_bytes(identifier, 64)
            .unwrap_or_else(|err| panic!("{case_name}: encrypt inputs failed: {err}"));
        assert_eq!(encrypted_inputs.len(), expected_slots, "{case_name}: input count");

        let encrypted_outputs = evaluator
            .evaluate_outputs_for_bytes(&encrypted_inputs, 64)
            .unwrap_or_else(|err| panic!("{case_name}: evaluation failed: {err}"));
        let actual_symbols = recipient
            .decrypt_many_outputs(&encrypted_outputs)
            .unwrap_or_else(|err| panic!("{case_name}: decryption failed: {err}"));

        assert_eq!(
            actual_symbols,
            expected_symbols,
            "{case_name}: mismatch in the 103 PRF symbols"
        );

        let actual_bytes = recipient
            .pack_symbols_to_bytes(&actual_symbols, 64)
            .unwrap_or_else(|err| panic!("{case_name}: packing actual output failed: {err}"));
        let expected_bytes = recipient
            .pack_symbols_to_bytes(&expected_symbols, 64)
            .unwrap_or_else(|err| panic!("{case_name}: packing reference output failed: {err}"));
        assert_eq!(actual_bytes.len(), 64, "{case_name}: output length");
        assert_eq!(
            actual_bytes,
            expected_bytes,
            "{case_name}: final 64-byte pseudonym differs from cleartext reference"
        );

        eprintln!("[STRESS] {case_name}: all {expected_slots} symbols matched");
    }
}
