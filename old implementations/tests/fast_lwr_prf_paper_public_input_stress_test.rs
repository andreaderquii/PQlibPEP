#![cfg(feature = "fast-prf-tfhe-private-input")]

use pq_libpep::core::fast_lwr_prf::{
    FastLwrPrf,
    FastLwrPrfParameters,
    FastLwrPrfSecretKey,
};
use pq_libpep::core::fast_lwr_prf_tfhe::setup_tfhe;

/// Stress-tests the paper's public-input depth-1 LWR PRF against its cleartext
/// reference on several inputs and all 103 symbols needed for a 64-byte output.
///
/// The same PRF key/evaluation key is deliberately used for all input queries:
/// a PRF is defined for repeated evaluations under one fixed secret key. A
/// fresh key is generated for this test run. These tests establish functional
/// consistency only, not a security proof or parameter validation.
#[test]
#[ignore = "paper-size TFHE multi-input stress test; run explicitly in release mode"]
fn paper_public_input_prf_matches_cleartext_for_multiple_identifiers() {
    let parameters = FastLwrPrfParameters::paper_default();
    let mut rng = rand::rngs::OsRng;
    let prf_key = FastLwrPrfSecretKey::generate(parameters, &mut rng)
        .expect("generate PRF key");
    let reference = FastLwrPrf::new(prf_key.clone());
    let (client_key, evaluation_key) = setup_tfhe(&prf_key);

    let long_identifier: Vec<u8> = (0..=255).collect();
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("empty", Vec::new()),
        ("one-byte", vec![0x00]),
        ("ordinary-ascii", b"student-number-2026-123456".to_vec()),
        ("binary", vec![0x00, 0xff, 0x10, 0x80, 0x00, 0x7f]),
        ("long-256-byte", long_identifier),
    ];
    const SYMBOLS: usize = 103;

    for (name, identifier) in cases {
        let expected = reference.evaluate_many(&identifier, SYMBOLS);
        let encrypted = evaluation_key.evaluate_many(&identifier, SYMBOLS);
        let actual = client_key.decrypt_many(&encrypted);

        assert_eq!(actual.len(), SYMBOLS, "{name}: wrong output length");
        assert!(
            actual.iter().all(|&symbol| symbol < parameters.output_modulus),
            "{name}: output symbol outside Z_p"
        );

        let mismatches: Vec<(usize, u64, u64)> = actual
            .iter()
            .zip(expected.iter())
            .enumerate()
            .filter_map(|(i, (&actual, &expected))| {
                (actual != expected).then_some((i + 1, actual, expected))
            })
            .collect();

        assert!(mismatches.is_empty(), "{name}: mismatches: {mismatches:?}");
        eprintln!("[PUBLIC-PRF-STRESS] {name}: all {SYMBOLS} symbols matched");
    }
}
