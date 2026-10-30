#![cfg(feature = "fast-prf-tfhe-private-input")]

use std::time::Instant;

use pq_libpep::core::fast_lwr_prf::{
    FastLwrPrf,
    FastLwrPrfParameters,
    FastLwrPrfSecretKey,
};
use pq_libpep::core::fast_lwr_prf_tfhe::setup_tfhe;

/// Benchmarks the paper's original public-input depth-1 LWR PRF path.
///
/// IMPORTANT: this is a comparison baseline, not the PEP private-input path.
/// The input is provided in clear to the evaluator; the PRF key is embedded
/// in the TFHE evaluation key. The test uses paper parameters but does not
/// constitute an independent security audit of the custom implementation.
#[test]
#[ignore = "paper-size public-input LWR PRF benchmark; run explicitly in release mode"]
fn paper_default_public_input_prf_64byte_benchmark() {
    let total = Instant::now();
    let parameters = FastLwrPrfParameters::paper_default();
    let mut rng = rand::rngs::OsRng;

    let t = Instant::now();
    let prf_key = FastLwrPrfSecretKey::generate(parameters, &mut rng)
        .expect("generate PRF key");
    eprintln!("[PUBLIC-PRF] PRF key generation: {:.3?}", t.elapsed());

    let reference = FastLwrPrf::new(prf_key.clone());
    let identifier = b"pqpep-paper-public-input-benchmark-64-byte";
    let output_count = 103usize; // ceil(64*8 / log2(32))

    let t = Instant::now();
    let (client_key, evaluation_key) = setup_tfhe(&prf_key);
    eprintln!("[PUBLIC-PRF] TFHE evaluation-key setup: {:.3?}", t.elapsed());

    let t = Instant::now();
    let encrypted_outputs = evaluation_key.evaluate_many(identifier, output_count);
    eprintln!("[PUBLIC-PRF] Evaluate {output_count} public-input slots: {:.3?}", t.elapsed());

    let t = Instant::now();
    let actual = client_key.decrypt_many(&encrypted_outputs);
    eprintln!("[PUBLIC-PRF] Decrypt outputs: {:.3?}", t.elapsed());

    let t = Instant::now();
    let expected = reference.evaluate_many(identifier, output_count);
    eprintln!("[PUBLIC-PRF] Cleartext reference: {:.3?}", t.elapsed());

    let mismatches: Vec<(usize, u64, u64)> = actual
        .iter()
        .zip(expected.iter())
        .enumerate()
        .filter_map(|(i, (&a, &e))| (a != e).then_some((i + 1, a, e)))
        .collect();
    assert!(mismatches.is_empty(), "public-input PRF mismatches: {mismatches:?}");
    assert_eq!(actual.len(), output_count);
    assert!(actual.iter().all(|&x| x < parameters.output_modulus));

    eprintln!("[PUBLIC-PRF] all {output_count} symbols matched cleartext");
    eprintln!("[PUBLIC-PRF] TOTAL: {:.3?}", total.elapsed());
}
