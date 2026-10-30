#![cfg(feature = "fast-prf-tfhe-private-input")]

use pq_libpep::core::fast_lwr_prf::{FastLwrPrf, FastLwrPrfParameters, FastLwrPrfSecretKey};
use pq_libpep::core::fast_lwr_prf_pep_tfhe::setup_pep_lwr_prf;

/// Experimental one-slot smoke test with a full-sized source GLWE/LWE key.
/// This avoids the 8-bit source-key flaw of the fast B8/E8 benchmark candidate.
/// It is NOT a security proof and may require several GB of RAM for the BSK.
#[test]
#[ignore = "paper-size full-dimension source key; run explicitly in release mode"]
fn paper_parameters_single_slot_matches_cleartext_with_full_source_dimension() {
    let parameters = FastLwrPrfParameters::paper_default();
    let mut rng = rand::rngs::OsRng;
    let prf_key = FastLwrPrfSecretKey::generate(parameters, &mut rng).unwrap();
    let reference = FastLwrPrf::new(prf_key.clone());

    let identifier = b"pqpep-full-source-key-single-slot-check";
    let slot = 77usize;
    let expected = reference.evaluate_many(identifier, slot)[slot - 1];

    eprintln!("[KEY512] creating TFHE contexts; source polynomial size should be 512");
    let t = std::time::Instant::now();
    let (source, recipient, evaluator) = setup_pep_lwr_prf(parameters, &prf_key).unwrap();
    eprintln!("[KEY512] setup: {:.3?}", t.elapsed());

    let t = std::time::Instant::now();
    let encrypted = source.encrypt_input(identifier, slot as u64).unwrap();
    eprintln!("[KEY512] encrypt one indexed input: {:.3?}", t.elapsed());

    let t = std::time::Instant::now();
    let encrypted_output = evaluator.evaluate(&encrypted).unwrap();
    eprintln!("[KEY512] evaluate one slot: {:.3?}", t.elapsed());

    let actual = recipient.decrypt_output(&encrypted_output).unwrap() as u64;
    eprintln!("[KEY512] actual={actual}, expected={expected}");
    assert_eq!(actual, expected, "full-dimension source-key single-slot check failed");
}
