use pq_libpep::core::fast_lwr_prf::{FastLwrPrf, FastLwrPrfParameters, FastLwrPrfSecretKey};
use pq_libpep::core::fast_lwr_prf_pep_tfhe::setup_pep_lwr_prf;
use pq_libpep::core::fast_lwr_prf_tfhe::setup_tfhe;
use rand::{rngs::StdRng, SeedableRng};

fn mismatches(actual: &[u64], expected: &[u64]) -> Vec<(usize, u64, u64)> {
    actual
        .iter()
        .zip(expected.iter())
        .enumerate()
        .filter_map(|(i, (&a, &e))| (a != e).then_some((i + 1, a, e)))
        .collect()
}

/// Diagnostic only: compare the public-input TFHE path and the private-input
/// GLWE adapter using the SAME PRF key, identifier, and expected clear outputs.
/// When explicitly enabled, it asserts equality and prints mismatch lists first
/// so a failure can be localized instead of tuning PBS parameters blindly.
#[test]
fn diagnose_public_vs_private_input_paths_on_same_prf_key() {
    let parameters = FastLwrPrfParameters::paper_default();
    let mut rng = StdRng::seed_from_u64(0x5051_5045_5020_2610);
    let prf_key = FastLwrPrfSecretKey::generate(parameters, &mut rng).unwrap();
    let reference = FastLwrPrf::new(prf_key.clone());
    let identifier = b"pqpep-paper-parameters-private-input-test";
    let count = 103;
    let expected: Vec<u64> = reference.evaluate_many(identifier, count);

    let (public_client, public_evaluator) = setup_tfhe(&prf_key);
    let public_ciphertexts = public_evaluator.evaluate_many(identifier, count);
    let public_actual = public_client.decrypt_many(&public_ciphertexts);
    let public_mismatches = mismatches(&public_actual, &expected);
    eprintln!("PUBLIC-PATH mismatches (slot, actual, expected): {public_mismatches:?}");
    assert!(
        public_mismatches.is_empty(),
        "public-input one-PBS path differs from cleartext reference: {public_mismatches:?}"
    );

    let (source, recipient, private_evaluator) = setup_pep_lwr_prf(parameters, &prf_key).unwrap();
    let encrypted_inputs = source.encrypt_inputs_for_output_bytes(identifier, 64).unwrap();
    let private_ciphertexts = private_evaluator.evaluate_outputs_for_bytes(&encrypted_inputs, 64).unwrap();
    let private_actual = recipient.decrypt_many_outputs(&private_ciphertexts).unwrap().into_iter().map(u64::from).collect::<Vec<_>>();
    let private_mismatches = mismatches(&private_actual, &expected);
    eprintln!("PRIVATE-PATH mismatches (slot, actual, expected): {private_mismatches:?}");
    assert!(
        private_mismatches.is_empty(),
        "PEP encrypted-input path differs from cleartext reference: {private_mismatches:?}"
    );

    eprintln!("Expected symbols: {expected:?}");
}








   