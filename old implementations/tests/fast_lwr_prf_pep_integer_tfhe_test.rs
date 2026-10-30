#![cfg(feature = "fast-prf-tfhe-private-input")]

use std::time::Instant;

use pq_libpep::core::fast_lwr_prf::{
    FastLwrPrf,
    FastLwrPrfParameters,
    FastLwrPrfSecretKey,
};
use pq_libpep::core::fast_lwr_prf_pep_integer_tfhe::setup_pep_integer_tfhe;

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

#[test]
fn pep_integer_fhe_matches_cleartext_and_returns_under_recipient_key() {
    // Tiny parameters are only for functional correctness, never security claims.
    let (parameters, prf_key) = small_fixture();
    let reference = FastLwrPrf::new(prf_key.clone());

    let t = Instant::now();
    let (source, recipient, evaluator) =
        setup_pep_integer_tfhe(&prf_key)
            .expect("create source/recipient/evaluator keys");
    eprintln!("[BENCH] key setup: {:.2?}", t.elapsed());

    let input = b"pep-source-to-recipient-test";

    let t = Instant::now();
    let expected = reference.evaluate_many(input, 4);
    eprintln!("[BENCH] cleartext reference: {:.2?}", t.elapsed());

    let t = Instant::now();
    let encrypted_inputs = source
        .encrypt_inputs(input, 4)
        .expect("encrypt source inputs");
    eprintln!("[BENCH] input encryption: {:.2?}", t.elapsed());

    assert!(encrypted_inputs
        .iter()
        .all(|slot| slot.coefficient_count() == parameters.lwr_dimension));

    let t = Instant::now();
    let encrypted_outputs = evaluator
        .evaluate_many(&encrypted_inputs)
        .expect("evaluate LWR PRF and keyswitch outputs");
    eprintln!(
        "[BENCH] evaluation + key switching: {:.2?}",
        t.elapsed()
    );

    assert_eq!(encrypted_outputs.len(), expected.len());

    let t = Instant::now();
    let actual = recipient
        .decrypt_many_outputs(&encrypted_outputs)
        .expect("recipient decrypts outputs");
    eprintln!("[BENCH] output decryption: {:.2?}", t.elapsed());

    assert_eq!(
        actual,
        expected.into_iter().map(|x| x as u8).collect::<Vec<_>>()
    );
}

#[test]
fn pep_integer_fhe_rejects_zero_slot() {
    let (_, prf_key) = small_fixture();

    let (source, _recipient, _evaluator) =
        setup_pep_integer_tfhe(&prf_key).expect("create keys");

    assert!(source.encrypt_input(b"x", 0).is_err());
}