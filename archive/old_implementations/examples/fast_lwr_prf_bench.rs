//! Standalone throughput check for the TFHE-backed Fast LWR PRF.
//!
//! Run from the project root:
//! cargo run --release --features fast-prf-tfhe --example fast_lwr_prf_bench

use std::hint::black_box;
use std::time::Instant;

use pq_libpep::core::fast_lwr_prf::{FastLwrPrf, FastLwrPrfParameters, FastLwrPrfSecretKey};
use pq_libpep::core::fast_lwr_prf_tfhe::setup_tfhe;
use rand::{rngs::StdRng, SeedableRng};

const INPUT: &[u8] = b"pq-libpep-fast-lwr-prf-benchmark-input";
const SINGLE_REPETITIONS: usize = 20;
const BATCH_SIZE: usize = 16;
const BATCH_REPETITIONS: usize = 4;

fn main() {
    let parameters = FastLwrPrfParameters::paper_default();
    let mut rng = StdRng::seed_from_u64(0x5051_4C50_4550);
    let secret_key = FastLwrPrfSecretKey::generate(parameters, &mut rng)
        .expect("paper-default PRF parameters should be valid");
    let clear_reference = FastLwrPrf::new(secret_key.clone());

    let setup_start = Instant::now();
    let (client_key, evaluation_key) = setup_tfhe(&secret_key);
    let setup_elapsed = setup_start.elapsed();
    println!(
        "Parameters: n={}, N={}, p={}",
        parameters.lwr_dimension, parameters.ring_dimension, parameters.output_modulus
    );
    println!(
        "TFHE evaluation-key setup: {:.3} s",
        setup_elapsed.as_secs_f64()
    );

    // Correctness check before timing.
    let encrypted_first = evaluation_key.evaluate(INPUT);
    let decrypted_first = client_key.decrypt(&encrypted_first);
    let expected_first = clear_reference.evaluate(INPUT);
    assert_eq!(
        decrypted_first, expected_first,
        "single-output correctness failed"
    );

    let single_start = Instant::now();
    for _ in 0..SINGLE_REPETITIONS {
        black_box(evaluation_key.evaluate(black_box(INPUT)));
    }
    let single_elapsed = single_start.elapsed();
    let single_avg_ms = single_elapsed.as_secs_f64() * 1_000.0 / SINGLE_REPETITIONS as f64;
    println!(
        "Single slot (hash + PBS): {:.3} ms average over {} runs",
        single_avg_ms, SINGLE_REPETITIONS
    );

    // Measure batch throughput with parallel PBS evaluations, then validate a batch separately.
    let batch_start = Instant::now();
    for _ in 0..BATCH_REPETITIONS {
        black_box(evaluation_key.evaluate_many(black_box(INPUT), BATCH_SIZE));
    }
    let batch_elapsed = batch_start.elapsed();
    let total_slots = BATCH_SIZE * BATCH_REPETITIONS;
    let slot_avg_ms = batch_elapsed.as_secs_f64() * 1_000.0 / total_slots as f64;
    let bits_per_slot = parameters.output_modulus.trailing_zeros() as f64;
    let output_bits_per_second = total_slots as f64 * bits_per_slot / batch_elapsed.as_secs_f64();
    println!(
        "Batch: {} slots x {} runs in {:.3} s",
        BATCH_SIZE,
        BATCH_REPETITIONS,
        batch_elapsed.as_secs_f64()
    );
    println!("Average time per slot in batch: {:.3} ms", slot_avg_ms);
    println!(
        "Encrypted PRF throughput: {:.1} output bits/s ({} bits/slot)",
        output_bits_per_second, bits_per_slot as usize
    );

    let encrypted_batch = evaluation_key.evaluate_many(INPUT, BATCH_SIZE);
    let decrypted_batch = client_key.decrypt_many(&encrypted_batch);
    let expected_batch = clear_reference.evaluate_many(INPUT, BATCH_SIZE);
    assert_eq!(
        decrypted_batch, expected_batch,
        "batch-output correctness failed"
    );
    println!(
        "Correctness: PASS (single output and {} indexed output slots)",
        BATCH_SIZE
    );
    println!("Note: timings include SHAKE256 hashing; key setup is reported separately.");
}
