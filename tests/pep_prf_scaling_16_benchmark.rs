//! PRF-output-length scaling benchmark. Functional/performance diagnostic only.
#![cfg(feature = "fast-prf-tfhe-private-input")]

use pq_libpep::core::fast_lwr_prf::{FastLwrPrf, FastLwrPrfParameters, FastLwrPrfSecretKey};
use pq_libpep::core::fast_lwr_prf_pep_ks128_e16_pipeline::setup_pep_lwr_prf;
use rand::rngs::OsRng;
use std::time::{Duration, Instant};

const REPETITIONS: usize = 10;
const OUTPUT_LENGTHS_BYTES: [usize; 1] = [16];

fn report(label: &str, samples: &[Duration]) {
    let mut values: Vec<f64> = samples.iter().map(Duration::as_secs_f64).collect();
    values.sort_by(f64::total_cmp);
    let mean = values.iter().sum::<f64>() / values.len() as f64;
    let median = if values.len() % 2 == 0 {
        (values[values.len() / 2 - 1] + values[values.len() / 2]) / 2.0
    } else {
        values[values.len() / 2]
    };
    let variance = values.iter().map(|x| (x - mean).powi(2)).sum::<f64>()
        / (values.len() - 1) as f64;
    println!(
        "[STATS] {label}: n={}, mean={mean:.6}s, median={median:.6}s, min={:.6}s, max={:.6}s, sd={:.6}s",
        values.len(), values[0], values[values.len() - 1], variance.sqrt()
    );
}

#[test]
#[ignore = "expensive: ten TFHE PRF evaluations at the 16-byte output length"]
fn prf_output_length_scaling_16() {
    println!("\n=== TFHE PRIVATE-INPUT PRF: 16-BYTE REPEAT ===");
    println!("Purpose: measure how PRF evaluation cost and envelope size scale with output length.");
    println!("Runs: {REPETITIONS} measured evaluations per length, plus one untimed warm-up per length.");
    println!("Security: functional/performance experiment only; it does not validate deployment security.");

    let parameters = FastLwrPrfParameters::paper_default();
    let mut rng = OsRng;
    println!("[START] Generate PRF key and TFHE evaluation setup (one setup shared across lengths)");
    let setup_start = Instant::now();
    let secret_key = FastLwrPrfSecretKey::generate(parameters, &mut rng).unwrap();
    let reference = FastLwrPrf::new(secret_key.clone());
    let (client, recipient, evaluator) = setup_pep_lwr_prf(parameters, &secret_key).unwrap();
    println!("[TIME] PRF key + TFHE setup: {:.6}s", setup_start.elapsed().as_secs_f64());

    let input = b"PQlibPEP PRF scaling benchmark; fixed canonical test input";
    println!("[INPUT] Fixed input length: {} bytes", input.len());

    for output_bytes in OUTPUT_LENGTHS_BYTES {
        let inputs = client
            .encrypt_inputs_for_output_bytes(input, output_bytes)
            .unwrap();
        let expected_symbols = reference.evaluate_many(input, inputs.len());
        let input_wire_bytes: usize = inputs
            .iter()
            .map(|item| item.to_wire_bytes().unwrap().len())
            .sum();
        println!(
            "\n[CASE] output_bytes={output_bytes}; symbols={}; input_envelope_bytes={input_wire_bytes}",
            inputs.len()
        );

        println!("[WARMUP] {output_bytes}-byte PRF output (excluded from statistics)");
        let warmup_outputs = evaluator
            .evaluate_outputs_for_bytes(&inputs, output_bytes)
            .unwrap();
        assert_eq!(
            recipient
                .decrypt_many_outputs(&warmup_outputs)
                .unwrap()
                .into_iter()
                .map(u64::from)
                .collect::<Vec<_>>(),
            expected_symbols
        );
        drop(warmup_outputs);

        let mut samples = Vec::with_capacity(REPETITIONS);
        let mut final_outputs = None;
        for run in 1..=REPETITIONS {
            let start = Instant::now();
            let outputs = evaluator
                .evaluate_outputs_for_bytes(&inputs, output_bytes)
                .unwrap();
            samples.push(start.elapsed());
            let decoded: Vec<u64> = recipient
                .decrypt_many_outputs(&outputs)
                .unwrap()
                .into_iter()
                .map(u64::from)
                .collect();
            assert_eq!(decoded, expected_symbols, "PRF mismatch at {output_bytes} bytes, run {run}");
            println!(
                "[SAMPLE] PRF eval {output_bytes} bytes run {run}/{REPETITIONS}: {:.6}s",
                samples.last().unwrap().as_secs_f64()
            );
            final_outputs = Some(outputs);
        }
        report(&format!("PRF evaluation, {output_bytes} output bytes",), &samples);
        let output_wire_bytes: usize = final_outputs
            .as_ref()
            .unwrap()
            .iter()
            .map(|item| item.to_wire_bytes().unwrap().len())
            .sum();
        println!("[SIZE] output_envelope_bytes={output_wire_bytes}");
        println!("[PASS] All {} output symbols match the clear PRF reference.", inputs.len());
    }

    println!("\nLIMIT: output-length scaling only; setup is shared, and this is not a full PEP transaction benchmark.");
    println!("LIMIT: measured samples reuse one key/setup and one fixed input; no security level is established.");
}
