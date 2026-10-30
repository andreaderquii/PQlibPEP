//! Multi-hop RLWE PRE correctness/noise and latency diagnostic. Not a security proof.

use pq_libpep::algebra::ring::{PolyRq, Q};
use pq_libpep::core::rlwe::KeyGenResult;
use pq_libpep::core::rlwe_pke::{decrypt_poly, encrypt_poly, Ciphertext};
use pq_libpep::core::rlwe_pre::{generate_rekey, reencrypt_and_rerandomize};
use pq_libpep::parameters::rlwe_prototype;
use rand::rngs::OsRng;
use std::time::{Duration, Instant};

const REPETITIONS: usize = 10;
const MAX_HOPS: usize = 10;
const CHECKPOINTS: [usize; 4] = [1, 3, 5, 10];
const RLWE_N: usize = rlwe_prototype::RING_DIMENSION;
const BASE_BITS: usize = rlwe_prototype::PRE_GADGET_BASE_BITS;
const PLAINTEXT_MODULUS: u64 = rlwe_prototype::PLAINTEXT_MODULUS;

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
        "[STATS] {label}: n={}, mean={mean:.9}s, median={median:.9}s, min={:.9}s, max={:.9}s, sd={:.9}s",
        values.len(), values[0], values[values.len() - 1], variance.sqrt()
    );
}

fn report_i64(label: &str, samples: &[i64]) {
    let mut values = samples.to_vec();
    values.sort_unstable();
    let median = if values.len() % 2 == 0 {
        (values[values.len() / 2 - 1] + values[values.len() / 2]) / 2
    } else {
        values[values.len() / 2]
    };
    println!(
        "[NOISE-STATS] {label}: n={}, min={}, median={}, max={} coefficients",
        values.len(), values[0], median, values[values.len() - 1]
    );
}

fn validate_ciphertext(
    secret_key: &pq_libpep::core::rlwe::SecretKey,
    ciphertext: &Ciphertext,
    expected_plaintext: &[u64],
) -> i64 {
    let delta = Q / PLAINTEXT_MODULUS;
    let phase = ciphertext.v.sub(&ciphertext.u.mul_ntt(&secret_key.s));
    let mut max_error = 0_i64;
    for (index, &message) in expected_plaintext.iter().enumerate() {
        let actual = phase.coefficients().get(index).copied().unwrap_or(0);
        let target = ((message as u128 * delta as u128) % Q as u128) as u64;
        let residue = (actual + Q - target) % Q;
        let centered = if residue > Q / 2 {
            residue as i64 - Q as i64
        } else {
            residue as i64
        };
        max_error = max_error.max(centered.abs());
    }

    let decoding_limit = delta / 2 - PLAINTEXT_MODULUS;
    assert!((max_error as u64) < decoding_limit, "RLWE decoding margin exhausted");
    let decoded = decrypt_poly(secret_key, ciphertext, RLWE_N);
    assert_eq!(&decoded.coefficients()[..RLWE_N], expected_plaintext);
    max_error
}

#[test]
#[ignore = "diagnostic: ten independently rerandomized chains of up to ten RLWE PRE hops"]
fn rlwe_hop_noise_sweep() {
    println!("\n=== RLWE/PRE HOP AND NOISE SWEEP ===");
    println!("Profile: N={RLWE_N}, q={Q}, t={PLAINTEXT_MODULUS}, PRE base=2^{BASE_BITS}.");
    println!("Runs: {REPETITIONS} fresh-randomness chains, each up to {MAX_HOPS} sequential rekey+rerandomize hops.");
    println!("Correctness is checked by decryption and phase-error margin at every hop.");
    println!("LIMIT: functional/noise diagnostic only; not a PRE security or collusion-resistance proof.");

    let mut rng = OsRng;
    let setup_start = Instant::now();
    let source = KeyGenResult::keygen(&mut rng, RLWE_N);
    let destinations: Vec<_> = (0..MAX_HOPS)
        .map(|_| KeyGenResult::keygen(&mut rng, RLWE_N))
        .collect();
    let mut rekeys = Vec::with_capacity(MAX_HOPS);
    for hop in 0..MAX_HOPS {
        let from_secret = if hop == 0 {
            &source.sk
        } else {
            &destinations[hop - 1].sk
        };
        rekeys.push(generate_rekey(
            &mut rng,
            from_secret,
            &destinations[hop].pk,
            BASE_BITS,
        ));
    }
    let plaintext: Vec<u64> = (0..RLWE_N)
        .map(|index| index as u64 % PLAINTEXT_MODULUS)
        .collect();
    let polynomial = PolyRq::from_coeffs(&plaintext, RLWE_N, Q);
    let source_ciphertext = encrypt_poly(&mut rng, &source.pk, &polynomial, RLWE_N);
    println!("[TIME] Key/rekey/ciphertext setup: {:.6}s", setup_start.elapsed().as_secs_f64());
    println!("[SIZE] Ciphertext coefficient storage: {} bytes", (source_ciphertext.u.coefficients().len() + source_ciphertext.v.coefficients().len()) * std::mem::size_of::<u64>());

    let delta = Q / PLAINTEXT_MODULUS;
    let decoding_limit = delta / 2 - PLAINTEXT_MODULUS;
    println!("[NOISE] Decoding limit per coefficient: {decoding_limit}");

    let mut cumulative_times: Vec<Vec<Duration>> = (0..MAX_HOPS)
        .map(|_| Vec::with_capacity(REPETITIONS))
        .collect();
    let mut hop_times: Vec<Vec<Duration>> = (0..MAX_HOPS)
        .map(|_| Vec::with_capacity(REPETITIONS))
        .collect();
    let mut noise_samples: Vec<Vec<i64>> = (0..MAX_HOPS)
        .map(|_| Vec::with_capacity(REPETITIONS))
        .collect();

    for run in 1..=REPETITIONS {
        // Use an independent fresh source encryption for each chain. Encryption
        // itself is outside the measured PRE hop timings.
        let mut ciphertext = encrypt_poly(&mut rng, &source.pk, &polynomial, RLWE_N);
        let chain_start = Instant::now();
        for hop in 0..MAX_HOPS {
            let hop_start = Instant::now();
            ciphertext = reencrypt_and_rerandomize(
                &mut rng,
                &ciphertext,
                &rekeys[hop],
                &destinations[hop].pk,
                BASE_BITS,
            );
            hop_times[hop].push(hop_start.elapsed());
            let max_error = validate_ciphertext(
                &destinations[hop].sk,
                &ciphertext,
                &plaintext,
            );
            noise_samples[hop].push(max_error);
            cumulative_times[hop].push(chain_start.elapsed());
            println!("[CHECK] run={run}/{REPETITIONS}, hop={}, decrypt=ok, max_phase_error={max_error}", hop + 1);
        }
    }

    for hop in 0..MAX_HOPS {
        report(&format!("single hop {} (rekey + rerandomize)", hop + 1), &hop_times[hop]);
        report_i64(&format!("phase error after hop {}", hop + 1), &noise_samples[hop]);
    }
    for depth in CHECKPOINTS {
        let samples: Vec<Duration> = (0..REPETITIONS)
            .map(|run| cumulative_times[depth - 1][run])
            .collect();
        report(&format!("cumulative chain through {depth} hops"), &samples);
    }

    println!("[PASS] All {REPETITIONS} chains decrypted correctly through {MAX_HOPS} hops.");
    println!("LIMIT: chains reuse the same keys/rekeys and source ciphertext; randomness is refreshed for each hop.");
    println!("LIMIT: this measures correctness/noise and latency for the prototype parameters, not deployment security.");
}
