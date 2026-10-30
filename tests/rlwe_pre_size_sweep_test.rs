//! Diagnostic RLWE/PRE parameter and hop-count benchmarks.
//!
//! These are functional engineering profiles, not security parameter sets.
//! The hop test stops at 75% of the conservative decryption margin or at the
//! hard cap. It is a single seeded run, not a failure-probability estimate.

#![cfg(feature = "experimental-linear-reshuffle")]

use pq_libpep::algebra::ring::{PolyRq, Q};
use pq_libpep::core::params::{prf_modulus_chain, RING_DIMENSION};
use pq_libpep::core::reshuffle::{
    derive_invertible_reshuffle_factor, lift_prf_output_to_q, reshuffle,
};
use pq_libpep::core::rlwe::{KeyGenResult, SecretKey};
use pq_libpep::core::rlwe_pke::{decrypt_poly, encrypt_poly, Ciphertext};
use pq_libpep::core::rlwe_pre::{generate_rekey, reencrypt, reencrypt_and_rerandomize};
use pq_libpep::core::rlwr_prf::{RlwrPrf, RlwrPrfBase};
use rand::{rngs::StdRng, SeedableRng};
use std::time::Instant;

const T: u64 = 17;
const BASE_BITS: usize = 4;
const CRITICAL_MARGIN_FRACTION: f64 = 0.50;
const WARNING_MARGIN_FRACTION: f64 = 0.30;
const MAX_HOPS: usize = 20;

fn timed<T>(label: &str, f: impl FnOnce() -> T) -> T {
    let start = Instant::now();
    let value = f();
    println!("[TIME] {label}: {:.6} s", start.elapsed().as_secs_f64());
    value
}

fn storage_bytes(ct: &Ciphertext) -> usize {
    (ct.u.coefficients().len() + ct.v.coefficients().len()) * 8
}

fn phase_error(sk: &SecretKey, ct: &Ciphertext, expected: &[u64], n: usize) -> u64 {
    let delta = Q / T;
    let phase = ct.v.sub(&ct.u.mul_ntt(&sk.s));
    (0..n)
        .map(|i| {
            let target = ((expected[i] as u128 * delta as u128) % Q as u128) as u64;
            let residue = (phase.coefficients()[i] + Q - target) % Q;
            residue.min(Q - residue)
        })
        .max()
        .unwrap_or(0)
}

fn check(label: &str, sk: &SecretKey, ct: &Ciphertext, expected: &[u64], n: usize) -> u64 {
    let error = phase_error(sk, ct, expected, n);
    let threshold = (Q / T) / 2 - T;
    let decoded = decrypt_poly(sk, ct, n);
    assert_eq!(
        &decoded.coefficients()[..n],
        expected,
        "{label}: decode mismatch"
    );
    assert!(
        error < threshold,
        "{label}: phase error reached decode threshold"
    );
    println!(
        "[NOISE] {label}: max phase error={error}; decode threshold={threshold}; used={:.1}%; margin left={:.1}%",
        100.0 * error as f64 / threshold as f64,
        100.0 * (threshold - error) as f64 / threshold as f64
    );
    error
}

fn run_profile(n: usize) {
    let mut rng = StdRng::seed_from_u64(0x5052_4553_5745_4550 ^ n as u64);
    let expected: Vec<u64> = (0..n).map(|i| ((i * 7 + 3) as u64) % T).collect();
    let message = PolyRq::from_coeffs(&expected, n, Q);

    println!("\n--- RLWE/PRE profile: N={n}, q={Q}, t={T}, CBD2, base=2^{BASE_BITS} ---");
    println!("[PARAM] q, plaintext, sampler and gadget base fixed; increasing N is not a security upgrade");

    let source = timed("source KeyGen", || KeyGenResult::keygen(&mut rng, n));
    let middle = timed("middle KeyGen", || KeyGenResult::keygen(&mut rng, n));
    let destination = timed("destination KeyGen", || KeyGenResult::keygen(&mut rng, n));
    let ct_a = timed("encrypt attribute under A", || {
        encrypt_poly(&mut rng, &source.pk, &message, n)
    });
    println!(
        "[SIZE] attribute plaintext={} bytes; one ciphertext coefficient storage={} bytes",
        n * 8,
        storage_bytes(&ct_a)
    );
    check("initial encryption", &source.sk, &ct_a, &expected, n);

    let rk_ab = timed("generate rekey A->B", || {
        generate_rekey(&mut rng, &source.sk, &middle.pk, BASE_BITS)
    });
    let rk_bc = timed("generate rekey B->C", || {
        generate_rekey(&mut rng, &middle.sk, &destination.pk, BASE_BITS)
    });
    let rk_ac = timed("generate direct rekey A->C", || {
        generate_rekey(&mut rng, &source.sk, &destination.pk, BASE_BITS)
    });
    let rekey_bytes: usize = rk_ab
        .entries
        .iter()
        .map(|e| (e.k0.coefficients().len() + e.k1.coefficients().len()) * 8)
        .sum();
    println!(
        "[SIZE] each rekey={} entries; coefficient storage={} bytes (excludes heap/struct overhead)",
        rk_ab.entries.len(),
        rekey_bytes
    );

    let ct_b = timed("rekey A->B", || reencrypt(&ct_a, &rk_ab, BASE_BITS));
    check("A->B", &middle.sk, &ct_b, &expected, n);
    let ct_c = timed("second rekey B->C", || reencrypt(&ct_b, &rk_bc, BASE_BITS));
    check("A->B->C", &destination.sk, &ct_c, &expected, n);
    let ct_c_rr = timed("second hop + fresh Enc_C(0)", || {
        reencrypt_and_rerandomize(&mut rng, &ct_b, &rk_bc, &destination.pk, BASE_BITS)
    });
    check(
        "A->B->C with rerandomization",
        &destination.sk,
        &ct_c_rr,
        &expected,
        n,
    );
    let ct_direct = timed("direct A->C + fresh Enc_C(0)", || {
        reencrypt_and_rerandomize(&mut rng, &ct_a, &rk_ac, &destination.pk, BASE_BITS)
    });
    check("direct A->C", &destination.sk, &ct_direct, &expected, n);
    assert_eq!(
        &decrypt_poly(&destination.sk, &ct_c_rr, n).coefficients()[..n],
        &decrypt_poly(&destination.sk, &ct_direct, n).coefficients()[..n]
    );
    println!("[PASS] chained and direct paths decrypt to the same attribute.");
}

fn run_max_hops_until_critical_margin() {
    const N: usize = RING_DIMENSION;
    let mut rng = StdRng::seed_from_u64(0x484f_5053_4352_4954);
    let chain = prf_modulus_chain();
    let leaf_count = 1usize << (chain.len() - 1);
    let highest_q = *chain.last().expect("BPR12 modulus chain");
    let prf = RlwrPrf::new(
        RlwrPrfBase::sample(&mut rng, N, highest_q, leaf_count),
        chain,
    );

    let critical_threshold = (Q / T) / 2 - T;
    println!("\n=== MAXIMUM-HOPS DIAGNOSTIC: LINEAR RESHUFFLE + RLWE PRE + RR ===");
    println!("Parameters: N={N}, q={Q}, t={T}, CBD2, base=2^{BASE_BITS}; fixed seed; maximum {MAX_HOPS} hops.");
    println!("Stop rule: stop after a correctly decoded hop reaches {:.0}% of the conservative decryption margin; if a hop fails to decode, record it as the first failed attempt and stop.", 100.0 * CRITICAL_MARGIN_FRACTION);
    println!("Note: benchmark inspects phase noise with each recipient secret; a real transcryptor cannot do this.");

    let domain_factors = timed("derive invertible factors for benchmark domains", || {
        (0..=MAX_HOPS)
            .map(|i| {
                derive_invertible_reshuffle_factor(&prf, &format!("bench-domain-{i:02}"), N, Q)
                    .expect("derive invertible factor")
            })
            .collect::<Vec<_>>()
    });

    let original: Vec<u64> = (0..N).map(|i| ((i * 7 + 3) as u64) % T).collect();
    let original_p = PolyRq::from_coeffs(&original, N, T);
    let represented_0 = original_p.mul_negacyclic(&domain_factors[0].factor_mod_p);
    let represented_0_q = lift_prf_output_to_q(&represented_0, Q);
    let mut current_keys = timed("initial RLWE KeyGen", || KeyGenResult::keygen(&mut rng, N));
    let mut ciphertext = timed("initial encrypt represented payload", || {
        encrypt_poly(&mut rng, &current_keys.pk, &represented_0_q, N)
    });
    println!(
        "[SIZE] payload={} bytes; ciphertext coefficient storage={} bytes",
        N * 8,
        storage_bytes(&ciphertext)
    );
    let mut last_error = check(
        "hop 0 / initial ciphertext",
        &current_keys.sk,
        &ciphertext,
        &represented_0.coefficients()[..N],
        N,
    );

    let mut completed = 0usize;
    let mut stop_reason = "maximum hop cap reached";
    for hop in 1..=MAX_HOPS {
        let source_factor = &domain_factors[hop - 1];
        let target_factor = &domain_factors[hop];
        let relative_p = source_factor
            .inverse_mod_p
            .mul_negacyclic(&target_factor.factor_mod_p);
        let factor_q = lift_prf_output_to_q(&relative_p, Q);
        let expected_p = original_p.mul_negacyclic(&target_factor.factor_mod_p);
        let next_keys = timed(&format!("hop {hop}: recipient KeyGen"), || {
            KeyGenResult::keygen(&mut rng, N)
        });
        let rekey = timed(&format!("hop {hop}: generate rekey"), || {
            generate_rekey(&mut rng, &current_keys.sk, &next_keys.pk, BASE_BITS)
        });
        if hop == 1 {
            let rekey_bytes: usize = rekey
                .entries
                .iter()
                .map(|entry| (entry.k0.coefficients().len() + entry.k1.coefficients().len()) * 8)
                .sum();
            println!(
                "[SIZE] rekey entries={}; coefficient storage={} bytes (excludes allocator/struct overhead)",
                rekey.entries.len(),
                rekey_bytes
            );
        }
        let start = Instant::now();
        let reshuffled = reshuffle(&ciphertext, &factor_q);
        ciphertext =
            reencrypt_and_rerandomize(&mut rng, &reshuffled, &rekey, &next_keys.pk, BASE_BITS);
        println!(
            "[TIME] hop {hop}: reshuffle + key switch + RR: {:.6} s",
            start.elapsed().as_secs_f64()
        );

        let error = phase_error(
            &next_keys.sk,
            &ciphertext,
            &expected_p.coefficients()[..N],
            N,
        );
        let decoded = decrypt_poly(&next_keys.sk, &ciphertext, N);
        let decoded_correct = decoded.coefficients()[..N] == expected_p.coefficients()[..N];
        println!(
            "[NOISE] hop {hop}: max phase error={error}; decode threshold={critical_threshold}; used={:.1}%; decoded_correct={decoded_correct}",
            100.0 * error as f64 / critical_threshold as f64
        );
        last_error = error;
        let fraction = error as f64 / critical_threshold as f64;
        if !decoded_correct {
            stop_reason = "decryption failed on attempted hop";
            println!("[STOP] hop {hop}: ciphertext no longer decodes to the expected plaintext; previous successful hop count={completed}.");
            break;
        }
        completed = hop;
        current_keys = next_keys;

        if fraction >= 0.90 {
            stop_reason = "90% hard stop reached";
            println!("[STOP] hop {hop}: 90% hard stop before risking a decode failure.");
            break;
        }
        if fraction >= CRITICAL_MARGIN_FRACTION {
            stop_reason = "critical margin threshold reached";
            println!(
                "[STOP] hop {hop}: observed phase error crossed the {:.0}% stop threshold.",
                100.0 * CRITICAL_MARGIN_FRACTION
            );
            break;
        }
        if fraction >= WARNING_MARGIN_FRACTION {
            println!("[WARNING] hop {hop}: more than half of the conservative margin is consumed.");
        }
    }

    println!(
        "[RESULT] successfully completed hops={completed}; stop reason={stop_reason}; last error fraction={:.1}%.",
        100.0 * last_error as f64 / critical_threshold as f64
    );
    println!("LIMIT: this is one seeded run at one parameter set; it does not establish a worst-case maximum or a failure probability.");
    println!("LIMIT: noise is checked with secret keys for diagnostics; this is not a runtime stop mechanism available to a proxy.");
}

#[test]
#[ignore = "diagnostic RLWE/PRE size sweep; run alone with --test-threads=1"]
fn rlwe_pre_size_sweep() {
    println!("\n=== RLWE/PRE PARAMETER SIZE SWEEP ===");
    println!("Profiles hold q, t, noise distribution and gadget base fixed; only N changes.");
    for n in [256, 512, 1024] {
        run_profile(n);
    }
}

#[test]
#[ignore = "diagnostic maximum-hop run; run alone with --test-threads=1"]
fn rlwe_max_hops_until_critical_margin() {
    run_max_hops_until_critical_margin();
}
