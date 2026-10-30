#![cfg(feature = "experimental-linear-reshuffle")]

//! Functional A -> B -> C test for the experimental linear RLWE reshuffle.
//! It does not test TFHE PID transitivity, unlinkability, RS2, or security.

use pq_libpep::algebra::ring::{PolyRq, Q};
use pq_libpep::core::params::{prf_modulus_chain, RING_DIMENSION};
use pq_libpep::core::reshuffle::{
    derive_invertible_reshuffle_factor, lift_prf_output_to_q, reshuffle,
};
use pq_libpep::core::rlwe::KeyGenResult;
use pq_libpep::core::rlwe_pke::{decrypt_poly, encrypt_poly, Ciphertext};
use pq_libpep::core::rlwe_pre::{generate_rekey, reencrypt_and_rerandomize};
use pq_libpep::core::rlwr_prf::{RlwrPrf, RlwrPrfBase};
use rand::{rngs::StdRng, SeedableRng};

const N: usize = RING_DIMENSION;
const T: u64 = 17;
const BASE_BITS: usize = 4;

fn relative_factor(source_inverse: &PolyRq, target_factor: &PolyRq) -> PolyRq {
    lift_prf_output_to_q(&source_inverse.mul_negacyclic(target_factor), Q)
}

fn phase_error(sk: &pq_libpep::core::rlwe::SecretKey, ct: &Ciphertext, expected: &[u64]) -> u64 {
    let delta = Q / T;
    let phase = ct.v.sub(&ct.u.mul_ntt(&sk.s));
    (0..N)
        .map(|i| {
            let target = ((expected[i] as u128 * delta as u128) % Q as u128) as u64;
            let residue = (phase.coefficients()[i] + Q - target) % Q;
            residue.min(Q - residue)
        })
        .max()
        .unwrap_or(0)
}

fn check(
    sk: &pq_libpep::core::rlwe::SecretKey,
    ct: &Ciphertext,
    expected: &[u64],
    label: &str,
) -> u64 {
    let decoded = decrypt_poly(sk, ct, N);
    assert_eq!(
        &decoded.coefficients()[..N],
        expected,
        "{label}: decoded payload mismatch"
    );
    phase_error(sk, ct, expected)
}

#[test]
fn linear_reshuffle_a_to_b_to_c_matches_direct_a_to_c() {
    let mut rng = StdRng::seed_from_u64(0x5452_414e_5349_5449);
    let chain = prf_modulus_chain();
    let leaf_count = 1usize << (chain.len() - 1);
    let highest_q = *chain.last().expect("BPR12 modulus chain");
    let prf = RlwrPrf::new(
        RlwrPrfBase::sample(&mut rng, N, highest_q, leaf_count),
        chain,
    );

    println!("\n=== LINEAR RESHUFFLE TRANSITIVITY TEST ===");
    println!("Payload RLWE: N={N}, Q={Q}, t={T}, rekey base=2^{BASE_BITS}; BPR12 factor PRF has {leaf_count} leaves.");
    println!("[1] Derive invertible factors for domains A, B and C.");
    let a = derive_invertible_reshuffle_factor(&prf, "hospital-A", N, Q).expect("factor A");
    let b = derive_invertible_reshuffle_factor(&prf, "hospital-B", N, Q).expect("factor B");
    let c = derive_invertible_reshuffle_factor(&prf, "hospital-C", N, Q).expect("factor C");
    let ab = relative_factor(&a.inverse_mod_p, &b.factor_mod_p);
    let bc = relative_factor(&b.inverse_mod_p, &c.factor_mod_p);
    let ac = relative_factor(&a.inverse_mod_p, &c.factor_mod_p);

    let original: Vec<u64> = (0..N).map(|i| ((i * 7 + 3) as u64) % T).collect();
    let original_p = PolyRq::from_coeffs(&original, N, T);
    let expected_a = original_p.mul_negacyclic(&a.factor_mod_p);
    let expected_b = original_p.mul_negacyclic(&b.factor_mod_p);
    let expected_c = original_p.mul_negacyclic(&c.factor_mod_p);
    let expected_a_q = lift_prf_output_to_q(&expected_a, Q);

    println!("[2] Encrypt M*g_A and transform A -> B -> C with fresh rekeys and rerandomization.");
    let ka = KeyGenResult::keygen(&mut rng, N);
    let kb = KeyGenResult::keygen(&mut rng, N);
    let kc = KeyGenResult::keygen(&mut rng, N);
    let ct_a = encrypt_poly(&mut rng, &ka.pk, &expected_a_q, N);
    let rk_ab = generate_rekey(&mut rng, &ka.sk, &kb.pk, BASE_BITS);
    let ct_b =
        reencrypt_and_rerandomize(&mut rng, &reshuffle(&ct_a, &ab), &rk_ab, &kb.pk, BASE_BITS);
    let noise_b = check(&kb.sk, &ct_b, &expected_b.coefficients()[..N], "A -> B");
    let rk_bc = generate_rekey(&mut rng, &kb.sk, &kc.pk, BASE_BITS);
    let ct_c_chain =
        reencrypt_and_rerandomize(&mut rng, &reshuffle(&ct_b, &bc), &rk_bc, &kc.pk, BASE_BITS);
    let noise_c_chain = check(
        &kc.sk,
        &ct_c_chain,
        &expected_c.coefficients()[..N],
        "A -> B -> C",
    );
    println!("[PASS] B and C open the expected domain representations.");

    println!("[3] Independently transform the original ciphertext directly A -> C.");
    let rk_ac = generate_rekey(&mut rng, &ka.sk, &kc.pk, BASE_BITS);
    let ct_c_direct =
        reencrypt_and_rerandomize(&mut rng, &reshuffle(&ct_a, &ac), &rk_ac, &kc.pk, BASE_BITS);
    let noise_c_direct = check(
        &kc.sk,
        &ct_c_direct,
        &expected_c.coefficients()[..N],
        "A -> C direct",
    );
    println!("[PASS] Direct A -> C decrypts to the same M*g_C as A -> B -> C.");
    println!(
        "[NOISE] A -> B={noise_b}; A -> B -> C={noise_c_chain}; direct A -> C={noise_c_direct}."
    );
    println!("[MARGIN] approximate Delta/2 threshold={}", (Q / T) / 2);
    println!("LIMIT: functional test for experimental linear RLWE reshuffling only; no unlinkability, TFHE PID transitivity, RS2 or security claim.");
}
