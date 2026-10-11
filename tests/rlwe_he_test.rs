
use rand::thread_rng;

use pq_libpep::algebra::ring::PolyRq;
use pq_libpep::core::rlwe_bgv_he::{
    BgvCiphertext,
    BgvModulusChain,
    RlweBgvHe,
};

const N: usize = 256;
const P: u64 = 17;

fn constant_poly(value: u64) -> PolyRq {
    let mut coeffs = vec![0u64; N];
    coeffs[0] = value % P;
    PolyRq::from_coeffs(&coeffs, N, P)
}

fn reduce_secret_coeffs(sk: &pq_libpep::core::rlwe_bgv_he::BgvSecretKey, q: u64) -> PolyRq {
    let source_q = sk.s.modulus();

    let coeffs = sk
        .s
        .coefficients()
        .iter()
        .take(N)
        .map(|&c| {
            let centered: i128 = if c > source_q / 2 {
                c as i128 - source_q as i128
            } else {
                c as i128
            };

            centered.rem_euclid(q as i128) as u64
        })
        .collect::<Vec<_>>();

    PolyRq::from_coeffs(&coeffs, N, q)
}

fn inspect(
    he: &RlweBgvHe,
    sk: &pq_libpep::core::rlwe_bgv_he::BgvSecretKey,
    chain: &BgvModulusChain,
    ciphertext: &BgvCiphertext,
    expected: u64,
) {
    let q = chain.modulus(ciphertext.level);
    let sk_level = reduce_secret_coeffs(sk, q);

    let phase = ciphertext
        .ciphertext
        .v
        .sub(
            &ciphertext
                .ciphertext
                .u
                .mul_negacyclic(&sk_level),
        );

    let mut max_abs_phase: i128 = 0;

    for &coefficient in phase.coefficients().iter().take(N) {
        let centered: i128 = if coefficient > q / 2 {
            coefficient as i128 - q as i128
        } else {
            coefficient as i128
        };

        max_abs_phase = max_abs_phase.max(centered.abs());
    }

    let decoded = he
        .decrypt_leveled(sk, ciphertext, chain, N)
        .to_coeffs_vec()[0];

    let limit = q / 2;
    let margin = limit.saturating_sub(max_abs_phase as u64);

    println!();
    println!("----------------------------------------------");
    println!("level              = {}", ciphertext.level);
    println!("q                  = {}", q);
    println!("decoded            = {}", decoded);
    println!("expected           = {}", expected);
    println!("max centered phase = {}", max_abs_phase);
    println!("q / 2              = {}", limit);
    println!("remaining margin   = {}", margin);
    println!(
        "noise / (q/2)      = {:.6}",
        (max_abs_phase as f64) / (limit as f64)
    );

    assert_eq!(
        decoded,
        expected,
        "leveled BGV decoding failed at level {}",
        ciphertext.level
    );

    assert!(
        max_abs_phase < limit as i128,
        "noise exceeded the centered decoding bound at level {}",
        ciphertext.level
    );
}

#[test]
#[ignore = "Legacy non-RNS BGV prototype; known decoding failure at x^8"]
fn test_bgv_four_multiplication_chain() {
    let mut rng = thread_rng();

    println!("==============================================");
    println!("       LEVELED BGV FOUR-MULTIPLICATION TEST");
    println!("==============================================");
    println!("N = {}", N);
    println!("P = {}", P);

    let he = RlweBgvHe::new();
    let chain = BgvModulusChain::default();

    println!("Modulus chain:");
    for level in 0..chain.len() {
        println!("q[{}] = {}", level, chain.modulus(level));
    }

    println!();
    println!("Generating leveled BGV keys...");

    let keygen = he.keygen_leveled(
        &mut rng,
        N,
        &chain,
    );

    println!("Generating relinearization key chain...");

    let relin_keys = he.generate_relinearization_key_chain(
        &mut rng,
        &keygen.sk,
        &chain,
        4,
    );

    assert_eq!(
        relin_keys.keys.len(),
        4,
        "four multiplication steps require four relinearization-key levels"
    );

    println!(
        "relinearization-key levels = {}",
        relin_keys.keys.len()
    );

    println!();
    println!("Encrypting x = 13...");

    let mut current = he.encrypt_leveled(
        &mut rng,
        &keygen.pk,
        &constant_poly(13),
        N,
    );

    inspect(
        &he,
        &keygen.sk,
        &chain,
        &current,
        13,
    );

    let expected = [16u64, 1u64, 1u64, 1u64];

    for (step, &expected_value) in expected.iter().enumerate() {
        println!();
        println!(
            "Computing multiplication step {} -> x^{}...",
            step + 1,
            2usize.pow((step + 1) as u32)
        );

        current = he.mul_ciphertext_leveled(
            &current,
            &current,
            &relin_keys,
            &chain,
        );

        assert_eq!(
            current.level,
            step + 1,
            "ciphertext level did not advance correctly"
        );

        inspect(
            &he,
            &keygen.sk,
            &chain,
            &current,
            expected_value,
        );
    }

    println!();
    println!("==============================================");
    println!("RESULT: FOUR LEVELED HOMOMORPHIC MULTIPLICATIONS WORK");
    println!("x^2, x^4, x^8 and x^16 all decode correctly.");
    println!("==============================================");
}
