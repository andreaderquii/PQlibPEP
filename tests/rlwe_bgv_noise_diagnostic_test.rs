use rand::{rngs::StdRng, SeedableRng};

use pq_libpep::algebra::ring::PolyRq;
use pq_libpep::core::rlwe_bgv_he::{
    BgvCiphertext,
    BgvModulusChain,
    BgvRelinearizationKey,
    BgvSecretKey,
    RlweBgvHe,
};
use pq_libpep::core::rlwe_pke::MulCiphertext;

const N: usize = 256;
const P: u64 = 17;

fn constant_poly(value: u64) -> PolyRq {
    let mut coeffs = vec![0u64; N];
    coeffs[0] = value % P;
    PolyRq::from_coeffs(&coeffs, N, P)
}

fn reduce_secret_coeffs(sk: &BgvSecretKey, q: u64) -> PolyRq {
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

fn raw_mul(lhs: &BgvCiphertext, rhs: &BgvCiphertext) -> MulCiphertext {
    let c0 = lhs
        .ciphertext
        .v
        .mul_negacyclic(&rhs.ciphertext.v);

    let c1 = lhs
        .ciphertext
        .v
        .mul_negacyclic(&rhs.ciphertext.u)
        .add(
            &lhs
                .ciphertext
                .u
                .mul_negacyclic(&rhs.ciphertext.v),
        )
        .neg();

    let c2 = lhs
        .ciphertext
        .u
        .mul_negacyclic(&rhs.ciphertext.u);

    MulCiphertext { c0, c1, c2 }
}

fn manual_relinearize(
    product: &MulCiphertext,
    key: &BgvRelinearizationKey,
    level: usize,
) -> BgvCiphertext {
    let digits = pq_libpep::core::rlwe_pre::decompose_poly(
        &product.c2,
        key.base_bits,
    );

    assert_eq!(
        digits.len(),
        key.entries.len(),
        "ciphertext decomposition and relinearization key lengths differ"
    );

    let mut u = product.c1.neg();
    let mut v = product.c0.clone();

    for (digit, entry) in digits.iter().zip(key.entries.iter()) {
        u = u.add(&digit.mul_negacyclic(&entry.k0));
        v = v.add(&digit.mul_negacyclic(&entry.k1));
    }

    BgvCiphertext {
        ciphertext: pq_libpep::core::rlwe_pke::Ciphertext { u, v },
        level,
    }
}

fn phase_from_ciphertext(
    ciphertext: &BgvCiphertext,
    secret: &PolyRq,
) -> PolyRq {
    ciphertext
        .ciphertext
        .v
        .sub(&ciphertext.ciphertext.u.mul_negacyclic(secret))
}

fn phase_from_raw(
    product: &MulCiphertext,
    secret: &PolyRq,
) -> PolyRq {
    let secret_squared = secret.mul_negacyclic(secret);

    product
        .c0
        .add(&product.c1.mul_negacyclic(secret))
        .add(&product.c2.mul_negacyclic(&secret_squared))
}

fn centered_coefficient(value: u64, q: u64) -> i128 {
    if value > q / 2 {
        value as i128 - q as i128
    } else {
        value as i128
    }
}

fn max_abs_value(poly: &PolyRq) -> i128 {
    poly.coefficients()
        .iter()
        .take(N)
        .map(|&c| centered_coefficient(c, poly.modulus()).abs())
        .max()
        .unwrap_or(0)
}

fn max_abs_noise(phase: &PolyRq, expected: u64) -> i128 {
    let q = phase.modulus();

    phase
        .coefficients()
        .iter()
        .take(N)
        .map(|&c| {
            let centered = centered_coefficient(c, q);
            (centered - expected as i128).abs()
        })
        .max()
        .unwrap_or(0)
}

fn max_abs_phase_difference(lhs: &PolyRq, rhs: &PolyRq) -> i128 {
    assert_eq!(lhs.modulus(), rhs.modulus());

    let q = lhs.modulus();

    let differences = lhs
        .coefficients()
        .iter()
        .zip(rhs.coefficients().iter())
        .take(N)
        .map(|(&a, &b)| {
            let raw = a as i128 - b as i128;
            let centered = raw.rem_euclid(q as i128);

            if centered > (q / 2) as i128 {
                centered - q as i128
            } else {
                centered
            }
        });

    differences.map(|x| x.abs()).max().unwrap_or(0)
}

fn print_measurement(
    label: &str,
    phase: &PolyRq,
    expected: u64,
) {
    let q = phase.modulus();
    let max_phase = max_abs_value(phase);
    let max_noise = max_abs_noise(phase, expected);
    let limit = q / 2;

    let noise_ratio =
        (max_noise as f64) / (limit as f64);

    let phase_ratio =
        (max_phase as f64) / (limit as f64);

    let margin =
        limit.saturating_sub(max_noise as u64);

    println!("\n{}", label);
    println!("  q                   = {}", q);
    println!("  expected plaintext  = {}", expected);
    println!("  max centered phase  = {}", max_phase);
    println!("  max abs noise       = {}", max_noise);
    println!("  q / 2               = {}", limit);
    println!("  noise margin        = {}", margin);
    println!("  phase / (q/2)       = {:.6}", phase_ratio);
    println!("  noise / (q/2)       = {:.6}", noise_ratio);
}

fn print_ciphertext_measurement(
    label: &str,
    he: &RlweBgvHe,
    sk: &BgvSecretKey,
    chain: &BgvModulusChain,
    ciphertext: &BgvCiphertext,
    expected: u64,
) {
    let q = chain.modulus(ciphertext.level);
    let sk_level = reduce_secret_coeffs(sk, q);

    let phase =
        phase_from_ciphertext(ciphertext, &sk_level);

    let decoded = he
        .decrypt_leveled(
            sk,
            ciphertext,
            chain,
            N,
        )
        .coefficients()[0];

    print_measurement(
        label,
        &phase,
        expected,
    );

    println!("  level               = {}", ciphertext.level);
    println!("  decoded[0]          = {}", decoded);
}

#[test]
fn test_bgv_noise_stage_diagnostic() {
    let mut rng =
        StdRng::seed_from_u64(0xBEEF_2026);

    println!("==============================================");
    println!("         BGV NOISE STAGE DIAGNOSTIC");
    println!("==============================================");
    println!("N = {}", N);
    println!("P = {}", P);

    let he = RlweBgvHe::new();
    let chain = BgvModulusChain::default();

    println!("\nModulus chain:");

    for level in 0..chain.len() {
        println!(
            "  q[{}] = {}",
            level,
            chain.modulus(level)
        );
    }

    println!("\nGenerating leveled BGV keys...");

    let keygen = he.keygen_leveled(
        &mut rng,
        N,
        &chain,
    );

    println!(
        "Generating relinearization key chain..."
    );

    let relin_keys =
        he.generate_relinearization_key_chain(
            &mut rng,
            &keygen.sk,
            &chain,
            4,
        );

    let mut current = he.encrypt_leveled(
        &mut rng,
        &keygen.pk,
        &constant_poly(13),
        N,
    );

    print_ciphertext_measurement(
        "[INPUT x]",
        &he,
        &keygen.sk,
        &chain,
        &current,
        13,
    );

    let expected_values =
        [16u64, 1u64, 1u64, 1u64];

    for (step, &expected)
        in expected_values.iter().enumerate()
    {
        let level = current.level;
        let q = chain.modulus(level);

        let sk_level =
            reduce_secret_coeffs(
                &keygen.sk,
                q,
            );

        println!(
            "\n=============================================="
        );

        println!(
            "STEP {}: x^{} -> x^{}",
            step + 1,
            1usize << step,
            1usize << (step + 1)
        );

        println!("current level = {}", level);
        println!("current q     = {}", q);
        println!("expected      = {}", expected);

        println!(
            "=============================================="
        );

        // =========================================================
        // A. RAW MULTIPLICATION
        // =========================================================

        let raw =
            raw_mul(&current, &current);

        let raw_phase =
            phase_from_raw(
                &raw,
                &sk_level,
            );

        print_measurement(
            "[A] RAW MULTIPLICATION",
            &raw_phase,
            expected,
        );

        // =========================================================
        // B. RELINEARIZATION
        // =========================================================

        let relin_key =
            relin_keys
                .keys
                .get(level)
                .expect(
                    "missing relinearization key for current level"
                );

        let relinearized =
            manual_relinearize(
                &raw,
                relin_key,
                level,
            );

        let relin_phase =
            phase_from_ciphertext(
                &relinearized,
                &sk_level,
            );

        print_measurement(
            "[B] AFTER RELINEARIZATION",
            &relin_phase,
            expected,
        );

        println!(
            "  relin phase delta   = {}",
            max_abs_phase_difference(
                &raw_phase,
                &relin_phase,
            )
        );

        // =========================================================
        // C. MODULUS SWITCHING
        // =========================================================

        let switched =
            he.modulus_switch(
                &relinearized,
                &chain,
            );

        print_ciphertext_measurement(
            "[C] AFTER MODULUS SWITCHING",
            &he,
            &keygen.sk,
            &chain,
            &switched,
            expected,
        );

        current = switched;
    }

    println!(
        "\n=============================================="
    );

    println!(
        "END OF NOISE DIAGNOSTIC"
    );

    println!(
        "=============================================="
    );

    println!(
        "No correctness assertion was used:"
    );

    println!(
        "this test is diagnostic only."
    );

    println!(
        "Compare A -> B -> C at every level."
    );
}