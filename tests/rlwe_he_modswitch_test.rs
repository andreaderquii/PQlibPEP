use pq_libpep::algebra::ring::PolyRq;
use pq_libpep::core::rlwe::{KeyGenResult, SecretKey};
use pq_libpep::core::rlwe_pke::{
    decrypt_poly,
    encrypt_poly,
    generate_relinearization_key,
    relinearize,
};
use rand::thread_rng;

const N: usize = 256;
const P: u64 = 17;

// Descending HE modulus chain:
//
// q4 -> q3 -> q2 -> q1 -> q0
//
// One ciphertext multiplication is performed at each level.
const Q4: u64 = 1_152_921_504_519_820_289; // ~2^60
const Q3: u64 = 1_125_899_819_845_121;     // ~2^50
const Q2: u64 = 1_099_424_591_873;         // ~2^40
const Q1: u64 = 986_720_257;               // ~2^30
const Q0: u64 = 557_057;                   // ~2^20

fn reduce_secret_key(
    sk: &SecretKey,
    modulus: u64,
) -> SecretKey {
    let source_modulus = sk.s.modulus();
    let coeffs = sk.s.coefficients();

    let mut reduced_coeffs =
        Vec::with_capacity(coeffs.len());

    for &c in coeffs {
        // The secret key is sampled as a small polynomial.
        //
        // Negative coefficients are stored modulo source_modulus:
        //
        //     -1 -> source_modulus - 1
        //     -2 -> source_modulus - 2
        //
        // Recover the centered representative first.

        let centered: i128 =
            if c > source_modulus / 2 {
                c as i128 - source_modulus as i128
            } else {
                c as i128
            };

        // Then map the signed small coefficient into
        // the new modulus.

        let reduced =
            centered.rem_euclid(
                modulus as i128
            ) as u64;

        reduced_coeffs.push(reduced);
    }

    let reduced =
        PolyRq::from_coeffs(
            &reduced_coeffs,
            sk.s.degree_bound(),
            modulus,
        );

    SecretKey {
        s: reduced,
    }
}

fn scale_correct_and_modulus_switch(
    ciphertext: &pq_libpep::core::rlwe_pke::Ciphertext,
    from_q: u64,
    to_q: u64,
) -> pq_libpep::core::rlwe_pke::Ciphertext {
    assert!(
        from_q > to_q,
        "modulus chain must strictly decrease"
    );

    assert_eq!(
        from_q % P,
        1,
        "source modulus must satisfy q = 17*Delta + 1"
    );

    assert_eq!(
        to_q % P,
        1,
        "target modulus must satisfy q = 17*Delta + 1"
    );

    // ------------------------------------------------------------
    // Step 1: Delta^2 -> Delta
    //
    // Since:
    //
    //     from_q = 17 * Delta + 1
    //
    // we have:
    //
    //     Delta^(-1) = -17 mod from_q
    // ------------------------------------------------------------

    let inv_delta = from_q - P;

    let u_scaled =
        ciphertext.u.mul_scalar(inv_delta);

    let v_scaled =
        ciphertext.v.mul_scalar(inv_delta);

    // ------------------------------------------------------------
    // Step 2: modulus switching
    //
    // Every coefficient must first be interpreted as its centered
    // representative in:
    //
    //     [-from_q/2, from_q/2)
    //
    // and only then scaled:
    //
    //     c' = round(c * to_q / from_q)
    //
    // This is essential because a coefficient near `from_q`
    // may actually represent a small negative integer.
    // ------------------------------------------------------------

    fn switch_poly(
        poly: &PolyRq,
        from_q: u64,
        to_q: u64,
    ) -> PolyRq {
        let coeffs = poly.coefficients();

        let denominator =
            from_q as i128;

        let half_from_q =
            from_q / 2;

        let mut switched =
            Vec::with_capacity(coeffs.len());

        for &c in coeffs {
            // Convert [0, from_q) into the centered interval
            // [-from_q/2, from_q/2).

            let centered: i128 =
                if c > half_from_q {
                    c as i128 - from_q as i128
                } else {
                    c as i128
                };

            // Scale and round to the nearest integer.

            let numerator =
                centered * to_q as i128;

            let scaled: i128 =
                if numerator >= 0 {
                    (numerator + denominator / 2)
                        / denominator
                } else {
                    -(
                        ((-numerator) + denominator / 2)
                            / denominator
                    )
                };

            // Return to Z_to_q.

            let reduced =
                scaled.rem_euclid(
                    to_q as i128
                ) as u64;

            switched.push(reduced);
        }

        PolyRq::from_coeffs(
            &switched,
            poly.degree_bound(),
            to_q,
        )
    }

    let u =
        switch_poly(
            &u_scaled,
            from_q,
            to_q,
        );

    let v =
        switch_poly(
            &v_scaled,
            from_q,
            to_q,
        );

    pq_libpep::core::rlwe_pke::Ciphertext {
        u,
        v,
    }
}

fn multiply_and_switch(
    ciphertext:
        &pq_libpep::core::rlwe_pke::Ciphertext,
    relin_key:
        &pq_libpep::core::rlwe_pke::RelinearizationKey,
    from_q: u64,
    to_q: u64,
) -> pq_libpep::core::rlwe_pke::Ciphertext {
    let product =
        ciphertext.mul_raw(ciphertext);

    let relinearized =
        relinearize(
            &product,
            relin_key,
        );

    scale_correct_and_modulus_switch(
        &relinearized,
        from_q,
        to_q,
    )
}

fn inspect_noise(
    label: &str,
    sk: &SecretKey,
    ciphertext:
        &pq_libpep::core::rlwe_pke::Ciphertext,
    q: u64,
    expected_plaintext: u64,
) {
    let delta = q / P;

    let phase =
        ciphertext
            .v
            .sub(
                &ciphertext
                    .u
                    .mul_ntt(&sk.s)
            );

    let coeffs =
        phase.to_coeffs_vec();

    let expected_encoded =
        (delta * (expected_plaintext % P)) % q;

    let mut max_abs_noise: i128 = 0;

    for i in 0..N {
        let expected =
            if i == 0 {
                expected_encoded
            } else {
                0
            };

        let diff =
            (coeffs[i] + q - expected) % q;

        let centered: i128 =
            if diff > q / 2 {
                diff as i128 - q as i128
            } else {
                diff as i128
            };

        max_abs_noise =
            max_abs_noise.max(centered.abs());
    }

    let decoded =
        decrypt_poly(
            sk,
            ciphertext,
            N,
        );

    let decoded_value =
        decoded.to_coeffs_vec()[0];

    println!();
    println!("----------------------------------------------");
    println!("{}", label);
    println!("----------------------------------------------");
    println!("q = {}", q);
    println!("Delta = {}", delta);
    println!(
        "decoded plaintext = {}",
        decoded_value
    );
    println!(
        "expected plaintext = {}",
        expected_plaintext
    );
    println!(
        "max absolute noise = {}",
        max_abs_noise
    );
    println!(
        "decoding limit = {}",
        delta / 2
    );
    println!(
        "noise / limit = {:.6}",
        (max_abs_noise as f64)
            / ((delta / 2) as f64)
    );
}

#[test]
#[ignore = "Legacy single-modulus Delta chain; known failure at x^8"]
fn test_rlwe_modulus_switch_power_chain() {
    let mut rng = thread_rng();

    println!("==============================================");
    println!("       RLWE MODULUS SWITCHING TEST");
    println!("==============================================");
    println!("N  = {}", N);
    println!("P  = {}", P);
    println!("Q4 = {}", Q4);
    println!("Q3 = {}", Q3);
    println!("Q2 = {}", Q2);
    println!("Q1 = {}", Q1);
    println!("Q0 = {}", Q0);

    // ------------------------------------------------------------
    // Plaintext x = 13
    // ------------------------------------------------------------

    let mut coeffs =
        vec![0u64; N];

    coeffs[0] = 13;

    let plaintext =
        PolyRq::from_coeffs(
            &coeffs,
            N,
            Q4,
        );

    // ------------------------------------------------------------
    // Top-level key generation.
    //
    // The same secret key is reused at every lower modulus.
    // ------------------------------------------------------------

    let keygen =
        KeyGenResult::keygen_with_modulus(
            &mut rng,
            N,
            Q4,
        );

    println!(
        "\nGenerating relinearization keys..."
    );

    let sk4 =
        reduce_secret_key(
            &keygen.sk,
            Q4,
        );

    let sk3 =
        reduce_secret_key(
            &keygen.sk,
            Q3,
        );

    let sk2 =
        reduce_secret_key(
            &keygen.sk,
            Q2,
        );

    let sk1 =
        reduce_secret_key(
            &keygen.sk,
            Q1,
        );

    let sk0 =
        reduce_secret_key(
            &keygen.sk,
            Q0,
        );

    let rk4 =
        generate_relinearization_key(
            &mut rng,
            &sk4,
            4,
        );

    let rk3 =
        generate_relinearization_key(
            &mut rng,
            &sk3,
            4,
        );

    let rk2 =
        generate_relinearization_key(
            &mut rng,
            &sk2,
            4,
        );

    let rk1 =
        generate_relinearization_key(
            &mut rng,
            &sk1,
            4,
        );

    // ------------------------------------------------------------
    // Encrypt x = 13 at the largest modulus.
    // ------------------------------------------------------------

    println!(
        "\nEncrypting x = 13 at Q4..."
    );

    let mut ciphertext =
        encrypt_poly(
            &mut rng,
            &keygen.pk,
            &plaintext,
            N,
        );

    // ------------------------------------------------------------
    // x^2:
    //
    // Q4 -> Q3
    // ------------------------------------------------------------

    println!("\nComputing x^2...");

    ciphertext =
        multiply_and_switch(
            &ciphertext,
            &rk4,
            Q4,
            Q3,
        );

    inspect_noise(
        "x^2 after Q4 -> Q3",
        &sk3,
        &ciphertext,
        Q3,
        16,
    );

    // ------------------------------------------------------------
    // x^4:
    //
    // Q3 -> Q2
    // ------------------------------------------------------------

    println!("\nComputing x^4...");

    ciphertext =
        multiply_and_switch(
            &ciphertext,
            &rk3,
            Q3,
            Q2,
        );

    inspect_noise(
        "x^4 after Q3 -> Q2",
        &sk2,
        &ciphertext,
        Q2,
        1,
    );

    // ------------------------------------------------------------
    // x^8:
    //
    // Q2 -> Q1
    // ------------------------------------------------------------

    println!("\nComputing x^8...");

    ciphertext =
        multiply_and_switch(
            &ciphertext,
            &rk2,
            Q2,
            Q1,
        );

    inspect_noise(
        "x^8 after Q2 -> Q1",
        &sk1,
        &ciphertext,
        Q1,
        1,
    );

    // ------------------------------------------------------------
    // x^16:
    //
    // Q1 -> Q0
    // ------------------------------------------------------------

    println!("\nComputing x^16...");

    ciphertext =
        multiply_and_switch(
            &ciphertext,
            &rk1,
            Q1,
            Q0,
        );

    inspect_noise(
        "x^16 after Q1 -> Q0",
        &sk0,
        &ciphertext,
        Q0,
        1,
    );

    let final_plaintext =
        decrypt_poly(
            &sk0,
            &ciphertext,
            N,
        );

    let final_value =
        final_plaintext.to_coeffs_vec()[0];

    println!();
    println!("==============================================");
    println!(
        "FINAL x^16 = {}",
        final_value
    );
    println!("EXPECTED   = 1");
    println!("==============================================");

    assert_eq!(
        final_value,
        1,
        "modulus switching chain failed at x^16"
    );
}