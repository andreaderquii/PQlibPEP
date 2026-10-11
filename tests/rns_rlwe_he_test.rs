use num_bigint::{BigInt, BigUint, Sign};
use pq_libpep::core::rns::{RnsModulusChain, RnsPoly};
use pq_libpep::core::rlwe_rns::RnsRlwe;
use pq_libpep::core::rns_rlwe_he::RnsRlweHe;
use rand::{rngs::StdRng, SeedableRng};
use pq_libpep::core::rlwe_rns::{
    RnsCiphertext,
    RnsSecretKey,
};

const N: usize = 256;
const P: u64 = 17;

fn constant_message(value: u64) -> Vec<u64> {
    let mut message = vec![0u64; N];
    message[0] = value % P;
    message
}

/// CRT-decode one coefficient of an RNS phase.
///
/// The phase is reconstructed modulo the full CRT modulus Q and then
/// centered before reduction modulo 17.
fn decode_rns_phase_coefficient(
    phase: &RnsPoly,
    coefficient_index: usize,
) -> u64 {
    let residue_count = phase.residue_count();

    let moduli: Vec<u64> = (0..residue_count)
        .map(|i| phase.residue(i).modulus())
        .collect();

    let full_modulus = moduli.iter().fold(
        BigUint::from(1u64),
        |acc, &q| acc * BigUint::from(q),
    );

    let half_modulus = &full_modulus >> 1usize;

    let mut crt_constants = Vec::with_capacity(residue_count);

    for &q_i in &moduli {
        let q_i_big = BigUint::from(q_i);
        let m_i = &full_modulus / &q_i_big;

        let m_i_mod_q = (&m_i % q_i)
            .to_u64_digits()
            .first()
            .copied()
            .unwrap_or(0);

        let inverse = mod_inverse_u64(
            m_i_mod_q,
            q_i,
        );

        crt_constants.push((m_i, inverse));
    }

    let q_mod_p = (&full_modulus % P)
        .to_u64_digits()
        .first()
        .copied()
        .unwrap_or(0);

    // CRT reconstruction.
    let mut x = BigUint::from(0u64);

    for residue_index in 0..residue_count {
        let residue =
            phase.residue(residue_index)
                .coefficients()[coefficient_index];

        let (ref m_i, inverse) =
            crt_constants[residue_index];

        x += BigUint::from(residue)
            * m_i
            * BigUint::from(inverse);
    }

    x %= &full_modulus;

    let x_mod_p = (&x % P)
        .to_u64_digits()
        .first()
        .copied()
        .unwrap_or(0);

    // Centered representative:
    //
    // if x <= Q/2:
    //     centered = x
    //
    // otherwise:
    //     centered = x - Q
    //
    // Therefore modulo P:
    //
    //     (x - Q) mod P
    //       = x_mod_p - Q_mod_p mod P
    if x > half_modulus {
        (
            x_mod_p
                + P
                - q_mod_p
        ) % P
    } else {
        x_mod_p
    }
}

fn mod_inverse_u64(
    value: u64,
    modulus: u64,
) -> u64 {
    let mut t: i128 = 0;
    let mut new_t: i128 = 1;

    let mut r = modulus as i128;
    let mut new_r = value as i128;

    while new_r != 0 {
        let quotient = r / new_r;

        let next_t = t - quotient * new_t;
        t = new_t;
        new_t = next_t;

        let next_r = r - quotient * new_r;
        r = new_r;
        new_r = next_r;
    }

    assert_eq!(
        r,
        1,
        "CRT value is not invertible"
    );

    t.rem_euclid(modulus as i128) as u64
}

#[test]
fn test_rns_raw_multiplication() {
    let chain =
        RnsModulusChain::default_for_degree(N);

    let mut rng =
        StdRng::seed_from_u64(
            0x524E535F48455F31,
        );

    let rlwe = RnsRlwe::new();
    let he = RnsRlweHe::new();

    let keys =
        rlwe.keygen(&mut rng, &chain);

    let ciphertext =
        rlwe.encrypt(
            &mut rng,
            &keys.pk,
            &constant_message(13),
        );

    let raw =
        he.mul_raw(
            &ciphertext,
            &ciphertext,
        );

    // phase =
    //
    // c0 + c1*s + c2*s^2
    let secret_squared =
        keys.sk
            .s
            .mul_negacyclic(&keys.sk.s);

    let raw_phase =
        raw.c0
            .add(
                &raw.c1
                    .mul_negacyclic(&keys.sk.s),
            )
            .add(
                &raw.c2
                    .mul_negacyclic(&secret_squared),
            );

    let decoded =
        decode_rns_phase_coefficient(
            &raw_phase,
            0,
        );

    println!();
    println!("==============================================");
    println!("             RAW RNS MULTIPLICATION");
    println!("==============================================");
    println!("expected = 16");
    println!("decoded  = {}", decoded);

    assert_eq!(
        decoded,
        16,
        "raw ciphertext multiplication already breaks the plaintext"
    );

    println!("RAW multiplication: OK");
}

#[test]
fn test_rns_relinearization_preserves_product() {
    let chain =
        RnsModulusChain::default_for_degree(N);

    let mut rng =
        StdRng::seed_from_u64(
            0x524E535F48455F31,
        );

    let rlwe = RnsRlwe::new();
    let he = RnsRlweHe::new();

    let keys =
        rlwe.keygen(&mut rng, &chain);

    let relin_key =
        he.generate_relinearization_key(
            &mut rng,
            &keys.sk,
            8,
        );

    let ciphertext =
        rlwe.encrypt(
            &mut rng,
            &keys.pk,
            &constant_message(13),
        );

    let raw =
        he.mul_raw(
            &ciphertext,
            &ciphertext,
        );

    let relinearized =
        he.relinearize(
            &raw,
            &relin_key,
        );
        println!();
        println!("==============================================");
        println!("       PER-LIMB RELINEARIZATION CHECK");
        println!("==============================================");

        for residue_index in 0..chain.len() {
            let decoded = decode_single_rns_residue(
                &relinearized,
                &keys.sk,
                residue_index,
                0,
            );

            println!(
                "q[{}] = {:>10} -> decoded = {}",
                residue_index,
                chain.modulus(residue_index),
                decoded
            );
        }

    let decoded =
        rlwe.decrypt(
            &keys.sk,
            &relinearized,
        );

    println!();
    println!("==============================================");
    println!("            RNS RELINEARIZATION");
    println!("==============================================");
    println!(
        "expected = 16"
    );
    println!(
        "decoded  = {}",
        decoded[0]
    );

    assert_eq!(
        decoded[0],
        16,
        "relinearization changes the plaintext"
    );

    println!(
        "RELINEARIZATION: OK"
    );
}

#[test]
fn test_rns_ciphertext_multiplication_and_relinearization() {
    let chain =
        RnsModulusChain::default_for_degree(N);

    let mut rng =
        StdRng::seed_from_u64(
            0x524E535F48455F31,
        );

    let rlwe = RnsRlwe::new();
    let he = RnsRlweHe::new();

    println!("==============================================");
    println!("       RNS HOMOMORPHIC MULTIPLICATION");
    println!("==============================================");
    println!("N = {}", N);
    println!("RNS residues = {}", chain.len());

    let keys =
        rlwe.keygen(
            &mut rng,
            &chain,
        );

    let relin_key =
        he.generate_relinearization_key(
            &mut rng,
            &keys.sk,
            8,
        );

    println!(
        "relinearization digits = {}",
        relin_key.entries.len()
    );

    let ciphertext =
        rlwe.encrypt(
            &mut rng,
            &keys.pk,
            &constant_message(13),
        );

    let product =
        he.mul_ciphertext(
            &ciphertext,
            &ciphertext,
            &relin_key,
        );

    let decrypted =
        rlwe.decrypt(
            &keys.sk,
            &product,
        );

    println!(
        "Encrypted 13 * 13 = {}",
        decrypted[0]
    );

    assert_eq!(
        decrypted[0],
        16
    );

    assert!(
        decrypted[1..]
            .iter()
            .all(|&c| c == 0),
        "unexpected nonzero coefficients"
    );

    println!(
        "RNS ciphertext multiplication + relinearization: OK"
    );
}

fn decode_single_rns_residue(
    ciphertext: &RnsCiphertext,
    sk: &RnsSecretKey,
    residue_index: usize,
    coefficient_index: usize,
) -> u64 {
    const P: u64 = 17;

    let u = ciphertext.u.residue(residue_index);
    let v = ciphertext.v.residue(residue_index);
    let s = sk.s.residue(residue_index);

    let us = u.mul_ntt(s);
    let phase = v.sub(&us);

    let q = phase.modulus();
    let x = phase.coefficients()[coefficient_index];

    let x_mod_p = x % P;

    if x > q / 2 {
        (
            x_mod_p
                + P
                - (q % P)
        ) % P
    } else {
        x_mod_p
    }
}

// helper
fn measure_max_noise(
    ciphertext: &pq_libpep::core::rlwe_rns::RnsCiphertext,
    sk: &pq_libpep::core::rlwe_rns::RnsSecretKey,
    expected_plaintext: &[u64],
) -> (BigUint, BigUint) {
    const P: u64 = 17;

    assert_eq!(
        expected_plaintext.len(),
        ciphertext.u.degree,
        "plaintext and ciphertext degrees do not match"
    );

    // phase = v - u*s, represented modulo the complete CRT modulus.
    let us = ciphertext.u.mul_negacyclic(&sk.s);
    let phase = ciphertext.v.sub(&us);

    let moduli: Vec<u64> = (0..phase.residue_count())
        .map(|i| phase.residue(i).modulus())
        .collect();

    let full_modulus = moduli.iter().fold(
        BigUint::from(1u64),
        |acc, &q| acc * BigUint::from(q),
    );

    let half_modulus = &full_modulus / BigUint::from(2u64);

    let q_mod_p = (&full_modulus % BigUint::from(P))
        .to_u64_digits()
        .first()
        .copied()
        .unwrap_or(0);

    let inv_q_mod_p = mod_inverse_u64(q_mod_p, P);

    let q_bigint = BigInt::from_biguint(
        Sign::Plus,
        full_modulus.clone(),
    );

    let p_bigint = BigInt::from(P);

    // Precompute CRT reconstruction constants:
    // M_i = Q/q_i, inv_i = M_i^(-1) mod q_i.
    let mut crt_constants = Vec::with_capacity(moduli.len());

    for &q_i in &moduli {
        let q_i_big = BigUint::from(q_i);
        let m_i = &full_modulus / &q_i_big;

        let m_i_mod_q = (&m_i % q_i)
            .to_u64_digits()
            .first()
            .copied()
            .unwrap_or(0);

        let inverse = mod_inverse_u64(m_i_mod_q, q_i);

        crt_constants.push((m_i, inverse));
    }

    let mut max_minimum_lift_noise = BigUint::from(0u64);

    for coefficient_index in 0..expected_plaintext.len() {
        // Reconstruct the coefficient in [0, Q).
        let mut value = BigUint::from(0u64);

        for residue_index in 0..moduli.len() {
            let residue = phase
                .residue(residue_index)
                .coefficients()[coefficient_index];

            let (m_i, inverse) = &crt_constants[residue_index];

            value += BigUint::from(residue)
                * m_i
                * BigUint::from(*inverse);
        }

        value %= &full_modulus;

        // Compute the decoded coefficient modulo P.
        let value_mod_p = (&value % BigUint::from(P))
            .to_u64_digits()
            .first()
            .copied()
            .unwrap_or(0);

        let is_negative = value > half_modulus;

        let observed_plaintext = if is_negative {
            (value_mod_p + P - q_mod_p) % P
        } else {
            value_mod_p
        };

        // Convert the CRT representative to the centered interval.
        let centered = if is_negative {
            BigInt::from_biguint(Sign::Plus, value)
                - q_bigint.clone()
        } else {
            BigInt::from_biguint(Sign::Plus, value)
        };

        let expected = expected_plaintext[coefficient_index] % P;

        // Find the smallest-magnitude wrap correction k satisfying:
        //
        // centered + k*Q == expected (mod P).
        //
        // This is necessary when centered decoding is already incorrect.
        let delta = (expected + P - observed_plaintext) % P;
        let k_unsigned = (delta * inv_q_mod_p) % P;

        let k_signed = if k_unsigned > P / 2 {
            k_unsigned as i64 - P as i64
        } else {
            k_unsigned as i64
        };

        let lifted_phase =
            centered + BigInt::from(k_signed) * q_bigint.clone();

        let difference = lifted_phase - BigInt::from(expected);

        assert_eq!(
            &difference % &p_bigint,
            BigInt::from(0u64),
            "CRT lift is not compatible with the expected plaintext"
        );

        // For a correct centered decoding this is the ordinary noise.
        // For an incorrect decoding this is the minimum-magnitude
        // noise compatible with the expected plaintext, hence a lower
        // bound on the actual noise magnitude.
        let noise = difference / &p_bigint;
        let magnitude = noise.magnitude().clone();

        if magnitude > max_minimum_lift_noise {
            max_minimum_lift_noise = magnitude;
        }
    }

    (max_minimum_lift_noise, full_modulus)
}
#[test]
fn test_rns_multiplication_depth_limit() {
    const X: u64 = 13;
    const P: u64 = 17;

    let chain = RnsModulusChain::default_for_degree(N);
    let mut rng = StdRng::seed_from_u64(0x524E535F44455054);

    let rlwe = RnsRlwe::new();
    let he = RnsRlweHe::new();

    println!("==============================================");
    println!("       RNS MULTIPLICATIVE DEPTH LIMIT");
    println!("==============================================");

    let keys = rlwe.keygen(&mut rng, &chain);

    let relin_key =
        he.generate_relinearization_key(&mut rng, &keys.sk, 8);

    let mut current = rlwe.encrypt(
        &mut rng,
        &keys.pk,
        &constant_message(X),
    );

    let expected_results = [
        (2usize, 16u64),
        (4usize, 1u64),
        (8usize, 1u64),
        (16usize, 1u64),
        (32usize, 1u64),
        (64usize, 1u64),
        (128usize, 1u64),
        (256usize, 1u64),
    ];

    let mut successful_levels = 0usize;
    let mut last_successful_exponent = 1usize;

    for (exponent, expected_value) in expected_results {
        println!();
        println!("Computing encrypted x^{}...", exponent);

        current = he.mul_ciphertext(
            &current,
            &current,
            &relin_key,
        );

        let decrypted = rlwe.decrypt(&keys.sk, &current);

        let mut expected_plaintext = vec![0u64; N];
        expected_plaintext[0] = expected_value % P;

        // Measure even if the decrypted plaintext is incorrect.
        let (noise_estimate, full_modulus) = measure_max_noise(
            &current,
            &keys.sk,
            &expected_plaintext,
        );

        let noise_limit =
            &full_modulus / BigUint::from(2 * P);

        let correct_constant =
            decrypted[0] == expected_value
                && decrypted[1..].iter().all(|&c| c == 0);

        println!("Expected coefficient[0] = {}", expected_value);
        println!("Decoded coefficient[0]  = {}", decrypted[0]);

        if correct_constant {
            println!(
                "Maximum absolute noise = {}",
                noise_estimate
            );
        } else {
            println!(
                "Minimum compatible-lift noise (lower bound) = {}",
                noise_estimate
            );
        }

        println!(
            "Noise magnitude in bits = {}",
            noise_estimate.bits()
        );
        println!(
            "Approximate decoding threshold Q/(2P) = {}",
            noise_limit
        );

        if noise_estimate >= noise_limit {
            println!(
                "The minimum compatible noise already reaches/exceeds the threshold."
            );

            println!(
                "Minimum threshold overshoot = {}",
                &noise_estimate - &noise_limit
            );
        } else if correct_constant {
            println!(
                "Remaining noise headroom = {}",
                &noise_limit - &noise_estimate
            );
        } else {
            println!(
                "The lower bound is below the threshold; actual noise may be larger."
            );
        }

        if !correct_constant {
            println!("DECODING FAILURE at x^{}", exponent);
            println!("Stopping at the first incorrect result.");
            break;
        }

        println!("x^{}: OK", exponent);

        successful_levels += 1;
        last_successful_exponent = exponent;
    }

    println!();
    println!("==============================================");
    println!("DEPTH EXPLORATION SUMMARY");
    println!(
        "Successful multiplication levels = {}",
        successful_levels
    );
    println!(
        "Last successful exponent = x^{}",
        last_successful_exponent
    );
    println!("==============================================");

    assert!(
        successful_levels >= 3,
        "Regression: the previously verified x^8 computation no longer works"
    );
}

#[test]
fn test_rns_extended_modulus_depth() {
    const X: u64 = 13;
    const P: u64 = 17;

    // Experimental chain: the original 9 RNS primes plus 3 more.
    // This changes only this test, not the default project parameters.
    let chain = RnsModulusChain::new(
        vec![
            8416769,
            8434177,
            8573441,
            8599553,
            8782337,
            8825857,
            8834561,
            8860673,
            8904193,
            9113089,
            9139201,
            9165313,
        ],
        N,
    );

    let mut rng = StdRng::seed_from_u64(0x524E535F45585444);

    let rlwe = RnsRlwe::new();
    let he = RnsRlweHe::new();

    let full_modulus = chain.moduli.iter().fold(
        BigUint::from(1u64),
        |acc, &q| acc * BigUint::from(q),
    );

    let noise_limit = &full_modulus / BigUint::from(2 * P);

    println!("==============================================");
    println!("     RNS EXTENDED MODULUS EXPERIMENT");
    println!("==============================================");
    println!("RNS residues = {}", chain.len());
    println!("Q bit length = {}", full_modulus.bits());
    println!("Approximate threshold bit length = {}", noise_limit.bits());

    let keys = rlwe.keygen(&mut rng, &chain);

    let relin_key = he.generate_relinearization_key(
        &mut rng,
        &keys.sk,
        8,
    );

    println!(
        "Relinearization digits = {}",
        relin_key.entries.len()
    );

    let mut current = rlwe.encrypt(
        &mut rng,
        &keys.pk,
        &constant_message(X),
    );

    let expected_results = [
        (2usize, 16u64),
        (4usize, 1u64),
        (8usize, 1u64),
        (16usize, 1u64),
        (32usize, 1u64),
        (64usize, 1u64),
        (128usize, 1u64),
        (256usize, 1u64),
    ];

    let mut successful_levels = 0usize;
    let mut last_successful_exponent = 1usize;

    for (exponent, expected_value) in expected_results {
        println!();
        println!("Computing encrypted x^{}...", exponent);

        current = he.mul_ciphertext(
            &current,
            &current,
            &relin_key,
        );

        let decrypted = rlwe.decrypt(&keys.sk, &current);

        let mut expected_plaintext = vec![0u64; N];
        expected_plaintext[0] = expected_value % P;

        let (noise_estimate, reconstructed_q) = measure_max_noise(
            &current,
            &keys.sk,
            &expected_plaintext,
        );

        assert_eq!(
            reconstructed_q,
            full_modulus,
            "Unexpected CRT modulus during noise measurement"
        );

        let correct_constant =
            decrypted[0] == expected_value
                && decrypted[1..].iter().all(|&c| c == 0);

        println!("Expected plaintext = {}", expected_value);
        println!("Decoded plaintext  = {}", decrypted[0]);
        println!("Noise estimate = {}", noise_estimate);
        println!("Noise estimate bit length = {}", noise_estimate.bits());

        if correct_constant {
            println!(
                "Remaining noise headroom = {}",
                if noise_estimate < noise_limit {
                    (&noise_limit - &noise_estimate).to_string()
                } else {
                    "0 or less".to_string()
                }
            );
        } else {
            println!("DECODING FAILURE at x^{}", exponent);
            println!(
                "The incompatible decoding means the reported noise is \
                 a lower bound, not necessarily the exact noise."
            );

            if noise_estimate >= noise_limit {
                println!(
                    "The lower bound already reaches/exceeds the \
                     approximate decoding threshold."
                );
            }

            break;
        }

        println!("x^{}: OK", exponent);

        successful_levels += 1;
        last_successful_exponent = exponent;
    }

    println!();
    println!("==============================================");
    println!("EXTENDED MODULUS SUMMARY");
    println!("Q bit length = {}", full_modulus.bits());
    println!("Successful multiplication levels = {}", successful_levels);
    println!("Last successful exponent = x^{}", last_successful_exponent);
    println!("==============================================");

    assert!(
        successful_levels >= 4,
        "The extended modulus did not preserve correct decoding through x^16"
    );
}


#[test]
fn test_rns_leveled_modswitch_depth_8() {
    const X: u64 = 13;
    const P: u64 = 17;

    // Start with 12 valid RNS primes.
    // One prime is removed after each multiplication level.
    const MODULI: [u64; 12] = [
        8416769,
        8434177,
        8573441,
        8599553,
        8782337,
        8825857,
        8834561,
        8860673,
        8904193,
        9113089,
        9139201,
        9165313,
    ];

    let initial_chain =
        RnsModulusChain::new(MODULI.to_vec(), N);

    let mut rng =
        StdRng::seed_from_u64(0x524E535F4C455638);

    let rlwe = RnsRlwe::new();
    let he = RnsRlweHe::new();

    let keys = rlwe.keygen(
        &mut rng,
        &initial_chain,
    );

    let mut current = rlwe.encrypt(
        &mut rng,
        &keys.pk,
        &constant_message(X),
    );

    // x^2 = 16 mod 17.
    // x^4 = 1 mod 17; every subsequent power here is also 1.
    let expected_results = [
        (2usize, 16u64),
        (4usize, 1u64),
        (8usize, 1u64),
        (16usize, 1u64),
        (32usize, 1u64),
        (64usize, 1u64),
        (128usize, 1u64),
        (256usize, 1u64),
    ];

    let mut successful_levels = 0usize;

    println!("==============================================");
    println!("      RNS-BGV LEVELED DEPTH TEST");
    println!("==============================================");
    println!("Initial RNS residues = {}", MODULI.len());

    for (level, (exponent, expected_value))
        in expected_results.iter().copied().enumerate()
    {
        // The input ciphertext must use this level's active RNS base.
        let active_len = MODULI.len() - level;

        assert_eq!(
            current.u.residue_count(),
            active_len,
            "ciphertext uses the wrong number of residues before level {}",
            level + 1,
        );

        let level_chain = RnsModulusChain::new(
            MODULI[..active_len].to_vec(),
            N,
        );

        // The same small secret polynomial is represented in the
        // current RNS base by retaining the matching residue prefix.
        let level_sk = RnsSecretKey {
            s: RnsPoly {
                residues: keys.sk.s.residues[..active_len].to_vec(),
                degree: N,
            },
        };

        // Relinearization keys are generated for the modulus currently
        // in use, rather than reusing a key from another level.
        let relin_key = he.generate_relinearization_key(
            &mut rng,
            &level_sk,
            8,
        );

        println!();
        println!(
            "Level {}: computing encrypted x^{}",
            level + 1,
            exponent,
        );
        println!("Input RNS residues = {}", level_chain.len());
        println!(
            "Relinearization digits = {}",
            relin_key.entries.len()
        );

        // Multiply ciphertext by itself and relinearize.
        let product = he.mul_ciphertext(
            &current,
            &current,
            &relin_key,
        );

        // Drop exactly one RNS modulus using the BGV correction.
        let target_chain = RnsModulusChain::new(
            MODULI[..active_len - 1].to_vec(),
            N,
        );

        current = he.modulus_switch(
            &product,
            &target_chain,
        );

        let target_sk = RnsSecretKey {
            s: RnsPoly {
                residues: keys.sk.s.residues[..active_len - 1].to_vec(),
                degree: N,
            },
        };

        // Decrypt the output at its new, smaller modulus.
        let decrypted = rlwe.decrypt(
            &target_sk,
            &current,
        );

        let mut expected_plaintext = vec![0u64; N];
        expected_plaintext[0] = expected_value % P;

        let (noise_estimate, switched_q) = measure_max_noise(
            &current,
            &target_sk,
            &expected_plaintext,
        );

        let decoding_limit =
            &switched_q / BigUint::from(2 * P);

        let correct_constant =
            decrypted[0] == expected_value
                && decrypted[1..].iter().all(|&c| c == 0);

        println!("Expected plaintext = {}", expected_value);
        println!("Decoded plaintext  = {}", decrypted[0]);
        println!("Noise estimate = {}", noise_estimate);
        println!("Noise magnitude in bits = {}", noise_estimate.bits());
        println!("Current Q bits = {}", switched_q.bits());

        if noise_estimate < decoding_limit {
            println!(
                "Estimated remaining headroom = {}",
                &decoding_limit - &noise_estimate
            );
        } else {
            println!(
                "Noise estimate reaches/exceeds the approximate decoding limit"
            );
        }

        if !correct_constant {
            println!(
                "DECODING FAILURE at level {} (x^{})",
                level + 1,
                exponent,
            );
            break;
        }

        println!("x^{}: OK", exponent);
        successful_levels += 1;
    }

    println!();
    println!("==============================================");
    println!("LEVELED DEPTH SUMMARY");
    println!("Successful levels = {}", successful_levels);
    println!("Required levels = 8");
    println!("==============================================");

    assert_eq!(
        successful_levels,
        8,
        "the leveled RNS-BGV prototype did not complete all eight multiplication levels"
    );
}