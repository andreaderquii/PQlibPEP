use pq_libpep::algebra::ring::{PolyRq, Q};
use pq_libpep::core::rlwe_pre::decompose_poly;

use rand::thread_rng;

use pq_libpep::core::rlwe::KeyGenResult;

use pq_libpep::core::rlwe_pke::{decrypt, encrypt};

use std::time::Instant;

use std::hint::black_box;

use pq_libpep::core::rlwe_pke::{decrypt_poly, encrypt_poly};
use pq_libpep::core::rlwe_pre::{generate_rekey, reencrypt};

use pq_libpep::core::reshuffle::{
    lift_prf_output_to_q,
    derive_reshuffle_factor,
    reshuffle,
};

use pq_libpep::core::id_encoding::{
    bytes_to_bits,
    string_to_id,
};
use pq_libpep::core::pseudonym::pseudonymize_32;

#[test]
fn test_decompose_and_reconstruct() {
    let n = 8;

    // B = 2^4 = 16
    let base_bits = 4;
    let base = 1u64 << base_bits;

    let input = PolyRq::from_coeffs(
        &[0, 1, 15, 16, 17, 255, 256, 998_244_352],
        n,
        Q,
    );

    println!("Input polynomial:");
    println!("{:?}", input.to_coeffs_vec()[..n].to_vec());

    println!("\nBase:");
    println!("B = {}", base);

    let digits = decompose_poly(&input, base_bits);

    println!("\nNumber of digits:");
    println!("{}", digits.len());

    for (i, digit_poly) in digits.iter().enumerate() {
        println!(
            "\nDigit d{}:",
            i
        );
        println!("{:?}", digit_poly.to_coeffs_vec()[..n].to_vec());
    }

    assert!(!digits.is_empty());

    let mut reconstructed = vec![0u64; n];

    for (digit_index, digit_poly) in digits.iter().enumerate() {
        let digit_coeffs = digit_poly.to_coeffs_vec();

        let power = (base as u128).pow(digit_index as u32);

        println!(
            "\nReconstructing digit {} with B^{} = {}",
            digit_index,
            digit_index,
            power
        );

        for j in 0..n {
            let contribution =
                (digit_coeffs[j] as u128 * power) % Q as u128;

            reconstructed[j] =
                ((reconstructed[j] as u128 + contribution)
                    % Q as u128) as u64;
        }
    }

    println!("\nReconstructed polynomial:");
    println!("{:?}", reconstructed);

    println!("\nExpected polynomial:");
    println!("{:?}", input.to_coeffs_vec()[..n].to_vec());

    assert_eq!(
        reconstructed,
        input.to_coeffs_vec()[..n].to_vec()
    );

    println!("\nDecomposition + reconstruction: OK");
}






//2nd test

#[test]
fn test_generate_rekey() {
    let mut rng = thread_rng();

    let n = 256;
    let base_bits = 4;
    let base = 1u64 << base_bits;

    println!("=== PRE KEY GENERATION TEST ===");
    println!("Ring dimension n = {}", n);
    println!("Modulus q = {}", pq_libpep::algebra::ring::Q);
    println!("Base B = {}", base);

    let alice = KeyGenResult::keygen(&mut rng, n);
    let bob = KeyGenResult::keygen(&mut rng, n);

    println!("\nGenerated Alice key pair.");
    println!("Generated Bob key pair.");

    let rekey = generate_rekey(
        &mut rng,
        &alice.sk,
        &bob.pk,
        base_bits,
    );

    println!(
        "\nNumber of KeySwitchEntry = {}",
        rekey.entries.len()
    );

    assert!(!rekey.entries.is_empty());

    for (i, entry) in rekey.entries.iter().enumerate() {
        println!(
            "Entry {}: k0 coeffs = {}, k1 coeffs = {}",
            i,
            entry.k0.to_coeffs_vec().len(),
            entry.k1.to_coeffs_vec().len()
        );
    }

    println!("\nReKey generation: OK");
}




#[test]
fn test_reencrypt_a_to_b() {
    let mut rng = thread_rng();

    let n = 256;
    let base_bits = 4;
    let base = 1u64 << base_bits;

    let message = vec![
        0, 1, 1, 0,
        1, 0, 1, 1,
    ];

    println!("=================================");
    println!("       PRE A -> B TEST");
    println!("=================================");
    println!("Ring dimension n = {}", n);
    println!("Modulus q = {}", Q);
    println!("Base B = {}", base);

    println!("\n[1] Generating Alice key pair...");
    let alice = KeyGenResult::keygen(&mut rng, n);

    println!("[2] Generating Bob key pair...");
    let bob = KeyGenResult::keygen(&mut rng, n);

    println!("\n[3] Original message:");
    println!("{:?}", message);

    println!("\n[4] Encrypting under Alice...");
    let ciphertext_a = encrypt(
        &mut rng,
        &alice.pk,
        &message,
        n,
    );

    println!(
        "ciphertext_a.u first coefficients = {:?}",
        &ciphertext_a.u.to_coeffs_vec()[..8]
    );

    println!(
        "ciphertext_a.v first coefficients = {:?}",
        &ciphertext_a.v.to_coeffs_vec()[..8]
    );

    println!("\n[5] Checking Alice can decrypt...");
    let recovered_a = decrypt(
        &alice.sk,
        &ciphertext_a,
        n,
        message.len(),
    );

    println!(
        "Alice recovered message = {:?}",
        recovered_a
    );

    assert_eq!(
        recovered_a,
        message,
        "Alice must decrypt her own ciphertext"
    );

    println!("\n[6] Generating re-encryption key Alice -> Bob...");
    let rekey = generate_rekey(
        &mut rng,
        &alice.sk,
        &bob.pk,
        base_bits,
    );

    println!(
        "ReKey entries = {}",
        rekey.entries.len()
    );

    println!("\n[7] Proxy re-encrypts Alice ciphertext...");
    let ciphertext_b = reencrypt(
        &ciphertext_a,
        &rekey,
        base_bits,
    );

    println!(
        "ciphertext_b.u first coefficients = {:?}",
        &ciphertext_b.u.to_coeffs_vec()[..8]
    );

    println!(
        "ciphertext_b.v first coefficients = {:?}",
        &ciphertext_b.v.to_coeffs_vec()[..8]
    );

    println!("\n[8] Bob decrypts re-encrypted ciphertext...");
    let recovered_b = decrypt(
        &bob.sk,
        &ciphertext_b,
        n,
        message.len(),
    );

    println!(
        "Bob recovered message = {:?}",
        recovered_b
    );

    println!("\n[9] Checking correctness...");

    assert_eq!(
        recovered_b,
        message,
        "Bob must recover the original message after re-encryption"
    );

    println!("=================================");
    println!("       PRE A -> B: OK");
    println!("=================================");
}

#[test]
fn test_reencrypt_a_to_b_to_c() {
    let mut rng = thread_rng();

    let n = 256;
    let base_bits = 4;
    let base = 1u64 << base_bits;

    let message = vec![
        1, 0, 1, 1,
        0, 1, 0, 0,
    ];

    println!("=================================");
    println!("      PRE A -> B -> C TEST");
    println!("=================================");
    println!("Ring dimension n = {}", n);
    println!("Modulus q = {}", Q);
    println!("Base B = {}", base);

    // ------------------------------------------------------------
    // 1. Key generation
    // ------------------------------------------------------------

    println!("\n[1] Generating Alice key pair...");
    let alice = KeyGenResult::keygen(&mut rng, n);

    println!("[2] Generating Bob key pair...");
    let bob = KeyGenResult::keygen(&mut rng, n);

    println!("[3] Generating Carol key pair...");
    let carol = KeyGenResult::keygen(&mut rng, n);

    // ------------------------------------------------------------
    // 2. Message
    // ------------------------------------------------------------

    println!("\n[4] Original message:");
    println!("{:?}", message);

    // ------------------------------------------------------------
    // 3. Encrypt under Alice
    // ------------------------------------------------------------

    println!("\n[5] Encrypting under Alice...");

    let ciphertext_a = encrypt(
        &mut rng,
        &alice.pk,
        &message,
        n,
    );

    println!(
        "ciphertext_a.u first coefficients = {:?}",
        &ciphertext_a.u.to_coeffs_vec()[..8]
    );

    println!(
        "ciphertext_a.v first coefficients = {:?}",
        &ciphertext_a.v.to_coeffs_vec()[..8]
    );

    // ------------------------------------------------------------
    // 4. Verify Alice can decrypt
    // ------------------------------------------------------------

    println!("\n[6] Checking Alice can decrypt...");

    let recovered_a = decrypt(
        &alice.sk,
        &ciphertext_a,
        n,
        message.len(),
    );

    println!(
        "Alice recovered message = {:?}",
        recovered_a
    );

    assert_eq!(
        recovered_a,
        message,
        "Alice must decrypt her own ciphertext"
    );

    // ------------------------------------------------------------
    // 5. Generate A -> B re-encryption key
    // ------------------------------------------------------------

    println!("\n[7] Generating re-encryption key Alice -> Bob...");

    let rekey_a_to_b = generate_rekey(
        &mut rng,
        &alice.sk,
        &bob.pk,
        base_bits,
    );

    println!(
        "RK_A->B entries = {}",
        rekey_a_to_b.entries.len()
    );

    // ------------------------------------------------------------
    // 6. Re-encrypt A -> B
    // ------------------------------------------------------------

    println!("\n[8] Proxy re-encrypts Alice -> Bob...");

    let ciphertext_b = reencrypt(
        &ciphertext_a,
        &rekey_a_to_b,
        base_bits,
    );

    println!(
        "ciphertext_b.u first coefficients = {:?}",
        &ciphertext_b.u.to_coeffs_vec()[..8]
    );

    println!(
        "ciphertext_b.v first coefficients = {:?}",
        &ciphertext_b.v.to_coeffs_vec()[..8]
    );

    // ------------------------------------------------------------
    // 7. Verify Bob can decrypt
    // ------------------------------------------------------------

    println!("\n[9] Checking Bob can decrypt after A -> B...");

    let recovered_b = decrypt(
        &bob.sk,
        &ciphertext_b,
        n,
        message.len(),
    );

    println!(
        "Bob recovered message = {:?}",
        recovered_b
    );

    assert_eq!(
        recovered_b,
        message,
        "Bob must recover the original message after A -> B"
    );

    // ------------------------------------------------------------
    // 8. Generate B -> C re-encryption key
    // ------------------------------------------------------------

    println!("\n[10] Generating re-encryption key Bob -> Carol...");

    let rekey_b_to_c = generate_rekey(
        &mut rng,
        &bob.sk,
        &carol.pk,
        base_bits,
    );

    println!(
        "RK_B->C entries = {}",
        rekey_b_to_c.entries.len()
    );

    // ------------------------------------------------------------
    // 9. Re-encrypt B -> C
    // ------------------------------------------------------------

    println!("\n[11] Proxy re-encrypts Bob -> Carol...");

    let ciphertext_c = reencrypt(
        &ciphertext_b,
        &rekey_b_to_c,
        base_bits,
    );

    println!(
        "ciphertext_c.u first coefficients = {:?}",
        &ciphertext_c.u.to_coeffs_vec()[..8]
    );

    println!(
        "ciphertext_c.v first coefficients = {:?}",
        &ciphertext_c.v.to_coeffs_vec()[..8]
    );

    // ------------------------------------------------------------
    // 10. Carol decrypts
    // ------------------------------------------------------------

    println!("\n[12] Carol decrypts after A -> B -> C...");

    let recovered_c = decrypt(
        &carol.sk,
        &ciphertext_c,
        n,
        message.len(),
    );

    println!(
        "Carol recovered message = {:?}",
        recovered_c
    );

    // ------------------------------------------------------------
    // 11. Final correctness check
    // ------------------------------------------------------------

    assert_eq!(
        recovered_c,
        message,
        "Carol must recover the original message after A -> B -> C"
    );

    println!("\n=================================");
    println!("      PRE A -> B -> C: OK");
    println!("=================================");
}

fn measure_noise(
    sk: &pq_libpep::core::rlwe::SecretKey,
    ciphertext: &pq_libpep::core::rlwe_pke::Ciphertext,
    message: &[u8],
    n: usize,
) -> (i64, f64) {
    let us = ciphertext.u.mul_ntt(&sk.s);
    let decoded_poly = ciphertext.v.sub(&us);
    let coeffs = decoded_poly.to_coeffs_vec();

    let delta = Q / 2;
    let q_i128 = Q as i128;

    let mut max_abs_noise = 0i64;
    let mut sum_abs_noise = 0i64;

    for j in 0..n {
        let expected = if j < message.len() && message[j] == 1 {
            delta
        } else {
            0u64
        };

        let raw_diff = coeffs[j] as i128 - expected as i128;

        // Center the noise in [-q/2, q/2).
        let mut centered = raw_diff.rem_euclid(q_i128);

        if centered > q_i128 / 2 {
            centered -= q_i128;
        }

        let noise = centered as i64;
        let abs_noise = noise.abs();

        max_abs_noise = max_abs_noise.max(abs_noise);
        sum_abs_noise += abs_noise;
    }

    let average_abs_noise = sum_abs_noise as f64 / n as f64;

    (max_abs_noise, average_abs_noise)
}


#[test]
fn test_noise_growth_a_to_b_to_c() {
    let mut rng = thread_rng();

    let n = 256;
    let base_bits = 4;

    let message = vec![
        1, 0, 1, 1,
        0, 1, 0, 0,
    ];

    println!("=================================");
    println!("      PRE NOISE GROWTH TEST");
    println!("=================================");
    println!("Ring dimension n = {}", n);
    println!("Modulus q = {}", Q);
    println!("Base B = {}", 1u64 << base_bits);
    println!("Decoding threshold |e| < q/4");
    println!("q/4 = {}", Q / 4);

    // ------------------------------------------------------------
    // Key generation
    // ------------------------------------------------------------

    println!("\n[1] Generating keys...");

    let alice = KeyGenResult::keygen(&mut rng, n);
    let bob = KeyGenResult::keygen(&mut rng, n);
    let carol = KeyGenResult::keygen(&mut rng, n);

    // ------------------------------------------------------------
    // Encrypt under Alice
    // ------------------------------------------------------------

    println!("\n[2] Encrypting under Alice...");

    let ciphertext_a = encrypt(
        &mut rng,
        &alice.pk,
        &message,
        n,
    );

    let (max_a, avg_a) = measure_noise(
        &alice.sk,
        &ciphertext_a,
        &message,
        n,
    );

    println!(
        "Alice ciphertext:"
    );
    println!(
        "  max |noise| = {}",
        max_a
    );
    println!(
        "  avg |noise| = {:.2}",
        avg_a
    );

    assert!(
        max_a < (Q / 4) as i64,
        "Alice ciphertext noise is outside the decoding region"
    );

    // ------------------------------------------------------------
    // A -> B
    // ------------------------------------------------------------

    println!("\n[3] Generating RK_A->B...");

    let rekey_a_to_b = generate_rekey(
        &mut rng,
        &alice.sk,
        &bob.pk,
        base_bits,
    );

    println!("[4] Re-encrypting A -> B...");

    let ciphertext_b = reencrypt(
        &ciphertext_a,
        &rekey_a_to_b,
        base_bits,
    );

    let (max_b, avg_b) = measure_noise(
        &bob.sk,
        &ciphertext_b,
        &message,
        n,
    );

    println!(
        "Bob ciphertext after A -> B:"
    );
    println!(
        "  max |noise| = {}",
        max_b
    );
    println!(
        "  avg |noise| = {:.2}",
        avg_b
    );

    assert!(
        max_b < (Q / 4) as i64,
        "A -> B noise is outside the decoding region"
    );

    let recovered_b = decrypt(
        &bob.sk,
        &ciphertext_b,
        n,
        message.len(),
    );

    assert_eq!(
        recovered_b,
        message,
        "Bob failed to decrypt after A -> B"
    );

    // ------------------------------------------------------------
    // B -> C
    // ------------------------------------------------------------

    println!("\n[5] Generating RK_B->C...");

    let rekey_b_to_c = generate_rekey(
        &mut rng,
        &bob.sk,
        &carol.pk,
        base_bits,
    );

    println!("[6] Re-encrypting B -> C...");

    let ciphertext_c = reencrypt(
        &ciphertext_b,
        &rekey_b_to_c,
        base_bits,
    );

    let (max_c, avg_c) = measure_noise(
        &carol.sk,
        &ciphertext_c,
        &message,
        n,
    );

    println!(
        "Carol ciphertext after A -> B -> C:"
    );
    println!(
        "  max |noise| = {}",
        max_c
    );
    println!(
        "  avg |noise| = {:.2}",
        avg_c
    );

    assert!(
        max_c < (Q / 4) as i64,
        "A -> B -> C noise is outside the decoding region"
    );

    let recovered_c = decrypt(
        &carol.sk,
        &ciphertext_c,
        n,
        message.len(),
    );

    assert_eq!(
        recovered_c,
        message,
        "Carol failed to decrypt after A -> B -> C"
    );

    // ------------------------------------------------------------
    // Summary
    // ------------------------------------------------------------

    println!("\n=================================");
    println!("          NOISE SUMMARY");
    println!("=================================");

    println!(
        "A       : max = {:>12}, avg = {:.2}",
        max_a, avg_a
    );

    println!(
        "A -> B  : max = {:>12}, avg = {:.2}",
        max_b, avg_b
    );

    println!(
        "A -> B -> C : max = {:>8}, avg = {:.2}",
        max_c, avg_c
    );

    println!(
        "\nDecoding boundary q/4 = {}",
        Q / 4
    );

    println!("Noise growth test: OK");
}


#[test]
fn test_multi_hop_noise_growth() {
    let mut rng = thread_rng();

    let n = 256;
    let base_bits = 4;
    let max_hops = 10;

    let message = vec![
        1, 0, 1, 1,
        0, 1, 0, 0,
    ];

    println!("===============================================");
    println!("         PRE MULTI-HOP NOISE TEST");
    println!("===============================================");
    println!("Ring dimension n = {}", n);
    println!("Modulus q = {}", Q);
    println!("Base B = {}", 1u64 << base_bits);
    println!("Maximum hops = {}", max_hops);
    println!("Decoding boundary |noise| < {}", Q / 4);

    // ------------------------------------------------------------
    // Initial party: Alice
    // ------------------------------------------------------------

    println!("\n[0] Generating Alice key pair...");

    let alice = KeyGenResult::keygen(&mut rng, n);

    println!("[0] Encrypting message under Alice...");

    let mut current_ciphertext = encrypt(
        &mut rng,
        &alice.pk,
        &message,
        n,
    );

    let mut current_sk = alice.sk;

    // ------------------------------------------------------------
    // Measure initial encryption noise
    // ------------------------------------------------------------

    let (max_noise, avg_noise) = measure_noise(
        &current_sk,
        &current_ciphertext,
        &message,
        n,
    );

    println!(
        "\nHop 0: max_noise = {:>12}, avg_noise = {:>12.2}, decrypt = OK",
        max_noise,
        avg_noise
    );

    // ------------------------------------------------------------
    // Re-encryption chain
    // ------------------------------------------------------------

    for hop in 1..=max_hops {
        println!("\n-----------------------------------------------");
        println!("Starting hop {}", hop);
        println!("-----------------------------------------------");

        println!(
            "[{}] Generating next key pair...",
            hop
        );

        let next = KeyGenResult::keygen(
            &mut rng,
            n,
        );

        println!(
            "[{}] Generating re-encryption key...",
            hop
        );

        let rekey = generate_rekey(
            &mut rng,
            &current_sk,
            &next.pk,
            base_bits,
        );

        println!(
            "[{}] Re-encrypting ciphertext...",
            hop
        );

        let next_ciphertext = reencrypt(
            &current_ciphertext,
            &rekey,
            base_bits,
        );

        let (max_noise, avg_noise) = measure_noise(
            &next.sk,
            &next_ciphertext,
            &message,
            n,
        );

        let recovered = decrypt(
            &next.sk,
            &next_ciphertext,
            n,
            message.len(),
        );

        let decrypt_ok = recovered == message;

        println!("\nHop {} result:", hop);

        println!(
            "  max |noise| = {}",
            max_noise
        );

        println!(
            "  avg |noise| = {:.2}",
            avg_noise
        );

        println!(
            "  decoding boundary = {}",
            Q / 4
        );

        println!(
            "  decrypt = {}",
            if decrypt_ok { "OK" } else { "FAILED" }
        );

        if !decrypt_ok {
            println!(
                "\nDecryption failed at hop {}.",
                hop
            );

            break;
        }

        current_ciphertext = next_ciphertext;
        current_sk = next.sk;
    }

    println!("\n===============================================");
    println!("        MULTI-HOP TEST FINISHED");
    println!("===============================================");
}


#[test]
fn test_mega_multi_hop_noise_experiment() {
    let runs = 100;
    let max_hops = 10;

    let n = 256;
    let base_bits = 4;
    let base = 1u64 << base_bits;

    let message = vec![
        1, 0, 1, 1,
        0, 1, 0, 0,
    ];

    let decoding_boundary = (Q / 4) as i64;

    // Aggregated statistics for each hop.
    let mut sum_max_noise = vec![0f64; max_hops + 1];
    let mut sum_avg_noise = vec![0f64; max_hops + 1];

    let mut worst_max_noise = vec![0i64; max_hops + 1];

    let mut samples = vec![0usize; max_hops + 1];

    let mut decryption_failures = vec![0usize; max_hops + 1];

    let mut total_failures = 0usize;
    let mut first_failure_hop: Option<usize> = None;

    println!("======================================================");
    println!("         PQPEP MEGA MULTI-HOP EXPERIMENT");
    println!("======================================================");
    println!("Runs                = {}", runs);
    println!("Maximum hops        = {}", max_hops);
    println!("Ring dimension n    = {}", n);
    println!("Modulus q           = {}", Q);
    println!("Base B              = {}", base);
    println!("Decoding boundary   = {}", decoding_boundary);

    for run in 0..runs {
        let mut rng = thread_rng();

        println!(
            "\n[RUN {:>3}/{:>3}] Starting experiment...",
            run + 1,
            runs
        );

        // --------------------------------------------------------
        // Initial party: Alice
        // --------------------------------------------------------

        let alice = KeyGenResult::keygen(&mut rng, n);

        let mut current_sk = alice.sk;

        let mut current_ciphertext = encrypt(
            &mut rng,
            &alice.pk,
            &message,
            n,
        );

        // --------------------------------------------------------
        // Hop 0: original encryption
        // --------------------------------------------------------

        let (max_noise, avg_noise) = measure_noise(
            &current_sk,
            &current_ciphertext,
            &message,
            n,
        );

        sum_max_noise[0] += max_noise as f64;
        sum_avg_noise[0] += avg_noise;

        worst_max_noise[0] =
            worst_max_noise[0].max(max_noise);

        samples[0] += 1;

        let recovered = decrypt(
            &current_sk,
            &current_ciphertext,
            n,
            message.len(),
        );

        if recovered != message {
            decryption_failures[0] += 1;
            total_failures += 1;

            if first_failure_hop.is_none() {
                first_failure_hop = Some(0);
            }

            println!(
                "[RUN {}] FAILURE at hop 0",
                run + 1
            );

            continue;
        }

        // --------------------------------------------------------
        // Multi-hop chain
        // --------------------------------------------------------

        for hop in 1..=max_hops {
            let next = KeyGenResult::keygen(
                &mut rng,
                n,
            );

            let rekey = generate_rekey(
                &mut rng,
                &current_sk,
                &next.pk,
                base_bits,
            );

            let next_ciphertext = reencrypt(
                &current_ciphertext,
                &rekey,
                base_bits,
            );

            // ----------------------------------------------------
            // Measure noise
            // ----------------------------------------------------

            let (max_noise, avg_noise) = measure_noise(
                &next.sk,
                &next_ciphertext,
                &message,
                n,
            );

            sum_max_noise[hop] += max_noise as f64;
            sum_avg_noise[hop] += avg_noise;

            worst_max_noise[hop] =
                worst_max_noise[hop].max(max_noise);

            samples[hop] += 1;

            // ----------------------------------------------------
            // Check decryption
            // ----------------------------------------------------

            let recovered = decrypt(
                &next.sk,
                &next_ciphertext,
                n,
                message.len(),
            );

            if recovered != message {
                decryption_failures[hop] += 1;
                total_failures += 1;

                if first_failure_hop.is_none() {
                    first_failure_hop = Some(hop);
                }

                println!(
                    "[RUN {}] FAILURE at hop {}",
                    run + 1,
                    hop
                );

                break;
            }

            // Move to next party.
            current_ciphertext = next_ciphertext;
            current_sk = next.sk;
        }

        // Progress output every 10 runs.
        if (run + 1) % 10 == 0 {
            println!(
                "[PROGRESS] Completed {}/{} runs",
                run + 1,
                runs
            );
        }
    }

    // ------------------------------------------------------------
    // Final aggregated report
    // ------------------------------------------------------------

    println!("\n======================================================");
    println!("                  FINAL RESULTS");
    println!("======================================================");

    println!(
        "{:<5} {:>18} {:>18} {:>18} {:>12}",
        "Hop",
        "Mean max |noise|",
        "Worst max |noise|",
        "Mean avg |noise|",
        "Failures"
    );

    println!(
        "{}",
        "-".repeat(80)
    );

    for hop in 0..=max_hops {
        if samples[hop] == 0 {
            println!(
                "{:<5} {:>18} {:>18} {:>18} {:>12}",
                hop,
                "N/A",
                "N/A",
                "N/A",
                decryption_failures[hop]
            );

            continue;
        }

        let mean_max =
            sum_max_noise[hop] / samples[hop] as f64;

        let mean_avg =
            sum_avg_noise[hop] / samples[hop] as f64;

        println!(
            "{:<5} {:>18.2} {:>18} {:>18.2} {:>12}",
            hop,
            mean_max,
            worst_max_noise[hop],
            mean_avg,
            decryption_failures[hop]
        );
    }

    println!("\n======================================================");
    println!("                  SUMMARY");
    println!("======================================================");

    println!("Total runs           = {}", runs);
    println!("Maximum hop count    = {}", max_hops);
    println!("Total failures       = {}", total_failures);

    match first_failure_hop {
        Some(hop) => {
            println!(
                "First observed failure = hop {}",
                hop
            );
        }

        None => {
            println!(
                "No decryption failures observed."
            );
        }
    }

    println!(
        "Decoding boundary    = {}",
        decoding_boundary
    );

    println!("======================================================");
}


//////////////////////////////////////////////// study on B parameter

#[test]
fn test_base_parameter_study() {
    let bases = [1usize, 2, 4, 8];
    let runs = 20;
    let max_hops = 10;

    let n = 256;

    let message = vec![
        1, 0, 1, 1,
        0, 1, 0, 0,
    ];

    println!("==============================================================");
    println!("              PRE BASE PARAMETER STUDY");
    println!("==============================================================");
    println!("Runs per base   = {}", runs);
    println!("Maximum hops    = {}", max_hops);
    println!("Ring dimension  = {}", n);
    println!("Modulus q       = {}", Q);

    for &base_bits in &bases {
        let base = 1u64 << base_bits;

        let mut sum_max_noise = 0f64;
        let mut sum_avg_noise = 0f64;
        let mut worst_max_noise = 0i64;

        let mut total_failures = 0usize;
        let mut total_hops = 0usize;

        let start = Instant::now();

        println!("\n==============================================================");
        println!(
            "Testing base B = {} (base_bits = {})",
            base,
            base_bits
        );
        println!("==============================================================");

        for run in 0..runs {
            let mut rng = thread_rng();

            let alice = KeyGenResult::keygen(&mut rng, n);

            let mut current_sk = alice.sk;

            let mut current_ciphertext = encrypt(
                &mut rng,
                &alice.pk,
                &message,
                n,
            );

            // Hop 0
            let (max_noise, avg_noise) = measure_noise(
                &current_sk,
                &current_ciphertext,
                &message,
                n,
            );

            sum_max_noise += max_noise as f64;
            sum_avg_noise += avg_noise;
            worst_max_noise = worst_max_noise.max(max_noise);
            total_hops += 1;

            let recovered = decrypt(
                &current_sk,
                &current_ciphertext,
                n,
                message.len(),
            );

            if recovered != message {
                total_failures += 1;
                continue;
            }

            // Re-encryption chain
            for _hop in 1..=max_hops {
                let next = KeyGenResult::keygen(
                    &mut rng,
                    n,
                );

                let rekey = generate_rekey(
                    &mut rng,
                    &current_sk,
                    &next.pk,
                    base_bits,
                );

                let next_ciphertext = reencrypt(
                    &current_ciphertext,
                    &rekey,
                    base_bits,
                );

                let (max_noise, avg_noise) = measure_noise(
                    &next.sk,
                    &next_ciphertext,
                    &message,
                    n,
                );

                sum_max_noise += max_noise as f64;
                sum_avg_noise += avg_noise;
                worst_max_noise =
                    worst_max_noise.max(max_noise);

                total_hops += 1;

                let recovered = decrypt(
                    &next.sk,
                    &next_ciphertext,
                    n,
                    message.len(),
                );

                if recovered != message {
                    total_failures += 1;
                    break;
                }

                current_ciphertext = next_ciphertext;
                current_sk = next.sk;
            }

            if (run + 1) % 5 == 0 {
                println!(
                    "Completed {}/{} runs",
                    run + 1,
                    runs
                );
            }
        }

        let elapsed = start.elapsed();

        let mean_max_noise =
            sum_max_noise / total_hops as f64;

        let mean_avg_noise =
            sum_avg_noise / total_hops as f64;

        let mut digit_count = 0usize;
        let mut value = Q;

        while value > 1 {
            value = (value + base - 1) / base;
            digit_count += 1;
        }

        println!("\nRESULTS FOR B = {}", base);
        println!("  KeySwitchEntry count = {}", digit_count);
        println!(
            "  Mean max |noise|     = {:.2}",
            mean_max_noise
        );
        println!(
            "  Worst max |noise|    = {}",
            worst_max_noise
        );
        println!(
            "  Mean avg |noise|     = {:.2}",
            mean_avg_noise
        );
        println!(
            "  Failures             = {}",
            total_failures
        );
        println!(
            "  Execution time       = {:.2?}",
            elapsed
        );
    }

    println!("\n==============================================================");
    println!("             BASE PARAMETER STUDY FINISHED");
    println!("==============================================================");
}



#[test]
fn test_operation_benchmark() {
    let bases = [1usize, 2, 4, 8];
    let repetitions = 20;

    let n = 256;

    let message = vec![
        1, 0, 1, 1,
        0, 1, 0, 0,
    ];

    println!("==============================================================");
    println!("                    PRE OPERATION BENCHMARK");
    println!("==============================================================");
    println!("Repetitions per operation = {}", repetitions);
    println!("Ring dimension             = {}", n);
    println!("Modulus q                  = {}", Q);

    // ------------------------------------------------------------
    // Key generation benchmark
    // ------------------------------------------------------------

    println!("\n--------------------------------------------------------------");
    println!("KEY GENERATION");
    println!("--------------------------------------------------------------");

    let mut keygen_rng = thread_rng();

    let start = Instant::now();

    for _ in 0..repetitions {
        let keygen = KeyGenResult::keygen(
            &mut keygen_rng,
            n,
        );

        black_box(keygen);
    }

    let keygen_elapsed = start.elapsed();

    let keygen_avg =
        keygen_elapsed.as_secs_f64() * 1000.0
        / repetitions as f64;

    println!(
        "Average KeyGen time = {:.4} ms",
        keygen_avg
    );

    // ------------------------------------------------------------
    // Prepare one key pair for the remaining benchmarks
    // ------------------------------------------------------------

    let mut rng = thread_rng();

    let alice = KeyGenResult::keygen(
        &mut rng,
        n,
    );

    let bob = KeyGenResult::keygen(
        &mut rng,
        n,
    );

    // ------------------------------------------------------------
    // Encryption benchmark
    // ------------------------------------------------------------

    println!("\n--------------------------------------------------------------");
    println!("ENCRYPTION");
    println!("--------------------------------------------------------------");

    let start = Instant::now();

    for _ in 0..repetitions {
        let ciphertext = encrypt(
            &mut rng,
            &alice.pk,
            &message,
            n,
        );

        black_box(ciphertext);
    }

    let encryption_elapsed = start.elapsed();

    let encryption_avg =
        encryption_elapsed.as_secs_f64() * 1000.0
        / repetitions as f64;

    println!(
        "Average Encrypt time = {:.4} ms",
        encryption_avg
    );

    // ------------------------------------------------------------
    // Benchmark for each decomposition base
    // ------------------------------------------------------------

    println!("\n==============================================================");
    println!("              BASE-DEPENDENT OPERATIONS");
    println!("==============================================================");

    println!(
        "{:<8} {:>10} {:>18} {:>18} {:>18}",
        "B",
        "Entries",
        "ReKeyGen (ms)",
        "ReEncrypt (ms)",
        "Decrypt (ms)"
    );

    println!("{}", "-".repeat(78));

    for &base_bits in &bases {
        let base = 1u64 << base_bits;

        // --------------------------------------------------------
        // Generate a ciphertext and rekey for this base
        // --------------------------------------------------------

        let ciphertext = encrypt(
            &mut rng,
            &alice.pk,
            &message,
            n,
        );

        let rekey = generate_rekey(
            &mut rng,
            &alice.sk,
            &bob.pk,
            base_bits,
        );

        let entry_count = rekey.entries.len();

        // --------------------------------------------------------
        // ReKeyGen benchmark
        // --------------------------------------------------------

        let start = Instant::now();

        for _ in 0..repetitions {
            let measured_rekey = generate_rekey(
                &mut rng,
                &alice.sk,
                &bob.pk,
                base_bits,
            );

            black_box(measured_rekey);
        }

        let rekey_elapsed = start.elapsed();

        let rekey_avg =
            rekey_elapsed.as_secs_f64() * 1000.0
            / repetitions as f64;

        // --------------------------------------------------------
        // ReEncrypt benchmark
        // --------------------------------------------------------

        let start = Instant::now();

        for _ in 0..repetitions {
            let reencrypted = reencrypt(
                &ciphertext,
                &rekey,
                base_bits,
            );

            black_box(reencrypted);
        }

        let reencrypt_elapsed = start.elapsed();

        let reencrypt_avg =
            reencrypt_elapsed.as_secs_f64() * 1000.0
            / repetitions as f64;

        // --------------------------------------------------------
        // Decryption benchmark
        // --------------------------------------------------------

        let reencrypted = reencrypt(
            &ciphertext,
            &rekey,
            base_bits,
        );

        let start = Instant::now();

        for _ in 0..repetitions {
            let recovered = decrypt(
                &bob.sk,
                &reencrypted,
                n,
                message.len(),
            );

            black_box(recovered);
        }

        let decrypt_elapsed = start.elapsed();

        let decrypt_avg =
            decrypt_elapsed.as_secs_f64() * 1000.0
            / repetitions as f64;

        println!(
            "{:<8} {:>10} {:>18.4} {:>18.4} {:>18.4}",
            base,
            entry_count,
            rekey_avg,
            reencrypt_avg,
            decrypt_avg
        );
    }

    println!("\n==============================================================");
    println!("               OPERATION BENCHMARK FINISHED");
    println!("==============================================================");
}


//integrazione test PRE con plaintext polinomiale
#[test]
fn test_reencrypt_polynomial_a_to_b() {
    let mut rng = rand::thread_rng();

    let n: usize = 256;
    let q: u64 = 998_244_353;
    let base_bits: usize = 4;

    // Polynomial plaintext with coefficients in R_17.
    let coeffs: Vec<u64> = (0..n)
        .map(|i| {
            let i = i as u64;
            (7 * i * i + 11 * i + 3) % 17
        })
        .collect();

    let message = PolyRq::from_coeffs(&coeffs, n, q);

    // Alice and Bob key pairs.
    let alice = KeyGenResult::keygen(&mut rng, n);
    let bob = KeyGenResult::keygen(&mut rng, n);

    // Alice encrypts the polynomial.
    let ciphertext_a = encrypt_poly(
        &mut rng,
        &alice.pk,
        &message,
        n,
    );

    // Alice -> Bob re-encryption key.
    let rekey_a_to_b = generate_rekey(
        &mut rng,
        &alice.sk,
        &bob.pk,
        base_bits,
    );

    // Proxy re-encrypts.
    let ciphertext_b = reencrypt(
        &ciphertext_a,
        &rekey_a_to_b,
        base_bits,
    );

        // Bob decrypts the transformed ciphertext.
    let recovered = decrypt_poly(
        &bob.sk,
        &ciphertext_b,
        n,
    );

    println!("Original polynomial:");
    println!("{:?}", &message.coefficients()[..n]);

    println!("Recovered polynomial after A -> B:");
    println!("{:?}", &recovered.coefficients()[..n]);

    // Check all coefficients.
    for i in 0..n {
        assert_eq!(
            recovered.coefficients()[i],
            message.coefficients()[i],
            "mismatch at coefficient {}",
            i
        );
    }
}

#[test]
fn test_reshuffle_polynomial() {
    let mut rng = rand::thread_rng();

    let n: usize = 256;
    let q: u64 = 998_244_353;
    let base_bits: usize = 4;

    // Plaintext polynomial M in R_17.
    let coeffs: Vec<u64> = (0..n)
        .map(|i| {
            let i = i as u64;
            (7 * i * i + 11 * i + 3) % 17
        })
        .collect();

    let message = PolyRq::from_coeffs(&coeffs, n, q);

    // Alice and Bob keys.
    let alice = KeyGenResult::keygen(&mut rng, n);
    let bob = KeyGenResult::keygen(&mut rng, n);

    // Alice encrypts.
    let ciphertext_a = encrypt_poly(
        &mut rng,
        &alice.pk,
        &message,
        n,
    );

    // Alice -> Bob re-key.
    let rekey_a_to_b = generate_rekey(
        &mut rng,
        &alice.sk,
        &bob.pk,
        base_bits,
    );

    // Proxy re-encryption.
    let ciphertext_b = reencrypt(
        &ciphertext_a,
        &rekey_a_to_b,
        base_bits,
    );

    // Reshuffling factor:
    //
    // g(X) = 1 + X
    let factor_coeffs = {
        let mut v = vec![0u64; n];
        v[0] = 1;
        v[1] = 1;
        v
    };

    let factor = PolyRq::from_coeffs(
        &factor_coeffs,
        n,
        q,
    );

    // Apply reshuffling to Bob's ciphertext.
    let reshuffled_ciphertext = reshuffle(
        &ciphertext_b,
        &factor,
    );

    // Bob decrypts the reshuffled ciphertext.
    let recovered = decrypt_poly(
        &bob.sk,
        &reshuffled_ciphertext,
        n,
    );

    // Expected plaintext:
    //
    // M' = M * (1 + X) in R_17.
    //
    // For i > 0:
    //     m'_i = m_i + m_{i-1}
    //
    // For i = 0, X^n = -1:
    //     m'_0 = m_0 - m_{n-1}
    let mut expected = vec![0u64; n];

    expected[0] = (coeffs[0] + 17 - coeffs[n - 1]) % 17;

    for i in 1..n {
        expected[i] = (coeffs[i] + coeffs[i - 1]) % 17;
    }

    println!(
        "Original first 16:   {:?}",
        &coeffs[..16]
    );

    println!(
        "Expected first 16:   {:?}",
        &expected[..16]
    );

    println!(
        "Recovered first 16: {:?}",
        &recovered.coefficients()[..16]
    );

    let mismatches = (0..n)
        .filter(|&i| recovered.coefficients()[i] != expected[i])
        .count();

    println!(
        "Coefficient mismatches: {}",
        mismatches
    );

    assert_eq!(
        mismatches,
        0,
        "reshuffled polynomial does not match expected plaintext"
    );
}

#[test]
fn test_lift_prf_output() {
    let n: usize = 256;
    let q: u64 = 998_244_353;

    // Example PRF output in R_17.
    let coeffs: Vec<u64> = (0..n)
        .map(|i| {
            let i = i as u64;
            (7 * i * i + 11 * i + 3) % 17
        })
        .collect();

    let prf_output = PolyRq::from_coeffs(
        &coeffs,
        n,
        17,
    );

    let factor = lift_prf_output_to_q(
        &prf_output,
        q,
    );

    println!(
        "PRF first 16:   {:?}",
        &prf_output.coefficients()[..16]
    );

    println!(
        "Factor first 16: {:?}",
        &factor.coefficients()[..16]
    );

    assert_eq!(factor.modulus(), q);
    assert_eq!(factor.degree_bound(), n);

    for i in 0..n {
        assert_eq!(
            factor.coefficients()[i],
            coeffs[i]
        );
    }
}

#[test]
fn test_domain_reshuffle_factors() {
    use pq_libpep::core::params::prf_modulus_chain;
    use pq_libpep::core::rlwr_prf::{
        RlwrPrf,
        RlwrPrfBase,
    };
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    let n: usize = 256;
    let q: u64 = 998_244_353;

    let mut rng = StdRng::seed_from_u64(42);

    let chain = prf_modulus_chain();
    let highest_modulus = *chain.last().unwrap();

    let base = RlwrPrfBase::sample(
        &mut rng,
        n,
        highest_modulus,
        256
    );

    let prf = RlwrPrf::new(
        base,
        chain,
    );

    let g_a = derive_reshuffle_factor(
        &prf,
        "hospital-A",
        n,
        q,
    );

    let g_b = derive_reshuffle_factor(
        &prf,
        "hospital-B",
        n,
        q,
    );

    println!(
        "g_A first 16: {:?}",
        &g_a.coefficients()[..16]
    );

    println!(
        "g_B first 16: {:?}",
        &g_b.coefficients()[..16]
    );

    assert_eq!(g_a.modulus(), q);
    assert_eq!(g_b.modulus(), q);

    assert_ne!(
        g_a.coefficients(),
        g_b.coefficients()
    );
}

#[test]
fn test_domain_encoding_and_prf() {
    use pq_libpep::core::params::{
        prf_modulus_chain,
        RING_DIMENSION,
    };
    use pq_libpep::core::rlwr_prf::{
        RlwrPrf,
        RlwrPrfBase,
    };
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    let n = RING_DIMENSION;

    let mut rng = StdRng::seed_from_u64(42);

    let chain = prf_modulus_chain();
    let highest_modulus = *chain.last().unwrap();

    let base = RlwrPrfBase::sample(
        &mut rng,
        n,
        highest_modulus,
        256
    );

    let prf = RlwrPrf::new(
        base,
        chain,
    );

    let id_a = string_to_id("hospital-A");
    let id_b = string_to_id("hospital-B");

    println!("ID A: {:02x?}", id_a);
    println!("ID B: {:02x?}", id_b);

    assert_ne!(
        id_a,
        id_b,
        "string_to_id() produced identical IDs"
    );

    let bits_a = bytes_to_bits(&id_a);
    let bits_b = bytes_to_bits(&id_b);

    println!("Bits A first 32: {:?}", &bits_a[..32]);
    println!("Bits B first 32: {:?}", &bits_b[..32]);

    assert_eq!(bits_a.len(), 256);
    assert_eq!(bits_b.len(), 256);

    assert_ne!(
        bits_a,
        bits_b,
        "bytes_to_bits() produced identical bit strings"
    );

    let poly_a = pseudonymize_32(
        &prf,
        &id_a,
    );

    let poly_b = pseudonymize_32(
        &prf,
        &id_b,
    );

    println!(
        "PRF A first 16: {:?}",
        &poly_a.coefficients()[..16]
    );

    println!(
        "PRF B first 16: {:?}",
        &poly_b.coefficients()[..16]
    );

    assert_ne!(
        poly_a,
        poly_b,
        "PRF produced identical outputs for different IDs"
    );
}

#[test]
fn test_prf_input_position_sensitivity() {
    use pq_libpep::core::params::{
        prf_modulus_chain,
        RING_DIMENSION,
    };
    use pq_libpep::core::pseudonym::pseudonymize_32;
    use pq_libpep::core::rlwr_prf::{
        RlwrPrf,
        RlwrPrfBase,
    };
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    let n = RING_DIMENSION;

    let mut rng = StdRng::seed_from_u64(42);

    let chain = prf_modulus_chain();
    let highest_modulus = *chain.last().unwrap();

    let base = RlwrPrfBase::sample(
        &mut rng,
        n,
        highest_modulus,
        256
    );

    let prf = RlwrPrf::new(
        base,
        chain,
    );

    let id0 = [0u8; 32];

    let mut id1 = id0;
    id1[0] = 1;

    let mut id2 = id0;
    id2[1] = 1;

    let mut id3 = id0;
    id3[10] = 1;

    let p0 = pseudonymize_32(&prf, &id0);
    let p1 = pseudonymize_32(&prf, &id1);
    let p2 = pseudonymize_32(&prf, &id2);
    let p3 = pseudonymize_32(&prf, &id3);

    println!("p0 first 16: {:?}", &p0.coefficients()[..16]);
    println!("p1 first 16: {:?}", &p1.coefficients()[..16]);
    println!("p2 first 16: {:?}", &p2.coefficients()[..16]);
    println!("p3 first 16: {:?}", &p3.coefficients()[..16]);

    assert_ne!(
        p0,
        p1,
        "PRF ignores changes in byte 0"
    );

    assert_ne!(
        p0,
        p2,
        "PRF ignores changes in byte 1"
    );

    assert_ne!(
        p0,
        p3,
        "PRF ignores changes in byte 10"
    );
}