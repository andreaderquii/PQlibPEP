//! Experimental blast-radius test for one-time RLWE source keys.
//!
//! This does NOT make the current key-switch PRE collusion-resistant: the test
//! deliberately recovers the ephemeral source key from (rekey, recipient key).
//! It checks that, if an ephemeral source key is used for exactly one request,
//! that recovered key does not decrypt ciphertexts protected by other keys.

use pq_libpep::algebra::ring::{PolyRq, Q};
use pq_libpep::core::rlwe::{KeyGenResult, SecretKey};
use pq_libpep::core::rlwe_pke::{decrypt_poly, encrypt_poly};
use pq_libpep::core::rlwe_pre::{generate_rekey, reencrypt_and_rerandomize};
use rand::{rngs::StdRng, SeedableRng};

// Smaller toy ring keeps this diagnostic quick.
const N: usize = 64;
const BASE_BITS: usize = 4;

fn circular_distance(a: u64, b: u64) -> u64 {
    let direct = a.abs_diff(b);
    direct.min(Q - direct)
}

/// Reproduces the prototype's known attack against the highest gadget entry.
/// Returns the recovered key; this is intentionally expected to succeed.
fn recover_source_key_from_rekey(
    rekey: &pq_libpep::core::rlwe_pre::ReEncryptionKey,
    recipient: &SecretKey,
) -> SecretKey {
    let base = 1u64 << BASE_BITS;
    let highest = rekey
        .entries
        .last()
        .expect("rekey must have gadget entries");
    let b_power = (0..rekey.entries.len() - 1).fold(1u64, |power, _| {
        ((power as u128 * base as u128) % Q as u128) as u64
    });

    // k1 - k0*s_B = B^i*s_A + small error in R_Q.
    let observed = highest.k1.sub(&highest.k0.mul_ntt(&recipient.s));
    let coefficients = observed.coefficients();
    let candidates: [u64; 5] = [0, 1, 2, Q - 1, Q - 2];
    let noise_bound = 8 * N as u64 + 2;
    let phases = candidates.map(|s| ((b_power as u128 * s as u128) % Q as u128) as u64);
    let min_gap = (0..phases.len())
        .flat_map(|i| (i + 1..phases.len()).map(move |j| (i, j)))
        .map(|(i, j)| circular_distance(phases[i], phases[j]))
        .min()
        .expect("candidate set is non-empty");

    assert!(
        2 * noise_bound < min_gap,
        "candidate spacing must exceed twice the conservative noise bound"
    );

    let recovered = (0..N)
        .map(|i| {
            let value = coefficients[i];
            let (candidate_index, residual) = phases
                .iter()
                .enumerate()
                .map(|(index, &phase)| (index, circular_distance(value, phase)))
                .min_by_key(|(_, distance)| *distance)
                .expect("candidate set is non-empty");
            assert!(
                residual <= noise_bound,
                "coefficient {i} exceeds noise bound"
            );
            candidates[candidate_index]
        })
        .collect::<Vec<_>>();

    SecretKey {
        s: PolyRq::from_coeffs(&recovered, N, Q),
    }
}

fn message(seed: u64) -> Vec<u64> {
    // Keep this diagnostic payload below the ring boundary so the example
    // resembles a short PEP request payload.
    let mut values = vec![0; N];
    for (i, value) in values.iter_mut().take(52).enumerate() {
        *value = (i as u64 * 7 + seed) % 17;
    }
    values
}

fn poly(values: &[u64]) -> PolyRq {
    PolyRq::from_coeffs(values, N, Q)
}

#[test]
fn ephemeral_source_key_limits_rekey_recovery_to_one_request() {
    let mut rng = StdRng::seed_from_u64(0x4550_4845_4d52_4b59);
    println!("\n=== RLWE EPHEMERAL REKEY SCOPE EXPERIMENT ===");
    println!("Parameters: N={N}, q={Q}, CBD2 secret/error, gadget base=2^{BASE_BITS}.");
    println!(
        "Model: each PEP request has a fresh source RLWE key; only that request's payloads use it."
    );

    println!("[1] Generate persistent domain key, two request keys and recipient key.");
    let domain = KeyGenResult::keygen(&mut rng, N);
    let request_1 = KeyGenResult::keygen(&mut rng, N);
    let request_2 = KeyGenResult::keygen(&mut rng, N);
    let recipient = KeyGenResult::keygen(&mut rng, N);

    let message_1 = message(3);
    let message_2 = message(11);
    let domain_message = message(5);
    let request_1_plaintext = poly(&message_1);
    let request_2_plaintext = poly(&message_2);
    let domain_plaintext = poly(&domain_message);

    println!("[2] Encrypt request 1 under its one-time source key.");
    let request_1_ciphertext = encrypt_poly(&mut rng, &request_1.pk, &request_1_plaintext, N);
    let source_opened = decrypt_poly(&request_1.sk, &request_1_ciphertext, N);
    assert_eq!(
        &source_opened.coefficients()[..N],
        message_1.as_slice(),
        "source must correctly open its own request ciphertext"
    );
    println!("[3] Encrypt request 2 and unrelated domain data under independent keys.");
    let request_2_ciphertext = encrypt_poly(&mut rng, &request_2.pk, &request_2_plaintext, N);
    let domain_ciphertext = encrypt_poly(&mut rng, &domain.pk, &domain_plaintext, N);

    println!("[4] Generate request-1 rekey and transform + rerandomize its ciphertext.");
    let request_1_rekey = generate_rekey(&mut rng, &request_1.sk, &recipient.pk, BASE_BITS);
    let response = reencrypt_and_rerandomize(
        &mut rng,
        &request_1_ciphertext,
        &request_1_rekey,
        &recipient.pk,
        BASE_BITS,
    );

    let opened_response = decrypt_poly(&recipient.sk, &response, N);
    assert_eq!(&opened_response.coefficients()[..N], message_1.as_slice());
    println!("[PASS] Recipient opens the authorized request-1 response.");

    println!(
        "[5] Simulate collusion: recover request-1 source key from (rekey, recipient secret)."
    );
    let recovered_request_1_sk = recover_source_key_from_rekey(&request_1_rekey, &recipient.sk);
    assert_eq!(
        recovered_request_1_sk.s.to_coeffs_vec(),
        request_1.sk.s.to_coeffs_vec()
    );
    println!("[CONFIRMED] Colluder recovers the request-1 ephemeral key exactly.");

    println!("[6] Try the recovered request-1 key against request 2 and domain ciphertexts.");
    let wrong_request_2 = decrypt_poly(&recovered_request_1_sk, &request_2_ciphertext, N);
    let wrong_domain = decrypt_poly(&recovered_request_1_sk, &domain_ciphertext, N);
    assert_ne!(&wrong_request_2.coefficients()[..N], message_2.as_slice());
    assert_ne!(&wrong_domain.coefficients()[..N], domain_message.as_slice());
    println!("[PASS] Recovered request-1 key does not recover request-2 plaintext.");
    println!("[PASS] Recovered request-1 key does not recover persistent-domain plaintext.");

    println!("LIMIT: this is key isolation / blast-radius containment, not cryptographic collusion resistance.");
    println!("LIMIT: the test does not prove secure erasure; production code must not reuse or persist request keys/rekeys.");
    println!("LIMIT: all data encrypted under request 1's ephemeral key remains exposed to this collusion.");
}
