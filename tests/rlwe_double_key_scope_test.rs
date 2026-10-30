//! Toy experiment for the two-key collusion-safe PRE wrapper.
//!
//! This is a functional illustration, not an implementation or proof of the
//! generic construction from ePrint 2025/1423. With the prototype's current
//! key-switch rekey, the proxy+recipient collusion recovers the source's
//! delegable key. The experiment checks that an independent protected key is
//! not thereby recovered, and explicitly demonstrates that other ciphertexts
//! under the delegable key are exposed too.

use pq_libpep::algebra::ring::{PolyRq, Q};
use pq_libpep::core::rlwe::{KeyGenResult, SecretKey};
use pq_libpep::core::rlwe_pke::{decrypt_poly, encrypt_poly};
use pq_libpep::core::rlwe_pre::{generate_rekey, reencrypt_and_rerandomize, ReEncryptionKey};
use rand::{rngs::StdRng, SeedableRng};

const N: usize = 64;
const BASE_BITS: usize = 4;

fn circular_distance(a: u64, b: u64) -> u64 {
    let direct = a.abs_diff(b);
    direct.min(Q - direct)
}

/// Reproduces the prototype attack: recover the five-valued CBD2 source
/// secret coefficients from the highest gadget entry and the recipient key.
fn recover_delegable_source_key(rekey: &ReEncryptionKey, recipient: &SecretKey) -> SecretKey {
    let base = 1u64 << BASE_BITS;
    let highest = rekey.entries.last().expect("rekey has gadget entries");
    let b_power = (0..rekey.entries.len() - 1).fold(1u64, |power, _| {
        ((power as u128 * base as u128) % Q as u128) as u64
    });
    let observed = highest.k1.sub(&highest.k0.mul_ntt(&recipient.s));
    let coefficients = observed.coefficients();
    let candidates: [u64; 5] = [0, 1, 2, Q - 1, Q - 2];
    let phases = candidates.map(|s| ((b_power as u128 * s as u128) % Q as u128) as u64);
    let noise_bound = 8 * N as u64 + 2;
    let min_gap = (0..phases.len())
        .flat_map(|i| (i + 1..phases.len()).map(move |j| (i, j)))
        .map(|(i, j)| circular_distance(phases[i], phases[j]))
        .min()
        .expect("candidate set is non-empty");
    assert!(2 * noise_bound < min_gap);

    let recovered = (0..N)
        .map(|i| {
            let (candidate_index, residual) = phases
                .iter()
                .enumerate()
                .map(|(index, &phase)| (index, circular_distance(coefficients[i], phase)))
                .min_by_key(|(_, distance)| *distance)
                .expect("candidate set is non-empty");
            assert!(
                residual <= noise_bound,
                "source coefficient {i} exceeds bound"
            );
            candidates[candidate_index]
        })
        .collect::<Vec<_>>();

    SecretKey {
        s: PolyRq::from_coeffs(&recovered, N, Q),
    }
}

fn message(seed: u64) -> Vec<u64> {
    (0..N).map(|i| (i as u64 * 7 + seed) % 17).collect()
}

fn poly(values: &[u64]) -> PolyRq {
    PolyRq::from_coeffs(values, N, Q)
}

#[test]
fn two_key_wrapper_separates_delegable_and_protected_ciphertexts_in_toy_model() {
    let mut rng = StdRng::seed_from_u64(0x444f_5542_4c45_4b59);
    let source_delegable = KeyGenResult::keygen(&mut rng, N);
    let source_protected = KeyGenResult::keygen(&mut rng, N);
    // The recipient's first-level pair exists in the wrapper model but this
    // direction delegates directly into the recipient's second-level pair.
    let _recipient_delegable = KeyGenResult::keygen(&mut rng, N);
    let recipient_second_level = KeyGenResult::keygen(&mut rng, N);

    let authorized_message = message(3);
    let other_delegable_message = message(9);
    let protected_message = message(14);
    let authorized_plaintext = poly(&authorized_message);
    let other_delegable_plaintext = poly(&other_delegable_message);
    let protected_plaintext = poly(&protected_message);

    println!("\n=== TWO-KEY PRE COLLUSION-SCOPE EXPERIMENT (TOY) ===");
    println!("Parameters: N={N}, q={Q}, CBD2, gadget base=2^{BASE_BITS}.");
    println!(
        "Construction model: source key-1 is delegable; source key-2 protects non-delegable data."
    );
    println!("Rekey direction: source key-1 -> recipient key-2.");

    println!("[1] Encrypt authorized and collateral delegable data under source key-1.");
    let authorized_ciphertext =
        encrypt_poly(&mut rng, &source_delegable.pk, &authorized_plaintext, N);
    let other_delegable_ciphertext = encrypt_poly(
        &mut rng,
        &source_delegable.pk,
        &other_delegable_plaintext,
        N,
    );
    println!("[2] Encrypt protected data under the independent source key-2.");
    let protected_ciphertext =
        encrypt_poly(&mut rng, &source_protected.pk, &protected_plaintext, N);
    assert_eq!(
        &decrypt_poly(&source_protected.sk, &protected_ciphertext, N).coefficients()[..N],
        protected_message.as_slice(),
        "the source's protected key must open its own ciphertext"
    );

    println!("[3] Generate key-switch material from source key-1 to recipient key-2.");
    let rekey = generate_rekey(
        &mut rng,
        &source_delegable.sk,
        &recipient_second_level.pk,
        BASE_BITS,
    );
    let transformed = reencrypt_and_rerandomize(
        &mut rng,
        &authorized_ciphertext,
        &rekey,
        &recipient_second_level.pk,
        BASE_BITS,
    );
    assert_eq!(
        &decrypt_poly(&recipient_second_level.sk, &transformed, N).coefficients()[..N],
        authorized_message.as_slice(),
        "recipient key-2 must open the transformed delegable ciphertext"
    );
    println!("[PASS] Recipient key-2 opens the authorized transformed ciphertext.");

    println!("[4] Simulate proxy+recipient collusion using (rekey, recipient key-2 secret).");
    let recovered_key_1 = recover_delegable_source_key(&rekey, &recipient_second_level.sk);
    assert_eq!(
        recovered_key_1.s.to_coeffs_vec(),
        source_delegable.sk.s.to_coeffs_vec(),
        "the current prototype attack is expected to recover source key-1"
    );
    assert_eq!(
        &decrypt_poly(&recovered_key_1, &other_delegable_ciphertext, N).coefficients()[..N],
        other_delegable_message.as_slice(),
        "the recovered delegable key exposes other ciphertexts in key-1 class"
    );
    println!("[CONFIRMED] Collusion recovers source key-1 and opens other key-1 ciphertexts.");

    let wrong_key_2_opening = decrypt_poly(&recovered_key_1, &protected_ciphertext, N);
    assert_ne!(
        &wrong_key_2_opening.coefficients()[..N],
        protected_message.as_slice(),
        "the recovered key-1 must not open an independent key-2 ciphertext"
    );
    println!("[PASS] Recovered source key-1 does not open ciphertext under source key-2.");

    println!("[5] Attempt to misuse the key-1 -> recipient-key-2 rekey on source key-2 data.");
    let wrongly_transformed = reencrypt_and_rerandomize(
        &mut rng,
        &protected_ciphertext,
        &rekey,
        &recipient_second_level.pk,
        BASE_BITS,
    );
    let wrong_recipient_opening = decrypt_poly(&recipient_second_level.sk, &wrongly_transformed, N);
    assert_ne!(
        &wrong_recipient_opening.coefficients()[..N],
        protected_message.as_slice(),
        "a key-1 rekey should not transform key-2 ciphertexts correctly"
    );
    println!("[PASS] Key-1 rekey does not correctly transform source key-2 ciphertext.");

    println!(
        "LIMIT: this only demonstrates key-class separation with the prototype's toy arithmetic."
    );
    println!(
        "LIMIT: all ciphertexts under the delegable key-1 class remain exposed by this collusion."
    );
    println!("LIMIT: no IND-CPA/single-hop proof, security estimate, or formal double-key wrapper is implemented.");
    println!(
        "LIMIT: a real wrapper needs explicit ciphertext levels and strict key/level binding."
    );
}
