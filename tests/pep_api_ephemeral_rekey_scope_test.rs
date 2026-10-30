#![cfg(feature = "fast-prf-tfhe-private-input")]

//! End-to-end PEP API experiment with one RLWE source key per request.
//!
//! This keeps the existing API and toy test unchanged. It deliberately shows
//! that `rk + sk_B` still reveals the current request's source key, while the
//! recovered key does not decrypt another request or a persistent domain key.

use pq_libpep::algebra::ring::{PolyRq, Q};
use pq_libpep::core::fast_lwr_prf::{FastLwrPrf, FastLwrPrfParameters, FastLwrPrfSecretKey};
use pq_libpep::core::fast_lwr_prf_pep_ks128_e16_pipeline::setup_pep_lwr_prf;
use pq_libpep::core::pep::{EncryptedAttribute, PepRecipient, PepSource, PepTranscryptor};
use pq_libpep::core::pep_context::{CanonicalIdentifier, DomainId, PepContext};
use pq_libpep::core::rlwe::{KeyGenResult, PublicKey, SecretKey};
use pq_libpep::core::rlwe_pke::{decrypt_poly, encrypt_poly};
use pq_libpep::core::rlwe_pre::{generate_rekey, ReEncryptionKey};
use rand::{rngs::StdRng, SeedableRng};

const N: usize = 64;
const BASE_BITS: usize = 4;
const PSEUDONYM_BYTES: usize = 32;
const PRF_SYMBOLS: usize = 52;

fn circular_distance(a: u64, b: u64) -> u64 {
    let direct = a.abs_diff(b);
    direct.min(Q - direct)
}

fn clone_public_key(public_key: &PublicKey) -> PublicKey {
    PublicKey {
        a: public_key.a.clone(),
        b: public_key.b.clone(),
    }
}

/// Reproduces the prototype's recovery from a rekey and recipient secret.
fn recover_source_key(rekey: &ReEncryptionKey, recipient: &SecretKey) -> SecretKey {
    let base = 1u64 << BASE_BITS;
    let highest = rekey.entries.last().expect("rekey has gadget entries");
    let b_power = (0..rekey.entries.len() - 1).fold(1u64, |power, _| {
        ((power as u128 * base as u128) % Q as u128) as u64
    });
    let observed = highest.k1.sub(&highest.k0.mul_ntt(&recipient.s));
    let coefficients = observed.coefficients();
    let candidates = [0, 1, 2, Q - 1, Q - 2];
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
                "source key coefficient {i} exceeds bound"
            );
            candidates[candidate_index]
        })
        .collect::<Vec<_>>();

    SecretKey {
        s: PolyRq::from_coeffs(&recovered, N, Q),
    }
}

fn pack_pid(symbols: &[u64]) -> [u8; PSEUDONYM_BYTES] {
    assert!(symbols.len() >= PRF_SYMBOLS);
    let mut output = [0u8; PSEUDONYM_BYTES];
    for bit in 0..PSEUDONYM_BYTES * 8 {
        let value = ((symbols[bit / 5] >> (4 - bit % 5)) & 1) as u8;
        output[bit / 8] |= value << (7 - bit % 8);
    }
    output
}

#[test]
fn pep_api_reuses_tfhe_setup_with_per_request_rlwe_keys() {
    let mut rng = StdRng::seed_from_u64(0x5045_5045_5048_454d);
    let tfhe_parameters = FastLwrPrfParameters {
        lwr_dimension: 8,
        ring_dimension: 64,
        output_modulus: 32,
    };
    let prf_key =
        FastLwrPrfSecretKey::generate(tfhe_parameters, &mut rng).expect("generate toy PRF key");
    let recipient_rlwe = KeyGenResult::keygen(&mut rng, N);
    let persistent_domain = KeyGenResult::keygen(&mut rng, N);
    let attribute_values = (0..N).map(|i| (i % 17) as u64).collect::<Vec<_>>();
    let attribute_plaintext = PolyRq::from_coeffs(&attribute_values, N, Q);
    let persistent_ciphertext =
        encrypt_poly(&mut rng, &persistent_domain.pk, &attribute_plaintext, N);
    let identifier = CanonicalIdentifier::new("hospital-patient-id", b"patient-001")
        .expect("valid canonical identifier");

    println!("[SETUP] Generate the TFHE source, recipient and evaluator materials once.");
    let setup_started = std::time::Instant::now();
    let (input_client, tfhe_recipient_key, evaluator) =
        setup_pep_lwr_prf(tfhe_parameters, &prf_key).expect("set up toy TFHE PEP keys");
    println!("[TIME] Shared TFHE setup: {:?}", setup_started.elapsed());
    let context = PepContext::new(
        DomainId::new("research-a").expect("valid domain"),
        1,
        input_client.source_context_id(),
        tfhe_recipient_key.recipient_key_id(),
    );
    let expected_pid = pack_pid(
        &FastLwrPrf::new(prf_key.clone())
            .evaluate_many(&context.encode_prf_input(&identifier), PRF_SYMBOLS),
    );
    let source = PepSource::new(context.clone(), input_client).expect("create PEP source");

    // Two source RLWE keys and their request-scoped rekeys. The TFHE setup
    // above, the PRF key, and the recipient RLWE key are reused.
    let first_source_rlwe = KeyGenResult::keygen(&mut rng, N);
    let first_ciphertext = encrypt_poly(&mut rng, &first_source_rlwe.pk, &attribute_plaintext, N);
    let first_collateral_ciphertext =
        encrypt_poly(&mut rng, &first_source_rlwe.pk, &attribute_plaintext, N);
    let first_rekey = generate_rekey(
        &mut rng,
        &first_source_rlwe.sk,
        &recipient_rlwe.pk,
        BASE_BITS,
    );
    let first_recovered_key = recover_source_key(&first_rekey, &recipient_rlwe.sk);
    assert_eq!(
        first_recovered_key.s.to_coeffs_vec(),
        first_source_rlwe.sk.s.to_coeffs_vec()
    );

    let second_source_rlwe = KeyGenResult::keygen(&mut rng, N);
    let second_ciphertext = encrypt_poly(&mut rng, &second_source_rlwe.pk, &attribute_plaintext, N);
    let second_collateral_ciphertext =
        encrypt_poly(&mut rng, &second_source_rlwe.pk, &attribute_plaintext, N);
    let second_rekey = generate_rekey(
        &mut rng,
        &second_source_rlwe.sk,
        &recipient_rlwe.pk,
        BASE_BITS,
    );

    // One transcryptor keeps the TFHE evaluator alive and accepts distinct
    // request-scoped RLWE rekeys through process_request_with_rekey.
    let transcryptor = PepTranscryptor::new(
        context.clone(),
        evaluator,
        first_rekey,
        clone_public_key(&recipient_rlwe.pk),
        BASE_BITS,
    )
    .expect("create reusable transcryptor");
    let recipient = PepRecipient::new(
        context.clone(),
        tfhe_recipient_key,
        SecretKey {
            s: recipient_rlwe.sk.s.clone(),
        },
        N,
    )
    .expect("create reusable recipient");

    println!("\n=== PEP API: PER-REQUEST RLWE KEY SCOPE EXPERIMENT ===");
    println!("Parameters: toy TFHE n=8,N=64,p=32; RLWE N={N},q={Q},base=16.");
    println!("One TFHE setup/evaluator is reused for both requests.");
    println!("Recipient RLWE key and PRF key stay stable; each request gets a fresh source RLWE key and rekey.");

    println!("[1] Prepare, transcrypt and open request 1.");
    let recovered_request_1_plaintext =
        decrypt_poly(&first_recovered_key, &first_collateral_ciphertext, N);
    assert_eq!(
        &recovered_request_1_plaintext.coefficients()[..N],
        attribute_values.as_slice()
    );
    let first_request = source
        .prepare_request(&identifier, &EncryptedAttribute::new(first_ciphertext))
        .expect("prepare request 1");
    let first_pending = first_request.pending();
    let first_response = transcryptor
        .process_request(first_request.wire_bytes(), &mut rng)
        .expect("transcrypt request 1");
    let first_opened = recipient
        .open_response(&first_response, &first_pending)
        .expect("open response 1");
    assert_eq!(first_opened.pseudonym.as_bytes(), &expected_pid);
    assert_eq!(first_opened.attribute_coefficients, attribute_values);
    println!("[PASS] Request 1 pseudonym matches the clear PRF; attribute is preserved.");
    println!("[CONFIRMED] Collusion recovers the request-1 ephemeral source key.");
    println!("[CONFIRMED] The recovered key opens another ciphertext from request 1.");

    println!("[2] Prepare, transcrypt and open request 2 using the same TFHE setup.");
    let second_request = source
        .prepare_request(&identifier, &EncryptedAttribute::new(second_ciphertext))
        .expect("prepare request 2");
    let second_pending = second_request.pending();
    let second_response = transcryptor
        .process_request_with_rekey(
            second_request.wire_bytes(),
            &second_rekey,
            &recipient_rlwe.pk,
            BASE_BITS,
            &mut rng,
        )
        .expect("transcrypt request 2");
    let second_opened = recipient
        .open_response(&second_response, &second_pending)
        .expect("open response 2");
    assert_eq!(second_opened.pseudonym.as_bytes(), &expected_pid);
    assert_eq!(second_opened.attribute_coefficients, attribute_values);
    println!("[PASS] Request 2 pseudonym matches the clear PRF; attribute is preserved.");
    assert_eq!(
        first_opened.pseudonym.as_bytes(),
        second_opened.pseudonym.as_bytes()
    );
    println!("[PASS] Same identifier/domain/epoch gives the same PID with fresh RLWE source keys.");

    println!(
        "[3] Try the request-1 recovered key against request 2 and persistent domain ciphertexts."
    );
    let request_2_attempt = decrypt_poly(&first_recovered_key, &second_collateral_ciphertext, N);
    let persistent_attempt = decrypt_poly(&first_recovered_key, &persistent_ciphertext, N);
    assert_ne!(
        &request_2_attempt.coefficients()[..N],
        attribute_values.as_slice()
    );
    assert_ne!(
        &persistent_attempt.coefficients()[..N],
        attribute_values.as_slice()
    );
    println!("[PASS] Request-1 recovered key does not recover request-2 plaintext.");
    println!("[PASS] Request-1 recovered key does not recover persistent-domain plaintext.");

    println!("LIMIT: the attack still recovers request 1's key and all request-1 ciphertexts.");
    println!("LIMIT: this test does not implement secure erasure or prove cryptographic collusion resistance.");
    println!("LIMIT: per-request rekey association remains trusted provisioning; wire context does not authenticate it.");
    println!("LIMIT: this toy test does not change the production key lifecycle or establish production security.");
}
