//! Experimental demonstrations of two different key exposure risks.
//! These tests do not alter production protocols and do not establish a
//! formal security break for every deployment model.

use pq_libpep::algebra::ring::{PolyRq, Q};
use pq_libpep::core::fast_lwr_prf::{FastLwrPrf, FastLwrPrfParameters, FastLwrPrfSecretKey};
use pq_libpep::core::pep_context::{CanonicalIdentifier, DomainId, PepContext};
use pq_libpep::core::rlwe::{KeyGenResult, SecretKey};
use pq_libpep::core::rlwe_pke::{decrypt_poly, encrypt_poly};
use pq_libpep::core::rlwe_pre::generate_rekey;
use rand::{rngs::OsRng, rngs::StdRng, RngCore, SeedableRng};

fn circular_distance(a: u64, b: u64, q: u64) -> u64 {
    let direct = a.abs_diff(b);
    direct.min(q - direct)
}

#[test]
fn recipient_secret_and_rekey_recover_toy_source_secret() {
    const N: usize = 256;
    const BASE_BITS: usize = 4;
    let base = 1u64 << BASE_BITS;
    let mut rng = StdRng::seed_from_u64(0x524c_5745_434f_4c4c);

    println!("\n=== RLWE REKEY COLLUSION DIAGNOSTIC ===");
    println!("Model: observer has the complete A->B rekey and recipient secret sk_B.");
    println!("Experiment: remove k0*s_B from the highest gadget entry, then nearest-candidate decode each source coefficient in the five CBD2 values.");
    println!("Parameters: N={N}, q={Q}, CBD2 secrets/errors, decomposition base={base}.");

    let source = KeyGenResult::keygen(&mut rng, N);
    let recipient = KeyGenResult::keygen(&mut rng, N);
    let rekey = generate_rekey(&mut rng, &source.sk, &recipient.pk, BASE_BITS);
    let highest = rekey.entries.last().expect("gadget rekey has entries");
    let b_power = (0..rekey.entries.len() - 1).fold(1u64, |power, _| {
        ((power as u128 * base as u128) % Q as u128) as u64
    });

    // k1 - k0*s_B = B^i*s_A + small error in R_Q.
    let observed = highest.k1.sub(&highest.k0.mul_ntt(&recipient.sk.s));
    let coefficients = observed.coefficients();
    let candidates: [u64; 5] = [0, 1, 2, Q - 1, Q - 2];
    let expected_noise_bound = 8 * N as u64 + 2;
    let candidate_phases = candidates.map(|s| ((b_power as u128 * s as u128) % Q as u128) as u64);
    let min_gap = (0..candidate_phases.len())
        .flat_map(|i| (i + 1..candidate_phases.len()).map(move |j| (i, j)))
        .map(|(i, j)| circular_distance(candidate_phases[i], candidate_phases[j], Q))
        .min()
        .unwrap();

    println!(
        "[ATTACK] Highest gadget power B^{} mod q = {b_power}",
        rekey.entries.len() - 1
    );
    println!("[ATTACK] Conservative coefficient noise bound = {expected_noise_bound}; minimum candidate spacing = {min_gap}");
    assert!(
        2 * expected_noise_bound < min_gap,
        "this parameter choice does not separate secret candidates from the noise bound"
    );

    let mut recovered = Vec::with_capacity(N);
    let mut max_residual = 0;
    for i in 0..N {
        let value = coefficients[i];
        let (candidate_index, residual) = candidate_phases
            .iter()
            .enumerate()
            .map(|(index, &phase)| (index, circular_distance(value, phase, Q)))
            .min_by_key(|(_, distance)| *distance)
            .unwrap();
        assert!(
            residual <= expected_noise_bound,
            "coefficient {i}: residual {residual} exceeds bound"
        );
        max_residual = max_residual.max(residual);
        recovered.push(candidates[candidate_index]);
    }
    println!("[ATTACK] Decoded all {N} secret coefficients; maximum residual={max_residual}.");

    let recovered_sk = SecretKey {
        s: PolyRq::from_coeffs(&recovered, N, Q),
    };
    assert_eq!(recovered_sk.s.to_coeffs_vec(), source.sk.s.to_coeffs_vec());
    println!("[PASS] Recovered sk_A exactly from (rk_A->B, sk_B).");

    let plaintext: Vec<u64> = (0..N).map(|i| ((i * 7 + 3) % 17) as u64).collect();
    let message = PolyRq::from_coeffs(&plaintext, N, Q);
    let ciphertext = encrypt_poly(&mut rng, &source.pk, &message, N);
    let decoded = decrypt_poly(&recovered_sk, &ciphertext, N);
    assert_eq!(&decoded.coefficients()[..N], plaintext.as_slice());
    println!("[PASS] Recovered key decrypts a fresh source ciphertext.");
    println!("Scope: demonstrates this prototype's current small-secret/base-16 setup; not a general attack on RLWE/PRE.");
}

fn pack_32_bytes(symbols: &[u64]) -> [u8; 32] {
    assert!(symbols.len() >= 52);
    let mut output = [0u8; 32];
    for bit in 0..256 {
        let value = ((symbols[bit / 5] >> (4 - bit % 5)) & 1) as u8;
        output[bit / 8] |= value << (7 - bit % 8);
    }
    output
}

#[test]
fn known_prf_key_and_clear_output_enable_low_entropy_dictionary() {
    let parameters = FastLwrPrfParameters {
        lwr_dimension: 8,
        ring_dimension: 64,
        output_modulus: 32,
    };
    let mut rng = StdRng::seed_from_u64(0x5052_4644_4943_5449);
    let key = FastLwrPrfSecretKey::generate(parameters, &mut rng).unwrap();
    let prf = FastLwrPrf::new(key.clone());
    let context = PepContext::new(DomainId::new("clinic-A").unwrap(), 1, [0u8; 16], [0u8; 16]);
    let target_id = CanonicalIdentifier::new("patient-number", b"patient-0042").unwrap();
    let observed_clear_pseudonym =
        pack_32_bytes(&prf.evaluate_many(&context.encode_prf_input(&target_id), 52));

    println!("\n=== PRF DICTIONARY DIAGNOSTIC ===");
    println!("Model: attacker knows the PRF key, domain/epoch encoding, and one clear 32-byte pseudonym.");
    println!("Search space: 1000 predictable patient identifiers; toy PRF key n=8, N=64, p=32.");

    let mut match_found = None;
    for number in 0..1000 {
        let candidate = format!("patient-{number:04}");
        let identifier = CanonicalIdentifier::new("patient-number", candidate.as_bytes()).unwrap();
        let candidate_output =
            pack_32_bytes(&prf.evaluate_many(&context.encode_prf_input(&identifier), 52));
        if candidate_output == observed_clear_pseudonym {
            match_found = Some(candidate);
            break;
        }
    }

    assert_eq!(match_found.as_deref(), Some("patient-0042"));
    println!("[PASS] Dictionary found {}.", match_found.unwrap());
    println!("Scope: PRF key plus comparable clear output and low-entropy IDs. It does not decrypt a TFHE ciphertext or break PRF security.");
    println!("Implication: a random stable canonical token blocks this particular enumeration only while the token remains unavailable to the attacker.");
}

#[test]
fn random_canonical_token_is_outside_the_predictable_dictionary() {
    let parameters = FastLwrPrfParameters {
        lwr_dimension: 8,
        ring_dimension: 64,
        output_modulus: 32,
    };
    let mut rng = StdRng::seed_from_u64(0x544f_4b45_4e44_4941);
    let key = FastLwrPrfSecretKey::generate(parameters, &mut rng).unwrap();
    let prf = FastLwrPrf::new(key);
    let context = PepContext::new(DomainId::new("clinic-A").unwrap(), 1, [0u8; 16], [0u8; 16]);
    let mut token = [0u8; 32];
    OsRng.fill_bytes(&mut token);
    let token_id = CanonicalIdentifier::new("random-person-token", &token).unwrap();
    let observed_clear_pseudonym =
        pack_32_bytes(&prf.evaluate_many(&context.encode_prf_input(&token_id), 52));

    println!("\n=== RANDOM TOKEN DICTIONARY MITIGATION DIAGNOSTIC ===");
    println!("Attacker still knows the toy PRF key and clear pseudonym, but searches only patient-0000..0999.");
    println!("Input token: 256 random bits. The test does not print or persist the token.");

    let mut match_found = None;
    for number in 0..1000 {
        let candidate = format!("patient-{number:04}");
        let identifier = CanonicalIdentifier::new("patient-number", candidate.as_bytes()).unwrap();
        let candidate_output =
            pack_32_bytes(&prf.evaluate_many(&context.encode_prf_input(&identifier), 52));
        if candidate_output == observed_clear_pseudonym {
            match_found = Some(candidate);
            break;
        }
    }

    assert!(
        match_found.is_none(),
        "unrelated predictable-ID dictionary unexpectedly matched the random-token output"
    );
    println!("[PASS] Predictable-ID dictionary did not match the random-token pseudonym.");
    println!("Limit: this only blocks enumeration if the token stays secret and the attacker cannot query a token-issuing or PRF oracle.");
}
