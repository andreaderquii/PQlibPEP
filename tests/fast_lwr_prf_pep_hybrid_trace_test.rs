#![cfg(feature = "experimental-linear-reshuffle")]
#![cfg(feature = "fast-prf-tfhe-private-input")]

//! Verbose end-to-end trace for the experimental hybrid PEP pipeline.
//!
//! This is an educational diagnostic test, not a production security test.
//! It explicitly prints and checks:
//!   1. 32-byte ID -> FastLwrPrf pseudonym through TFHE;
//!   2. a separate Ring-LWR/RlwrPrf derives invertible domain factors g_A/g_B;
//!   3. the plaintext is domain-encoded as M*g_A BEFORE RLWE encryption;
//!   4. the RLWE ciphertext is encrypted under A, and wrong-key decryption fails;
//!   5. reshuffling under the same source key transforms M*g_A -> M*g_B;
//!   6. rekey A->B changes which secret key can decrypt the ciphertext;
//!   7. rerandomization changes ciphertext components but not the decoded payload;
//!   8. a wrong factor and a wrong-direction rekey are negative counterexamples;
//!   9. the actual HPRQ/HPRS pipeline produces the same expected results.
//!
//! Secret-key material is NEVER printed. The test prints public-key fingerprints
//! and identifies secret-key roles through success/failure of decryption.

use rand::{rngs::StdRng, SeedableRng};
use sha3::{Digest, Sha3_256};

use pq_libpep::algebra::ring::{PolyRq, Q};
use pq_libpep::core::fast_lwr_prf::{FastLwrPrf, FastLwrPrfParameters, FastLwrPrfSecretKey};
use pq_libpep::core::fast_lwr_prf_pep_ks128_e16_pipeline::{
    output_symbols_for_bytes, setup_pep_lwr_prf,
};
use pq_libpep::core::fast_lwr_prf_pep_hybrid_pipeline::{
    HybridPepRecipient, HybridPepSource, HybridPepTranscryptor,
};
use pq_libpep::core::id_encoding::string_to_id;
use pq_libpep::core::params::prf_modulus_chain;
use pq_libpep::core::reshuffle::{
    derive_domain_transform_factor, derive_invertible_reshuffle_factor, reshuffle,
};
use pq_libpep::core::rlwe::KeyGenResult;
use pq_libpep::core::rlwe_pke::{decrypt_poly, encrypt_poly, Ciphertext};
use pq_libpep::core::rlwe_pre::{
    generate_rekey, reencrypt, reencrypt_and_rerandomize,
};
use pq_libpep::core::rlwr_prf::{RlwrPrf, RlwrPrfBase};

const N: usize = 256;
const P: u64 = 17;
const BASE_BITS: usize = 4;
const PSEUDONYM_BYTES: usize = 32;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn fingerprint(poly: &PolyRq) -> String {
    // A diagnostic fingerprint only; never print the underlying secret key.
    let mut h = Sha3_256::new();
    h.update((poly.degree_bound() as u64).to_le_bytes());
    h.update(poly.modulus().to_le_bytes());
    for &coefficient in poly.coefficients().iter().take(poly.degree_bound()) {
        h.update(coefficient.to_le_bytes());
    }
    let digest = h.finalize();
    hex(&digest[..8])
}

fn ciphertext_prefix(ciphertext: &Ciphertext) -> (Vec<u64>, Vec<u64>) {
    let mut u = ciphertext.u.to_coeffs_vec();
    let mut v = ciphertext.v.to_coeffs_vec();
    u.resize(N, 0);
    v.resize(N, 0);
    (u[..4].to_vec(), v[..4].to_vec())
}

fn decrypted_coefficients(
    ciphertext: &Ciphertext,
    secret_key: &pq_libpep::core::rlwe::SecretKey,
) -> Vec<u64> {
    let decrypted = decrypt_poly(secret_key, ciphertext, N);
    decrypted.coefficients()[..N].to_vec()
}

fn mismatch_count(left: &[u64], right: &[u64]) -> usize {
    assert_eq!(left.len(), right.len());
    left.iter().zip(right).filter(|(a, b)| a != b).count()
}

fn show_plain(label: &str, coefficients: &[u64]) {
    println!("{label} (first 12 coefficients): {:?}", &coefficients[..12]);
}

fn pack_symbols(
    parameters: FastLwrPrfParameters,
    symbols: &[u64],
    output_len: usize,
) -> Vec<u8> {
    let bits_per_symbol = parameters.output_modulus.trailing_zeros() as usize;
    let required_bits = output_len * 8;
    assert!(symbols.len() * bits_per_symbol >= required_bits);

    let mut output = vec![0u8; output_len];
    let mut bit_index = 0usize;

    for &symbol in symbols {
        assert!(symbol < parameters.output_modulus);
        for bit_position in (0..bits_per_symbol).rev() {
            if bit_index >= required_bits {
                return output;
            }
            let bit = ((symbol >> bit_position) & 1) as u8;
            output[bit_index / 8] |= bit << (7 - bit_index % 8);
            bit_index += 1;
        }
    }

    output
}

fn assert_differs(label: &str, observed: &[u64], expected: &[u64]) {
    let mismatches = mismatch_count(observed, expected);
    println!("{label}: {mismatches}/{} coefficients differ (expected counterexample)", expected.len());
    assert!(
        mismatches > 0,
        "counterexample failed: observed result unexpectedly equals the target plaintext"
    );
}

fn assert_same_plaintext(label: &str, decrypted: &[u64], expected: &[u64]) {
    let mismatches = mismatch_count(decrypted, expected);
    println!("{label}: {mismatches}/{} coefficient mismatches", expected.len());
    assert_eq!(mismatches, 0, "{label}: plaintext mismatch");
}

fn ciphertexts_differ(a: &Ciphertext, b: &Ciphertext) -> bool {
    a.u.to_coeffs_vec() != b.u.to_coeffs_vec()
        || a.v.to_coeffs_vec() != b.v.to_coeffs_vec()
}

#[test]
fn hybrid_pep_key_trace_all_transforms_and_wrong_key_counterexamples() {
    println!("\n============================================================");
    println!("HYBRID PEP KEY TRACE: FastLwrPrf + Ring-LWR factor + RLWE PRE");
    println!("============================================================");
    println!("WARNING: test-only toy TFHE parameters; not production security.");

    let mut rng = StdRng::seed_from_u64(0x5045_5054_5241_4345);

    // ------------------------------------------------------------
    // A. Application ID and the new FastLwrPrf pseudonym branch.
    // ------------------------------------------------------------
    let id = string_to_id("patient-001");
    println!("\n[A] INPUT ID");
    println!("ID length: {} bytes", id.len());
    println!("ID bytes : {}", hex(&id));
    println!("The source keeps this ID locally; the HPRQ wire carries encrypted H(ID,i) slots, not this raw ID.");

    let fast_parameters = FastLwrPrfParameters {
        lwr_dimension: 8,
        ring_dimension: 64,
        output_modulus: 4,
    };
    let fast_key = FastLwrPrfSecretKey::generate(fast_parameters, &mut rng)
        .expect("generate toy FastLwrPrf key");
    let fast_reference = FastLwrPrf::new(fast_key.clone());
    let (tfhe_source, tfhe_recipient, tfhe_evaluator) =
        setup_pep_lwr_prf(fast_parameters, &fast_key)
            .expect("set up TFHE pseudonym branch");

    let symbol_count = output_symbols_for_bytes(fast_parameters, PSEUDONYM_BYTES)
        .expect("calculate symbol count");
    println!("\n[B] FastLwrPrf / TFHE branch");
    println!("Toy FastLwrPrf output modulus p_fast = {}", fast_parameters.output_modulus);
    println!("Bits per output symbol = {}", fast_parameters.output_modulus.trailing_zeros());
    println!("For {} output bytes: {} toy symbols are evaluated.", PSEUDONYM_BYTES, symbol_count);
    println!("TFHE roles: source encrypts inputs; evaluator computes on ciphertexts; recipient holds the output decryption key.");
    println!("The TFHE ciphertext/key system is independent of the RLWE payload keys below.");

    // ------------------------------------------------------------
    // C. Separate existing Ring-LWR PRF derives g_A and g_B.
    // ------------------------------------------------------------
    let moduli = prf_modulus_chain();
    let highest_modulus = *moduli.last().expect("non-empty modulus chain");
    let leaf_count = 1usize << (moduli.len() - 1);
    assert_eq!(leaf_count, N, "Ring-LWR input tree is expected to match the 32-byte ID bit count");
    let base = RlwrPrfBase::sample(&mut rng, N, highest_modulus, leaf_count);
    let domain_prf = RlwrPrf::new(base, moduli);

    let domain_a = "hospital-A";
    let domain_b = "hospital-B";
    let g_a = derive_invertible_reshuffle_factor(&domain_prf, domain_a, N, Q)
        .expect("derive invertible g_A");
    let g_b = derive_invertible_reshuffle_factor(&domain_prf, domain_b, N, Q)
        .expect("derive invertible g_B");
    let factor_a_to_b_q = derive_domain_transform_factor(
        &domain_prf, domain_a, domain_b, N, Q,
    )
    .expect("derive t_A_to_B");
    let factor_a_to_b_p = g_a.inverse_mod_p.mul_negacyclic(&g_b.factor_mod_p);

    let identity_a = g_a.factor_mod_p.mul_negacyclic(&g_a.inverse_mod_p);
    let identity_b = g_b.factor_mod_p.mul_negacyclic(&g_b.inverse_mod_p);
    assert_eq!(identity_a.coefficients()[0], 1);
    assert!(identity_a.coefficients()[1..N].iter().all(|&x| x == 0));
    assert_eq!(identity_b.coefficients()[0], 1);
    assert!(identity_b.coefficients()[1..N].iter().all(|&x| x == 0));

    println!("\n[C] Ring-LWR PRF / domain factors");
    println!("This is the existing RlwrPrf branch, distinct from FastLwrPrf.");
    println!("Ring degree N = {N}; plaintext factor ring R_17 = Z_17[X]/(X^{N}+1); ciphertext modulus Q = {Q}.");
    println!("Domain A = {domain_a}; g_A mod 17 first 12: {:?}", &g_a.factor_mod_p.coefficients()[..12]);
    println!("Domain B = {domain_b}; g_B mod 17 first 12: {:?}", &g_b.factor_mod_p.coefficients()[..12]);
    println!("g_A inverse check: g_A*g_A^(-1)=1 in R_17: PASS");
    println!("g_B inverse check: g_B*g_B^(-1)=1 in R_17: PASS");
    println!("Relative transform t_A_to_B = g_A^(-1)*g_B mod 17, first 12: {:?}", &factor_a_to_b_p.coefficients()[..12]);
    println!("The coefficient-wise lift to Q is approximate, not an exact ring embedding.");

    // ------------------------------------------------------------
    // D. The logical payload and source-domain encoding BEFORE encryption.
    // ------------------------------------------------------------
    let logical_m: Vec<u64> = (0..N).map(|i| ((7 * i + 3) as u64) % P).collect();
    let m_p = PolyRq::from_coeffs(&logical_m, N, P);
    let encoded_a_p = m_p.mul_negacyclic(&g_a.factor_mod_p);
    let expected_b_p = m_p.mul_negacyclic(&g_b.factor_mod_p);
    let encoded_a_q = PolyRq::from_coeffs(&encoded_a_p.coefficients()[..N], N, Q);

    println!("\n[D] PAYLOAD PREPARATION — before encryption");
    show_plain("Logical payload M in R_17", &logical_m);
    show_plain("Source-domain plaintext M*g_A mod 17", &encoded_a_p.coefficients()[..N]);
    show_plain("Expected target-domain plaintext M*g_B mod 17", &expected_b_p.coefficients()[..N]);
    println!("RLWE encrypt_poly uses Delta=floor(Q/17)={} and encodes each coefficient as Delta*m + noise.", Q / P);
    println!("The payload is intentionally encrypted as M*g_A, not raw M, because this test demonstrates a domain transition A -> B.");

    // ------------------------------------------------------------
    // E. Generate distinct RLWE key pairs A and B; print safe fingerprints.
    // ------------------------------------------------------------
    let alice = KeyGenResult::keygen(&mut rng, N);
    let bob = KeyGenResult::keygen(&mut rng, N);
    println!("\n[E] RLWE KEYS");
    println!("pk_A.a fingerprint: {}", fingerprint(&alice.pk.a));
    println!("pk_A.b fingerprint: {}", fingerprint(&alice.pk.b));
    println!("sk_A is held only by A; secret material is not printed.");
    println!("pk_B.a fingerprint: {}", fingerprint(&bob.pk.a));
    println!("pk_B.b fingerprint: {}", fingerprint(&bob.pk.b));
    println!("sk_B is held only by B; secret material is not printed.");
    assert_ne!(fingerprint(&alice.pk.a), fingerprint(&bob.pk.a), "A and B must have distinct public keys");

    // ------------------------------------------------------------
    // F. Encrypt under A and demonstrate the key boundary.
    // ------------------------------------------------------------
    let ciphertext_a = encrypt_poly(&mut rng, &alice.pk, &encoded_a_q, N);
    let (u_a_prefix, v_a_prefix) = ciphertext_prefix(&ciphertext_a);
    println!("\n[F] RLWE ENCRYPTION under pk_A");
    println!("C_A = Enc_A(M*g_A): u first 4 = {u_a_prefix:?}; v first 4 = {v_a_prefix:?}");
    let decrypt_a = decrypted_coefficients(&ciphertext_a, &alice.sk);
    assert_same_plaintext("Decrypt C_A with sk_A", &decrypt_a, &encoded_a_p.coefficients()[..N]);
    let decrypt_b_wrong = decrypted_coefficients(&ciphertext_a, &bob.sk);
    assert_differs("Counterexample: decrypt C_A with sk_B (no A->B rekey yet)", &decrypt_b_wrong, &encoded_a_p.coefficients()[..N]);

    // ------------------------------------------------------------
    // G. Counterexample: multiplying M*g_A by g_B is NOT A -> B.
    // ------------------------------------------------------------
    let wrong_factor_ciphertext = reshuffle(&ciphertext_a, &g_b.factor_mod_q);
    let wrong_factor_plain = decrypted_coefficients(&wrong_factor_ciphertext, &alice.sk);
    let wrong_factor_expected_p = encoded_a_p.mul_negacyclic(&g_b.factor_mod_p);
    assert_ne!(
        wrong_factor_expected_p.coefficients()[..N],
        expected_b_p.coefficients()[..N],
        "test setup must make the wrong g_B-only transformation algebraically distinct",
    );
    assert_differs(
        "Counterexample: applying g_B directly to M*g_A does not produce M*g_B",
        &wrong_factor_plain,
        &expected_b_p.coefficients()[..N],
    );
    println!("Algebraically, g_B applied to an already encoded M*g_A gives M*g_A*g_B, not M*g_B.");
    println!("Correct A->B transition needs t_A_to_B = g_A^(-1)*g_B, not g_B alone.");

    // ------------------------------------------------------------
    // H. Correct reshuffling still leaves the ciphertext under A.
    // ------------------------------------------------------------
    let reshuffled_under_a = reshuffle(&ciphertext_a, &factor_a_to_b_q);
    let (u_r_prefix, v_r_prefix) = ciphertext_prefix(&reshuffled_under_a);
    println!("\n[H] RESHUFFLE before key switching");
    println!("Operation: C_A=(u,v) -> C'_A=(u*t_A_to_B, v*t_A_to_B) in R_Q.");
    println!("C'_A components: u first 4 = {u_r_prefix:?}; v first 4 = {v_r_prefix:?}");
    let transformed_still_a = decrypted_coefficients(&reshuffled_under_a, &alice.sk);
    assert_same_plaintext("Decrypt reshuffled C'_A with sk_A", &transformed_still_a, &expected_b_p.coefficients()[..N]);
    let bob_before_rekey = decrypted_coefficients(&reshuffled_under_a, &bob.sk);
    assert_differs("Counterexample: sk_B still cannot decrypt C'_A before rekey", &bob_before_rekey, &expected_b_p.coefficients()[..N]);

    // ------------------------------------------------------------
    // I. Generate a correctly directed A -> B re-encryption key.
    // ------------------------------------------------------------
    let rekey_ab = generate_rekey(&mut rng, &alice.sk, &bob.pk, BASE_BITS);
    println!("\n[I] KEY SWITCH KEY");
    println!("ReKey_AB generated from sk_A and pk_B; base_bits={BASE_BITS}; decomposition entries={}", rekey_ab.entries.len());
    println!("The rekey is directional: it is for ciphertexts under A, with output under B.");

    let rekeyed_only = reencrypt(&reshuffled_under_a, &rekey_ab, BASE_BITS);
    let (u_b_prefix, v_b_prefix) = ciphertext_prefix(&rekeyed_only);
    println!("\n[J] REKEY A -> B (without rerandomization)");
    println!("C'_B = ReKey_AB(C'_A): u first 4 = {u_b_prefix:?}; v first 4 = {v_b_prefix:?}");
    let bob_after_rekey = decrypted_coefficients(&rekeyed_only, &bob.sk);
    assert_same_plaintext("Decrypt rekeyed C'_B with sk_B", &bob_after_rekey, &expected_b_p.coefficients()[..N]);
    let alice_after_rekey_wrong = decrypted_coefficients(&rekeyed_only, &alice.sk);
    assert_differs("Counterexample: sk_A no longer decrypts the rekeyed result", &alice_after_rekey_wrong, &expected_b_p.coefficients()[..N]);

    // Wrong-direction counterexample: this key is generated B -> A, but is
    // deliberately misapplied to a ciphertext that is under A (not B).
    let rekey_ba = generate_rekey(&mut rng, &bob.sk, &alice.pk, BASE_BITS);
    let wrong_direction_output = reencrypt(&reshuffled_under_a, &rekey_ba, BASE_BITS);
    let wrong_direction_plain_a = decrypted_coefficients(&wrong_direction_output, &alice.sk);
    assert_differs(
        "Counterexample: applying ReKey_BA to a ciphertext under A does not recover target plaintext under A",
        &wrong_direction_plain_a,
        &expected_b_p.coefficients()[..N],
    );
    println!("Wrong-direction ReKey_BA was rejected semantically by the plaintext check; the API returns a ciphertext, not an error.");

    // ------------------------------------------------------------
    // K. Rerandomize by adding a fresh Enc_B(0).
    // ------------------------------------------------------------
    let rekeyed_rerandomized = reencrypt_and_rerandomize(
        &mut rng,
        &reshuffled_under_a,
        &rekey_ab,
        &bob.pk,
        BASE_BITS,
    );
    println!("\n[K] RERANDOMIZATION under pk_B");
    println!("Operation: C''_B = ReKey_AB(C'_A) + Enc_B(0).");
    assert!(
        ciphertexts_differ(&rekeyed_only, &rekeyed_rerandomized),
        "rerandomization should change ciphertext components",
    );
    println!("Ciphertext components changed after adding fresh Enc_B(0): PASS");
    let bob_after_rerandomize = decrypted_coefficients(&rekeyed_rerandomized, &bob.sk);
    assert_same_plaintext("Decrypt rerandomized C''_B with sk_B", &bob_after_rerandomize, &expected_b_p.coefficients()[..N]);
    let alice_after_rerandomize_wrong = decrypted_coefficients(&rekeyed_rerandomized, &alice.sk);
    assert_differs("Counterexample: sk_A does not decrypt the final B ciphertext", &alice_after_rerandomize_wrong, &expected_b_p.coefficients()[..N]);

    // ------------------------------------------------------------
    // L. Run the actual hybrid HPRQ/HPRS path, independently verifying both branches.
    // ------------------------------------------------------------
    println!("\n[L] FULL HYBRID TRANSACTION HPRQ -> HPRS");
    println!("TFHE branch: ID -> encrypted H(ID,i) slots -> FastLwrPrf evaluation -> 32-byte pseudonym under recipient TFHE key.");
    println!("RLWE branch: Enc_A(M*g_A) -> reshuffle by t_A_to_B -> rekey A->B -> add Enc_B(0) -> decrypt as M*g_B.");
    println!("No TFHE ciphertext is converted to or multiplied into an RLWE ciphertext.");

    let source = HybridPepSource::new(tfhe_source);
    let transcryptor = HybridPepTranscryptor::new_with_domain_transition(
        tfhe_evaluator,
        rekey_ab,
        bob.pk,
        BASE_BITS,
        &domain_prf,
        domain_a,
        domain_b,
    )
    .expect("configure hybrid transcryptor for hospital-A -> hospital-B");
    let recipient = HybridPepRecipient::new(tfhe_recipient, bob.sk, N)
        .expect("configure recipient B");

    let request = source
        .prepare_request(&id, &ciphertext_a, PSEUDONYM_BYTES)
        .expect("source prepares HPRQ");
    let transaction_id = request.transaction_id();
    let batch_id = request.batch_id();
    let wire = request.wire_bytes();
    let slot_count = u32::from_le_bytes(wire[41..45].try_into().unwrap());
    println!("HPRQ version={}, encrypted TFHE slots={}, request bytes={}", wire[4], slot_count, wire.len());
    println!("HPRQ carries IDs and ciphertext envelopes; it does not carry the raw patient ID.");

    let response = transcryptor
        .process_request_wire(wire, &mut rng)
        .expect("transcryptor processes all transformations");
    println!("HPRS magic={}, response bytes={}", String::from_utf8_lossy(&response[..4]), response.len());

    let result = recipient
        .open_response_wire(&response, &transaction_id, &batch_id, PSEUDONYM_BYTES)
        .expect("recipient checks transaction and decrypts both branches");

    let expected_symbols = fast_reference.evaluate_many(&id, symbol_count as usize);
    let expected_pseudonym = pack_symbols(fast_parameters, &expected_symbols, PSEUDONYM_BYTES);
    assert_eq!(result.pseudonym, expected_pseudonym);
    assert_eq!(result.pseudonym.len(), PSEUDONYM_BYTES);
    println!("TFHE pseudonym ({} bytes): {}", result.pseudonym.len(), hex(&result.pseudonym));
    println!("TFHE pseudonym equals cleartext FastLwrPrf reference: PASS");

    assert_same_plaintext(
        "Hybrid final payload under sk_B equals M*g_B",
        &result.payload_coefficients,
        &expected_b_p.coefficients()[..N],
    );
    assert_eq!(result.transaction_id, transaction_id);
    assert_eq!(result.batch_id, batch_id);

    println!("\n============================================================");
    println!("ALL TRACE CHECKS PASSED");
    println!("  ID -> FastLwrPrf/TFHE pseudonym: verified");
    println!("  RLWR domain factor g_A/g_B and inverse: verified in R_17");
    println!("  Before encryption: M -> M*g_A: explicitly computed");
    println!("  Ciphertext under A: sk_A succeeds; sk_B counterexample fails");
    println!("  Reshuffle: M*g_A -> M*g_B while the ciphertext remains under A");
    println!("  Correct ReKey_AB: output under B; sk_A no longer succeeds");
    println!("  Wrong ReKey_BA and wrong factor g_B-alone: counterexamples detected");
    println!("  Rerandomization: ciphertext changes; B's decoded plaintext is preserved");
    println!("  HPRQ/HPRS transaction matches both independent references");
    println!("============================================================\n");
}
