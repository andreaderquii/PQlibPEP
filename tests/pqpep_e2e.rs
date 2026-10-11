use pq_libpep::algebra::ring::PolyRq;
use pq_libpep::core::id_encoding::{bytes_to_bits, string_to_id};
use pq_libpep::core::params::{Q0, RING_DIMENSION};

#[test]
fn test_id_to_plaintext_polynomial() {
    let input = "patient-001";

    // 1. String -> canonical 32-byte ID
    let id = string_to_id(input);

    // 2. ID -> 256 bits
    let bits = bytes_to_bits(&id);

    assert_eq!(id.len(), 32);
    assert_eq!(bits.len(), 256);
    assert!(bits.iter().all(|&b| b == 0 || b == 1));

    // 3. Bits -> plaintext polynomial in R_17
    let message = PolyRq::from_coeffs(
        &bits.iter().map(|&b| b as u64).collect::<Vec<_>>(),
        RING_DIMENSION,
        Q0,
    );

    assert_eq!(message.degree_bound(), RING_DIMENSION);
    assert_eq!(message.modulus(), Q0);

    // Every plaintext coefficient must be 0 or 1.
    assert!(message
        .coefficients()
        .iter()
        .take(RING_DIMENSION)
        .all(|&c| c == 0 || c == 1));

    println!("ID      : {:02x?}", id);
    println!("Bits[0..32] : {:?}", &bits[..32]);
    println!(
        "Message[0..32] : {:?}",
        &message.coefficients()[..32]
    );
}

#[test]
fn test_id_to_prf_factor() {
    use pq_libpep::core::id_encoding::string_to_id;
    use pq_libpep::core::params::{prf_modulus_chain, RING_DIMENSION};
    use pq_libpep::core::pseudonym::pseudonymize_32;
    use pq_libpep::core::rlwr_prf::{RlwrPrf, RlwrPrfBase};
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    let input = "patient-001";

    // Deterministic test PRF key/material.
    let mut rng = StdRng::seed_from_u64(42);

    let chain = prf_modulus_chain();
    let highest_modulus = *chain.last().unwrap();

    let base = RlwrPrfBase::sample(
        &mut rng,
        RING_DIMENSION,
        highest_modulus,
        256,
    );

    let prf = RlwrPrf::new(base, chain);

    // String -> 32-byte identifier
    let id = string_to_id(input);

    // ID -> PRF output
    let g1 = pseudonymize_32(&prf, &id);
    let g2 = pseudonymize_32(&prf, &id);

    assert_eq!(
        g1,
        g2,
        "same ID and same PRF must produce the same factor"
    );

    println!("ID      : {}", input);
    println!(
        "g[0..16]: {:?}",
        &g1.coefficients()[..16]
    );
}

#[test]
fn test_full_id_prf_reshuffle_e2e() {
    use pq_libpep::algebra::ring::PolyRq;
    use pq_libpep::core::id_encoding::{bytes_to_bits, string_to_id};
    use pq_libpep::core::params::{
        prf_modulus_chain,
        Q0,
        RING_DIMENSION,
    };
    use pq_libpep::core::pseudonym::pseudonymize_32;
    use pq_libpep::core::reshuffle::{
        lift_prf_output_to_q,
        reshuffle,
    };
    use pq_libpep::core::rlwe::KeyGenResult;
    use pq_libpep::core::rlwe_pke::{
        decrypt_poly,
        encrypt_poly,
    };
    use pq_libpep::core::rlwr_prf::{
        RlwrPrf,
        RlwrPrfBase,
    };

    use rand::rngs::StdRng;
    use rand::SeedableRng;

    const N: usize = RING_DIMENSION;
    const Q: u64 = 998_244_353;
    const P: u64 = Q0;

    // ------------------------------------------------------------
    // 1. USER IDENTIFIER
    // ------------------------------------------------------------
    let input = "patient-001";

    let id = string_to_id(input);
    let bits = bytes_to_bits(&id);

    assert_eq!(id.len(), 32);
    assert_eq!(bits.len(), 256);
    assert!(bits.iter().all(|&b| b == 0 || b == 1));

    println!("==============================================");
    println!("   PQPEP FULL END-TO-END TEST");
    println!("==============================================");
    println!("[1] User identifier");
    println!("    ID = {}", input);

    // ------------------------------------------------------------
    // 2. ID -> PLAINTEXT COEFFICIENTS
    // ------------------------------------------------------------
    let message_coeffs: Vec<u64> =
        bits.iter().map(|&b| b as u64).collect();

    // Semantic plaintext in R_17.
    let message_p = PolyRq::from_coeffs(
        &message_coeffs,
        N,
        P,
    );

    // RLWE encryption representation in R_q.
    let message_q = PolyRq::from_coeffs(
        &message_coeffs,
        N,
        Q,
    );

    assert_eq!(message_p.modulus(), P);
    assert_eq!(message_q.modulus(), Q);

    println!("[2] ID -> plaintext polynomial");
    println!(
        "    M[0..16] = {:?}",
        &message_coeffs[..16]
    );

    // ------------------------------------------------------------
    // 3. BUILD PRF
    // ------------------------------------------------------------
    let mut rng = StdRng::seed_from_u64(42);

    let chain = prf_modulus_chain();
    let highest_modulus = *chain.last().unwrap();

    let base = RlwrPrfBase::sample(
        &mut rng,
        RING_DIMENSION,
        highest_modulus,
        256,
    );

    let prf = RlwrPrf::new(base, chain);

    // ------------------------------------------------------------
    // 4. ID -> PRF OUTPUT g in R_17
    // ------------------------------------------------------------
    let g17 = pseudonymize_32(&prf, &id);

    assert_eq!(g17.modulus(), P);
    assert_eq!(g17.degree_bound(), N);

    println!("[3] ID -> Ring-LWR PRF");
    println!(
        "    g17[0..16] = {:?}",
        &g17.coefficients()[..16]
    );

    // ------------------------------------------------------------
    // 5. LIFT g : R_17 -> R_q
    // ------------------------------------------------------------
    let gq = lift_prf_output_to_q(&g17, Q);

    assert_eq!(gq.modulus(), Q);
    assert_eq!(gq.degree_bound(), N);

    println!("[4] Lift PRF output");
    println!("    R_17 -> R_q");
    println!(
        "    gq[0..16] = {:?}",
        &gq.coefficients()[..16]
    );

    // ------------------------------------------------------------
    // 6. RLWE KEY GENERATION
    // ------------------------------------------------------------
    let keygen = KeyGenResult::keygen(&mut rng, N);

    println!("[5] RLWE key generation");
    println!("    Alice key pair generated");

    // ------------------------------------------------------------
    // 7. ENCRYPT REAL ID POLYNOMIAL
    // ------------------------------------------------------------
    let ciphertext = encrypt_poly(
        &mut rng,
        &keygen.pk,
        &message_q,
        N,
    );

    println!("[6] RLWE encryption");
    println!("    Enc_A(M) generated");

    // ------------------------------------------------------------
    // 8. CHECK ORIGINAL DECRYPTION
    // ------------------------------------------------------------
    let recovered_original = decrypt_poly(
        &keygen.sk,
        &ciphertext,
        N,
    );

    let recovered_original_coeffs: Vec<u64> = recovered_original
        .coefficients()
        .iter()
        .take(N)
        .map(|&c| c % P)
        .collect();

    let original_coeffs: Vec<u64> = message_p
        .coefficients()
        .iter()
        .take(N)
        .map(|&c| c % P)
        .collect();

    assert_eq!(
        recovered_original_coeffs,
        original_coeffs,
        "original RLWE encryption/decryption failed"
    );

    println!("[7] Original decryption");
    println!("    Dec_A(Enc_A(M)) = M");
    println!("    OK");

    // ------------------------------------------------------------
    // 9. RESHUFFLE WITH PRF-DERIVED FACTOR
    // ------------------------------------------------------------
    let reshuffled = reshuffle(
        &ciphertext,
        &gq,
    );

    println!("[8] Reshuffle");
    println!("    CT' = Reshuffle(CT, g)");
    println!("    Algebraically: (u,v) -> (u*g, v*g)");

    // ------------------------------------------------------------
    // 10. DECRYPT RESHUFFLED CIPHERTEXT
    // ------------------------------------------------------------
    let recovered = decrypt_poly(
        &keygen.sk,
        &reshuffled,
        N,
    );

    let recovered_coeffs: Vec<u64> = recovered
        .coefficients()
        .iter()
        .take(N)
        .map(|&c| c % P)
        .collect();

    println!("[9] Decrypt reshuffled ciphertext");
    println!(
        "    Recovered[0..16] = {:?}",
        &recovered_coeffs[..16]
    );

    // ------------------------------------------------------------
    // 11. EXPECTED RESULT = M * g mod 17
    // ------------------------------------------------------------
    let g17_coeffs: Vec<u64> = g17
        .coefficients()
        .iter()
        .take(N)
        .map(|&c| c % P)
        .collect();

    let g17_for_expected = PolyRq::from_coeffs(
        &g17_coeffs,
        N,
        P,
    );

    let expected = message_p.mul_negacyclic(
        &g17_for_expected,
    );

    let expected_coeffs: Vec<u64> = expected
        .coefficients()
        .iter()
        .take(N)
        .map(|&c| c % P)
        .collect();

    println!("[10] Expected plaintext");
    println!(
        "     Expected = M * g mod 17"
    );
    println!(
        "     Expected[0..16] = {:?}",
        &expected_coeffs[..16]
    );

    // ------------------------------------------------------------
    // 12. FINAL VERIFICATION
    // ------------------------------------------------------------
    assert_eq!(
        recovered_coeffs,
        expected_coeffs,
        "reshuffled plaintext does not match M * g mod 17"
    );

    println!("[11] Verification");
    println!("     Dec_A(Reshuffle(Enc_A(M), g)) = M * g mod 17");
    println!("     OK");

    println!("==============================================");
    println!("    PQPEP E2E TEST: OK");
    println!("==============================================");
}

















// ============================================================================
// COMPOSED PQPEP TESTS
// ============================================================================

#[test]
fn test_full_id_reshuffle_rekey_e2e() {
    use pq_libpep::algebra::ring::PolyRq;
    use pq_libpep::core::id_encoding::{bytes_to_bits, string_to_id};
    use pq_libpep::core::params::{prf_modulus_chain, Q0, RING_DIMENSION};
    use pq_libpep::core::pseudonym::pseudonymize_32;
    use pq_libpep::core::reshuffle::{lift_prf_output_to_q, reshuffle};
    use pq_libpep::core::rlwe::KeyGenResult;
    use pq_libpep::core::rlwe_pke::{decrypt_poly, encrypt_poly};
    use pq_libpep::core::rlwe_pre::{generate_rekey, reencrypt};
    use pq_libpep::core::rlwr_prf::{RlwrPrf, RlwrPrfBase};
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    const N: usize = RING_DIMENSION;
    const Q: u64 = 998_244_353;
    const P: u64 = Q0;
    const BASE_BITS: usize = 4;

    let input = "patient-001";

    println!("==============================================");
    println!("   PQPEP RESHUFFLE + REKEY E2E TEST");
    println!("==============================================");
    println!("[1] User identifier");
    println!("    ID = {}", input);

    // ID -> 256-bit polynomial.
    let id = string_to_id(input);
    let bits = bytes_to_bits(&id);
    assert_eq!(id.len(), 32);
    assert_eq!(bits.len(), 256);
    assert!(bits.iter().all(|&b| b == 0 || b == 1));

    let message_coeffs: Vec<u64> = bits.iter().map(|&b| b as u64).collect();
    let message_p = PolyRq::from_coeffs(&message_coeffs, N, P);
    let message_q = PolyRq::from_coeffs(&message_coeffs, N, Q);

    // Same deterministic PRF material as the previous E2E test.
    let mut prf_rng = StdRng::seed_from_u64(42);
    let chain = prf_modulus_chain();
    let highest_modulus = *chain.last().unwrap();
    let base = RlwrPrfBase::sample(
        &mut prf_rng,
        N,
        highest_modulus,
        256,
    );
    let prf = RlwrPrf::new(base, chain);

    let g17 = pseudonymize_32(&prf, &id);
    let gq = lift_prf_output_to_q(&g17, Q);

    println!("[2] ID -> PRF -> lift");
    println!("    g17[0..16] = {:?}", &g17.coefficients()[..16]);
    println!("    gq.modulus  = {}", gq.modulus());

    // Independent cryptographic RNG for Alice/Bob and encryption.
    let mut rng = StdRng::seed_from_u64(1337);
    let alice = KeyGenResult::keygen(&mut rng, N);
    let bob = KeyGenResult::keygen(&mut rng, N);

    println!("[3] Alice and Bob key pairs generated");

    let ciphertext_a = encrypt_poly(&mut rng, &alice.pk, &message_q, N);
    println!("[4] Enc_A(M) generated");

    // First transformation: pseudonym reshuffling.
    let ciphertext_reshuffled = reshuffle(&ciphertext_a, &gq);
    println!("[5] Reshuffle applied");

    // Second transformation: Alice -> Bob key switching.
    let rekey_ab = generate_rekey(
        &mut rng,
        &alice.sk,
        &bob.pk,
        BASE_BITS,
    );
    println!("[6] ReKey_A->B generated");

    let ciphertext_b = reencrypt(
        &ciphertext_reshuffled,
        &rekey_ab,
        BASE_BITS,
    );
    println!("[7] Reshuffled ciphertext re-encrypted to Bob");

    // Expected semantic result: M * g in R_17.
    let g17_for_expected = PolyRq::from_coeffs(
        &g17.coefficients()[..N],
        N,
        P,
    );
    let expected = message_p.mul_negacyclic(&g17_for_expected);
    let expected_coeffs: Vec<u64> = expected
        .coefficients()
        .iter()
        .take(N)
        .map(|&c| c % P)
        .collect();

    let recovered = decrypt_poly(&bob.sk, &ciphertext_b, N);
    let recovered_coeffs: Vec<u64> = recovered
        .coefficients()
        .iter()
        .take(N)
        .map(|&c| c % P)
        .collect();

    println!("[8] Bob decrypts composed ciphertext");
    println!("    Recovered[0..16] = {:?}", &recovered_coeffs[..16]);
    println!("    Expected[0..16]  = {:?}", &expected_coeffs[..16]);

    assert_eq!(
        recovered_coeffs,
        expected_coeffs,
        "Reshuffle + ReKey composition failed"
    );

    println!("[9] Verification");
    println!("    Dec_B(ReEnc_A->B(Reshuffle(Enc_A(M), g))) = M*g");
    println!("    OK");
    println!("==============================================");
    println!("    RESHUFFLE + REKEY E2E TEST: OK");
    println!("==============================================");
}

#[test]
fn test_full_id_reshuffle_rekey_multihop_e2e() {
    use pq_libpep::algebra::ring::PolyRq;
    use pq_libpep::core::id_encoding::{bytes_to_bits, string_to_id};
    use pq_libpep::core::params::{prf_modulus_chain, Q0, RING_DIMENSION};
    use pq_libpep::core::pseudonym::pseudonymize_32;
    use pq_libpep::core::reshuffle::{lift_prf_output_to_q, reshuffle};
    use pq_libpep::core::rlwe::KeyGenResult;
    use pq_libpep::core::rlwe_pke::{decrypt_poly, encrypt_poly};
    use pq_libpep::core::rlwe_pre::{generate_rekey, reencrypt};
    use pq_libpep::core::rlwr_prf::{RlwrPrf, RlwrPrfBase};
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    const N: usize = RING_DIMENSION;
    const Q: u64 = 998_244_353;
    const P: u64 = Q0;
    const BASE_BITS: usize = 4;

    let input = "patient-001";

    println!("==============================================");
    println!("   PQPEP RESHUFFLE + MULTI-HOP E2E TEST");
    println!("==============================================");

    // ID -> plaintext polynomial.
    let id = string_to_id(input);
    let bits = bytes_to_bits(&id);
    assert_eq!(id.len(), 32);
    assert_eq!(bits.len(), 256);
    assert!(bits.iter().all(|&b| b == 0 || b == 1));

    let message_coeffs: Vec<u64> = bits.iter().map(|&b| b as u64).collect();
    let message_p = PolyRq::from_coeffs(&message_coeffs, N, P);
    let message_q = PolyRq::from_coeffs(&message_coeffs, N, Q);

    // Deterministic PRF.
    let mut prf_rng = StdRng::seed_from_u64(42);
    let chain = prf_modulus_chain();
    let highest_modulus = *chain.last().unwrap();
    let base = RlwrPrfBase::sample(
        &mut prf_rng,
        N,
        highest_modulus,
        256,
    );
    let prf = RlwrPrf::new(base, chain);

    let g17 = pseudonymize_32(&prf, &id);
    let gq = lift_prf_output_to_q(&g17, Q);

    // Expected semantic plaintext after reshuffle.
    let g17_for_expected = PolyRq::from_coeffs(
        &g17.coefficients()[..N],
        N,
        P,
    );
    let expected = message_p.mul_negacyclic(&g17_for_expected);
    let expected_coeffs: Vec<u64> = expected
        .coefficients()
        .iter()
        .take(N)
        .map(|&c| c % P)
        .collect();

    // Alice -> Bob -> Carol.
    let mut rng = StdRng::seed_from_u64(2026);
    let alice = KeyGenResult::keygen(&mut rng, N);
    let bob = KeyGenResult::keygen(&mut rng, N);
    let carol = KeyGenResult::keygen(&mut rng, N);

    let ciphertext_a = encrypt_poly(&mut rng, &alice.pk, &message_q, N);
    println!("[1] Enc_A(M) generated");

    let ciphertext_reshuffled = reshuffle(&ciphertext_a, &gq);
    println!("[2] Reshuffle applied");

    let rekey_ab = generate_rekey(
        &mut rng,
        &alice.sk,
        &bob.pk,
        BASE_BITS,
    );
    let ciphertext_b = reencrypt(
        &ciphertext_reshuffled,
        &rekey_ab,
        BASE_BITS,
    );
    println!("[3] A -> B key switching applied");

    let recovered_b = decrypt_poly(&bob.sk, &ciphertext_b, N);
    let recovered_b_coeffs: Vec<u64> = recovered_b
        .coefficients()
        .iter()
        .take(N)
        .map(|&c| c % P)
        .collect();

    assert_eq!(
        recovered_b_coeffs,
        expected_coeffs,
        "Bob could not recover M*g after reshuffle + A->B"
    );
    println!("[4] Bob decrypts = M*g");
    println!("    OK");

    let rekey_bc = generate_rekey(
        &mut rng,
        &bob.sk,
        &carol.pk,
        BASE_BITS,
    );
    let ciphertext_c = reencrypt(
        &ciphertext_b,
        &rekey_bc,
        BASE_BITS,
    );
    println!("[5] B -> C key switching applied");

    let recovered_c = decrypt_poly(&carol.sk, &ciphertext_c, N);
    let recovered_c_coeffs: Vec<u64> = recovered_c
        .coefficients()
        .iter()
        .take(N)
        .map(|&c| c % P)
        .collect();

    assert_eq!(
        recovered_c_coeffs,
        expected_coeffs,
        "Carol could not recover M*g after reshuffle + A->B->C"
    );

    println!("[6] Carol decrypts after second hop");
    println!("    Recovered[0..16] = {:?}", &recovered_c_coeffs[..16]);
    println!("    Expected[0..16]  = {:?}", &expected_coeffs[..16]);
    println!("    OK");

    println!("==============================================");
    println!("    RESHUFFLE + 2-HOP REKEY TEST: OK");
    println!("==============================================");
}

#[test]
fn test_multiple_ids_reshuffle_correctness() {
    use pq_libpep::algebra::ring::PolyRq;
    use pq_libpep::core::id_encoding::{bytes_to_bits, string_to_id};
    use pq_libpep::core::params::{prf_modulus_chain, Q0, RING_DIMENSION};
    use pq_libpep::core::pseudonym::pseudonymize_32;
    use pq_libpep::core::reshuffle::{lift_prf_output_to_q, reshuffle};
    use pq_libpep::core::rlwe::KeyGenResult;
    use pq_libpep::core::rlwe_pke::{decrypt_poly, encrypt_poly};
    use pq_libpep::core::rlwr_prf::{RlwrPrf, RlwrPrfBase};
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    const N: usize = RING_DIMENSION;
    const Q: u64 = 998_244_353;
    const P: u64 = Q0;

    let ids = [
        "patient-001",
        "patient-002",
        "patient-003",
        "patient-010",
        "patient-100",
        "user-alpha",
        "user-beta",
        "research-subject-01",
    ];

    // One PRF key/material is reused for all identifiers.
    let mut prf_rng = StdRng::seed_from_u64(42);
    let chain = prf_modulus_chain();
    let highest_modulus = *chain.last().unwrap();
    let base = RlwrPrfBase::sample(
        &mut prf_rng,
        N,
        highest_modulus,
        256,
    );
    let prf = RlwrPrf::new(base, chain);

    let mut rng = StdRng::seed_from_u64(9001);
    let keygen = KeyGenResult::keygen(&mut rng, N);

    println!("==============================================");
    println!("   PQPEP MULTI-ID RESHUFFLE TEST");
    println!("==============================================");

    for input in ids {
        let id = string_to_id(input);
        let bits = bytes_to_bits(&id);
        assert_eq!(id.len(), 32);
        assert_eq!(bits.len(), 256);
        assert!(bits.iter().all(|&b| b == 0 || b == 1));

        let message_coeffs: Vec<u64> = bits.iter().map(|&b| b as u64).collect();
        let message_p = PolyRq::from_coeffs(&message_coeffs, N, P);
        let message_q = PolyRq::from_coeffs(&message_coeffs, N, Q);

        let g17 = pseudonymize_32(&prf, &id);
        let gq = lift_prf_output_to_q(&g17, Q);

        let ciphertext = encrypt_poly(&mut rng, &keygen.pk, &message_q, N);
        let reshuffled = reshuffle(&ciphertext, &gq);

        let recovered = decrypt_poly(&keygen.sk, &reshuffled, N);
        let recovered_coeffs: Vec<u64> = recovered
            .coefficients()
            .iter()
            .take(N)
            .map(|&c| c % P)
            .collect();

        let g17_for_expected = PolyRq::from_coeffs(
            &g17.coefficients()[..N],
            N,
            P,
        );
        let expected = message_p.mul_negacyclic(&g17_for_expected);
        let expected_coeffs: Vec<u64> = expected
            .coefficients()
            .iter()
            .take(N)
            .map(|&c| c % P)
            .collect();

        assert_eq!(
            recovered_coeffs,
            expected_coeffs,
            "reshuffle mismatch for ID {}",
            input
        );

        println!("ID = {:<20} -> reshuffle OK", input);
    }

    println!("==============================================");
    println!("    MULTI-ID RESHUFFLE TEST: OK");
    println!("==============================================");
}

#[test]
fn test_full_id_noise_growth_composed() {
    use pq_libpep::algebra::ring::PolyRq;
    use pq_libpep::core::id_encoding::{bytes_to_bits, string_to_id};
    use pq_libpep::core::params::{
        prf_modulus_chain,
        Q0,
        RING_DIMENSION,
    };
    use pq_libpep::core::pseudonym::pseudonymize_32;
    use pq_libpep::core::reshuffle::{
        lift_prf_output_to_q,
        reshuffle,
    };
    use pq_libpep::core::rlwe::KeyGenResult;
    use pq_libpep::core::rlwe_pke::{
        decrypt_poly,
        encrypt_poly,
    };
    use pq_libpep::core::rlwe_pre::{
        generate_rekey,
        reencrypt,
    };
    use pq_libpep::core::rlwr_prf::{
        RlwrPrf,
        RlwrPrfBase,
    };
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    const N: usize = RING_DIMENSION;
    const Q: u64 = 998_244_353;
    const P: u64 = Q0;
    const BASE_BITS: usize = 4;
    const DELTA: u64 = Q / P;
    const DECODING_BOUNDARY: u64 = Q / 4;

    println!("==============================================================");
    println!("       PQPEP COMPOSED NOISE GROWTH TEST");
    println!("==============================================================");
    println!("Ring dimension N        = {}", N);
    println!("RLWE modulus Q          = {}", Q);
    println!("Plaintext modulus P     = {}", P);
    println!("Delta = floor(Q/P)      = {}", DELTA);
    println!("Key-switch base         = {}", 1u64 << BASE_BITS);
    println!("Decoding boundary Q/4   = {}", DECODING_BOUNDARY);
    println!();

    // ------------------------------------------------------------
    // 1. USER IDENTIFIER -> MESSAGE M
    // ------------------------------------------------------------
    let input = "patient-001";
    let id = string_to_id(input);
    let bits = bytes_to_bits(&id);

    assert_eq!(id.len(), 32);
    assert_eq!(bits.len(), 256);
    assert!(bits.iter().all(|&b| b == 0 || b == 1));

    let message_coeffs: Vec<u64> =
        bits.iter().map(|&b| b as u64).collect();

    let message_p =
        PolyRq::from_coeffs(&message_coeffs, N, P);

    let message_q =
        PolyRq::from_coeffs(&message_coeffs, N, Q);

    println!("[1] User identifier");
    println!("    ID = {}", input);

    // ------------------------------------------------------------
    // 2. ID -> PRF -> g17 -> gq
    // ------------------------------------------------------------
    let mut prf_rng = StdRng::seed_from_u64(42);

    let chain = prf_modulus_chain();
    let highest_modulus = *chain.last().unwrap();

    let base = RlwrPrfBase::sample(
        &mut prf_rng,
        N,
        highest_modulus,
        256,
    );

    let prf = RlwrPrf::new(base, chain);

    let g17 = pseudonymize_32(&prf, &id);

    assert_eq!(g17.modulus(), P);
    assert_eq!(g17.degree_bound(), N);

    let gq = lift_prf_output_to_q(&g17, Q);

    assert_eq!(gq.modulus(), Q);
    assert_eq!(gq.degree_bound(), N);

    println!("[2] ID -> Ring-LWR PRF -> lift");
    println!(
        "    g17[0..16] = {:?}",
        &g17.coefficients()[..16]
    );
    println!(
        "    gq[0..16]  = {:?}",
        &gq.coefficients()[..16]
    );

    // ------------------------------------------------------------
    // 3. EXPECTED RESHUFFLED PLAINTEXT M*g mod P
    // ------------------------------------------------------------
    let expected_p =
        message_p.mul_negacyclic(&g17);

    let expected_p_coeffs: Vec<u64> = expected_p
        .coefficients()
        .iter()
        .take(N)
        .map(|&c| c % P)
        .collect();

    // Convert M*g from R_P into the scaled RLWE plaintext
    // representation Delta * (M*g).
    let expected_q_coeffs: Vec<u64> = expected_p_coeffs
        .iter()
        .map(|&c| (c * DELTA) % Q)
        .collect();

    let expected_q =
        PolyRq::from_coeffs(
            &expected_q_coeffs,
            N,
            Q,
        );

    // Original plaintext expected by RLWE encryption:
    let original_q_coeffs: Vec<u64> = message_coeffs
        .iter()
        .map(|&c| (c * DELTA) % Q)
        .collect();

    let original_expected_q =
        PolyRq::from_coeffs(
            &original_q_coeffs,
            N,
            Q,
        );

    // ------------------------------------------------------------
    // 4. HELPER: MEASURE CENTERED DECRYPTION NOISE
    // ------------------------------------------------------------
    let compute_noise =
        |u: &PolyRq,
         v: &PolyRq,
         s: &PolyRq,
         expected: &PolyRq|
         -> (u64, f64) {
            // RLWE phase:
            //
            //     v - u*s
            //
            // which should equal:
            //
            //     Delta*M + noise
            //
            // or, after reshuffling/re-keying:
            //
            //     Delta*(M*g) + noise
            let phase =
                v.sub(&u.mul_negacyclic(s));

            let residual =
                phase.sub(expected);

            let mut max_noise = 0u64;
            let mut sum_noise = 0f64;

            for &c in residual
                .coefficients()
                .iter()
                .take(N)
            {
                let c = c % Q;

                // Convert modular coefficient to centered representative.
                let abs_noise =
                    if c <= Q / 2 {
                        c
                    } else {
                        Q - c
                    };

                if abs_noise > max_noise {
                    max_noise = abs_noise;
                }

                sum_noise += abs_noise as f64;
            }

            let avg_noise =
                sum_noise / N as f64;

            (max_noise, avg_noise)
        };

    // ------------------------------------------------------------
    // 5. KEY GENERATION
    // ------------------------------------------------------------
    let mut rng = StdRng::seed_from_u64(7777);

    let alice =
        KeyGenResult::keygen(&mut rng, N);

    let bob =
        KeyGenResult::keygen(&mut rng, N);

    let carol =
        KeyGenResult::keygen(&mut rng, N);

    println!("[3] Alice, Bob and Carol key pairs generated");

    // ------------------------------------------------------------
    // 6. ENCRYPTION
    // ------------------------------------------------------------
    let ciphertext_a =
        encrypt_poly(
            &mut rng,
            &alice.pk,
            &message_q,
            N,
        );

    let (noise_a_max, noise_a_avg) =
        compute_noise(
            &ciphertext_a.u,
            &ciphertext_a.v,
            &alice.sk.s,
            &original_expected_q,
        );

    println!("[4] Encryption");
    println!(
        "    A                 : max = {:>10}, avg = {:>10.2}",
        noise_a_max,
        noise_a_avg
    );

    assert!(
        noise_a_max < DECODING_BOUNDARY,
        "encryption noise exceeds decoding boundary"
    );

    // ------------------------------------------------------------
    // 7. RESHUFFLE
    // ------------------------------------------------------------
    let ciphertext_r =
        reshuffle(
            &ciphertext_a,
            &gq,
        );

    let (noise_r_max, noise_r_avg) =
        compute_noise(
            &ciphertext_r.u,
            &ciphertext_r.v,
            &alice.sk.s,
            &expected_q,
        );

    println!("[5] Reshuffle");
    println!(
        "    Reshuffled A       : max = {:>10}, avg = {:>10.2}",
        noise_r_max,
        noise_r_avg
    );

    assert!(
        noise_r_max < DECODING_BOUNDARY,
        "reshuffle noise exceeds decoding boundary"
    );

    // ------------------------------------------------------------
    // 8. A -> B
    // ------------------------------------------------------------
    let rekey_ab =
        generate_rekey(
            &mut rng,
            &alice.sk,
            &bob.pk,
            BASE_BITS,
        );

    let ciphertext_b =
        reencrypt(
            &ciphertext_r,
            &rekey_ab,
            BASE_BITS,
        );

    let (noise_b_max, noise_b_avg) =
        compute_noise(
            &ciphertext_b.u,
            &ciphertext_b.v,
            &bob.sk.s,
            &expected_q,
        );

    println!("[6] ReKey A -> B");
    println!(
        "    A -> B            : max = {:>10}, avg = {:>10.2}",
        noise_b_max,
        noise_b_avg
    );

    assert!(
        noise_b_max < DECODING_BOUNDARY,
        "A -> B noise exceeds decoding boundary"
    );

    // ------------------------------------------------------------
    // 9. B -> C
    // ------------------------------------------------------------
    let rekey_bc =
        generate_rekey(
            &mut rng,
            &bob.sk,
            &carol.pk,
            BASE_BITS,
        );

    let ciphertext_c =
        reencrypt(
            &ciphertext_b,
            &rekey_bc,
            BASE_BITS,
        );

    let (noise_c_max, noise_c_avg) =
        compute_noise(
            &ciphertext_c.u,
            &ciphertext_c.v,
            &carol.sk.s,
            &expected_q,
        );

    println!("[7] ReKey B -> C");
    println!(
        "    A -> B -> C       : max = {:>10}, avg = {:>10.2}",
        noise_c_max,
        noise_c_avg
    );

    assert!(
        noise_c_max < DECODING_BOUNDARY,
        "B -> C noise exceeds decoding boundary"
    );

    // ------------------------------------------------------------
    // 10. FINAL DECRYPTION
    // ------------------------------------------------------------
    let recovered =
        decrypt_poly(
            &carol.sk,
            &ciphertext_c,
            N,
        );

    let recovered_coeffs: Vec<u64> =
        recovered
            .coefficients()
            .iter()
            .take(N)
            .map(|&c| c % P)
            .collect();

    assert_eq!(
        recovered_coeffs,
        expected_p_coeffs,
        "final plaintext does not match M*g mod P"
    );

    println!("[8] Final decryption");
    println!(
        "    Recovered[0..16] = {:?}",
        &recovered_coeffs[..16]
    );
    println!(
        "    Expected[0..16]  = {:?}",
        &expected_p_coeffs[..16]
    );
    println!("    OK");

    // ------------------------------------------------------------
    // 11. SUMMARY
    // ------------------------------------------------------------
    println!();
    println!("==============================================================");
    println!("                    NOISE SUMMARY");
    println!("==============================================================");
    println!(
        "A                 : max = {:>10}, avg = {:>10.2}",
        noise_a_max,
        noise_a_avg
    );
    println!(
        "Reshuffled A      : max = {:>10}, avg = {:>10.2}",
        noise_r_max,
        noise_r_avg
    );
    println!(
        "A -> B            : max = {:>10}, avg = {:>10.2}",
        noise_b_max,
        noise_b_avg
    );
    println!(
        "A -> B -> C       : max = {:>10}, avg = {:>10.2}",
        noise_c_max,
        noise_c_avg
    );
    println!();
    println!(
        "Decoding boundary Q/4 = {}",
        DECODING_BOUNDARY
    );
    println!("All stages below decoding boundary: OK");
    println!("==============================================================");
    println!("      PQPEP COMPOSED NOISE GROWTH TEST: OK");
    println!("==============================================================");
}


#[test]
fn test_prf_factors_are_invertible() {
    use pq_libpep::core::id_encoding::string_to_id;
    use pq_libpep::core::params::{
        prf_modulus_chain,
        Q0,
        RING_DIMENSION,
    };
    use pq_libpep::core::pseudonym::pseudonymize_32;
    use pq_libpep::core::rlwr_prf::{
        RlwrPrf,
        RlwrPrfBase,
    };

    use rand::rngs::StdRng;
    use rand::SeedableRng;

    const N: usize = RING_DIMENSION;
    const P: i64 = Q0 as i64;

    // ------------------------------------------------------------
    // Polynomial helpers over F_17
    // ------------------------------------------------------------

    fn mod_p(x: i64, p: i64) -> i64 {
        let r = x % p;
        if r < 0 {
            r + p
        } else {
            r
        }
    }

    fn trim(mut a: Vec<i64>, p: i64) -> Vec<i64> {
        for x in &mut a {
            *x = mod_p(*x, p);
        }

        while a.len() > 1 && *a.last().unwrap() == 0 {
            a.pop();
        }

        if a.is_empty() {
            vec![0]
        } else {
            a
        }
    }

    fn mod_inv(a: i64, p: i64) -> i64 {
        let mut t = 0i64;
        let mut new_t = 1i64;
        let mut r = p;
        let mut new_r = mod_p(a, p);

        while new_r != 0 {
            let quotient = r / new_r;

            let temp_t = t - quotient * new_t;
            t = new_t;
            new_t = temp_t;

            let temp_r = r - quotient * new_r;
            r = new_r;
            new_r = temp_r;
        }

        assert_eq!(
            r, 1,
            "coefficient {} has no inverse modulo {}",
            a, p
        );

        mod_p(t, p)
    }

    fn polynomial_remainder(
        mut a: Vec<i64>,
        b: &[i64],
        p: i64,
    ) -> Vec<i64> {
        a = trim(a, p);
        let b = trim(b.to_vec(), p);

        if b.len() == 1 && b[0] == 0 {
            panic!("division by zero polynomial");
        }

        if a.len() < b.len() {
            return a;
        }

        let inv_leading = mod_inv(*b.last().unwrap(), p);

        while !(a.len() == 1 && a[0] == 0)
            && a.len() >= b.len()
        {
            let shift = a.len() - b.len();

            let leading = *a.last().unwrap();
            let factor =
                mod_p(leading * inv_leading, p);

            for i in 0..b.len() {
                let index = i + shift;

                a[index] =
                    mod_p(a[index] - factor * b[i], p);
            }

            a = trim(a, p);
        }

        a
    }

    fn polynomial_gcd(
        mut a: Vec<i64>,
        mut b: Vec<i64>,
        p: i64,
    ) -> Vec<i64> {
        a = trim(a, p);
        b = trim(b, p);

        while !(b.len() == 1 && b[0] == 0) {
            let r =
                polynomial_remainder(a, &b, p);
            a = b;
            b = r;
        }

        // Normalize gcd to monic form.
        a = trim(a, p);

        if a.len() == 1 && a[0] == 0 {
            return a;
        }

        let inv_leading =
            mod_inv(*a.last().unwrap(), p);

        for x in &mut a {
            *x =
                mod_p(*x * inv_leading, p);
        }

        trim(a, p)
    }

    // ------------------------------------------------------------
    // Build deterministic PRF
    // ------------------------------------------------------------

    let mut rng =
        StdRng::seed_from_u64(42);

    let chain = prf_modulus_chain();
    let highest_modulus =
        *chain.last().unwrap();

    let base =
        RlwrPrfBase::sample(
            &mut rng,
            N,
            highest_modulus,
            256,
        );

    let prf =
        RlwrPrf::new(base, chain);

    // ------------------------------------------------------------
    // Modulus polynomial X^N + 1
    //
    // coeffs:
    // [1, 0, 0, ..., 0, 1]
    // ------------------------------------------------------------

    let mut modulus_poly =
        vec![0i64; N + 1];

    modulus_poly[0] = 1;
    modulus_poly[N] = 1;

    let ids = [
        "patient-001",
        "patient-002",
        "patient-003",
        "patient-010",
        "patient-100",
        "user-alpha",
        "user-beta",
        "research-subject-01",
    ];

    println!("==============================================================");
    println!("       PRF FACTOR INVERTIBILITY TEST");
    println!("==============================================================");
    println!("Ring: Z_17[X] / (X^{} + 1)", N);
    println!();

    for input in ids {
        let id =
            string_to_id(input);

        let g =
            pseudonymize_32(
                &prf,
                &id,
            );

        let g_coeffs: Vec<i64> =
            g.coefficients()
                .iter()
                .take(N)
                .map(|&c| mod_p(c as i64, P))
                .collect();

        let is_zero =
            g_coeffs.iter().all(|&c| c == 0);

        assert!(
            !is_zero,
            "PRF factor for {} is the zero polynomial",
            input
        );

        let gcd =
            polynomial_gcd(
                g_coeffs.clone(),
                modulus_poly.clone(),
                P,
            );

        let invertible =
            gcd.len() == 1
                && gcd[0] == 1;

        println!(
            "{:<24} -> non-zero: {:<5}  gcd degree: {:<3}  invertible: {}",
            input,
            !is_zero,
            gcd.len() - 1,
            invertible
        );

        assert!(
            invertible,
            "PRF factor for {} is not invertible in R_17",
            input
        );
    }

    println!();
    println!("==============================================================");
    println!("      ALL TESTED PRF FACTORS ARE INVERTIBLE: OK");
    println!("==============================================================");
}

#[test]
fn test_reshuffle_noise_vs_prf_factor() {
    use pq_libpep::algebra::ring::PolyRq;
    use pq_libpep::core::id_encoding::{
        bytes_to_bits,
        string_to_id,
    };
    use pq_libpep::core::params::{
        prf_modulus_chain,
        Q0,
        RING_DIMENSION,
    };
    use pq_libpep::core::pseudonym::pseudonymize_32;
    use pq_libpep::core::reshuffle::{
        lift_prf_output_to_q,
        reshuffle,
    };
    use pq_libpep::core::rlwe::KeyGenResult;
    use pq_libpep::core::rlwe_pke::{
        decrypt_poly,
        encrypt_poly,
        Ciphertext,
    };
    use pq_libpep::core::rlwr_prf::{
        RlwrPrf,
        RlwrPrfBase,
    };

    use rand::rngs::StdRng;
    use rand::SeedableRng;

    const N: usize = RING_DIMENSION;
    const Q: u64 = 998_244_353;
    const P: u64 = Q0;
    const DELTA: u64 = Q / P;
    const DECODING_BOUNDARY: u64 = Q / 4;

    // ------------------------------------------------------------
    // Measure centered RLWE noise.
    //
    // phase = v - u*s
    //
    // noise = phase - expected_plaintext
    // ------------------------------------------------------------
    fn measure_noise(
        ciphertext: &Ciphertext,
        secret: &PolyRq,
        expected_plaintext_q: &PolyRq,
    ) -> (u64, f64) {
        let phase = ciphertext
            .v
            .sub(&ciphertext.u.mul_negacyclic(secret));

        let residual =
            phase.sub(expected_plaintext_q);

        let mut max_noise = 0u64;
        let mut sum_noise = 0f64;

        for &c in residual
            .coefficients()
            .iter()
            .take(N)
        {
            let c = c % Q;

            // Center the modular representative in
            // approximately [-Q/2, Q/2].
            let abs_noise =
                if c <= Q / 2 {
                    c
                } else {
                    Q - c
                };

            max_noise =
                max_noise.max(abs_noise);

            sum_noise += abs_noise as f64;
        }

        (
            max_noise,
            sum_noise / N as f64,
        )
    }

    fn normalized_coeffs(
        poly: &PolyRq,
        modulus: u64,
    ) -> Vec<u64> {
        poly.coefficients()
            .iter()
            .take(N)
            .map(|&c| c % modulus)
            .collect()
    }

    // ------------------------------------------------------------
    // 1. Fixed plaintext
    // ------------------------------------------------------------
    let message_input = "patient-001";

    let message_id =
        string_to_id(message_input);

    let bits =
        bytes_to_bits(&message_id);

    assert_eq!(message_id.len(), 32);
    assert_eq!(bits.len(), 256);

    let message_coeffs: Vec<u64> =
        bits.iter()
            .map(|&b| b as u64)
            .collect();

    let message_p =
        PolyRq::from_coeffs(
            &message_coeffs,
            N,
            P,
        );

    let message_q =
        PolyRq::from_coeffs(
            &message_coeffs,
            N,
            Q,
        );

    // ------------------------------------------------------------
    // 2. One deterministic PRF
    // ------------------------------------------------------------
    let mut prf_rng =
        StdRng::seed_from_u64(42);

    let chain =
        prf_modulus_chain();

    let highest_modulus =
        *chain.last().unwrap();

    let base =
        RlwrPrfBase::sample(
            &mut prf_rng,
            N,
            highest_modulus,
            256,
        );

    let prf =
        RlwrPrf::new(
            base,
            chain,
        );

    // ------------------------------------------------------------
    // 3. One fixed RLWE ciphertext
    //
    // IMPORTANT:
    // the ciphertext is identical for every factor.
    // This isolates the effect of g.
    // ------------------------------------------------------------
    let mut rng =
        StdRng::seed_from_u64(7777);

    let keygen =
        KeyGenResult::keygen(
            &mut rng,
            N,
        );

    let ciphertext =
        encrypt_poly(
            &mut rng,
            &keygen.pk,
            &message_q,
            N,
        );

    // Expected plaintext contribution BEFORE reshuffle:
    // Delta * M
    let original_expected_q_coeffs: Vec<u64> =
        message_coeffs
            .iter()
            .map(|&c| {
                (c as u128
                    * DELTA as u128
                    % Q as u128) as u64
            })
            .collect();

    let original_expected_q =
        PolyRq::from_coeffs(
            &original_expected_q_coeffs,
            N,
            Q,
        );

    let (original_max_noise, original_avg_noise) =
        measure_noise(
            &ciphertext,
            &keygen.sk.s,
            &original_expected_q,
        );

    println!("==============================================================");
    println!("       RESHUFFLE NOISE VS PRF FACTOR");
    println!("==============================================================");
    println!("Fixed plaintext ID = {}", message_input);
    println!("Ring dimension     = {}", N);
    println!("RLWE modulus Q     = {}", Q);
    println!("Plaintext modulus  = {}", P);
    println!("Decoding boundary  = {}", DECODING_BOUNDARY);
    println!();
    println!(
        "Original ciphertext: max = {}, avg = {:.2}",
        original_max_noise,
        original_avg_noise
    );
    println!();

    assert!(
        original_max_noise < DECODING_BOUNDARY,
        "original ciphertext already exceeds decoding boundary"
    );

    // ------------------------------------------------------------
    // 4. Different PRF inputs -> different factors
    // ------------------------------------------------------------
    let factor_inputs = [
        "patient-001",
        "patient-002",
        "patient-003",
        "patient-010",
        "patient-100",
        "user-alpha",
        "user-beta",
        "research-subject-01",
    ];

    println!(
        "{:<24} {:>15} {:>15} {:>15} {:>10}",
        "Factor source ID",
        "g max coeff",
        "Noise max",
        "Noise avg",
        "Decrypt",
    );

    println!(
        "--------------------------------------------------------------------------"
    );

    for factor_input in factor_inputs {
        // --------------------------------------------------------
        // Compute g = PRF(ID)
        // --------------------------------------------------------
        let factor_id =
            string_to_id(factor_input);

        let g17 =
            pseudonymize_32(
                &prf,
                &factor_id,
            );

        assert_eq!(
            g17.modulus(),
            P
        );
        assert_eq!(
            g17.degree_bound(),
            N
        );

        let gq =
            lift_prf_output_to_q(
                &g17,
                Q,
            );

        // --------------------------------------------------------
        // Reshuffle the SAME ciphertext
        // --------------------------------------------------------
        let reshuffled =
            reshuffle(
                &ciphertext,
                &gq,
            );

        // --------------------------------------------------------
        // Expected plaintext after reshuffle:
        //
        //     M' = M * g mod P
        //
        // represented in RLWE as:
        //
        //     Delta * M'
        // --------------------------------------------------------
        let expected_p =
            message_p.mul_negacyclic(
                &g17,
            );

        let expected_p_coeffs =
            normalized_coeffs(
                &expected_p,
                P,
            );

        let expected_q_coeffs: Vec<u64> =
            expected_p_coeffs
                .iter()
                .map(|&c| {
                    (c as u128
                        * DELTA as u128
                        % Q as u128) as u64
                })
                .collect();

        let expected_q =
            PolyRq::from_coeffs(
                &expected_q_coeffs,
                N,
                Q,
            );

        // --------------------------------------------------------
        // Measure reshuffled noise
        // --------------------------------------------------------
        let (
            reshuffled_max_noise,
            reshuffled_avg_noise,
        ) =
            measure_noise(
                &reshuffled,
                &keygen.sk.s,
                &expected_q,
            );

        // Largest coefficient of g for display only.
        let g_max_coeff =
            g17
                .coefficients()
                .iter()
                .take(N)
                .copied()
                .max()
                .unwrap_or(0);

        // --------------------------------------------------------
        // Check correctness
        // --------------------------------------------------------
        let recovered =
            decrypt_poly(
                &keygen.sk,
                &reshuffled,
                N,
            );

        let recovered_coeffs =
            normalized_coeffs(
                &recovered,
                P,
            );

        let decrypt_ok =
            recovered_coeffs
                == expected_p_coeffs;

        assert!(
            decrypt_ok,
            "decryption failed for factor source ID {}",
            factor_input
        );

        assert!(
            reshuffled_max_noise
                < DECODING_BOUNDARY,
            "noise exceeded decoding boundary for factor source ID {}",
            factor_input
        );

        println!(
            "{:<24} {:>15} {:>15} {:>15.2} {:>10}",
            factor_input,
            g_max_coeff,
            reshuffled_max_noise,
            reshuffled_avg_noise,
            "OK",
        );
    }

    println!();
    println!("==============================================================");
    println!("Observation:");
    println!(
        "  The RLWE ciphertext and plaintext were fixed."
    );
    println!(
        "  Only the PRF-derived reshuffling factor g was changed."
    );
    println!(
        "  The experiment therefore measures factor-dependent noise growth."
    );
    println!("==============================================================");
    println!(
        "       RESHUFFLE NOISE VS PRF FACTOR: OK"
    );
    println!("==============================================================");
}