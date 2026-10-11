use pq_libpep::algebra::ring::PolyRq;
use pq_libpep::core::id_encoding::string_to_id;
use pq_libpep::core::params::{
    prf_modulus_chain,
    RING_DIMENSION,
};
use pq_libpep::core::pseudonym::pseudonymize_32;
use pq_libpep::core::reshuffle::{
    derive_reshuffle_factor,
    lift_prf_output_to_q,
};
use pq_libpep::core::rlwr_prf::{
    RlwrPrf,
    RlwrPrfBase,
};

use rand::rngs::StdRng;
use rand::SeedableRng;

const Q: u64 = 998_244_353;
const P: u64 = 17;
const N: usize = RING_DIMENSION;

fn test_prf() -> RlwrPrf {
    let mut rng = StdRng::seed_from_u64(42);

    let chain = prf_modulus_chain();
    let highest_modulus = *chain.last().unwrap();

    let base = RlwrPrfBase::sample(
        &mut rng,
        N,
        highest_modulus,
        256,
    );

    RlwrPrf::new(base, chain)
}

#[test]
fn test_domain_to_reshuffle_factor_e2e() {
    println!();
    println!("==============================================================");
    println!(" TEST 1: DOMAIN -> PRF -> RESHUFFLING FACTOR");
    println!("==============================================================");

    let prf = test_prf();

    
    let domain_a = "hospital-A";
    let domain_b = "hospital-B";

    println!("Domain A = {}", domain_a);
    println!("Domain B = {}", domain_b);
    println!();

    // Convert each domain name into a fixed 32-byte identifier.
    // This identifier is then encoded as 256 bits before PRF evaluation.
    let id_a = string_to_id(domain_a);
    let id_b = string_to_id(domain_b);
    println!("ID A first 32 bytes : {:02x?}", &id_a[..32]);
    println!("ID B first 32 bytes : {:02x?}", &id_b[..32]);
    println!();

    // Evaluate the Ring-LWR PRF on the two domain identifiers.
    // Different inputs should produce different polynomial outputs.
    let prf_a = pseudonymize_32(&prf, &id_a);
    let prf_b = pseudonymize_32(&prf, &id_b);

    println!(
        "PRF A first 32 coefficients (poly) : {:?}",
        &prf_a.coefficients()[..32]
    );

    println!(
        "PRF B first 32 coefficients (poly) : {:?}",
        &prf_b.coefficients()[..32]
    );

    assert_ne!(
        prf_a,
        prf_b,
        "different domains must produce different PRF outputs"
    );

    println!();
    println!("PRF outputs are different: OK");

    // Derive the actual reshuffling factors in R_q from the PRF outputs.
    // The factor is domain-dependent, so two different domains must produce
    // different factors while remaining valid for the RLWE ciphertext modulus.
    let g_a = derive_reshuffle_factor(
        &prf,
        domain_a,
        N,
        Q,
    );

    let g_b = derive_reshuffle_factor(
        &prf,
        domain_b,
        N,
        Q,
    );

    println!();
    println!(
        "g_A first 32 coefficients : {:?}",
        &g_a.coefficients()[..32]
    );

    println!(
        "g_B first 32 coefficients : {:?}",
        &g_b.coefficients()[..32]
    );

    assert_eq!(g_a.modulus(), Q);
    assert_eq!(g_b.modulus(), Q);

    assert_ne!(
        g_a,
        g_b,
        "different domains must produce different reshuffling factors"
    );

    println!();
    println!("Reshuffling factors are different: OK");
    println!("==============================================================");
}
// weak and useless, different IDs in different domains -> different reshuffling factors, but no guarantee that same ID in different domains -> different factors

#[test]
fn test_full_prf_derived_reshuffle() {
    use pq_libpep::algebra::ring::PolyRq;
    use pq_libpep::core::id_encoding::string_to_id;
    use pq_libpep::core::pseudonym::pseudonymize_32;
    use pq_libpep::core::rlwe::KeyGenResult;
    use pq_libpep::core::rlwe_pke::{decrypt_poly, encrypt_poly};
    use pq_libpep::core::rlwr_prf::{RlwrPrf, RlwrPrfBase};
    use pq_libpep::core::reshuffle::{derive_reshuffle_factor, reshuffle};
    use rand::thread_rng;

    const N: usize = 256;
    const P: u64 = 17;
    const Q: u64 = 998_244_353;

    println!("\n==============================================================");
    println!(" TEST 3: FULL PRF-DERIVED RESHUFFLING");
    println!("==============================================================");

    let mut rng = thread_rng();

    let moduli = vec![
        17u64,
        289,
        4_913,
        83_521,
        1_419_857,
        24_137_569,
        410_338_673,
        6_975_757_441,
        118_587_876_497,
    ];

    let base = RlwrPrfBase::sample(
        &mut rng,
        N,
        *moduli.last().unwrap(),
        1 << (moduli.len() - 1),
    );

    let prf = RlwrPrf::new(base, moduli);

    // ----------------------------------------------------------
    // 1. Domain -> ID -> PRF output
    // ----------------------------------------------------------

    let domain = "hospital-A";
    let id = string_to_id(domain);

    let prf_output = pseudonymize_32(&prf, &id);

    println!("\n[1] DOMAIN -> PRF");
    println!("Domain                  : {}", domain);
    println!(
        "PRF output modulus      : {}",
        prf_output.modulus()
    );
    println!(
        "PRF output first 16     : {:?}",
        &prf_output.coefficients()[..16]
    );

    // ----------------------------------------------------------
    // 2. Lift PRF output R17 -> Rq
    // ----------------------------------------------------------

    let factor = derive_reshuffle_factor(&prf, domain, N, Q);

    println!("\n[2] LIFT: R17 -> Rq");
    println!(
        "Lifted factor modulus   : {}",
        factor.modulus()
    );
    println!(
        "Lifted factor first 16  : {:?}",
        &factor.coefficients()[..16]
    );

    // ----------------------------------------------------------
    // 3. Create plaintext
    // ----------------------------------------------------------

    let message_coeffs: Vec<u64> = (0..N)
        .map(|i| {
            (7 * i as u64 * i as u64 + 11 * i as u64 + 3) % P
        })
        .collect();

    let message = PolyRq::from_coeffs(
        &message_coeffs,
        N,
        Q,
    );

    println!("\n[3] PLAINTEXT");
    println!("Plaintext modulus       : {}", P);
    println!(
        "Plaintext first 16      : {:?}",
        &message_coeffs[..16]
    );

    // ----------------------------------------------------------
    // 4. Encrypt
    // ----------------------------------------------------------

    let keygen = KeyGenResult::keygen(&mut rng, N);

    let ciphertext = encrypt_poly(
        &mut rng,
        &keygen.pk,
        &message,
        N,
    );

    println!("\n[4] RLWE ENCRYPTION");
    println!(
        "Ciphertext u first 4    : {:?}",
        &ciphertext.u.coefficients()[..4]
    );
    println!(
        "Ciphertext v first 4    : {:?}",
        &ciphertext.v.coefficients()[..4]
    );

    // ----------------------------------------------------------
    // 5. Apply reshuffle to ciphertext
    // ----------------------------------------------------------

    let reshuffled = reshuffle(
        &ciphertext,
        &factor,
    );

    println!("\n[5] RESHUFFLE");
    println!(
        "Operation               : (u, v) -> (u * g, v * g)"
    );
    println!(
        "Reshuffled u first 4    : {:?}",
        &reshuffled.u.coefficients()[..4]
    );
    println!(
        "Reshuffled v first 4    : {:?}",
        &reshuffled.v.coefficients()[..4]
    );

    // ----------------------------------------------------------
    // 6. Decrypt reshuffled ciphertext
    // ----------------------------------------------------------

    let recovered = decrypt_poly(
        &keygen.sk,
        &reshuffled,
        N,
    );

    println!("\n[6] DECRYPT RESHUFFLED CIPHERTEXT");
    println!(
        "Recovered first 16      : {:?}",
        &recovered.coefficients()[..16]
    );

    // ----------------------------------------------------------
    // 7. Compute expected plaintext M * g mod 17
    // ----------------------------------------------------------

    let message_p = PolyRq::from_coeffs(
        &message_coeffs,
        N,
        P,
    );

    let factor_p_coeffs: Vec<u64> = factor
        .coefficients()
        .iter()
        .take(N)
        .map(|&c| c % P)
        .collect();

    let factor_p = PolyRq::from_coeffs(
        &factor_p_coeffs,
        N,
        P,
    );

    let expected = message_p.mul_negacyclic(&factor_p);

    println!("\n[7] EXPECTED RESULT");
    println!(
        "Expected = M * g mod {}",
        P
    );
    println!(
        "Expected first 16      : {:?}",
        &expected.coefficients()[..16]
    );

    // ----------------------------------------------------------
    // 8. Compare expected vs recovered
    // ----------------------------------------------------------

    let expected_coeffs = expected.coefficients();
    let recovered_coeffs = recovered.coefficients();

    let mut mismatches = 0usize;

    for i in 0..N {
        if expected_coeffs[i] != recovered_coeffs[i] {
            mismatches += 1;
        }
    }

    println!("\n[8] VERIFICATION");
    println!(
        "Coefficient mismatches : {} / {}",
        mismatches, N
    );

    assert_eq!(
        mismatches,
        0,
        "reshuffled plaintext does not match M * g mod 17"
    );

    println!("Verification            : OK");
    println!("Full PRF-derived reshuffling: OK");
    println!("==============================================================");
}