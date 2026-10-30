#![cfg(feature = "fast-prf-tfhe-private-input")]

//! Experimental hybrid end-to-end test for PQlibPEP.
//!
//! Branch A: canonical 32-byte identifier -> private-input depth-1 LWR PRF
//!          (TFHE ciphertexts over the wire) -> 32-byte pseudonym at recipient B.
//! Branch B: an application payload encrypted under RLWE key A -> proxy rekey
//!           A->B + rerandomization -> payload decryptable under B's RLWE key.
//!
//! Important: TFHE and RLWE ciphertext types are distinct. This test composes
//! them at the application boundary; it does NOT claim that the LWR output is
//! an RLWE ring reshuffling factor or that the two cryptosystems are interchangeable.
//! The toy test is functional-only. The paper-parameter test is expensive and ignored.

use pq_libpep::algebra::ring::{PolyRq, Q};
use pq_libpep::core::fast_lwr_prf::{
    FastLwrPrf, FastLwrPrfParameters, FastLwrPrfSecretKey,
};
use pq_libpep::core::fast_lwr_prf_pep_ks128_e16_pipeline::setup_pep_lwr_prf;
use pq_libpep::core::id_encoding::string_to_id;
use pq_libpep::core::rlwe::KeyGenResult;
use pq_libpep::core::rlwe_pke::{decrypt_poly, encrypt_poly};
use pq_libpep::core::rlwe_pre::{
    generate_rekey, reencrypt, reencrypt_and_rerandomize,
};
use rand::{rngs::StdRng, SeedableRng};

const RECORD_RING_N: usize = 64;
const REKEY_BASE_BITS: usize = 4;
const TARGET_BYTES: usize = 32;

fn derive_pseudonym_through_wire(
    parameters: FastLwrPrfParameters,
    prf_key: &FastLwrPrfSecretKey,
    canonical_id: &[u8; 32],
) -> Vec<u8> {
    let reference = FastLwrPrf::new(prf_key.clone());
    let (source, recipient, evaluator) =
        setup_pep_lwr_prf(parameters, prf_key).expect("TFHE PEP setup");

    let expected_symbols = reference
        .evaluate_many(canonical_id, pq_libpep::core::fast_lwr_prf_pep_ks128_e16_pipeline::output_symbols_for_bytes(parameters, TARGET_BYTES).unwrap())
        .into_iter()
        .map(|symbol| symbol as u8)
        .collect::<Vec<_>>();

    let encrypted_inputs = source
        .encrypt_inputs_for_output_bytes(canonical_id, TARGET_BYTES)
        .expect("encrypt indexed hash vectors under source TFHE key");
    assert_eq!(encrypted_inputs.len(), pq_libpep::core::fast_lwr_prf_pep_ks128_e16_pipeline::output_symbols_for_bytes(parameters, TARGET_BYTES).unwrap());

    // Simulate source -> evaluator -> recipient as separate wire boundaries.
    let input_wires = encrypted_inputs
        .iter()
        .map(|input| input.to_wire_bytes().expect("serialize encrypted input"))
        .collect::<Vec<_>>();
    let output_wires = input_wires
        .iter()
        .map(|wire| evaluator.evaluate_wire_input(wire).expect("evaluate wire input"))
        .collect::<Vec<_>>();

    let actual = recipient
        .decrypt_wire_outputs_to_bytes(&output_wires, TARGET_BYTES)
        .expect("recipient decrypts the 32-byte pseudonym");
    let expected = recipient
        .pack_symbols_to_bytes(&expected_symbols, TARGET_BYTES)
        .expect("pack cleartext reference symbols");

    assert_eq!(actual, expected, "private-input TFHE PRF must match reference");
    assert_eq!(actual.len(), TARGET_BYTES);
    actual
}

fn rekey_payload_a_to_b_and_check() {
    let mut rng = StdRng::seed_from_u64(0x5045_5052_4B59_0001);
    let alice = KeyGenResult::keygen(&mut rng, RECORD_RING_N);
    let bob = KeyGenResult::keygen(&mut rng, RECORD_RING_N);

    // Simulated application payload in Z_17, independent of the identifier.
    let expected_coefficients = (0..RECORD_RING_N)
        .map(|i| ((i * 7 + 3) % 17) as u64)
        .collect::<Vec<_>>();
    let payload = PolyRq::from_coeffs(&expected_coefficients, RECORD_RING_N, Q);
    let ciphertext_a = encrypt_poly(&mut rng, &alice.pk, &payload, RECORD_RING_N);

    // Centrally generated PRE material is intentional for this prototype.
    let rekey_ab = generate_rekey(
        &mut rng,
        &alice.sk,
        &bob.pk,
        REKEY_BASE_BITS,
    );

    // Verify rekeying alone preserves the payload.
    let rekeyed_b = reencrypt(&ciphertext_a, &rekey_ab, REKEY_BASE_BITS);
    let mut recovered_rekeyed = decrypt_poly(&bob.sk, &rekeyed_b, RECORD_RING_N).to_coeffs_vec();
    recovered_rekeyed.resize(RECORD_RING_N, 0);
    recovered_rekeyed.truncate(RECORD_RING_N);
    assert_eq!(recovered_rekeyed, expected_coefficients);

    // PEP rule: follow rekeying with a fresh encryption of zero under B.
    let randomized_b = reencrypt_and_rerandomize(
        &mut rng,
        &ciphertext_a,
        &rekey_ab,
        &bob.pk,
        REKEY_BASE_BITS,
    );
    let mut recovered_randomized = decrypt_poly(&bob.sk, &randomized_b, RECORD_RING_N).to_coeffs_vec();
    recovered_randomized.resize(RECORD_RING_N, 0);
    recovered_randomized.truncate(RECORD_RING_N);
    assert_eq!(recovered_randomized, expected_coefficients);

    let same_u = rekeyed_b.u.to_coeffs_vec() == randomized_b.u.to_coeffs_vec();
    let same_v = rekeyed_b.v.to_coeffs_vec() == randomized_b.v.to_coeffs_vec();
    assert!( !(same_u && same_v), "rerandomization should change the ciphertext representation" );
}

#[test]
fn toy_hybrid_pseudonym_and_rekeyed_payload_e2e() {
    let mut rng = StdRng::seed_from_u64(0x5045_5052_464B_0001);
    let id = string_to_id("patient-001");
    let parameters = FastLwrPrfParameters {
        lwr_dimension: 8,
        ring_dimension: 64,
        output_modulus: 4,
    };
    let prf_key = FastLwrPrfSecretKey::generate(parameters, &mut rng).unwrap();

    let pseudonym = derive_pseudonym_through_wire(parameters, &prf_key, &id);
    assert_eq!(pseudonym.len(), 32);

    rekey_payload_a_to_b_and_check();
    eprintln!("[HYBRID-E2E/TOY] TFHE pseudonym: 32 bytes; RLWE payload rekey + rerandomization: OK");
}

#[test]
#[ignore = "paper parameters; 52 TFHE PBS evaluations plus RLWE PRE; run explicitly in release mode"]
fn paper_parameters_hybrid_pseudonym_and_rekeyed_payload_e2e() {
    let mut rng = rand::rngs::OsRng;
    let id = string_to_id("patient-001");
    let parameters = FastLwrPrfParameters::paper_default();
    let prf_key = FastLwrPrfSecretKey::generate(parameters, &mut rng).unwrap();

    let pseudonym = derive_pseudonym_through_wire(parameters, &prf_key, &id);
    assert_eq!(pseudonym.len(), 32);

    rekey_payload_a_to_b_and_check();
    eprintln!("[HYBRID-E2E/PAPER] TFHE pseudonym: 32 bytes; RLWE payload rekey + rerandomization: OK");
}
