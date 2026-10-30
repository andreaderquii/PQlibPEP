//! Demonstration of the experimental hybrid PEP transaction.
//!
//! This example demonstrates two independent cryptographic branches:
//!
//! 1. TFHE: compute an LWR pseudonym from encrypted input vectors.
//! 2. RLWE: rekey and rerandomize an encrypted application payload.
//!
//! Both branches are associated with the same application transaction.
//! They are not combined algebraically.
//!
//! IMPORTANT: the small TFHE parameters below are for demonstration only.
//! They do not provide a production security level.

use std::time::Instant;

use rand::{rngs::OsRng, RngCore};

use pq_libpep::algebra::ring::{PolyRq, Q};

use pq_libpep::core::fast_lwr_prf::{
    FastLwrPrf,
    FastLwrPrfParameters,
    FastLwrPrfSecretKey,
};

use pq_libpep::core::fast_lwr_prf_pep_ks128_e16_pipeline::{
    output_symbols_for_bytes,
    setup_pep_lwr_prf,
};

use pq_libpep::core::fast_lwr_prf_pep_hybrid_pipeline::{
    HybridPepRecipient,
    HybridPepSource,
    HybridPepTranscryptor,
};

use pq_libpep::core::id_encoding::string_to_id;
use pq_libpep::core::rlwe::KeyGenResult;
use pq_libpep::core::rlwe_pke::encrypt_poly;
use pq_libpep::core::rlwe_pre::generate_rekey;

const PSEUDONYM_BYTES: usize = 32;
const RLWE_RING_N: usize = 64;
const REKEY_BASE_BITS: usize = 4;

/// Pack PRF output symbols into bytes using the same MSB-first convention
/// as the test reference.
fn pack_symbols(
    parameters: FastLwrPrfParameters,
    symbols: &[u64],
    output_len: usize,
) -> Vec<u8> {
    assert!(
        parameters.output_modulus.is_power_of_two(),
        "this helper assumes a power-of-two output modulus"
    );

    let bits_per_symbol =
        parameters.output_modulus.trailing_zeros() as usize;

    let required_bits = output_len * 8;

    assert!(
        symbols.len() * bits_per_symbol >= required_bits,
        "not enough PRF output symbols"
    );

    let mut output = vec![0u8; output_len];
    let mut bit_index = 0usize;

    for &symbol in symbols {
        assert!(symbol < parameters.output_modulus);

        for bit_pos in (0..bits_per_symbol).rev() {
            if bit_index >= required_bits {
                return output;
            }

            let bit = ((symbol >> bit_pos) & 1) as u8;

            output[bit_index / 8] |=
                bit << (7 - bit_index % 8);

            bit_index += 1;
        }
    }

    output
}

fn to_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join("")
}

fn main() {
    println!("=== Hybrid PEP transaction demo ===\n");

    let mut rng = OsRng;

    // ------------------------------------------------------------
    // STEP 1: Choose a demo identifier and configure the LWR PRF.
    // ------------------------------------------------------------

    // This is a toy configuration, not a security recommendation.
    // It allows us to demonstrate the full transaction quickly.
    let parameters = FastLwrPrfParameters {
        lwr_dimension: 8,
        ring_dimension: 64,
        output_modulus: 4,
    };

    let identifier = string_to_id("patient-001");

    println!("[1] Identifier prepared locally.");
    println!(
        "    Requested pseudonym length: {} bytes",
        PSEUDONYM_BYTES
    );

    // The identifier itself is not added to the hybrid wire envelope.
    // The source API prepares encrypted PRF inputs from the identifier.

    // ------------------------------------------------------------
    // STEP 2: Set up TFHE and the cleartext reference implementation.
    // ------------------------------------------------------------

    let prf_secret_key =
        FastLwrPrfSecretKey::generate(parameters, &mut rng)
            .expect("generate LWR PRF key");

    let cleartext_reference =
        FastLwrPrf::new(prf_secret_key.clone());

    // Experimental setup: generated centrally for this demonstration.
    let (tfhe_source, tfhe_recipient, tfhe_evaluator) =
        setup_pep_lwr_prf(parameters, &prf_secret_key)
            .expect("set up TFHE PEP components");

    let expected_symbol_count =
        output_symbols_for_bytes(parameters, PSEUDONYM_BYTES)
            .expect("calculate PRF output count");

    println!("\n[2] TFHE components initialized.");
    println!(
        "    Output symbols required: {}",
        expected_symbol_count
    );

    // ------------------------------------------------------------
    // STEP 3: Create an RLWE payload for a separate data branch.
    // ------------------------------------------------------------

    // Imagine these coefficients represent an application payload.
    // This demo uses visible test data so we can verify decryption.
    let expected_payload: Vec<u64> = (0..RLWE_RING_N)
        .map(|i| ((i * 7 + 3) % 17) as u64)
        .collect();

    let plaintext_payload =
        PolyRq::from_coeffs(&expected_payload, RLWE_RING_N, Q);

    // Generate sender A and recipient B RLWE key pairs.
    let alice = KeyGenResult::keygen(&mut rng, RLWE_RING_N);
    let bob = KeyGenResult::keygen(&mut rng, RLWE_RING_N);

    // Encrypt the payload for Alice's key.
    let encrypted_payload_a = encrypt_poly(
        &mut rng,
        &alice.pk,
        &plaintext_payload,
        RLWE_RING_N,
    );

    println!("\n[3] RLWE payload encrypted for sender A.");
    println!(
        "    Payload coefficients: {}",
        expected_payload.len()
    );

    // ------------------------------------------------------------
    // STEP 4: Prepare the RLWE re-encryption key A -> B.
    // ------------------------------------------------------------

    let rekey_ab = generate_rekey(
        &mut rng,
        &alice.sk,
        &bob.pk,
        REKEY_BASE_BITS,
    );

    println!("\n[4] RLWE re-encryption key generated.");
    println!("    Direction: A -> B");

    // ------------------------------------------------------------
    // STEP 5: Assemble source, transcryptor, and recipient.
    // ------------------------------------------------------------

    let source = HybridPepSource::new(tfhe_source);

    let transcryptor = HybridPepTranscryptor::new(
        tfhe_evaluator,
        rekey_ab,
        bob.pk,
        REKEY_BASE_BITS,
    )
    .expect("initialize hybrid transcryptor");

    let recipient = HybridPepRecipient::new(
        tfhe_recipient,
        bob.sk,
        RLWE_RING_N,
    )
    .expect("initialize hybrid recipient");

    println!("\n[5] Hybrid roles initialized.");
    println!("    Source: prepares TFHE input ciphertexts.");
    println!("    Transcryptor: evaluates TFHE and rekeys RLWE.");
    println!("    Recipient: decrypts the two output branches.");

    // ------------------------------------------------------------
    // STEP 6: Prepare the application request.
    // ------------------------------------------------------------

    let start_prepare = Instant::now();

    let request = source
        .prepare_request(
            &identifier,
            &encrypted_payload_a,
            PSEUDONYM_BYTES,
        )
        .expect("prepare hybrid request");

    let prepare_elapsed = start_prepare.elapsed();

    let transaction_id = request.transaction_id();
    let batch_id = request.batch_id();

    println!("\n[6] Hybrid request prepared.");
    println!("    Wire magic: HPRQ");
    println!("    Transaction ID: {}", to_hex(&transaction_id));
    println!("    Batch ID:       {}", to_hex(&batch_id));
    println!("    Request size:   {} bytes", request.wire_bytes().len());
    println!("    Preparation:    {:.2?}", prepare_elapsed);

    // HPRQ contains the correlation IDs, encrypted TFHE input envelopes,
    // and the RLWE payload ciphertext. The clear identifier is not included.
    //
    // The IDs bind the application-level transaction, but are not a MAC
    // or signature and do not authenticate the request.

    // ------------------------------------------------------------
    // STEP 7: Process the request at the transcryptor.
    // ------------------------------------------------------------

    let start_process = Instant::now();

    let response_wire = transcryptor
        .process_request_wire(request.wire_bytes(), &mut rng)
        .expect("process hybrid request");

    let process_elapsed = start_process.elapsed();

    println!("\n[7] Hybrid request processed.");
    println!("    Wire magic: HPRS");
    println!("    Response size: {} bytes", response_wire.len());
    println!("    Processing:    {:.2?}", process_elapsed);

    // Two independent operations have occurred:
    //
    // TFHE branch:
    //   encrypted PRF inputs -> homomorphic evaluation -> output ciphertexts
    //
    // RLWE branch:
    //   ciphertext under A -> rekey + rerandomization -> ciphertext for B

    // ------------------------------------------------------------
    // STEP 8: Recipient checks the IDs and decrypts the response.
    // ------------------------------------------------------------

    let start_open = Instant::now();

    let result = recipient
        .open_response_wire(
            &response_wire,
            &transaction_id,
            &batch_id,
            PSEUDONYM_BYTES,
        )
        .expect("validate and decrypt hybrid response");

    let open_elapsed = start_open.elapsed();

    println!("\n[8] Recipient opened the response.");
    println!("    Pseudonym: {}", to_hex(&result.pseudonym));
    println!(
        "    Pseudonym length: {} bytes",
        result.pseudonym.len()
    );
    println!(
        "    Decrypted payload coefficients: {}",
        result.payload_coefficients.len()
    );
    println!("    Response opening: {:.2?}", open_elapsed);

    // ------------------------------------------------------------
    // STEP 9: Check both results against the expected plaintext values.
    // ------------------------------------------------------------

    // This reference computation is for the demo only: it lets us compare
    // the TFHE result against a cleartext PRF evaluation.
    let expected_symbols =
        cleartext_reference.evaluate_many(
            &identifier,
            expected_symbol_count,
        );

    let expected_pseudonym =
        pack_symbols(parameters, &expected_symbols, PSEUDONYM_BYTES);

    assert_eq!(
        result.pseudonym,
        expected_pseudonym,
        "TFHE pseudonym differs from the cleartext reference"
    );

    assert_eq!(
        result.payload_coefficients,
        expected_payload,
        "RLWE payload differs from the original plaintext"
    );

    assert_eq!(
        result.transaction_id,
        transaction_id,
        "transaction ID mismatch"
    );

    assert_eq!(
        result.batch_id,
        batch_id,
        "batch ID mismatch"
    );

    println!("\n=== VERIFICATION PASSED ===");
    println!("  [OK] Pseudonym matches cleartext LWR PRF reference.");
    println!("  [OK] Pseudonym has the expected length.");
    println!("  [OK] RLWE payload is preserved through rekeying.");
    println!("  [OK] Transaction and batch IDs match.");
    println!("\nThe demo completed successfully.");
}