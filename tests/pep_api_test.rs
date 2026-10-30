
#![cfg(feature = "fast-prf-tfhe-private-input")]

use pq_libpep::algebra::ring::{PolyRq, Q};
use pq_libpep::core::fast_lwr_prf::{
    FastLwrPrf, FastLwrPrfParameters, FastLwrPrfSecretKey,
};
use pq_libpep::core::fast_lwr_prf_pep_ks128_e16_pipeline::setup_pep_lwr_prf;
use pq_libpep::core::pep::*;
use pq_libpep::core::pep_context::*;
use pq_libpep::core::rlwe::KeyGenResult;
use pq_libpep::core::rlwe_pke::encrypt_poly;
use pq_libpep::core::rlwe_pre::generate_rekey;
use rand::{rngs::StdRng, SeedableRng};
use std::time::Instant;

#[test]
fn canonical_input_produces_domain_pseudonym_and_preserves_attribute() {
    let total_start = Instant::now();

    println!("\n{}", "=".repeat(75));
    println!("              PQLIBPEP - TOY END-TO-END PIPELINE");
    println!("{}", "=".repeat(75));

    // ----------------------------------------------------------
    // 1. PARAMETERS
    // ----------------------------------------------------------
    println!("\n[1/8] CRYPTOGRAPHIC PARAMETERS");

    // Functional toy TFHE parameters, NOT a security preset.
    let parameters = FastLwrPrfParameters {
        lwr_dimension: 8,
        ring_dimension: 64,
        output_modulus: 32,
    };

    const N: usize = 64;

    println!("  Mode                : TOY / functional validation");
    println!("  LWR dimension       : {}", parameters.lwr_dimension);
    println!("  LWR ring dimension  : {}", parameters.ring_dimension);
    println!("  LWR output modulus  : {}", parameters.output_modulus);
    println!("  RLWE ring dimension : {}", N);
    println!("  RLWE modulus Q      : {}", Q);
    println!("  PRF output          : 256 bits / 32 bytes");
    println!("  PRF symbols         : 52");
    println!("  Security preset     : NOT production-secure");

    let mut rng = StdRng::seed_from_u64(0x50455001);

    // ----------------------------------------------------------
    // 2. PRF KEY GENERATION AND TFHE SETUP
    // ----------------------------------------------------------
    println!("\n[2/8] TFHE + DEPTH-1 LWR PRF SETUP");

    let setup_start = Instant::now();

    let key = FastLwrPrfSecretKey::generate(parameters, &mut rng).unwrap();
    let reference = FastLwrPrf::new(key.clone());

    println!("  [OK] LWR PRF secret key generated");

    let (client, recipient_key, evaluator) =
        setup_pep_lwr_prf(parameters, &key).unwrap();

    println!("  [OK] TFHE client initialized");
    println!("  [OK] TFHE evaluator initialized");
    println!("  [OK] Recipient TFHE key initialized");
    println!("  Setup time: {:?}", setup_start.elapsed());

    // ----------------------------------------------------------
    // 3. DOMAIN CONTEXT AND CANONICAL IDENTIFIER
    // ----------------------------------------------------------
    println!("\n[3/8] PEP DOMAIN CONTEXT");

    let context = PepContext::new(
        DomainId::new("research-a").unwrap(),
        1,
        client.source_context_id(),
        recipient_key.recipient_key_id(),
    );

    let identifier =
        CanonicalIdentifier::new("hospital-patient-id", b"patient-001").unwrap();

    println!("  Domain              : {:?}", context.domain());
    println!("  Identifier namespace: hospital-patient-id");
    println!("  Identifier value    : patient-001");
    println!("  Context version     : 1");

    // Reference PRF evaluation for correctness testing.
    let reference_start = Instant::now();

    let encoded = context.encode_prf_input(&identifier);
    let symbols = reference.evaluate_many(&encoded, 52);

    let mut expected_pid = [0u8; 32];

    for bit in 0..256 {
        let value = ((symbols[bit / 5] >> (4 - bit % 5)) & 1) as u8;
        expected_pid[bit / 8] |= value << (7 - bit % 8);
    }

    println!("  [OK] Canonical identifier encoded");
    println!("  [OK] Reference PRF evaluated");
    println!("  Reference evaluation time: {:?}", reference_start.elapsed());

    println!("  Expected pseudonym (hex):");
    println!("  {}", to_hex(&expected_pid));

    // ----------------------------------------------------------
    // 4. RLWE ENCRYPTION AND REKEY GENERATION
    // ----------------------------------------------------------
    println!("\n[4/8] RLWE ENCRYPTION AND REKEYING SETUP");

    let rlwe_start = Instant::now();

    let source_keys = KeyGenResult::keygen(&mut rng, N);
    let recipient_keys = KeyGenResult::keygen(&mut rng, N);

    println!("  [OK] Source RLWE key pair generated");
    println!("  [OK] Recipient RLWE key pair generated");

    let plain: Vec<u64> = (0..N).map(|i| (i % 17) as u64).collect();

    println!("  Attribute coefficients: {}", plain.len());
    println!("  First 16 coefficients : {:?}", &plain[..16]);

    let attribute = EncryptedAttribute::new(encrypt_poly(
        &mut rng,
        &source_keys.pk,
        &PolyRq::from_coeffs(&plain, N, Q),
        N,
    ));

    println!("  [OK] Attribute encrypted under SOURCE public key");

    let rekey = generate_rekey(
        &mut rng,
        &source_keys.sk,
        &recipient_keys.pk,
        4,
    );

    println!("  [OK] Rekey material generated: SOURCE -> RECIPIENT");
    println!("  Rekey decomposition parameter: 4");
    println!("  RLWE setup time: {:?}", rlwe_start.elapsed());

    // ----------------------------------------------------------
    // 5. PEP ROLES INITIALIZATION
    // ----------------------------------------------------------
    println!("\n[5/8] PEP ARCHITECTURE INITIALIZATION");

    let source = PepSource::new(
        context.clone(),
        client,
    )
    .unwrap();

    println!("  [OK] PEP Source initialized");

    let converter = PepTranscryptor::new(
        context.clone(),
        evaluator,
        rekey,
        recipient_keys.pk,
        4,
    )
    .unwrap();

    println!("  [OK] PEP Transcryptor initialized");

    let recipient = PepRecipient::new(
        context.clone(),
        recipient_key,
        recipient_keys.sk,
        N,
    )
    .unwrap();

    println!("  [OK] PEP Recipient initialized");

    println!("\n  Architecture:");
    println!("    SOURCE -> TRANSCRYPTOR -> RECIPIENT");
    println!("    PRF branch  : encrypted ID -> TFHE evaluation");
    println!("    RLWE branch : encrypted attribute -> rekeying");

    // ----------------------------------------------------------
    // 6. SOURCE REQUEST
    // ----------------------------------------------------------
    println!("\n[6/8] PEP SOURCE - REQUEST PREPARATION");

    let request_start = Instant::now();

    let request = source
        .prepare_request(&identifier, &attribute)
        .unwrap();

    let pending = request.pending();

    println!("  [OK] Canonical identifier prepared");
    println!("  [OK] Private-input PRF request prepared");
    println!("  [OK] Encrypted attribute included");
    println!("  Request size: {} bytes", request.wire_bytes().len());
    println!("  Preparation time: {:?}", request_start.elapsed());

    // ----------------------------------------------------------
    // 7. TRANSCRYPTOR EVALUATION
    // ----------------------------------------------------------
    println!("\n[7/8] PEP TRANSCRYPTOR - HOMOMORPHIC PROCESSING");

    let evaluation_start = Instant::now();

    println!("  Processing encrypted request...");
    println!("  Expected logical operations:");
    println!("    - TFHE private-input LWR PRF evaluation");
    println!("    - RLWE attribute rekeying A -> B");
    println!("    - RLWE ciphertext rerandomization");

    let response = converter
        .process_request(request.wire_bytes(), &mut rng)
        .unwrap();

    let evaluation_time = evaluation_start.elapsed();

    println!("  [OK] Transcryptor evaluation completed");
    println!("  Response size: {} bytes", response.len());
    println!("  Transcryptor time: {:?}", evaluation_time);

    // ----------------------------------------------------------
    // 8. RECIPIENT DECRYPTION AND VERIFICATION
    // ----------------------------------------------------------
    println!("\n[8/8] PEP RECIPIENT - DECRYPTION AND VALIDATION");

    let recipient_start = Instant::now();

    let opened = recipient
        .open_response(&response, &pending)
        .unwrap();

    println!("  [OK] Response opened successfully");

    println!("\n  PRF RESULT");
    println!("  Expected PID : {}", to_hex(&expected_pid));
    println!(
        "  Actual PID   : {}",
        to_hex(opened.pseudonym.as_bytes())
    );

    assert_eq!(opened.pseudonym.as_bytes(), &expected_pid);
    println!("  [PASS] TFHE pseudonym matches reference PRF");

    assert_eq!(opened.pseudonym.domain(), context.domain());
    println!("  [PASS] Pseudonym belongs to expected domain");

    println!("\n  RLWE ATTRIBUTE RESULT");
    println!("  Original coefficients : {:?}", &plain[..16]);
    println!(
        "  Decrypted coefficients: {:?}",
        &opened.attribute_coefficients[..16]
    );

    assert_eq!(opened.attribute_coefficients, plain);
    println!("  [PASS] RLWE attribute preserved after rekeying");

    println!("  Recipient time: {:?}", recipient_start.elapsed());

    // ----------------------------------------------------------
    // 9. NEGATIVE TESTS
    // ----------------------------------------------------------
    println!("\n[SECURITY CHECKS] CONTEXT AND BATCH CONSISTENCY");

    let security_start = Instant::now();

    // Same input, different pending batch.
    let other = source
        .prepare_request(&identifier, &attribute)
        .unwrap();

    assert!(
        recipient
            .open_response(&response, &other.pending())
            .is_err()
    );

    println!("  [PASS] Old response rejected for another pending batch");

    // Modified request context.
    let mut wrong_context = request.wire_bytes().to_vec();
    wrong_context[5] ^= 1;

    assert!(
        converter
            .process_request(&wrong_context, &mut rng)
            .is_err()
    );

    println!("  [PASS] Modified request context rejected");

    // Modified response.
    let mut wrong_response = response;
    wrong_response[5] ^= 1;

    assert!(
        recipient
            .open_response(&wrong_response, &pending)
            .is_err()
    );

    println!("  [PASS] Modified response rejected");
    println!("  Validation time: {:?}", security_start.elapsed());

    // ----------------------------------------------------------
    // FINAL SUMMARY
    // ----------------------------------------------------------
    println!("\n{}", "=".repeat(75));
    println!("                     FINAL TEST SUMMARY");
    println!("{}", "=".repeat(75));

    println!("  [PASS] Domain-specific pseudonym generation");
    println!("  [PASS] TFHE private-input PRF evaluation");
    println!("  [PASS] RLWE attribute encryption");
    println!("  [PASS] RLWE proxy re-encryption");
    println!("  [PASS] Recipient attribute recovery");
    println!("  [PASS] Reference pseudonym equality");
    println!("  [PASS] Domain consistency");
    println!("  [PASS] Pending batch mismatch rejection");
    println!("  [PASS] Request context mutation rejection");
    println!("  [PASS] Response mutation rejection");

    println!("\n  TFHE setup time       : {:?}", setup_start.elapsed());
    println!("  Transcryptor time     : {:?}", evaluation_time);
    println!("  Total elapsed time    : {:?}", total_start.elapsed());

    println!("\n  RESULT: ALL FUNCTIONAL TOY CHECKS PASSED");
    println!("  NOTE: Collusion resistance and production security");
    println!("        are NOT established by this test.");

    println!("{}\n", "=".repeat(75));
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>()
}
