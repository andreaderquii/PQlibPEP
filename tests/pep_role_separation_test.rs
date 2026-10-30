#![cfg(feature = "pep-role-lab")]

use pq_libpep::core::fast_lwr_prf::FastLwrPrfParameters;
use pq_libpep::core::pep_context::{CanonicalIdentifier, DomainId};
use pq_libpep::core::pep_roles::*;
use rand::{rngs::OsRng, RngCore};
use std::time::Instant;

fn heading(title: &str) {
    println!("\n{}\n{title}\n{}", "=".repeat(76), "=".repeat(76));
}

#[test]
fn distinct_role_bundles_roundtrip_preserve_data_and_reject_cross_role_and_replay() {
    let total_start = Instant::now();
    heading("PEP: LOCAL ROLE SEPARATION CHECK - A / TRANSCRYPTOR / B");
    println!("[ENVIRONMENT] One Rust process, OS process ID={}", std::process::id());
    println!("[NETWORK] No host, container, IP endpoint, socket or TLS handshake is started.");
    println!("[METHOD] The three roles are distinct objects; bytes are passed through local function calls.");
    println!("[AUTH] These APIs assume an authenticated source A; this test does NOT exercise mTLS.");
    println!("[SCOPE] Check role-specific materials, serialization, the pipeline and application checks.");

    let mut rng = OsRng;
    let parameters = FastLwrPrfParameters {
        lwr_dimension: 8,
        ring_dimension: 64,
        output_modulus: 32,
    };
    println!("\n[1/8] TOY SETUP USING A TRUSTED OFFLINE DEALER");
    println!("      PRF: n=8, N=64, p=32; final PID: 32 bytes / 52 symbols.");
    println!("      RLWE: N=64; attribute coefficients belong to Z_17.");
    println!("      The dealer sees all secrets during setup; this is not distributed key generation.");
    let (a, t, b) = trusted_dealer_setup(
        parameters,
        64,
        DomainId::new("domain-b").unwrap(),
        1,
        &mut rng,
    )
    .unwrap();
    println!("      [A] Bundle with source TFHE/RLWE keys and public routing configuration.");
    println!("      [T] Bundle with the CLEAR PRF key, evaluation keys and RLWE rekey material.");
    println!("      [B] Bundle with recipient TFHE/RLWE decryption keys and public routing configuration.");
    println!("      T's bundle structure does not contain A/B plaintext decryption-key fields.");
    println!("      This does not establish collusion resistance of the switching material.");

    println!("\n[2/8] WRITE AND RELOAD THE THREE ROLE BUNDLES");
    let dir = std::env::temp_dir().join(format!(
        "pqpep-role-test-{}-{}",
        std::process::id(),
        rng.next_u64()
    ));
    std::fs::create_dir(&dir).unwrap();
    a.write_new(dir.join("a.bin")).unwrap();
    t.write_new(dir.join("t.bin")).unwrap();
    b.write_new(dir.join("b.bin")).unwrap();
    println!("      Wrote three distinct local files to a temporary directory.");
    assert!(SourceBundle::read_trusted(dir.join("t.bin")).is_err());
    assert!(TranscryptorBundle::read_trusted(dir.join("b.bin")).is_err());
    assert!(RecipientBundle::read_trusted(dir.join("a.bin")).is_err());
    println!("      [PASS] Each parser rejects a bundle tagged for a different role.");
    assert!(
        a.write_new(dir.join("a.bin")).is_err(),
        "must never overwrite provisioned keys"
    );
    println!("      [PASS] Existing key files cannot be silently overwritten.");
    drop((a, t, b));
    let a =
        SourceRole::from_bundle(SourceBundle::read_trusted(dir.join("a.bin")).unwrap()).unwrap();
    let mut t =
        TranscryptorRole::from_bundle(TranscryptorBundle::read_trusted(dir.join("t.bin")).unwrap())
            .unwrap();
    let mut b =
        RecipientRole::from_bundle(RecipientBundle::read_trusted(dir.join("b.bin")).unwrap())
            .unwrap();
    println!("      [PASS] Reconstructed A, T and B from their own files after dropping the original objects.");

    println!("\n[3/8] A: ENCRYPT AND PREPARE THE REQUEST");
    let id = CanonicalIdentifier::new("patients", b"same-test-id").unwrap();
    let attribute: Vec<u64> = (0..64).map(|i| i % 17).collect();
    let (request, control) = a.prepare(&id, &attribute, &mut rng).unwrap();
    println!("      A encrypts the PRF input and encrypts 64 attribute coefficients under its own RLWE key.");
    println!("      Request for T: {} bytes; separate source control for B: {} bytes.", request.len(), control.len());
    println!("      The identifier and secret keys are not printed.");

    println!("\n[4/8] T: ROUTE CHECK, PRF EVALUATION, REKEYING AND RERANDOMIZATION");
    let mut wrong_route = request.clone();
    wrong_route[0] ^= 1;
    assert!(t
        .process_from_authenticated_source(&wrong_route, &mut rng)
        .is_err());
    println!("      [PASS] A modified route is rejected before processing.");
    let response = t
        .process_from_authenticated_source(&request, &mut rng)
        .unwrap();
    println!("      T evaluates the PRF on encrypted input using its clear PRF key.");
    println!("      T applies RLWE rekeying A->B and adds a fresh Enc_B(0).");
    println!("      Encrypted response: {} bytes.", response.len());
    assert!(t
        .process_from_authenticated_source(&request, &mut rng)
        .is_err());
    println!("      [PASS] An exact request replay is rejected by T's in-memory cache.");

    println!("\n[5/8] B: OPEN THE RESPONSE USING THE CONTROL CREATED BY A");
    let opened = b
        .open_from_authenticated_source(&control, &response)
        .unwrap();
    assert_eq!(opened.attribute_coefficients, attribute);
    assert_eq!(opened.pseudonym.domain().as_str(), "domain-b");
    println!("      [PASS] B opens a {}-byte PID for domain-b.", opened.pseudonym.as_bytes().len());
    println!("      [PASS] All 64 decrypted coefficients match A's original attribute exactly.");
    assert!(b
        .open_from_authenticated_source(&control, &response)
        .is_err());
    println!("      [PASS] B rejects a second opening of the same transaction.");

    println!("\n[6/8] NEW REQUEST, SAME ID / DOMAIN / EPOCH");
    let (request2, control2) = a.prepare(&id, &attribute, &mut rng).unwrap();
    let response2 = t
        .process_from_authenticated_source(&request2, &mut rng)
        .unwrap();
    assert!(
        b.open_from_authenticated_source(&control2, &response)
            .is_err(),
        "foreign transaction must not consume pending control"
    );
    println!("      [PASS] The previous response is rejected for the new pending control.");
    let opened2 = b
        .open_from_authenticated_source(&control2, &response2)
        .unwrap();
    assert_eq!(opened2.pseudonym.as_bytes(), opened.pseudonym.as_bytes());
    assert_eq!(opened2.attribute_coefficients, attribute);
    println!("      [PASS] The correct response remains openable after the transaction-mixing attempt.");
    println!("      [PASS] The fresh encrypted request yields the same PID and preserves the attribute.");

    println!("\n[7/8] ENCRYPTION-KEY ROTATION WITH A PERSISTENT PRF KEY");
    let epoch_key = OfflinePrfKey::generate(
        parameters,
        DomainId::new("rotating-b").unwrap(),
        3,
        &mut rng,
    )
    .unwrap();
    epoch_key.write_new(dir.join("offline-prf.bin")).unwrap();
    let epoch_key = OfflinePrfKey::read_trusted(dir.join("offline-prf.bin")).unwrap();
    let mut pids = Vec::new();
    for generation in 1..=2 {
        println!("      Generation {generation}/2: fresh TFHE/RLWE keys and fresh evaluation/rekey material.");
        let (aa, tt, bb) = epoch_key.provision(64, &mut rng).unwrap();
        let aa = SourceRole::from_bundle(aa).unwrap();
        let mut tt = TranscryptorRole::from_bundle(tt).unwrap();
        let mut bb = RecipientRole::from_bundle(bb).unwrap();
        let (req, ctl) = aa.prepare(&id, &attribute, &mut rng).unwrap();
        let resp = tt
            .process_from_authenticated_source(&req, &mut rng)
            .unwrap();
        let opened = bb.open_from_authenticated_source(&ctl, &resp).unwrap();
        pids.push(*opened.pseudonym.as_bytes());
    }
    assert_eq!(
        pids[0], pids[1],
        "encryption-key rotation must preserve domain/epoch PID"
    );
    println!("      [PASS] The PID is stable across independent encryption setups sharing the PRF key/domain/epoch.");
    println!("      This checks consistency across encryption-key rotation, not domain transitivity or RS2.");

    println!("\n[8/8] CLEANUP AND RESULT");
    std::fs::remove_dir_all(dir).unwrap();
    println!("      Removed temporary files; this does not prove secure erasure of secrets.");
    println!("[PASS] Role bundles, pipeline, route/transaction/replay checks and PID stability passed.");
    println!("[TIME] {:.3} s for this functional test, including setup and checks.", total_start.elapsed().as_secs_f64());
    println!("[LIMIT] One process: no host isolation and no network/mTLS verification.");
    println!("[LIMIT] Toy parameters; no security, unlinkability or collusion-resistance proof.");
}

#[test]
fn transcryptor_rejects_malformed_switching_polynomials_before_processing() {
    use pq_libpep::algebra::ring::{PolyRq, Q};
    use pq_libpep::core::fast_lwr_prf::FastLwrPrfSecretKey;
    use pq_libpep::core::fast_lwr_prf_pep_hybrid_pipeline::HybridPepTranscryptor;
    use pq_libpep::core::fast_lwr_prf_pep_ks128_e16_pipeline::setup_pep_lwr_prf;
    use pq_libpep::core::rlwe::KeyGenResult;
    use pq_libpep::core::rlwe_pre::generate_rekey;

    heading("PEP: REJECT MALFORMED REKEY MATERIAL");
    println!("[ENVIRONMENT] Local validation check; no hosts or network traffic.");
    let mut rng = OsRng;
    let parameters = FastLwrPrfParameters {
        lwr_dimension: 8,
        ring_dimension: 64,
        output_modulus: 32,
    };
    let key = FastLwrPrfSecretKey::generate(parameters, &mut rng).unwrap();
    let (_, _, evaluator) = setup_pep_lwr_prf(parameters, &key).unwrap();
    let source = KeyGenResult::keygen(&mut rng, 64);
    let recipient = KeyGenResult::keygen(&mut rng, 64);
    let mut rekey = generate_rekey(&mut rng, &source.sk, &recipient.pk, 4);
    println!("[SETUP] Valid A/B RLWE keys and rekey material with N=64 and base=16.");
    rekey.entries[0].k0 = PolyRq::from_coeffs(&[0; 128], 128, Q);
    println!("[MUTATION] Replaced k0 in the first entry with a dimension-128 polynomial.");
    assert!(HybridPepTranscryptor::new(evaluator, rekey, recipient.pk, 4).is_err());
    println!("[PASS] The constructor rejects incompatible rekey material before processing any request.");
    println!("[LIMIT] This checks parameter compatibility; it does not prove PRE security.");
}
