use pq_libpep::algebra::ring::{PolyRq, Q};
use pq_libpep::core::rlwe::KeyGenResult;
use pq_libpep::core::rlwe_pke::{decrypt_poly, encrypt_poly};
use pq_libpep::core::rlwe_pre::{generate_rekey, reencrypt, reencrypt_and_rerandomize};
use rand::{rngs::StdRng, SeedableRng};

#[test]
fn rekey_and_rerandomize_preserves_plaintext_for_recipient() {
    const N: usize = 64;
    const BASE_BITS: usize = 4;

    let mut rng = StdRng::seed_from_u64(0x5045_5052_524E_4401);
    let alice = KeyGenResult::keygen(&mut rng, N);
    let bob = KeyGenResult::keygen(&mut rng, N);

    // Use a nontrivial plaintext polynomial in Z_17.
    let expected: Vec<u64> = (0..N)
        .map(|i| ((i * 7 + 3) % 17) as u64)
        .collect();
    let message = PolyRq::from_coeffs(&expected, N, Q);
    let ciphertext_a = encrypt_poly(&mut rng, &alice.pk, &message, N);

    // Rekey material is intentionally generated centrally for this prototype.
    let rekey_ab = generate_rekey(&mut rng, &alice.sk, &bob.pk, BASE_BITS);

    // Plain rekey: check that the existing PRE function preserves the message.
    let ciphertext_b = reencrypt(&ciphertext_a, &rekey_ab, BASE_BITS);
    let recovered_b = decrypt_poly(&bob.sk, &ciphertext_b, N).to_coeffs_vec();
    let mut recovered_b = recovered_b;
    recovered_b.resize(N, 0);
    assert_eq!(recovered_b, expected, "rekey alone must preserve plaintext");

    // Rekey + fresh Enc_B(0): same plaintext, different ciphertext.
    let randomized_b = reencrypt_and_rerandomize(
        &mut rng,
        &ciphertext_a,
        &rekey_ab,
        &bob.pk,
        BASE_BITS,
    );

    let mut recovered_randomized = decrypt_poly(&bob.sk, &randomized_b, N).to_coeffs_vec();
    recovered_randomized.resize(N, 0);
    assert_eq!(
        recovered_randomized, expected,
        "rekey + rerandomization must preserve plaintext"
    );

    let same_u = ciphertext_b.u.to_coeffs_vec() == randomized_b.u.to_coeffs_vec();
    let same_v = ciphertext_b.v.to_coeffs_vec() == randomized_b.v.to_coeffs_vec();
    assert!(
        !(same_u && same_v),
        "rerandomization should change the ciphertext representation"
    );
}
