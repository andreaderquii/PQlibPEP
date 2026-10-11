use pq_libpep::core::rlwe::KeyGenResult;
use pq_libpep::core::rlwe_pke::{
    decrypt,
    encrypt,
    generate_relinearization_key,
    relinearize,
};

use rand::thread_rng;

const N: usize = 256;
fn print_poly_head(label: &str, poly: &pq_libpep::algebra::ring::PolyRq) {
    let coeffs = poly.to_coeffs_vec();
    let count = 8.min(poly.degree_bound());

    println!(
        "{:<30} {:?}",
        label,
        &coeffs[..count]
    );
}

#[test]
fn test_ciphertext_addition_zero_plus_one() {
    let mut rng = thread_rng();

    let keygen = KeyGenResult::keygen(
        &mut rng,
        N,
    );

    let message_zero = vec![0u8];
    let message_one = vec![1u8];

    let ciphertext_zero = encrypt(
        &mut rng,
        &keygen.pk,
        &message_zero,
        N,
    );

    let ciphertext_one = encrypt(
        &mut rng,
        &keygen.pk,
        &message_one,
        N,
    );

    let ciphertext_sum = ciphertext_zero.add(
        &ciphertext_one,
    );

    let recovered = decrypt(
        &keygen.sk,
        &ciphertext_sum,
        N,
        1,
    );

    println!(
        "Dec(Enc(0) + Enc(1)) = {:?}",
        recovered
    );

    assert_eq!(
        recovered,
        vec![1],
        "Enc(0) + Enc(1) should decrypt to 1"
    );
}

#[test]
fn test_ciphertext_addition_one_plus_zero() {
    let mut rng = thread_rng();

    println!("==============================================");
    println!("   RLWE HOMOMORPHIC ADDITION: 1 + 0");
    println!("==============================================");
    println!("Ring dimension N = {}", N);

    let keygen = KeyGenResult::keygen(&mut rng, N);

    let ciphertext_one = encrypt(
        &mut rng,
        &keygen.pk,
        &[1],
        N,
    );

    let ciphertext_zero = encrypt(
        &mut rng,
        &keygen.pk,
        &[0],
        N,
    );

    println!("Message A = [1]");
    println!("Message B = [0]");

    let ciphertext_sum = ciphertext_one.add(
        &ciphertext_zero
    );

    let recovered = decrypt(
        &keygen.sk,
        &ciphertext_sum,
        N,
        1,
    );

    println!(
        "Dec(Enc(1) + Enc(0)) = {:?}",
        recovered
    );

    assert_eq!(
        recovered,
        vec![1],
        "Enc(1) + Enc(0) should decrypt to 1"
    );

    println!("RESULT: ADDITION OK");
}

#[test]
fn test_ciphertext_raw_multiplication() {
    let mut rng = thread_rng();

    println!("==============================================");
    println!("   RLWE RAW CIPHERTEXT MULTIPLICATION");
    println!("==============================================");
    println!("Ring dimension N = {}", N);

    let keygen = KeyGenResult::keygen(&mut rng, N);

    let ciphertext_a = encrypt(
        &mut rng,
        &keygen.pk,
        &[1],
        N,
    );

    let ciphertext_b = encrypt(
        &mut rng,
        &keygen.pk,
        &[1],
        N,
    );

    println!("Plaintext A = [1]");
    println!("Plaintext B = [1]");

    print_poly_head(
        "A.u",
        &ciphertext_a.u,
    );

    print_poly_head(
        "A.v",
        &ciphertext_a.v,
    );

    print_poly_head(
        "B.u",
        &ciphertext_b.u,
    );

    print_poly_head(
        "B.v",
        &ciphertext_b.v,
    );

    println!("\nComputing raw product...");

    let product = ciphertext_a.mul_raw(
        &ciphertext_b
    );

    print_poly_head(
        "product.c0 = v1*v2",
        &product.c0,
    );

    print_poly_head(
        "product.c1 = -(v1*u2+u1*v2)",
        &product.c1,
    );

    print_poly_head(
        "product.c2 = u1*u2",
        &product.c2,
    );

    assert_eq!(
        product.c0.degree_bound(),
        N
    );

    assert_eq!(
        product.c1.degree_bound(),
        N
    );

    assert_eq!(
        product.c2.degree_bound(),
        N
    );

    println!("RESULT: RAW MULTIPLICATION STRUCTURE OK");
}


#[test]
fn test_ciphertext_raw_multiplication_relation() {
    let mut rng = thread_rng();

    let keygen = KeyGenResult::keygen(&mut rng, N);

    let ciphertext_a = encrypt(
        &mut rng,
        &keygen.pk,
        &[1],
        N,
    );

    let ciphertext_b = encrypt(
        &mut rng,
        &keygen.pk,
        &[1],
        N,
    );

    let product = ciphertext_a.mul_raw(
        &ciphertext_b
    );

    // Compute the two decrypted phases:
    //
    // phase_a = v_a - u_a * s
    // phase_b = v_b - u_b * s
    //
    // Their product must be represented by:
    //
    // c0 + c1*s + c2*s^2
    let phase_a = ciphertext_a
        .v
        .sub(&ciphertext_a.u.mul_ntt(&keygen.sk.s));

    let phase_b = ciphertext_b
        .v
        .sub(&ciphertext_b.u.mul_ntt(&keygen.sk.s));

    let expected = phase_a.mul_ntt(&phase_b);

    let c1_s = product
        .c1
        .mul_ntt(&keygen.sk.s);

    let c2_s2 = product
        .c2
        .mul_ntt(&keygen.sk.s)
        .mul_ntt(&keygen.sk.s);

    let reconstructed = product
        .c0
        .add(&c1_s)
        .add(&c2_s2);

    assert_eq!(
        reconstructed.coefficients()[..N],
        expected.coefficients()[..N],
        "raw ciphertext multiplication does not represent the product of the decrypted phases"
    );
}

#[test]
fn test_ciphertext_relinearization_relation() {
    let mut rng = thread_rng();

    println!("==============================================");
    println!("   RLWE CIPHERTEXT RELINEARIZATION");
    println!("==============================================");
    println!("Ring dimension N = {}", N);
    println!("Base bits        = 4");
    println!("Base             = {}", 1u64 << 4);

    let keygen = KeyGenResult::keygen(
        &mut rng,
        N,
    );

    println!("\nGenerating ciphertexts...");

    let ciphertext_a = encrypt(
        &mut rng,
        &keygen.pk,
        &[1],
        N,
    );

    let ciphertext_b = encrypt(
        &mut rng,
        &keygen.pk,
        &[1],
        N,
    );

    println!("Ciphertexts generated.");

    println!("\nComputing raw ciphertext product...");

    let product = ciphertext_a.mul_raw(
        &ciphertext_b,
    );

    print_poly_head(
        "product.c0",
        &product.c0,
    );

    print_poly_head(
        "product.c1",
        &product.c1,
    );

    print_poly_head(
        "product.c2",
        &product.c2,
    );

    println!("\nGenerating relinearization key...");

    let relin_key =
        generate_relinearization_key(
            &mut rng,
            &keygen.sk,
            4,
        );

    println!(
        "Relinearization key entries = {}",
        relin_key.entries.len(),
    );

    println!("\nRelinearizing product...");

    let relinearized =
        relinearize(
            &product,
            &relin_key,
        );

    print_poly_head(
        "relinearized.u",
        &relinearized.u,
    );

    print_poly_head(
        "relinearized.v",
        &relinearized.v,
    );

    // ------------------------------------------------------------
    // Compute the phase of the relinearized ciphertext:
    //
    // v' - u'*s
    // ------------------------------------------------------------

    println!("\nComputing relinearized phase...");

    let relinearized_phase =
        relinearized
            .v
            .sub(
                &relinearized
                    .u
                    .mul_ntt(&keygen.sk.s),
            );

    print_poly_head(
        "relinearized phase",
        &relinearized_phase,
    );

    // ------------------------------------------------------------
    // Compute the original degree-2 phase:
    //
    // c0 + c1*s + c2*s^2
    // ------------------------------------------------------------

    println!("\nComputing expected phase...");

    let c1_s =
        product
            .c1
            .mul_ntt(&keygen.sk.s);

    let c2_s2 =
        product
            .c2
            .mul_ntt(&keygen.sk.s)
            .mul_ntt(&keygen.sk.s);

    let expected =
        product
            .c0
            .add(&c1_s)
            .add(&c2_s2);

    print_poly_head(
        "expected phase",
        &expected,
    );

    // ------------------------------------------------------------
    // The two phases are NOT expected to be exactly equal.
    //
    // Their difference is the relinearization/key-switch noise:
    //
    // noise =
    //     relinearized_phase - expected
    // ------------------------------------------------------------

    println!("\nComputing relinearization noise...");

    let noise =
        relinearized_phase.sub(
            &expected,
        );

    let coeffs = noise.to_coeffs_vec();

    let q = keygen.sk.s.modulus();

    let mut max_noise = 0u64;

    for &coeff in coeffs.iter().take(N) {
        let centered = if coeff <= q / 2 {
            coeff as i64
        } else {
            coeff as i64 - q as i64
        };

        max_noise = max_noise.max(
            centered.unsigned_abs(),
        );
    }

    print_poly_head(
        "relinearization noise",
        &noise,
    );

    println!("\nChecking relinearization relation...");
    println!(
        "max |relinearization noise| = {}",
        max_noise
    );

    // Conservative functional bound for the current prototype.
    //
    // With:
    //   N = 256
    //   base = 16
    //   small error coefficients approximately in [-2, 2]
    //
    // the expected key-switch noise is much smaller than Q.
    let noise_bound = 100_000u64;

    assert!(
        max_noise < noise_bound,
        "relinearization noise is too large: {} >= {}",
        max_noise,
        noise_bound,
    );

    println!("\nRESULT: RELINEARIZATION RELATION OK");
    println!(
        "The degree-2 phase is preserved up to relinearization noise."
    );
}

#[test]
fn test_ciphertext_polynomial_multiplication_scaling() {
    use pq_libpep::algebra::ring::PolyRq;
    use pq_libpep::core::rlwe_pke::{
        decrypt_poly,
        encrypt_poly,
        generate_relinearization_key,
        relinearize,
    };

    let mut rng = thread_rng();

    println!("==============================================");
    println!("   RLWE POLYNOMIAL MULTIPLICATION");
    println!("==============================================");
    println!("Ring dimension N = {}", N);

    const P: u64 = 17;
    const Q: u64 = 998_244_353;

    // ------------------------------------------------------------
    // Plaintexts
    //
    // IMPORTANT:
    // encrypt_poly() currently expects the plaintext polynomial
    // to already use modulus q.
    //
    // The plaintext values themselves are in {0,...,16}.
    // ------------------------------------------------------------

    let mut message_a_coeffs = vec![0u64; N];
    let mut message_b_coeffs = vec![0u64; N];

    message_a_coeffs[0] = 3;
    message_b_coeffs[0] = 4;

    let message_a = PolyRq::from_coeffs(
        &message_a_coeffs,
        N,
        Q,
    );

    let message_b = PolyRq::from_coeffs(
        &message_b_coeffs,
        N,
        Q,
    );

    println!("Plaintext modulus P = {}", P);
    println!("Ciphertext modulus Q = {}", Q);

    println!("Plaintext A = 3");
    println!("Plaintext B = 4");
    println!("Expected product = 12");

    // ------------------------------------------------------------
    // RLWE key generation
    // ------------------------------------------------------------

    let keygen = KeyGenResult::keygen(
        &mut rng,
        N,
    );

    // ------------------------------------------------------------
    // Encrypt
    // ------------------------------------------------------------

    println!("\nEncrypting A...");

    let ciphertext_a = encrypt_poly(
        &mut rng,
        &keygen.pk,
        &message_a,
        N,
    );

    println!("Encrypting B...");

    let ciphertext_b = encrypt_poly(
        &mut rng,
        &keygen.pk,
        &message_b,
        N,
    );

    // ------------------------------------------------------------
    // Check normal decryption
    // ------------------------------------------------------------

    println!("\nDecrypting A...");

    let recovered_a = decrypt_poly(
        &keygen.sk,
        &ciphertext_a,
        N,
    );

    println!(
        "Recovered A[0] = {}",
        recovered_a.coefficients()[0]
    );

    println!("Decrypting B...");

    let recovered_b = decrypt_poly(
        &keygen.sk,
        &ciphertext_b,
        N,
    );

    println!(
        "Recovered B[0] = {}",
        recovered_b.coefficients()[0]
    );

    assert_eq!(
        recovered_a.coefficients()[0],
        3,
        "encryption/decryption of A failed",
    );

    assert_eq!(
        recovered_b.coefficients()[0],
        4,
        "encryption/decryption of B failed",
    );

    // ------------------------------------------------------------
    // Raw multiplication
    // ------------------------------------------------------------

    println!("\nComputing raw ciphertext product...");

    let product = ciphertext_a.mul_raw(
        &ciphertext_b,
    );

    print_poly_head(
        "product.c0",
        &product.c0,
    );

    print_poly_head(
        "product.c1",
        &product.c1,
    );

    print_poly_head(
        "product.c2",
        &product.c2,
    );

    // ------------------------------------------------------------
    // Relinearization
    // ------------------------------------------------------------

    println!("\nGenerating relinearization key...");

    let relin_key = generate_relinearization_key(
        &mut rng,
        &keygen.sk,
        4,
    );

    println!(
        "Relinearization key entries = {}",
        relin_key.entries.len(),
    );

    println!("\nRelinearizing product...");

    let relinearized = relinearize(
        &product,
        &relin_key,
    );

    print_poly_head(
        "relinearized.u",
        &relinearized.u,
    );

    print_poly_head(
        "relinearized.v",
        &relinearized.v,
    );

    // ------------------------------------------------------------
    // Decrypt relinearized product
    //
    // IMPORTANT:
    //
    // We expect the decrypted value to expose the scaling problem:
    //
    //     Delta^2 * (3 * 4)
    //
    // instead of:
    //
    //     Delta * 12
    //
    // ------------------------------------------------------------

    println!("\nDecrypting relinearized product...");

    let recovered_product = decrypt_poly(
        &keygen.sk,
        &relinearized,
        N,
    );

    println!(
        "Recovered product coefficient [0] = {}",
        recovered_product.coefficients()[0]
    );

    println!("\nExpected plaintext product = 12");

    println!(
        "Current ciphertext scale after multiplication = Delta^2"
    );

    println!(
        "Current decrypt_poly expects scale = Delta"
    );

    println!(
        "\nRESULT: multiplication + relinearization completed"
    );

    println!(
        "Next step: implement scale correction after multiplication"
    );
}