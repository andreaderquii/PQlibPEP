use pq_libpep::algebra::ring::{round_poly, PolyRq};
use pq_libpep::core::bpr12_oblivious::{
    compose_radix17, decompose_radix17, encrypted_carry_ge_9,
    encrypted_radix17_accumulate_products, encrypted_radix17_accumulate_three_products,
    encrypted_radix17_accumulate_two_products, encrypted_radix17_add_values_prefix,
    encrypted_radix17_digit_add, encrypted_radix17_digit_product,
    encrypted_radix17_low_limb_negacyclic_product,
    encrypted_radix17_negacyclic_product_two_limbs_reference, encrypted_radix17_product_two_limbs,
    encrypted_radix17_scalar_product_nine_limbs, round_one_level_homomorphic,
    round_one_level_radix17, Bpr12HePolynomialValue, Bpr12HeValue,
};
use pq_libpep::core::rlwe_he::RlweHe;
use pq_libpep::core::rlwr::synthesize;
use pq_libpep::core::rlwr_prf::RlwrPrfBase;
use pq_libpep::core::rns::RnsModulusChain;
use rand::thread_rng;

const N: usize = 256;
const N_SMALL: usize = 8;
const PLAINTEXT_MODULUS: u64 = 17;
const Q8: u64 = 17u64.pow(9);
const TEST_RNS_MODULI: [u64; 12] = [
    8_416_769, 8_434_177, 8_573_441, 8_599_553, 8_782_337, 8_825_857, 8_834_561, 8_860_673,
    8_904_193, 9_113_089, 9_139_201, 9_165_313,
];
const CRT17_SLOTS: usize = 8;

fn small_evaluator() -> RlweHe {
    RlweHe::with_chain(RnsModulusChain::new(TEST_RNS_MODULI.to_vec(), N_SMALL))
}

fn test_poly_for_degree(n: usize) -> PolyRq {
    let mut coeffs = vec![0u64; n];
    let values = [0, 1, 16, 17, 289, 12_345, 987_654_321, Q8 - 1];
    for (index, value) in values.iter().copied().enumerate().take(n) {
        coeffs[index] = value;
    }
    PolyRq::from_coeffs(&coeffs, n, Q8)
}

fn test_poly() -> PolyRq {
    test_poly_for_degree(N)
}

#[test]
fn test_bpr12_radix17_roundtrip() {
    let value = test_poly();
    let digits = decompose_radix17(&value, 9);

    assert_eq!(digits.len(), 9);
    for digit in &digits {
        assert_eq!(digit.modulus(), PLAINTEXT_MODULUS);
        assert_eq!(digit.degree_bound(), N);
    }

    let recovered = compose_radix17(&digits, N);
    assert_eq!(recovered.modulus(), Q8);
    assert_eq!(recovered.to_coeffs_vec(), value.to_coeffs_vec());
}

#[test]
fn test_bpr12_value_encrypted_as_radix17_limbs() {
    let mut rng = thread_rng();
    let evaluator = RlweHe::new();
    let keygen = evaluator.keygen(&mut rng, N);

    // Exercise all 256 coefficients with varied radix-17 digits.
    let coeffs: Vec<u64> = (0..N)
        .map(|i| ((i as u64 + 1) * 987_654_321 + 123_456_789) % Q8)
        .collect();

    let value = PolyRq::from_coeffs(&coeffs, N, Q8);
    let expected_digits = decompose_radix17(&value, 9);

    let encrypted = Bpr12HeValue::encrypt(&evaluator, &mut rng, &keygen.pk, &value, 9, N);

    assert_eq!(encrypted.digits(), 9);
    assert_eq!(encrypted.level(), 0);
    assert_eq!(encrypted.slots_per_ciphertext, CRT17_SLOTS);

    // Each limb should now occupy 32 packed ciphertexts, not 256.
    for (limb_index, (encrypted_batch, expected_digit)) in encrypted
        .limbs
        .iter()
        .zip(expected_digits.iter())
        .enumerate()
    {
        assert_eq!(encrypted_batch.len(), N / CRT17_SLOTS);

        for (batch_index, ciphertext) in encrypted_batch.iter().enumerate() {
            let decrypted = evaluator.decrypt(&keygen.sk, ciphertext, N);
            let packed_coeffs = &decrypted.coefficients()[..N];

            let actual_slots = crt17_decode_slots(packed_coeffs);
            let start = batch_index * CRT17_SLOTS;

            let expected_slots: [u64; CRT17_SLOTS] =
                std::array::from_fn(|i| expected_digit.coefficients()[start + i]);

            assert_eq!(
                actual_slots, expected_slots,
                "CRT roundtrip failed for limb {limb_index}, batch {batch_index}"
            );

            // Check that the packed plaintext remains in the expected subring.
            for i in 0..N {
                if i % 32 != 0 {
                    assert_eq!(
                        packed_coeffs[i], 0,
                        "unexpected coefficient {i} in limb {limb_index}, batch {batch_index}"
                    );
                }
            }

            // PolyRq stores N+1 coefficients; the last is padding.
            assert_eq!(
                decrypted.coefficients()[N],
                0,
                "PolyRq padding must remain zero"
            );
        }
    }

    // Verify that all packed limbs reconstruct the original polynomial.
    let recovered = encrypted.decrypt(&evaluator, &keygen.sk, N);

    assert_eq!(recovered.modulus(), Q8);
    assert_eq!(
        &recovered.coefficients()[..N],
        &value.coefficients()[..N],
        "packed limb reconstruction failed"
    );
    assert_eq!(
        recovered.coefficients()[N],
        0,
        "reconstructed PolyRq padding must remain zero"
    );
}

#[test]
fn test_bpr12_encrypted_leaf_selection() {
    let mut rng = thread_rng();
    let evaluator = small_evaluator();
    let keygen = evaluator.keygen(&mut rng, N_SMALL);

    let base = RlwrPrfBase::sample(&mut rng, N_SMALL, Q8, 1);
    assert_eq!(base.s0.len(), 1);
    assert_eq!(base.s1.len(), 1);

    for bit in [0u64, 1u64] {
        let mut coeffs = vec![0u64; N_SMALL];
        coeffs[0] = bit;
        let bit_plaintext = PolyRq::from_coeffs(&coeffs, N_SMALL, PLAINTEXT_MODULUS);
        let encrypted_bit = evaluator.encrypt(&mut rng, &keygen.pk, &bit_plaintext, N_SMALL);

        let selected =
            Bpr12HeValue::select_leaf(&evaluator, &encrypted_bit, &base.s0[0], &base.s1[0]);
        let recovered = selected.decrypt(&evaluator, &keygen.sk, N_SMALL);
        let expected = if bit == 0 { &base.s0[0] } else { &base.s1[0] };
        assert_eq!(
            recovered.to_coeffs_vec(),
            expected.to_coeffs_vec(),
            "encrypted BPR12 leaf selection failed for bit={}",
            bit
        );
    }
}

#[test]
fn test_bpr12_encrypted_leaf_selection_crt_packed_n256() {
    let mut rng = thread_rng();
    let evaluator = RlweHe::new();
    let keygen = evaluator.keygen(&mut rng, N);
    let base = RlwrPrfBase::sample(&mut rng, N, Q8, 1);

    for bit in [0u64, 1u64] {
        // The encrypted selector must be a constant plaintext polynomial.
        let mut bit_coefficients = vec![0u64; N];
        bit_coefficients[0] = bit;
        let bit_plaintext = PolyRq::from_coeffs(&bit_coefficients, N, PLAINTEXT_MODULUS);
        let encrypted_bit = evaluator.encrypt(&mut rng, &keygen.pk, &bit_plaintext, N);

        let selected =
            Bpr12HeValue::select_leaf(&evaluator, &encrypted_bit, &base.s0[0], &base.s1[0]);

        assert_eq!(selected.slots_per_ciphertext, CRT17_SLOTS);
        assert_eq!(selected.digits(), 9);
        for (limb_index, limb) in selected.limbs.iter().enumerate() {
            assert_eq!(
                limb.len(),
                N / CRT17_SLOTS,
                "selected limb {limb_index} must use 32 packed ciphertexts"
            );
        }

        let recovered = selected.decrypt(&evaluator, &keygen.sk, N);
        let expected = if bit == 0 { &base.s0[0] } else { &base.s1[0] };
        assert_eq!(recovered.modulus(), Q8);
        assert_eq!(
            &recovered.coefficients()[..N],
            &expected.coefficients()[..N],
            "CRT-packed leaf selection returned the wrong polynomial for bit={bit}"
        );
        assert_eq!(
            recovered.coefficients()[N],
            0,
            "PolyRq trailing padding must remain zero after CRT-packed leaf selection"
        );
    }
}

#[test]
fn test_bpr12_radix17_rounding_matches_reference() {
    const Q7: u64 = 17u64.pow(8);

    let mut coeffs = vec![0u64; N];
    coeffs[0] = 0;
    coeffs[1] = 8;
    coeffs[2] = 9;
    coeffs[3] = 16;
    coeffs[4] = 17;
    coeffs[5] = 17 + 8;
    coeffs[6] = 17 + 9;
    coeffs[7] = 17u64.pow(4) + 16;
    coeffs[8] = Q8 - 1;

    let value = PolyRq::from_coeffs(&coeffs, N, Q8);
    let reference = round_poly(&value, Q7);
    let radix17 = round_one_level_radix17(&value);

    assert_eq!(reference.modulus(), Q7);
    assert_eq!(radix17.modulus(), Q7);
    assert_eq!(
        radix17.to_coeffs_vec(),
        reference.to_coeffs_vec(),
        "radix-17 rounding does not match BPR12 round_poly()"
    );
}

#[test]
fn test_bpr12_homomorphic_rounding() {
    let mut rng = thread_rng();
    let evaluator = small_evaluator();
    let keygen = evaluator.keygen(&mut rng, N_SMALL);
    let relin_keys = evaluator.generate_relinearization_key_chain(&mut rng, &keygen.sk, 8);

    // Different low/high radix digits in every coefficient. A correct
    // coefficient-wise rounding must produce [2, 5, 7, 9, 1, 0, 5, 4].
    let low_digits = [0u64, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

    let high_digits = [0u64, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

    let coeffs = (0..N_SMALL)
        .map(|i| low_digits[i] + 17 * high_digits[i])
        .collect::<Vec<_>>();
    let value = PolyRq::from_coeffs(&coeffs, N_SMALL, Q8);
    let mut expected = (0..N_SMALL)
        .map(|i| high_digits[i] + (if low_digits[i] >= 9 { 1 } else { 0 }))
        .collect::<Vec<_>>();
    for coefficient in &mut expected {
        *coefficient %= PLAINTEXT_MODULUS;
    }

    let encrypted = Bpr12HeValue::encrypt(&evaluator, &mut rng, &keygen.pk, &value, 2, N_SMALL);
    let fresh_decrypted = encrypted.decrypt(&evaluator, &keygen.sk, N_SMALL);
    assert_eq!(fresh_decrypted.to_coeffs_vec(), value.to_coeffs_vec());

    let rounded = round_one_level_homomorphic(&evaluator, &encrypted, &relin_keys);
    let recovered = rounded.decrypt(&evaluator, &keygen.sk, N_SMALL);
    assert_eq!(
        &recovered.coefficients()[..N_SMALL],
        expected.as_slice(),
        "homomorphic BPR12 rounding must operate independently on every coefficient"
    );
    assert_eq!(
        recovered.coefficients()[N_SMALL],
        0,
        "PolyRq trailing padding coefficient must remain zero"
    );
    assert_eq!(rounded.digits(), 1);
    assert!(rounded.level() > encrypted.level());
}

#[test]
fn test_bpr12_homomorphic_rounding_matches_reference_at_n256() {
    // Use a three-limb modulus here so the active regression exercises a real
    // encrypted overflow from d1 into d2 without requiring the full-depth
    // nine-limb circuit. All 256 coefficients are varied and packed 8 per CT.
    const Q3: u64 = 17u64.pow(3);
    const Q2: u64 = 17u64.pow(2);

    let mut rng = thread_rng();
    let evaluator = RlweHe::new();
    let keygen = evaluator.keygen(&mut rng, N);
    let relin_keys = evaluator.generate_relinearization_key_chain(&mut rng, &keygen.sk, 8);

    let low_pattern = [0u64, 8, 9, 10, 16, 7, 15, 9];
    let middle_pattern = [16u64, 16, 16, 15, 0, 16, 15, 16];
    let high_digits: Vec<u64> = (0..N)
        .map(|i| ((i as u64) * 11 + 5) % PLAINTEXT_MODULUS)
        .collect();
    let low_digits: Vec<u64> = (0..N).map(|i| low_pattern[i % low_pattern.len()]).collect();
    let middle_digits: Vec<u64> = (0..N)
        .map(|i| middle_pattern[i % middle_pattern.len()])
        .collect();

    let input_coefficients: Vec<u64> = (0..N)
        .map(|i| low_digits[i] + 17 * middle_digits[i] + 17u64.pow(2) * high_digits[i])
        .collect();
    let value = PolyRq::from_coeffs(&input_coefficients, N, Q3);

    // Keep the independent arithmetic implementations aligned first.
    let reference = round_one_level_radix17(&value);
    let arithmetic = round_poly(&value, Q2);
    assert_eq!(reference.modulus(), Q2);
    assert_eq!(arithmetic.modulus(), Q2);
    assert_eq!(
        &reference.coefficients()[..N],
        &arithmetic.coefficients()[..N],
        "radix-17 reference must agree with round_poly for the test polynomial"
    );

    let encrypted = Bpr12HeValue::encrypt(&evaluator, &mut rng, &keygen.pk, &value, 3, N);
    assert_eq!(encrypted.slots_per_ciphertext, CRT17_SLOTS);
    assert_eq!(encrypted.digits(), 3);
    assert!(encrypted
        .limbs
        .iter()
        .all(|limb| limb.len() == N / CRT17_SLOTS));

    let fresh = encrypted.decrypt(&evaluator, &keygen.sk, N);
    assert_eq!(fresh.modulus(), Q3);
    assert_eq!(
        &fresh.coefficients()[..N],
        &value.coefficients()[..N],
        "CRT-packed BPR12 encryption roundtrip failed before rounding"
    );
    assert_eq!(
        fresh.coefficients()[N],
        0,
        "PolyRq input padding must remain zero"
    );

    // This verifies full integer rounding modulo 17^2, not merely the result
    // modulo 17. Cases with d0 >= 9 and d1 == 16 must propagate a carry into d2.
    let rounded = round_one_level_homomorphic(&evaluator, &encrypted, &relin_keys);
    let recovered = rounded.decrypt(&evaluator, &keygen.sk, N);
    assert_eq!(rounded.slots_per_ciphertext, CRT17_SLOTS);
    assert_eq!(rounded.digits(), 2);
    assert_eq!(rounded.level(), 5);
    assert_eq!(recovered.modulus(), Q2);
    assert!(rounded
        .limbs
        .iter()
        .all(|limb| limb.len() == N / CRT17_SLOTS));
    assert_eq!(
        &recovered.coefficients()[..N],
        &arithmetic.coefficients()[..N],
        "CRT-packed homomorphic rounding must match the full arithmetic result at N=256"
    );
    assert_eq!(
        recovered.coefficients()[N],
        0,
        "PolyRq output padding must remain zero"
    );
}

#[test]
fn test_bpr12_encrypted_carry_at_ring_dimension_256() {
    // Test the carry indicator at the production-shaped ring dimension N=256.
    // We exercise representative scalar inputs instead of encrypting all 256
    // source coefficients, keeping this regression test reasonably fast.
    let mut rng = thread_rng();
    let evaluator = RlweHe::new();
    let keygen = evaluator.keygen(&mut rng, N);
    let relin_keys = evaluator.generate_relinearization_key_chain(&mut rng, &keygen.sk, 8);

    let low_digits = [8u64, 9, 10, 16, 0, 1, 7, 12];
    let high_digits = [2u64, 4, 6, 8, 1, 0, 5, 3];

    for index in 0..low_digits.len() {
        let mut low_coefficients = vec![0u64; N];
        low_coefficients[0] = low_digits[index];
        let low_plaintext = PolyRq::from_coeffs(&low_coefficients, N, PLAINTEXT_MODULUS);
        let low_ciphertext = evaluator.encrypt(&mut rng, &keygen.pk, &low_plaintext, N);

        let carry = encrypted_carry_ge_9(&evaluator, &low_ciphertext, &relin_keys);
        assert_eq!(
            carry.level, 4,
            "indicator should consume four multiplication levels"
        );

        let mut high_coefficients = vec![0u64; N];
        high_coefficients[0] = high_digits[index];
        let high_plaintext = PolyRq::from_coeffs(&high_coefficients, N, PLAINTEXT_MODULUS);
        let high_ciphertext = evaluator.encrypt(&mut rng, &keygen.pk, &high_plaintext, N);
        let high_at_carry_level = evaluator.modulus_switch_to_level(&high_ciphertext, carry.level);
        let rounded = evaluator.add_ciphertexts(&high_at_carry_level, &carry);
        let recovered = evaluator.decrypt(&keygen.sk, &rounded, N);

        let expected = (high_digits[index] + u64::from(low_digits[index] >= 9)) % PLAINTEXT_MODULUS;
        assert_eq!(
            recovered.coefficients()[0],
            expected,
            "N=256 carry/rounding failed at vector index {index}"
        );
        assert!(
            recovered.coefficients()[1..N]
                .iter()
                .all(|&coefficient| coefficient == 0),
            "scalar rounding at index {index} produced nonconstant ring coefficients"
        );
        assert_eq!(
            recovered.coefficients()[N],
            0,
            "PolyRq trailing padding coefficient must remain zero at index {index}"
        );
    }
}

#[test]
fn test_bpr12_homomorphic_power_chain() {
    let mut rng = thread_rng();
    let evaluator = RlweHe::new();
    let keygen = evaluator.keygen(&mut rng, N);
    let relin_keys = evaluator.generate_relinearization_key_chain(&mut rng, &keygen.sk, 8);

    let mut coeffs = vec![0u64; N];
    coeffs[0] = 13;
    let x = PolyRq::from_coeffs(&coeffs, N, PLAINTEXT_MODULUS);
    let mut ciphertext = evaluator.encrypt(&mut rng, &keygen.pk, &x, N);

    // The powers are x^2, x^4, x^8, x^16 in R_17.
    for (expected_level, expected_constant) in [(1usize, 16u64), (2, 1), (3, 1), (4, 1)] {
        ciphertext = evaluator.mul_ciphertext(&ciphertext, &ciphertext, &relin_keys);
        let decoded = evaluator.decrypt(&keygen.sk, &ciphertext, N);
        assert_eq!(ciphertext.level, expected_level);
        assert_eq!(
            decoded.coefficients()[0],
            expected_constant,
            "homomorphic power at level {} decoded incorrectly",
            expected_level
        );
        assert!(
            decoded.coefficients()[1..]
                .iter()
                .all(|&coefficient| coefficient == 0),
            "constant input acquired nonzero plaintext coefficients at level {}",
            expected_level
        );
    }
}

#[test]
#[ignore = "Slow extended regression: full q=17^9 carry propagation across all 256 coefficients"]
fn test_bpr12_homomorphic_rounding_all_256_coefficients() {
    let test_started = std::time::Instant::now();
    eprintln!("[BPR12 TEST +0.0s] starting full q=17^9 regression: N=256, 9 limbs, 32 CRT batches per limb");

    let mut rng = thread_rng();
    let evaluator = RlweHe::new();
    eprintln!(
        "[BPR12 TEST +{:.1}s] generating HE/RNS keys",
        test_started.elapsed().as_secs_f64()
    );
    let keygen = evaluator.keygen(&mut rng, N);
    eprintln!(
        "[BPR12 TEST +{:.1}s] key generation complete; generating relinearization keys",
        test_started.elapsed().as_secs_f64()
    );
    let relin_keys = evaluator.generate_relinearization_key_chain(&mut rng, &keygen.sk, 8);
    eprintln!(
        "[BPR12 TEST +{:.1}s] relinearization keys ready",
        test_started.elapsed().as_secs_f64()
    );

    // Build full nine-limb coefficients with varied digits. Every 32nd
    // coefficient includes d0 >= 9 and a run of d1..d7 == 16, exercising
    // propagation through several higher digits. Other coefficients cover the
    // threshold boundary and varied nonzero digits across the polynomial.
    let input_coefficients: Vec<u64> = (0..N)
        .map(|i| {
            let mut digits: [u64; 9] =
                std::array::from_fn(|j| ((i as u64) * 7 + (j as u64) * 11 + 3) % PLAINTEXT_MODULUS);
            digits[0] = (i as u64) % PLAINTEXT_MODULUS;
            if i % 32 == 0 {
                digits[0] = 9;
                for digit in &mut digits[1..8] {
                    *digit = 16;
                }
            }

            digits
                .iter()
                .enumerate()
                .map(|(digit_index, digit)| *digit * 17u64.pow(digit_index as u32))
                .sum()
        })
        .collect();
    let value = PolyRq::from_coeffs(&input_coefficients, N, Q8);
    eprintln!("[BPR12 TEST +{:.1}s] constructed 256 inputs, including long carry chains; checking plaintext references", test_started.elapsed().as_secs_f64());
    let expected = round_one_level_radix17(&value);
    let arithmetic = round_poly(&value, 17u64.pow(8));
    assert_eq!(
        &expected.coefficients()[..N],
        &arithmetic.coefficients()[..N],
        "radix-17 rounding reference disagrees with round_poly"
    );

    eprintln!(
        "[BPR12 TEST +{:.1}s] plaintext references agree; encrypting all 9 CRT-packed limbs",
        test_started.elapsed().as_secs_f64()
    );
    let encrypted = Bpr12HeValue::encrypt(&evaluator, &mut rng, &keygen.pk, &value, 9, N);
    eprintln!(
        "[BPR12 TEST +{:.1}s] encryption complete; checking encrypt/decrypt roundtrip",
        test_started.elapsed().as_secs_f64()
    );
    assert_eq!(encrypted.slots_per_ciphertext, CRT17_SLOTS);
    assert_eq!(encrypted.digits(), 9);
    assert!(encrypted
        .limbs
        .iter()
        .all(|limb| limb.len() == N / CRT17_SLOTS));

    let fresh = encrypted.decrypt(&evaluator, &keygen.sk, N);
    assert_eq!(
        &fresh.coefficients()[..N],
        &value.coefficients()[..N],
        "full CRT-packed BPR12 encryption roundtrip failed"
    );
    assert_eq!(
        fresh.coefficients()[N],
        0,
        "PolyRq input padding must remain zero"
    );
    eprintln!("[BPR12 TEST +{:.1}s] roundtrip passed; starting homomorphic rounding (most expensive phase)", test_started.elapsed().as_secs_f64());

    let rounded = round_one_level_homomorphic(&evaluator, &encrypted, &relin_keys);
    eprintln!(
        "[BPR12 TEST +{:.1}s] homomorphic rounding returned at level {}; decrypting final result",
        test_started.elapsed().as_secs_f64(),
        rounded.level()
    );
    let recovered = rounded.decrypt(&evaluator, &keygen.sk, N);
    assert_eq!(rounded.slots_per_ciphertext, CRT17_SLOTS);
    assert_eq!(rounded.digits(), 8);
    assert_eq!(rounded.level(), 8);
    assert_eq!(recovered.modulus(), 17u64.pow(8));
    assert!(rounded
        .limbs
        .iter()
        .all(|limb| limb.len() == N / CRT17_SLOTS));
    assert_eq!(
        &recovered.coefficients()[..N],
        &arithmetic.coefficients()[..N],
        "full q=17^9 BPR12 rounding failed at N=256"
    );
    assert_eq!(
        recovered.coefficients()[N],
        0,
        "PolyRq output padding must remain zero"
    );
    eprintln!(
        "[BPR12 TEST +{:.1}s] PASS: full q=17^9 rounding validated",
        test_started.elapsed().as_secs_f64()
    );
}

/////// prova 256
const CRT17_MODULUS: u64 = 17;
const CRT17_N: usize = 256;
const CRT17_SLOT_CONSTANTS: [u64; 8] = [3, 5, 6, 7, 10, 11, 12, 14];

fn crt17_inverse(a: u64) -> u64 {
    (1u64..17)
        .find(|candidate| (a * candidate) % 17 == 1)
        .expect("CRT denominator must be invertible modulo 17")
}

// Encodes 8 scalar slots into F_17[X] / (X^256 + 1).
// X^256 + 1 = product_i (X^32 + c_i) over F_17.
fn crt17_encode_slots(slots: [u64; 8]) -> Vec<u64> {
    let mut encoded = vec![0u64; CRT17_N];

    for i in 0..8 {
        let mut h = vec![1u64];

        // H_i(Y) = product_{j != i} (Y + c_j), with Y = X^32.
        for j in 0..8 {
            if i == j {
                continue;
            }

            let mut next = vec![0u64; h.len() + 1];

            for (k, &coefficient) in h.iter().enumerate() {
                next[k] = (next[k] + coefficient * CRT17_SLOT_CONSTANTS[j]) % 17;
                next[k + 1] = (next[k + 1] + coefficient) % 17;
            }

            h = next;
        }

        // Normalize so that H_i(-c_i) = 1 in slot i.
        let mut denominator = 1u64;
        for j in 0..8 {
            if i != j {
                let difference = (CRT17_SLOT_CONSTANTS[j] + 17 - CRT17_SLOT_CONSTANTS[i]) % 17;
                denominator = denominator * difference % 17;
            }
        }

        let scale = crt17_inverse(denominator);

        for (k, &coefficient) in h.iter().enumerate() {
            let index = 32 * k;
            let term = (slots[i] % 17) * coefficient % 17 * scale % 17;
            encoded[index] = (encoded[index] + term) % 17;
        }
    }

    encoded
}

// Decodes the eight scalar components from their CRT representation.
fn crt17_decode_slots(poly: &[u64]) -> [u64; 8] {
    assert_eq!(poly.len(), CRT17_N);

    let mut slots = [0u64; 8];

    for i in 0..8 {
        let base = (17 - CRT17_SLOT_CONSTANTS[i]) % 17;
        let mut power = 1u64;
        let mut value = 0u64;

        for k in 0..8 {
            value = (value + poly[32 * k] * power) % 17;
            power = power * base % 17;
        }

        slots[i] = value;
    }

    slots
}

/// Verifies the first exact arithmetic primitive needed by an encrypted
/// radix-17 product: one digit multiplication with an explicit carry digit.
/// Eight CRT slots are used in parallel, including zero and upper-bound cases.
#[test]
fn test_encrypted_radix17_digit_product_crt_packed() {
    let mut rng = thread_rng();
    let evaluator = RlweHe::new();

    eprintln!("[BPR12 DIGIT PRODUCT] 1/5: generating RLWE keys");
    let keygen = evaluator.keygen(&mut rng, N);
    eprintln!("[BPR12 DIGIT PRODUCT] 2/5: generating relinearization-key chain");
    let relin_keys = evaluator.generate_relinearization_key_chain(&mut rng, &keygen.sk, 8);

    // Include cases that exercise both ends of the digit range and nontrivial
    // carries. All eight pairs are evaluated simultaneously in CRT slots.
    let a_slots = [0u64, 1, 2, 8, 9, 12, 16, 16];
    let b_slots = [0u64, 16, 9, 8, 9, 16, 16, 9];
    let a_plaintext = PolyRq::from_coeffs(&crt17_encode_slots(a_slots), N, PLAINTEXT_MODULUS);
    let b_plaintext = PolyRq::from_coeffs(&crt17_encode_slots(b_slots), N, PLAINTEXT_MODULUS);

    eprintln!("[BPR12 DIGIT PRODUCT] 3/5: encrypting eight digit pairs");
    let encrypted_a = evaluator.encrypt(&mut rng, &keygen.pk, &a_plaintext, N);
    let encrypted_b = evaluator.encrypt(&mut rng, &keygen.pk, &b_plaintext, N);

    eprintln!("[BPR12 DIGIT PRODUCT] 4/5: evaluating low and high radix-17 digits");
    eprintln!("[BPR12 DIGIT PRODUCT]    set PQBPR12_PROGRESS=1 for detailed circuit-stage logs");
    let (encrypted_low, encrypted_high) =
        encrypted_radix17_digit_product(&evaluator, &encrypted_a, &encrypted_b, &relin_keys);
    assert_eq!(encrypted_low.level, 5);
    assert_eq!(encrypted_high.level, 5);

    eprintln!("[BPR12 DIGIT PRODUCT] 5/5: decrypting and checking all CRT slots");
    let low_plaintext = evaluator.decrypt(&keygen.sk, &encrypted_low, N);
    let high_plaintext = evaluator.decrypt(&keygen.sk, &encrypted_high, N);
    let actual_low = crt17_decode_slots(&low_plaintext.coefficients()[..N]);
    let actual_high = crt17_decode_slots(&high_plaintext.coefficients()[..N]);
    let expected_low: [u64; CRT17_SLOTS] =
        std::array::from_fn(|i| (a_slots[i] * b_slots[i]) % PLAINTEXT_MODULUS);
    let expected_high: [u64; CRT17_SLOTS] =
        std::array::from_fn(|i| (a_slots[i] * b_slots[i]) / PLAINTEXT_MODULUS);

    assert_eq!(
        actual_low, expected_low,
        "low radix-17 digits are incorrect"
    );
    assert_eq!(
        actual_high, expected_high,
        "high radix-17 carry digits are incorrect"
    );
    assert_eq!(
        low_plaintext.coefficients()[N],
        0,
        "low digit padding must remain zero"
    );
    assert_eq!(
        high_plaintext.coefficients()[N],
        0,
        "high digit padding must remain zero"
    );
    eprintln!("[BPR12 DIGIT PRODUCT] PASS: low and high digits match the integer reference");
}

/// Composes the single-digit multiplier into an exact two-limb product
/// modulo 17^2, independently in each CRT17 SIMD slot.
/// This validates radix cross terms, but does not claim polynomial convolution.
#[test]
fn test_encrypted_radix17_two_limb_product_crt_packed() {
    use std::time::Instant;

    let started = Instant::now();
    let mut rng = thread_rng();
    let evaluator = RlweHe::new();
    eprintln!("[BPR12 TWO-LIMB] 1/6: generating RLWE keys");
    let keygen = evaluator.keygen(&mut rng, N);
    eprintln!(
        "[BPR12 TWO-LIMB +{:.1}s] 2/6: generating relinearization-key chain",
        started.elapsed().as_secs_f64()
    );
    let relin_keys = evaluator.generate_relinearization_key_chain(&mut rng, &keygen.sk, 8);

    let lhs_low_slots = [0u64, 1, 2, 8, 9, 12, 16, 16];
    let lhs_high_slots = [0u64, 3, 4, 16, 2, 13, 16, 7];
    let rhs_low_slots = [0u64, 16, 9, 8, 9, 16, 16, 9];
    let rhs_high_slots = [1u64, 1, 8, 0, 16, 2, 1, 10];

    eprintln!(
        "[BPR12 TWO-LIMB +{:.1}s] 3/6: encoding and encrypting four digit vectors",
        started.elapsed().as_secs_f64()
    );
    let lhs_low_plain =
        PolyRq::from_coeffs(&crt17_encode_slots(lhs_low_slots), N, PLAINTEXT_MODULUS);
    let lhs_high_plain =
        PolyRq::from_coeffs(&crt17_encode_slots(lhs_high_slots), N, PLAINTEXT_MODULUS);
    let rhs_low_plain =
        PolyRq::from_coeffs(&crt17_encode_slots(rhs_low_slots), N, PLAINTEXT_MODULUS);
    let rhs_high_plain =
        PolyRq::from_coeffs(&crt17_encode_slots(rhs_high_slots), N, PLAINTEXT_MODULUS);
    let encrypted_lhs_low = evaluator.encrypt(&mut rng, &keygen.pk, &lhs_low_plain, N);
    let encrypted_lhs_high = evaluator.encrypt(&mut rng, &keygen.pk, &lhs_high_plain, N);
    let encrypted_rhs_low = evaluator.encrypt(&mut rng, &keygen.pk, &rhs_low_plain, N);
    let encrypted_rhs_high = evaluator.encrypt(&mut rng, &keygen.pk, &rhs_high_plain, N);

    eprintln!(
        "[BPR12 TWO-LIMB +{:.1}s] 4/6: evaluating product modulo 17^2",
        started.elapsed().as_secs_f64()
    );
    let (encrypted_product_low, encrypted_product_high) = encrypted_radix17_product_two_limbs(
        &evaluator,
        &encrypted_lhs_low,
        &encrypted_lhs_high,
        &encrypted_rhs_low,
        &encrypted_rhs_high,
        &relin_keys,
    );
    assert_eq!(encrypted_product_low.level, 5);
    assert_eq!(encrypted_product_high.level, 5);

    eprintln!(
        "[BPR12 TWO-LIMB +{:.1}s] 5/6: decrypting and extracting CRT slots",
        started.elapsed().as_secs_f64()
    );
    let low_plain = evaluator.decrypt(&keygen.sk, &encrypted_product_low, N);
    let high_plain = evaluator.decrypt(&keygen.sk, &encrypted_product_high, N);
    let actual_low = crt17_decode_slots(&low_plain.coefficients()[..N]);
    let actual_high = crt17_decode_slots(&high_plain.coefficients()[..N]);

    eprintln!(
        "[BPR12 TWO-LIMB +{:.1}s] 6/6: comparing all eight slots with integer arithmetic",
        started.elapsed().as_secs_f64()
    );
    let expected_pairs: [(u64, u64); CRT17_SLOTS] = std::array::from_fn(|i| {
        let lhs = lhs_low_slots[i] + 17 * lhs_high_slots[i];
        let rhs = rhs_low_slots[i] + 17 * rhs_high_slots[i];
        let product = (lhs * rhs) % 289;
        (product % 17, product / 17)
    });
    let expected_low: [u64; CRT17_SLOTS] = std::array::from_fn(|i| expected_pairs[i].0);
    let expected_high: [u64; CRT17_SLOTS] = std::array::from_fn(|i| expected_pairs[i].1);

    assert_eq!(
        actual_low, expected_low,
        "two-limb product low digit is incorrect"
    );
    assert_eq!(
        actual_high, expected_high,
        "two-limb product second digit is incorrect"
    );
    assert!(
        low_plain.coefficients()[N..].iter().all(|&x| x == 0),
        "low-digit padding must remain zero"
    );
    assert!(
        high_plain.coefficients()[N..].iter().all(|&x| x == 0),
        "high-digit padding must remain zero"
    );
    eprintln!(
        "[BPR12 TWO-LIMB +{:.1}s] PASS: product modulo 289 is exact in all CRT slots",
        started.elapsed().as_secs_f64()
    );
}

/// Checks carry-aware addition of two radix-17 digits in eight CRT17 slots.
/// The exhaustive arithmetic table is checked in the module unit test; this test
/// verifies the actual HE circuit, level alignment, and slot decoding.
#[test]
fn test_encrypted_radix17_digit_add_crt_packed() {
    use std::time::Instant;

    let started = Instant::now();
    let mut rng = thread_rng();
    let evaluator = RlweHe::new();
    eprintln!("[BPR12 DIGIT ADD] 1/6: generating RLWE keys");
    let keygen = evaluator.keygen(&mut rng, N);
    eprintln!(
        "[BPR12 DIGIT ADD +{:.1}s] 2/6: generating relinearization-key chain",
        started.elapsed().as_secs_f64()
    );
    let relin_keys = evaluator.generate_relinearization_key_chain(&mut rng, &keygen.sk, 8);

    let a_slots = [0u64, 1, 8, 9, 16, 16, 7, 15];
    let b_slots = [0u64, 1, 8, 8, 1, 16, 10, 16];
    let a_plain = PolyRq::from_coeffs(&crt17_encode_slots(a_slots), N, PLAINTEXT_MODULUS);
    let b_plain = PolyRq::from_coeffs(&crt17_encode_slots(b_slots), N, PLAINTEXT_MODULUS);
    eprintln!(
        "[BPR12 DIGIT ADD +{:.1}s] 3/6: encrypting eight digit pairs",
        started.elapsed().as_secs_f64()
    );
    let encrypted_a = evaluator.encrypt(&mut rng, &keygen.pk, &a_plain, N);
    let encrypted_b = evaluator.encrypt(&mut rng, &keygen.pk, &b_plain, N);

    eprintln!(
        "[BPR12 DIGIT ADD +{:.1}s] 4/6: evaluating encrypted sum and carry",
        started.elapsed().as_secs_f64()
    );
    let (encrypted_low, encrypted_carry) =
        encrypted_radix17_digit_add(&evaluator, &encrypted_a, &encrypted_b, &relin_keys);
    assert_eq!(encrypted_low.level, 5);
    assert_eq!(encrypted_carry.level, 5);

    eprintln!(
        "[BPR12 DIGIT ADD +{:.1}s] 5/6: decrypting and extracting CRT slots",
        started.elapsed().as_secs_f64()
    );
    let low_plain = evaluator.decrypt(&keygen.sk, &encrypted_low, N);
    let carry_plain = evaluator.decrypt(&keygen.sk, &encrypted_carry, N);
    let actual_low = crt17_decode_slots(&low_plain.coefficients()[..N]);
    let actual_carry = crt17_decode_slots(&carry_plain.coefficients()[..N]);

    eprintln!(
        "[BPR12 DIGIT ADD +{:.1}s] 6/6: comparing all slots with integer addition",
        started.elapsed().as_secs_f64()
    );
    let expected_low: [u64; CRT17_SLOTS] = std::array::from_fn(|i| (a_slots[i] + b_slots[i]) % 17);
    let expected_carry: [u64; CRT17_SLOTS] =
        std::array::from_fn(|i| (a_slots[i] + b_slots[i]) / 17);
    assert_eq!(
        actual_low, expected_low,
        "low digit of encrypted sum is incorrect"
    );
    assert_eq!(
        actual_carry, expected_carry,
        "carry of encrypted sum is incorrect"
    );
    assert!(
        low_plain.coefficients()[N..].iter().all(|&x| x == 0),
        "low-digit padding must remain zero"
    );
    assert!(
        carry_plain.coefficients()[N..].iter().all(|&x| x == 0),
        "carry padding must remain zero"
    );
    eprintln!(
        "[BPR12 DIGIT ADD +{:.1}s] PASS: sum and carry match all eight CRT slots",
        started.elapsed().as_secs_f64()
    );
}

/// Checks that encrypted leaf selection preserves ordinary polynomial
/// coefficients (one encrypted polynomial per radix digit, not CRT slots).
#[test]
fn test_bpr12_polynomial_coefficient_basis_leaf_selection() {
    use std::time::Instant;

    let started = Instant::now();
    let mut rng = thread_rng();
    let evaluator = RlweHe::new();
    eprintln!("[BPR12 POLY-LEAF] 1/5: generating RLWE keys");
    let keygen = evaluator.keygen(&mut rng, N);

    eprintln!(
        "[BPR12 POLY-LEAF +{:.1}s] 2/5: building two q=17^9 polynomial leaves",
        started.elapsed().as_secs_f64()
    );
    let s0_coeffs: Vec<u64> = (0..N)
        .map(|i| ((i as u64 * 987_654_321 + 123_456_789) % Q8))
        .collect();
    let s1_coeffs: Vec<u64> = (0..N)
        .map(|i| ((i as u64 * 314_159_265 + 17 * i as u64 * i as u64 + Q8 - 77) % Q8))
        .collect();
    let s0 = PolyRq::from_coeffs(&s0_coeffs, N, Q8);
    let s1 = PolyRq::from_coeffs(&s1_coeffs, N, Q8);

    for (bit, expected) in [(0u64, &s0), (1u64, &s1)] {
        eprintln!(
            "[BPR12 POLY-LEAF +{:.1}s] 3/5: encrypting selector bit {}",
            started.elapsed().as_secs_f64(),
            bit
        );
        let mut bit_coeffs = vec![0u64; N];
        bit_coeffs[0] = bit;
        let encrypted_bit = evaluator.encrypt(
            &mut rng,
            &keygen.pk,
            &PolyRq::from_coeffs(&bit_coeffs, N, PLAINTEXT_MODULUS),
            N,
        );

        eprintln!(
            "[BPR12 POLY-LEAF +{:.1}s] 4/5: selecting all 256 coefficients across 9 limbs",
            started.elapsed().as_secs_f64()
        );
        let selected = Bpr12HePolynomialValue::select_leaf(&evaluator, &encrypted_bit, &s0, &s1);
        assert_eq!(selected.digits(), 9);
        assert_eq!(selected.level, 0);

        let actual = selected.decrypt(&evaluator, &keygen.sk, N);
        assert_eq!(
            &actual.coefficients()[..N],
            &expected.coefficients()[..N],
            "coefficient-basis leaf selection returned the wrong polynomial for bit {bit}"
        );
        eprintln!(
            "[BPR12 POLY-LEAF +{:.1}s] 5/5: PASS for encrypted bit {}",
            started.elapsed().as_secs_f64(),
            bit
        );
    }
}

/// Bridges the radix-17 representation to the actual ring operation.
/// The first digit of a product in R_(17^9) is the negacyclic product of the
/// first digit polynomials in R_17. Unlike CRT-packed SIMD multiplication,
/// this path uses the ordinary coefficient basis and therefore computes the
/// polynomial convolution required by BPR12.
#[test]
fn test_bpr12_encrypted_low_limb_matches_negacyclic_product() {
    use std::time::Instant;

    let started = Instant::now();
    let mut rng = thread_rng();
    let evaluator = RlweHe::new();
    eprintln!("[BPR12 LOW-LIMB] 1/6: generating RLWE keys");
    let keygen = evaluator.keygen(&mut rng, N);
    eprintln!(
        "[BPR12 LOW-LIMB +{:.1}s] 2/6: generating relinearization-key chain",
        started.elapsed().as_secs_f64()
    );
    let relin_keys = evaluator.generate_relinearization_key_chain(&mut rng, &keygen.sk, 8);

    eprintln!(
        "[BPR12 LOW-LIMB +{:.1}s] 3/6: building deterministic q=17^9 test polynomials",
        started.elapsed().as_secs_f64()
    );
    let lhs_coeffs: Vec<u64> = (0..N)
        .map(|i| ((i as u64 * 7_919_191 + 17 * i as u64 * i as u64 + 123_456_789) % Q8))
        .collect();
    let rhs_coeffs: Vec<u64> = (0..N)
        .map(|i| ((i as u64 * 1_234_567 + 31 * i as u64 * i as u64 + Q8 - 19) % Q8))
        .collect();
    let lhs_plain = PolyRq::from_coeffs(&lhs_coeffs, N, Q8);
    let rhs_plain = PolyRq::from_coeffs(&rhs_coeffs, N, Q8);

    let expected_product = lhs_plain.mul_negacyclic(&rhs_plain);
    let expected_product_digits = decompose_radix17(&expected_product, 9);
    let expected_low = &expected_product_digits[0];
    let lhs_digits = decompose_radix17(&lhs_plain, 9);
    let rhs_digits = decompose_radix17(&rhs_plain, 9);
    let low_limb_reference = lhs_digits[0].mul_negacyclic(&rhs_digits[0]);
    assert_eq!(
        &expected_low.coefficients()[..N],
        &low_limb_reference.coefficients()[..N],
        "plaintext identity (A*B mod 17) = (A_0*B_0 mod 17) must hold"
    );

    eprintln!(
        "[BPR12 LOW-LIMB +{:.1}s] 4/6: encrypting coefficient-basis radix-17 limbs",
        started.elapsed().as_secs_f64()
    );
    let encrypted_lhs =
        Bpr12HePolynomialValue::encrypt(&evaluator, &mut rng, &keygen.pk, &lhs_plain, 9, N);
    let encrypted_rhs =
        Bpr12HePolynomialValue::encrypt(&evaluator, &mut rng, &keygen.pk, &rhs_plain, 9, N);
    assert_eq!(encrypted_lhs.digits(), 9);
    assert_eq!(encrypted_rhs.digits(), 9);
    assert_eq!(encrypted_lhs.level, 0);
    assert_eq!(encrypted_rhs.level, 0);
    assert_eq!(
        &encrypted_lhs
            .decrypt(&evaluator, &keygen.sk, N)
            .coefficients()[..N],
        &lhs_plain.coefficients()[..N],
        "coefficient-basis lhs radix decomposition must round-trip"
    );
    assert_eq!(
        &encrypted_rhs
            .decrypt(&evaluator, &keygen.sk, N)
            .coefficients()[..N],
        &rhs_plain.coefficients()[..N],
        "coefficient-basis rhs radix decomposition must round-trip"
    );

    eprintln!(
        "[BPR12 LOW-LIMB +{:.1}s] 5/6: evaluating one encrypted negacyclic product",
        started.elapsed().as_secs_f64()
    );
    let encrypted_low = encrypted_radix17_low_limb_negacyclic_product(
        &evaluator,
        &encrypted_lhs,
        &encrypted_rhs,
        &relin_keys,
    );
    assert_eq!(
        encrypted_low.level, 1,
        "one ciphertext product should consume one HE level"
    );

    eprintln!(
        "[BPR12 LOW-LIMB +{:.1}s] 6/6: decrypting and comparing all 256 coefficients",
        started.elapsed().as_secs_f64()
    );
    let actual_low = evaluator.decrypt(&keygen.sk, &encrypted_low, N);
    assert_eq!(
        &actual_low.coefficients()[..N],
        &expected_low.coefficients()[..N],
        "encrypted lowest product limb must match the plaintext R_(17^9) product"
    );
    eprintln!(
        "[BPR12 LOW-LIMB +{:.1}s] PASS: encrypted low digit matches the q-ring product",
        started.elapsed().as_secs_f64()
    );
}

/// Documents an important representation boundary for BPR12 synthesis:
/// multiplying two CRT-packed ciphertexts multiplies their eight slots
/// pointwise. It does NOT compute the negacyclic convolution of the original
/// 256-coefficient polynomials whose first eight coefficients supplied those
/// slots. A future encrypted synthesizer must explicitly account for this.
#[test]
fn test_crt17_packed_product_is_slotwise_not_polynomial_convolution() {
    let mut rng = thread_rng();
    let evaluator = RlweHe::new();
    let keygen = evaluator.keygen(&mut rng, CRT17_N);
    let relin_keys = evaluator.generate_relinearization_key_chain(&mut rng, &keygen.sk, 8);

    // The same eight values are treated in two different ways:
    // 1. as eight independent SIMD slots in the CRT-packed encoding;
    // 2. as the first eight coefficients of an ordinary ring polynomial.
    let a_slots = [1u64, 2, 4, 7, 11, 13, 15, 16];
    let b_slots = [3u64, 5, 8, 9, 12, 14, 6, 10];

    let packed_a = crt17_encode_slots(a_slots);
    let packed_b = crt17_encode_slots(b_slots);
    let plaintext_a = PolyRq::from_coeffs(&packed_a, CRT17_N, CRT17_MODULUS);
    let plaintext_b = PolyRq::from_coeffs(&packed_b, CRT17_N, CRT17_MODULUS);

    let encrypted_a = evaluator.encrypt(&mut rng, &keygen.pk, &plaintext_a, CRT17_N);
    let encrypted_b = evaluator.encrypt(&mut rng, &keygen.pk, &plaintext_b, CRT17_N);
    let encrypted_product = evaluator.mul_ciphertext(&encrypted_a, &encrypted_b, &relin_keys);
    assert_eq!(encrypted_product.level, 1);

    let decrypted_product = evaluator.decrypt(&keygen.sk, &encrypted_product, CRT17_N);
    let actual_slots = crt17_decode_slots(&decrypted_product.coefficients()[..CRT17_N]);
    let expected_slots = std::array::from_fn(|i| (a_slots[i] * b_slots[i]) % CRT17_MODULUS);
    assert_eq!(
        actual_slots, expected_slots,
        "CRT product must multiply each slot pointwise"
    );
    assert_eq!(
        decrypted_product.coefficients()[CRT17_N],
        0,
        "PolyRq padding must remain zero after packed multiplication"
    );

    // Now interpret the same arrays as ordinary polynomial coefficients. The
    // RLWR/BPR12 synthesizer requires this negacyclic convolution, which is a
    // different operation from the slot-wise product above.
    let mut a_coefficients = vec![0u64; CRT17_N];
    let mut b_coefficients = vec![0u64; CRT17_N];
    a_coefficients[..CRT17_SLOTS].copy_from_slice(&a_slots);
    b_coefficients[..CRT17_SLOTS].copy_from_slice(&b_slots);
    let polynomial_a = PolyRq::from_coeffs(&a_coefficients, CRT17_N, CRT17_MODULUS);
    let polynomial_b = PolyRq::from_coeffs(&b_coefficients, CRT17_N, CRT17_MODULUS);
    let expected_convolution = polynomial_a.mul_negacyclic(&polynomial_b);
    let convolution_prefix: [u64; CRT17_SLOTS] =
        std::array::from_fn(|i| expected_convolution.coefficients()[i]);

    assert_ne!(
        actual_slots, convolution_prefix,
        "slot-wise CRT multiplication must not be mistaken for polynomial convolution"
    );
}

// Negacyclic multiplication in F_17[X] / (X^256 + 1).
fn crt17_mul_negacyclic(a: &[u64], b: &[u64]) -> Vec<u64> {
    assert_eq!(a.len(), CRT17_N);
    assert_eq!(b.len(), CRT17_N);

    let mut out = vec![0u64; CRT17_N];

    for i in 0..CRT17_N {
        for j in 0..CRT17_N {
            let term = (a[i] % 17) * (b[j] % 17) % 17;
            let index = i + j;

            if index < CRT17_N {
                out[index] = (out[index] + term) % 17;
            } else {
                // X^256 = -1.
                let wrapped = index - CRT17_N;
                out[wrapped] = (out[wrapped] + 17 - term) % 17;
            }
        }
    }

    out
}

// Evaluates the BPR12 carry indicator polynomial in the plaintext ring.
fn crt17_eval_carry_indicator(x: &[u64]) -> Vec<u64> {
    let mut powers = Vec::with_capacity(17);

    let mut one = vec![0u64; CRT17_N];
    one[0] = 1;
    powers.push(one);

    for exponent in 1..=16 {
        let next = crt17_mul_negacyclic(&powers[exponent - 1], x);
        powers.push(next);
    }

    // f(x) = 8x + 9x^3 + 10x^5 + 11x^7
    //      + 15x^11 + 4x^13 + 2x^15 + 9x^16 (mod 17).
    let terms = [
        (1usize, 8u64),
        (3, 9),
        (5, 10),
        (7, 11),
        (11, 15),
        (13, 4),
        (15, 2),
        (16, 9),
    ];

    let mut out = vec![0u64; CRT17_N];

    for (exponent, coefficient) in terms {
        for i in 0..CRT17_N {
            out[i] = (out[i] + coefficient * powers[exponent][i]) % 17;
        }
    }

    out
}

#[test]
fn test_crt17_eight_slots_encode_decode_and_carry() {
    let batches: [[u64; 8]; 3] = [
        [0, 1, 2, 3, 4, 5, 6, 7],
        [8, 9, 10, 11, 12, 13, 14, 15],
        [16, 0, 8, 9, 16, 1, 7, 10],
    ];

    for slots in batches {
        let encoded = crt17_encode_slots(slots);

        assert_eq!(encoded.len(), CRT17_N);
        assert_eq!(
            crt17_decode_slots(&encoded),
            slots,
            "CRT encode/decode failed"
        );

        // Encoded scalar slots should occupy only powers X^(32*k).
        for i in 0..CRT17_N {
            if i % 32 != 0 {
                assert_eq!(encoded[i], 0, "unexpected coefficient at {i}");
            }
        }

        // Test the carry indicator with ring arithmetic, not HE yet.
        let carry_poly = crt17_eval_carry_indicator(&encoded);
        let actual = crt17_decode_slots(&carry_poly);
        let expected = slots.map(|x| u64::from(x >= 9));

        assert_eq!(
            actual, expected,
            "CRT-batched carry indicator returned incorrect slots"
        );

        for i in 0..CRT17_N {
            if i % 32 != 0 {
                assert_eq!(
                    carry_poly[i], 0,
                    "carry result escaped the scalar-slot subspace at {i}"
                );
            }
        }
    }
}

//actual cipher

#[test]
fn test_crt17_eight_slots_actual_ciphertext_carry() {
    let mut rng = thread_rng();
    let evaluator = RlweHe::new();

    // Generate real RNS RLWE keys and relinearization keys.
    let keygen = evaluator.keygen(&mut rng, CRT17_N);
    let relin_keys = evaluator.generate_relinearization_key_chain(&mut rng, &keygen.sk, 8);

    // Eight independent plaintext slots, including threshold cases.
    let slots = [0u64, 1, 8, 9, 10, 16, 4, 12];

    // Pack the eight values into one polynomial in R_17.
    let packed = crt17_encode_slots(slots);
    let plaintext = PolyRq::from_coeffs(&packed, CRT17_N, CRT17_MODULUS);

    // Encrypt the entire packed polynomial as ONE ciphertext.
    let ciphertext = evaluator.encrypt(&mut rng, &keygen.pk, &plaintext, CRT17_N);

    // First establish that encryption preserves the CRT representation.
    let fresh = evaluator.decrypt(&keygen.sk, &ciphertext, CRT17_N);

    assert_eq!(
        crt17_decode_slots(&fresh.coefficients()[..CRT17_N]),
        slots,
        "encrypted CRT-slot roundtrip failed"
    );

    // Evaluate the carry indicator homomorphically.
    // No plaintext decryption occurs inside this evaluation.
    let encrypted_carry = encrypted_carry_ge_9(&evaluator, &ciphertext, &relin_keys);

    assert_eq!(encrypted_carry.level, 4);

    // Decrypt only the FINAL ciphertext and decode the eight slots.
    let recovered = evaluator.decrypt(&keygen.sk, &encrypted_carry, CRT17_N);

    let actual = crt17_decode_slots(&recovered.coefficients()[..CRT17_N]);

    let expected = slots.map(|x| u64::from(x >= 9));

    assert_eq!(
        actual, expected,
        "encrypted CRT-batched carry returned incorrect slots"
    );

    // The result must remain in the subring generated by X^32.
    for i in 0..CRT17_N {
        if i % 32 != 0 {
            assert_eq!(
                recovered.coefficients()[i],
                0,
                "carry result escaped the packed subring at coefficient {i}"
            );
        }
    }

    // PolyRq uses N+1 stored coefficients; the last is padding.
    assert_eq!(recovered.coefficients()[CRT17_N], 0);
}

//real ctr 256 cipher?
#[test]
#[ignore = "Slow regression: 256 values packed into 32 RNS ciphertexts"]
fn test_crt17_256_values_batched_in_32_ciphertexts() {
    let mut rng = thread_rng();
    let evaluator = RlweHe::new();

    // Generate keys once and reuse them across all 32 batches.
    let keygen = evaluator.keygen(&mut rng, CRT17_N);
    let relin_keys = evaluator.generate_relinearization_key_chain(&mut rng, &keygen.sk, 8);

    for batch in 0..(CRT17_N / 8) {
        let start = batch * 8;

        // Eight independent low radix-17 digits.
        let slots: [u64; 8] = std::array::from_fn(|j| ((start + j) as u64 * 7 + 3) % 17);

        // Eight independent high radix-17 digits.
        let high_slots: [u64; 8] = std::array::from_fn(|j| ((start + j) as u64 * 11 + 4) % 17);

        // Pack the low digits into one polynomial.
        let packed = crt17_encode_slots(slots);
        let plaintext = PolyRq::from_coeffs(&packed, CRT17_N, CRT17_MODULUS);

        // Encrypt the entire packed polynomial as one RNS ciphertext.
        let ciphertext = evaluator.encrypt(&mut rng, &keygen.pk, &plaintext, CRT17_N);

        // Evaluate the carry indicator without decrypting intermediates.
        let encrypted_carry = encrypted_carry_ge_9(&evaluator, &ciphertext, &relin_keys);

        assert_eq!(
            encrypted_carry.level, 4,
            "unexpected HE level in batch {batch}"
        );

        // Decrypt only the final carry result.
        let recovered_carry = evaluator.decrypt(&keygen.sk, &encrypted_carry, CRT17_N);

        let actual_carry = crt17_decode_slots(&recovered_carry.coefficients()[..CRT17_N]);

        let expected_carry = slots.map(|x| u64::from(x >= 9));

        assert_eq!(
            actual_carry, expected_carry,
            "carry mismatch in batch {batch}, input slots {slots:?}"
        );

        // Pack and encrypt the high digits.
        let high_packed = crt17_encode_slots(high_slots);
        let high_plaintext = PolyRq::from_coeffs(&high_packed, CRT17_N, CRT17_MODULUS);

        let high_ciphertext = evaluator.encrypt(&mut rng, &keygen.pk, &high_plaintext, CRT17_N);

        // Bring the high digit to the carry's level.
        let high_at_level =
            evaluator.modulus_switch_to_level(&high_ciphertext, encrypted_carry.level);

        assert_eq!(
            high_at_level.level, encrypted_carry.level,
            "high digit and carry must be at the same level"
        );

        // Perform the actual homomorphic rounding step:
        // rounded_digit = high_digit + carry (mod 17).
        let encrypted_rounded = evaluator.add_ciphertexts(&high_at_level, &encrypted_carry);

        // Decrypt only the final rounded ciphertext.
        let decrypted_rounded = evaluator.decrypt(&keygen.sk, &encrypted_rounded, CRT17_N);

        let actual_rounded = crt17_decode_slots(&decrypted_rounded.coefficients()[..CRT17_N]);

        let expected_rounded: [u64; 8] =
            std::array::from_fn(|j| (high_slots[j] + u64::from(slots[j] >= 9)) % 17);

        assert_eq!(
            actual_rounded, expected_rounded,
            "rounding mismatch in batch {batch}; \
             low={slots:?}, high={high_slots:?}"
        );

        // The packed result must remain in the subring generated by X^32.
        for i in 0..CRT17_N {
            if i % 32 != 0 {
                assert_eq!(
                    decrypted_rounded.coefficients()[i],
                    0,
                    "unexpected coefficient {i} in batch {batch}"
                );
            }
        }

        // PolyRq stores N+1 elements: the last is padding.
        assert_eq!(
            decrypted_rounded.coefficients()[CRT17_N],
            0,
            "PolyRq padding must remain zero in batch {batch}"
        );

        println!("Batch {}/32 passed", batch + 1);
    }
}

/// Test accumulation of two encrypted products modulo 17^2
/// in all eight CRT17 slots.
#[test]
fn test_encrypted_radix17_accumulate_two_products_crt_packed() {
    use std::time::Instant;

    let started = Instant::now();
    let mut rng = thread_rng();
    let evaluator = RlweHe::new();

    eprintln!("[BPR12 TWO-PRODUCT-SUM] 1/7: generating RLWE keys");
    let keygen = evaluator.keygen(&mut rng, N);

    eprintln!(
        "[BPR12 TWO-PRODUCT-SUM +{:.1}s] 2/7: generating relinearization-key chain",
        started.elapsed().as_secs_f64()
    );
    let relin_keys = evaluator.generate_relinearization_key_chain(&mut rng, &keygen.sk, 8);

    let a_slots = [0u64, 1, 2, 8, 9, 12, 16, 16];
    let b_slots = [0u64, 16, 9, 8, 9, 16, 16, 9];
    let c_slots = [0u64, 16, 8, 9, 15, 5, 16, 16];
    let d_slots = [1u64, 1, 16, 8, 16, 16, 16, 16];

    eprintln!(
        "[BPR12 TWO-PRODUCT-SUM +{:.1}s] 3/7: encoding four digit vectors",
        started.elapsed().as_secs_f64()
    );

    let a_plain = PolyRq::from_coeffs(&crt17_encode_slots(a_slots), N, PLAINTEXT_MODULUS);
    let b_plain = PolyRq::from_coeffs(&crt17_encode_slots(b_slots), N, PLAINTEXT_MODULUS);
    let c_plain = PolyRq::from_coeffs(&crt17_encode_slots(c_slots), N, PLAINTEXT_MODULUS);
    let d_plain = PolyRq::from_coeffs(&crt17_encode_slots(d_slots), N, PLAINTEXT_MODULUS);

    eprintln!(
        "[BPR12 TWO-PRODUCT-SUM +{:.1}s] 4/7: encrypting four digit vectors",
        started.elapsed().as_secs_f64()
    );

    let encrypted_a = evaluator.encrypt(&mut rng, &keygen.pk, &a_plain, N);
    let encrypted_b = evaluator.encrypt(&mut rng, &keygen.pk, &b_plain, N);
    let encrypted_c = evaluator.encrypt(&mut rng, &keygen.pk, &c_plain, N);
    let encrypted_d = evaluator.encrypt(&mut rng, &keygen.pk, &d_plain, N);

    eprintln!(
        "[BPR12 TWO-PRODUCT-SUM +{:.1}s] 5/7: evaluating (a*b + c*d) mod 289",
        started.elapsed().as_secs_f64()
    );

    let (encrypted_low, encrypted_high) = encrypted_radix17_accumulate_two_products(
        &evaluator,
        &encrypted_a,
        &encrypted_b,
        &encrypted_c,
        &encrypted_d,
        &relin_keys,
    );

    assert_eq!(encrypted_low.level, 10, "low result should reach level 10");
    assert_eq!(
        encrypted_high.level, 10,
        "high result should reach level 10"
    );

    eprintln!(
        "[BPR12 TWO-PRODUCT-SUM +{:.1}s] 6/7: decrypting results",
        started.elapsed().as_secs_f64()
    );

    let low_plain = evaluator.decrypt(&keygen.sk, &encrypted_low, N);
    let high_plain = evaluator.decrypt(&keygen.sk, &encrypted_high, N);

    let actual_low = crt17_decode_slots(&low_plain.coefficients()[..N]);
    let actual_high = crt17_decode_slots(&high_plain.coefficients()[..N]);

    eprintln!(
        "[BPR12 TWO-PRODUCT-SUM +{:.1}s] 7/7: comparing all eight slots",
        started.elapsed().as_secs_f64()
    );

    let expected_values: [u64; CRT17_SLOTS] =
        std::array::from_fn(|i| (a_slots[i] * b_slots[i] + c_slots[i] * d_slots[i]) % 289);

    let expected_low: [u64; CRT17_SLOTS] = std::array::from_fn(|i| expected_values[i] % 17);
    let expected_high: [u64; CRT17_SLOTS] = std::array::from_fn(|i| (expected_values[i] / 17) % 17);

    assert_eq!(
        actual_low, expected_low,
        "accumulated low digit is incorrect"
    );
    assert_eq!(
        actual_high, expected_high,
        "accumulated high digit is incorrect"
    );

    assert!(
        low_plain.coefficients()[N..].iter().all(|&x| x == 0),
        "low result padding must remain zero"
    );
    assert!(
        high_plain.coefficients()[N..].iter().all(|&x| x == 0),
        "high result padding must remain zero"
    );

    eprintln!(
        "[BPR12 TWO-PRODUCT-SUM +{:.1}s] PASS: two products accumulated exactly modulo 289",
        started.elapsed().as_secs_f64()
    );
}

#[test]
fn test_encrypted_radix17_accumulate_three_products_crt_packed() {
    use std::time::Instant;

    let started = Instant::now();
    let mut rng = thread_rng();
    let evaluator = RlweHe::new();

    eprintln!("[BPR12 THREE-PRODUCT] 1/7: generating RLWE keys");
    let keygen = evaluator.keygen(&mut rng, N);

    eprintln!(
        "[BPR12 THREE-PRODUCT +{:.1}s] 2/7: generating relinearization keys",
        started.elapsed().as_secs_f64()
    );
    let relin_keys = evaluator.generate_relinearization_key_chain(&mut rng, &keygen.sk, 8);

    let a = [0u64, 1, 2, 8, 9, 12, 16, 16];
    let b = [0u64, 16, 9, 8, 9, 16, 16, 9];
    let c = [0u64, 16, 8, 9, 15, 5, 16, 16];
    let d = [1u64, 1, 16, 8, 16, 16, 16, 16];
    let e = [4u64, 3, 5, 10, 16, 7, 11, 2];
    let f = [7u64, 14, 12, 6, 15, 8, 3, 16];

    eprintln!(
        "[BPR12 THREE-PRODUCT +{:.1}s] 3/7: encoding six digit vectors",
        started.elapsed().as_secs_f64()
    );

    let pa = PolyRq::from_coeffs(&crt17_encode_slots(a), N, PLAINTEXT_MODULUS);
    let pb = PolyRq::from_coeffs(&crt17_encode_slots(b), N, PLAINTEXT_MODULUS);
    let pc = PolyRq::from_coeffs(&crt17_encode_slots(c), N, PLAINTEXT_MODULUS);
    let pd = PolyRq::from_coeffs(&crt17_encode_slots(d), N, PLAINTEXT_MODULUS);
    let pe = PolyRq::from_coeffs(&crt17_encode_slots(e), N, PLAINTEXT_MODULUS);
    let pf = PolyRq::from_coeffs(&crt17_encode_slots(f), N, PLAINTEXT_MODULUS);

    eprintln!(
        "[BPR12 THREE-PRODUCT +{:.1}s] 4/7: encrypting inputs",
        started.elapsed().as_secs_f64()
    );

    let ea = evaluator.encrypt(&mut rng, &keygen.pk, &pa, N);
    let eb = evaluator.encrypt(&mut rng, &keygen.pk, &pb, N);
    let ec = evaluator.encrypt(&mut rng, &keygen.pk, &pc, N);
    let ed = evaluator.encrypt(&mut rng, &keygen.pk, &pd, N);
    let ee = evaluator.encrypt(&mut rng, &keygen.pk, &pe, N);
    let ef = evaluator.encrypt(&mut rng, &keygen.pk, &pf, N);

    eprintln!(
        "[BPR12 THREE-PRODUCT +{:.1}s] 5/7: evaluating sum modulo 289",
        started.elapsed().as_secs_f64()
    );

    let (encrypted_low, encrypted_high) = encrypted_radix17_accumulate_three_products(
        &evaluator,
        &ea,
        &eb,
        &ec,
        &ed,
        &ee,
        &ef,
        &relin_keys,
    );

    assert_eq!(encrypted_low.level, 10);
    assert_eq!(encrypted_high.level, 10);

    eprintln!(
        "[BPR12 THREE-PRODUCT +{:.1}s] 6/7: decrypting outputs",
        started.elapsed().as_secs_f64()
    );

    let low_plain = evaluator.decrypt(&keygen.sk, &encrypted_low, N);
    let high_plain = evaluator.decrypt(&keygen.sk, &encrypted_high, N);

    let actual_low = crt17_decode_slots(&low_plain.coefficients()[..N]);
    let actual_high = crt17_decode_slots(&high_plain.coefficients()[..N]);

    eprintln!(
        "[BPR12 THREE-PRODUCT +{:.1}s] 7/7: checking all eight slots",
        started.elapsed().as_secs_f64()
    );

    let expected: [u64; CRT17_SLOTS] =
        std::array::from_fn(|i| (a[i] * b[i] + c[i] * d[i] + e[i] * f[i]) % 289);
    let expected_low = std::array::from_fn(|i| expected[i] % 17);
    let expected_high = std::array::from_fn(|i| (expected[i] / 17) % 17);

    assert_eq!(actual_low, expected_low, "incorrect accumulated low digit");
    assert_eq!(
        actual_high, expected_high,
        "incorrect accumulated high digit"
    );

    assert!(
        low_plain.coefficients()[N..].iter().all(|&x| x == 0),
        "low-digit padding must remain zero"
    );
    assert!(
        high_plain.coefficients()[N..].iter().all(|&x| x == 0),
        "high-digit padding must remain zero"
    );

    eprintln!(
        "[BPR12 THREE-PRODUCT +{:.1}s] PASS: three products are exact modulo 289",
        started.elapsed().as_secs_f64()
    );
}

#[test]
fn test_encrypted_radix17_accumulate_four_products_crt_packed() {
    use std::time::Instant;

    let started = Instant::now();
    let mut rng = thread_rng();
    let evaluator = RlweHe::new();

    eprintln!("[BPR12 PRODUCT TREE] 1/7: generating RLWE keys");
    let keygen = evaluator.keygen(&mut rng, N);

    eprintln!(
        "[BPR12 PRODUCT TREE +{:.1}s] 2/7: generating relinearization keys",
        started.elapsed().as_secs_f64()
    );
    let relin_keys = evaluator.generate_relinearization_key_chain(&mut rng, &keygen.sk, 8);

    let a = [0u64, 1, 2, 8, 9, 12, 16, 16];
    let b = [0u64, 16, 9, 8, 9, 16, 16, 9];
    let c = [0u64, 16, 8, 9, 15, 5, 16, 16];
    let d = [1u64, 1, 16, 8, 16, 16, 16, 16];
    let e = [4u64, 3, 5, 10, 16, 7, 11, 2];
    let f = [7u64, 14, 12, 6, 15, 8, 3, 16];
    let g = [16u64, 5, 3, 1, 12, 9, 4, 15];
    let h = [16u64, 8, 14, 16, 3, 6, 13, 7];

    eprintln!(
        "[BPR12 PRODUCT TREE +{:.1}s] 3/7: encoding eight digit vectors",
        started.elapsed().as_secs_f64()
    );

    let pa = PolyRq::from_coeffs(&crt17_encode_slots(a), N, PLAINTEXT_MODULUS);
    let pb = PolyRq::from_coeffs(&crt17_encode_slots(b), N, PLAINTEXT_MODULUS);
    let pc = PolyRq::from_coeffs(&crt17_encode_slots(c), N, PLAINTEXT_MODULUS);
    let pd = PolyRq::from_coeffs(&crt17_encode_slots(d), N, PLAINTEXT_MODULUS);
    let pe = PolyRq::from_coeffs(&crt17_encode_slots(e), N, PLAINTEXT_MODULUS);
    let pf = PolyRq::from_coeffs(&crt17_encode_slots(f), N, PLAINTEXT_MODULUS);
    let pg = PolyRq::from_coeffs(&crt17_encode_slots(g), N, PLAINTEXT_MODULUS);
    let ph = PolyRq::from_coeffs(&crt17_encode_slots(h), N, PLAINTEXT_MODULUS);

    eprintln!(
        "[BPR12 PRODUCT TREE +{:.1}s] 4/7: encrypting inputs",
        started.elapsed().as_secs_f64()
    );

    let ea = evaluator.encrypt(&mut rng, &keygen.pk, &pa, N);
    let eb = evaluator.encrypt(&mut rng, &keygen.pk, &pb, N);
    let ec = evaluator.encrypt(&mut rng, &keygen.pk, &pc, N);
    let ed = evaluator.encrypt(&mut rng, &keygen.pk, &pd, N);
    let ee = evaluator.encrypt(&mut rng, &keygen.pk, &pe, N);
    let ef = evaluator.encrypt(&mut rng, &keygen.pk, &pf, N);
    let eg = evaluator.encrypt(&mut rng, &keygen.pk, &pg, N);
    let eh = evaluator.encrypt(&mut rng, &keygen.pk, &ph, N);

    let factors = [(&ea, &eb), (&ec, &ed), (&ee, &ef), (&eg, &eh)];

    eprintln!(
        "[BPR12 PRODUCT TREE +{:.1}s] 5/7: evaluating four products with carry tree",
        started.elapsed().as_secs_f64()
    );

    let (encrypted_low, encrypted_high) =
        encrypted_radix17_accumulate_products(&evaluator, &factors, &relin_keys);

    assert_eq!(encrypted_low.level, 10);
    assert_eq!(encrypted_high.level, 10);

    eprintln!(
        "[BPR12 PRODUCT TREE +{:.1}s] 6/7: decrypting outputs",
        started.elapsed().as_secs_f64()
    );

    let low_plain = evaluator.decrypt(&keygen.sk, &encrypted_low, N);
    let high_plain = evaluator.decrypt(&keygen.sk, &encrypted_high, N);

    let actual_low = crt17_decode_slots(&low_plain.coefficients()[..N]);
    let actual_high = crt17_decode_slots(&high_plain.coefficients()[..N]);

    eprintln!(
        "[BPR12 PRODUCT TREE +{:.1}s] 7/7: validating all eight slots",
        started.elapsed().as_secs_f64()
    );

    let expected: [u64; CRT17_SLOTS] =
        std::array::from_fn(|i| (a[i] * b[i] + c[i] * d[i] + e[i] * f[i] + g[i] * h[i]) % 289);

    let expected_low: [u64; CRT17_SLOTS] = std::array::from_fn(|i| expected[i] % 17);
    let expected_high: [u64; CRT17_SLOTS] = std::array::from_fn(|i| (expected[i] / 17) % 17);

    assert_eq!(actual_low, expected_low, "incorrect accumulated low digit");
    assert_eq!(
        actual_high, expected_high,
        "incorrect accumulated high digit"
    );

    assert!(
        low_plain.coefficients()[N..].iter().all(|&x| x == 0),
        "low-digit padding must remain zero"
    );
    assert!(
        high_plain.coefficients()[N..].iter().all(|&x| x == 0),
        "high-digit padding must remain zero"
    );

    eprintln!(
        "[BPR12 PRODUCT TREE +{:.1}s] PASS: four products accumulated exactly modulo 289",
        started.elapsed().as_secs_f64()
    );
}

#[test]
fn test_encrypted_radix17_accumulate_five_products_crt_packed() {
    use std::time::Instant;

    let started = Instant::now();
    let mut rng = thread_rng();
    let evaluator = RlweHe::new();

    eprintln!("[BPR12 FIVE-PRODUCT] 1/7: generating RLWE keys");
    let keygen = evaluator.keygen(&mut rng, N);

    eprintln!(
        "[BPR12 FIVE-PRODUCT +{:.1}s] 2/7: generating relinearization keys",
        started.elapsed().as_secs_f64()
    );
    let relin_keys = evaluator.generate_relinearization_key_chain(&mut rng, &keygen.sk, 8);

    let a = [0u64, 1, 2, 8, 9, 12, 16, 16];
    let b = [0u64, 16, 9, 8, 9, 16, 16, 9];
    let c = [0u64, 16, 8, 9, 15, 5, 16, 16];
    let d = [1u64, 1, 16, 8, 16, 16, 16, 16];
    let e = [4u64, 3, 5, 10, 16, 7, 11, 2];
    let f = [7u64, 14, 12, 6, 15, 8, 3, 16];
    let g = [16u64, 5, 3, 1, 12, 9, 4, 15];
    let h = [16u64, 8, 14, 16, 3, 6, 13, 7];
    let i = [2u64, 11, 6, 14, 0, 13, 8, 1];
    let j = [5u64, 4, 15, 3, 16, 2, 7, 10];

    let slots = [a, b, c, d, e, f, g, h, i, j];

    eprintln!(
        "[BPR12 FIVE-PRODUCT +{:.1}s] 3/7: encoding ten digit vectors",
        started.elapsed().as_secs_f64()
    );

    let plaintexts: Vec<PolyRq> = slots
        .iter()
        .map(|s| PolyRq::from_coeffs(&crt17_encode_slots(*s), N, PLAINTEXT_MODULUS))
        .collect();

    eprintln!(
        "[BPR12 FIVE-PRODUCT +{:.1}s] 4/7: encrypting ten inputs",
        started.elapsed().as_secs_f64()
    );

    let encrypted: Vec<_> = plaintexts
        .iter()
        .map(|p| evaluator.encrypt(&mut rng, &keygen.pk, p, N))
        .collect();

    let factors = [
        (&encrypted[0], &encrypted[1]),
        (&encrypted[2], &encrypted[3]),
        (&encrypted[4], &encrypted[5]),
        (&encrypted[6], &encrypted[7]),
        (&encrypted[8], &encrypted[9]),
    ];

    eprintln!(
        "[BPR12 FIVE-PRODUCT +{:.1}s] 5/7: evaluating five products with carry tree",
        started.elapsed().as_secs_f64()
    );

    let (encrypted_low, encrypted_high) =
        encrypted_radix17_accumulate_products(&evaluator, &factors, &relin_keys);

    assert_eq!(encrypted_low.level, 10);
    assert_eq!(encrypted_high.level, 10);

    eprintln!(
        "[BPR12 FIVE-PRODUCT +{:.1}s] 6/7: decrypting outputs",
        started.elapsed().as_secs_f64()
    );

    let low_plain = evaluator.decrypt(&keygen.sk, &encrypted_low, N);
    let high_plain = evaluator.decrypt(&keygen.sk, &encrypted_high, N);

    let actual_low = crt17_decode_slots(&low_plain.coefficients()[..N]);
    let actual_high = crt17_decode_slots(&high_plain.coefficients()[..N]);

    eprintln!(
        "[BPR12 FIVE-PRODUCT +{:.1}s] 7/7: validating all eight slots",
        started.elapsed().as_secs_f64()
    );

    let expected: [u64; CRT17_SLOTS] = std::array::from_fn(|slot| {
        (a[slot] * b[slot]
            + c[slot] * d[slot]
            + e[slot] * f[slot]
            + g[slot] * h[slot]
            + i[slot] * j[slot])
            % 289
    });

    let expected_low: [u64; CRT17_SLOTS] = std::array::from_fn(|slot| expected[slot] % 17);
    let expected_high: [u64; CRT17_SLOTS] = std::array::from_fn(|slot| (expected[slot] / 17) % 17);

    assert_eq!(actual_low, expected_low, "incorrect accumulated low digit");
    assert_eq!(
        actual_high, expected_high,
        "incorrect accumulated high digit"
    );

    assert!(
        low_plain.coefficients()[N..].iter().all(|&x| x == 0),
        "low-digit padding must remain zero"
    );
    assert!(
        high_plain.coefficients()[N..].iter().all(|&x| x == 0),
        "high-digit padding must remain zero"
    );

    eprintln!(
        "[BPR12 FIVE-PRODUCT +{:.1}s] PASS: five products accumulated exactly modulo 289",
        started.elapsed().as_secs_f64()
    );
}

#[test]
fn test_encrypted_synthesize_q289_to_17_negacyclic_toy() {
    use std::time::Instant;

    const N_TOY: usize = 4;
    const Q_TOY: u64 = 17 * 17;

    let started = Instant::now();
    let mut rng = thread_rng();

    // All primes satisfy q_i = 1 mod 2*N_TOY and q_i = 1 mod 17.
    // Fifteen primes provide levels 0..14: product/carry ends at 10,
    // then the final rounding indicator can consume four more levels.
    let moduli = vec![
        8_416_769, 8_434_177, 8_573_441, 8_599_553, 8_782_337, 8_825_857, 8_834_561, 8_860_673,
        8_904_193, 9_113_089, 9_139_201, 9_165_313, 9_201_217, 9_202_577, 9_204_073, 9_206_521,
        9_206_657, 9_208_289,
    ];

    eprintln!("[BPR12 SYNTH-TOY] 1/7: building N=4 HE evaluator");
    let evaluator = RlweHe::with_chain(RnsModulusChain::new(moduli, N_TOY));

    eprintln!(
        "[BPR12 SYNTH-TOY +{:.1}s] 2/7: generating keys",
        started.elapsed().as_secs_f64()
    );
    let keygen = evaluator.keygen(&mut rng, N_TOY);
    let relin_keys = evaluator.generate_relinearization_key_chain(&mut rng, &keygen.sk, 8);

    // Dense inputs: every coefficient participates in the convolution.
    let lhs_coeffs = [276, 17, 144, 258];
    let rhs_coeffs = [9, 255, 18, 128];

    let lhs_plain = PolyRq::from_coeffs(&lhs_coeffs, N_TOY, Q_TOY);
    let rhs_plain = PolyRq::from_coeffs(&rhs_coeffs, N_TOY, Q_TOY);

    eprintln!(
        "[BPR12 SYNTH-TOY +{:.1}s] 3/7: encrypting two-limb polynomials",
        started.elapsed().as_secs_f64()
    );

    let lhs_enc = Bpr12HeValue::encrypt(&evaluator, &mut rng, &keygen.pk, &lhs_plain, 2, N_TOY);
    let rhs_enc = Bpr12HeValue::encrypt(&evaluator, &mut rng, &keygen.pk, &rhs_plain, 2, N_TOY);

    eprintln!(
        "[BPR12 SYNTH-TOY +{:.1}s] 4/7: evaluating full negacyclic product mod 289",
        started.elapsed().as_secs_f64()
    );

    let encrypted_product = encrypted_radix17_negacyclic_product_two_limbs_reference(
        &evaluator,
        &lhs_enc,
        &rhs_enc,
        &relin_keys,
    );

    assert_eq!(encrypted_product.level, 10);

    let decrypted_product = encrypted_product.decrypt(&evaluator, &keygen.sk, N_TOY);
    let expected_product = lhs_plain.mul_negacyclic(&rhs_plain);

    assert_eq!(
        &decrypted_product.coefficients()[..N_TOY],
        &expected_product.coefficients()[..N_TOY],
        "encrypted two-limb negacyclic product differs from the clear ring product"
    );

    eprintln!(
        "[BPR12 SYNTH-TOY +{:.1}s] 5/7: applying homomorphic rounding to p=17",
        started.elapsed().as_secs_f64()
    );

    let encrypted_output = round_one_level_homomorphic(&evaluator, &encrypted_product, &relin_keys);

    assert_eq!(encrypted_output.level, 14);

    eprintln!(
        "[BPR12 SYNTH-TOY +{:.1}s] 6/7: decrypting final result",
        started.elapsed().as_secs_f64()
    );

    let actual = encrypted_output.decrypt(&evaluator, &keygen.sk, N_TOY);
    let expected = synthesize(&lhs_plain, &rhs_plain, 17);

    eprintln!(
        "[BPR12 SYNTH-TOY +{:.1}s] 7/7: comparing with rlwr::synthesize",
        started.elapsed().as_secs_f64()
    );

    assert_eq!(actual.modulus(), 17);
    assert_eq!(
        &actual.coefficients()[..N_TOY],
        &expected.coefficients()[..N_TOY],
        "encrypted BPR12 toy synthesize differs from rlwr::synthesize"
    );

    eprintln!(
        "[BPR12 SYNTH-TOY +{:.1}s] PASS: full q=289 -> p=17 synthesize matches",
        started.elapsed().as_secs_f64()
    );
}

#[test]
fn test_encrypted_radix17_nine_limb_prefix_add_n4() {
    use std::time::Instant;

    const N_TOY: usize = 4;
    const Q: u64 = 17u64.pow(9);

    let started = Instant::now();
    let mut rng = thread_rng();

    eprintln!("[BPR12 PREFIX-ADD] 1/5: creating HE evaluator");
    let evaluator = RlweHe::with_chain(RnsModulusChain::new(TEST_RNS_MODULI.to_vec(), N_TOY));

    let keygen = evaluator.keygen(&mut rng, N_TOY);
    let relin_keys = evaluator.generate_relinearization_key_chain(&mut rng, &keygen.sk, 8);

    let lhs_coeffs = [
        Q - 1,
        Q - 17u64.pow(5) + 1234,
        17u64.pow(8) + 16,
        Q / 2 + 17u64.pow(4),
    ];
    let rhs_coeffs = [1, 17u64.pow(5) + 47, Q - 1, Q - 4321];

    let lhs_plain = PolyRq::from_coeffs(&lhs_coeffs, N_TOY, Q);
    let rhs_plain = PolyRq::from_coeffs(&rhs_coeffs, N_TOY, Q);

    eprintln!(
        "[BPR12 PREFIX-ADD +{:.1}s] 2/5: encrypting nine-limb operands",
        started.elapsed().as_secs_f64()
    );

    let lhs = Bpr12HeValue::encrypt(&evaluator, &mut rng, &keygen.pk, &lhs_plain, 9, N_TOY);
    let rhs = Bpr12HeValue::encrypt(&evaluator, &mut rng, &keygen.pk, &rhs_plain, 9, N_TOY);

    eprintln!(
        "[BPR12 PREFIX-ADD +{:.1}s] 3/5: evaluating parallel-prefix addition",
        started.elapsed().as_secs_f64()
    );

    let encrypted_sum = encrypted_radix17_add_values_prefix(&evaluator, &lhs, &rhs, &relin_keys);

    assert_eq!(encrypted_sum.level, 9);

    eprintln!(
        "[BPR12 PREFIX-ADD +{:.1}s] 4/5: decrypting and reconstructing",
        started.elapsed().as_secs_f64()
    );

    let actual = encrypted_sum.decrypt(&evaluator, &keygen.sk, N_TOY);

    let expected_coeffs: Vec<u64> = (0..N_TOY)
        .map(|i| (lhs_coeffs[i] + rhs_coeffs[i]) % Q)
        .collect();
    let expected = PolyRq::from_coeffs(&expected_coeffs, N_TOY, Q);

    eprintln!(
        "[BPR12 PREFIX-ADD +{:.1}s] 5/5: comparing with reference addition",
        started.elapsed().as_secs_f64()
    );

    assert_eq!(actual.modulus(), Q);
    assert_eq!(
        actual.to_coeffs_vec(),
        expected.to_coeffs_vec(),
        "nine-limb prefix addition differs from clear addition"
    );

    eprintln!(
        "[BPR12 PREFIX-ADD +{:.1}s] PASS: nine-limb addition is exact",
        started.elapsed().as_secs_f64()
    );
}

#[test]
fn test_encrypted_radix17_scalar_product_nine_limbs() {
    use std::time::Instant;

    const N_TOY: usize = 4;
    const Q: u64 = 17u64.pow(9);

    let started = Instant::now();
    let mut rng = thread_rng();

    eprintln!("[BPR12 SCALAR-MUL] 1/6: generating 24 compatible RNS primes");
    let moduli = bpr12_toy_moduli(24, N_TOY);
    let evaluator = RlweHe::with_chain(RnsModulusChain::new(moduli, N_TOY));

    eprintln!(
        "[BPR12 SCALAR-MUL +{:.1}s] 2/6: generating RLWE and relinearization keys",
        started.elapsed().as_secs_f64()
    );
    let keygen = evaluator.keygen(&mut rng, N_TOY);
    let relin_keys = evaluator.generate_relinearization_key_chain(&mut rng, &keygen.sk, 8);

    // Large inputs exercise nontrivial digits and carries.
    let a = Q - 1_234_567;
    let b = Q - 9_876_543;

    let lhs_plain = PolyRq::from_coeffs(&[a, 0, 0, 0], N_TOY, Q);
    let rhs_plain = PolyRq::from_coeffs(&[b, 0, 0, 0], N_TOY, Q);

    eprintln!(
        "[BPR12 SCALAR-MUL +{:.1}s] 3/6: encrypting nine-limb operands",
        started.elapsed().as_secs_f64()
    );

    let lhs = Bpr12HeValue::encrypt(&evaluator, &mut rng, &keygen.pk, &lhs_plain, 9, N_TOY);
    let rhs = Bpr12HeValue::encrypt(&evaluator, &mut rng, &keygen.pk, &rhs_plain, 9, N_TOY);

    let lhs_digits: Vec<_> = lhs.limbs.iter().map(|limb| &limb[0]).collect();
    let rhs_digits: Vec<_> = rhs.limbs.iter().map(|limb| &limb[0]).collect();

    eprintln!(
        "[BPR12 SCALAR-MUL +{:.1}s] 4/6: evaluating full product modulo 17^9",
        started.elapsed().as_secs_f64()
    );

    let product_digits = encrypted_radix17_scalar_product_nine_limbs(
        &evaluator,
        &lhs_digits,
        &rhs_digits,
        &relin_keys,
    );

    assert_eq!(product_digits.len(), 9);
    assert!(
        product_digits.iter().all(|digit| digit.level == 19),
        "optimized product must finish at level 19"
    );

    eprintln!(
        "[BPR12 SCALAR-MUL +{:.1}s] 5/6: decrypting and reconstructing the result",
        started.elapsed().as_secs_f64()
    );

    let mut actual = 0u128;
    let mut place_value = 1u128;

    for (index, encrypted_digit) in product_digits.iter().enumerate() {
        let decoded = evaluator.decrypt(&keygen.sk, encrypted_digit, N_TOY);
        let digit = decoded.coefficients()[0];

        assert!(digit < 17, "digit {index} is outside the radix-17 range");
        assert!(
            decoded.coefficients()[1..N_TOY].iter().all(|&c| c == 0),
            "digit {index} must decrypt to a constant polynomial"
        );

        actual += digit as u128 * place_value;
        place_value *= 17;
    }

    let expected = ((a as u128 * b as u128) % Q as u128) as u64;

    eprintln!(
        "[BPR12 SCALAR-MUL +{:.1}s] 6/6: comparing against integer multiplication",
        started.elapsed().as_secs_f64()
    );

    assert_eq!(actual as u64, expected);

    eprintln!(
        "[BPR12 SCALAR-MUL +{:.1}s] PASS: nine-limb scalar product modulo 17^9 is exact",
        started.elapsed().as_secs_f64()
    );
}

// Test-only prime generator for small N=4 circuits.
// Every modulus satisfies q == 1 mod 2N and q == 1 mod 17.
fn bpr12_toy_moduli(count: usize, degree: usize) -> Vec<u64> {
    fn gcd(mut a: u64, mut b: u64) -> u64 {
        while b != 0 {
            let remainder = a % b;
            a = b;
            b = remainder;
        }
        a
    }

    fn is_prime(value: u64) -> bool {
        if value < 2 {
            return false;
        }
        for p in [2u64, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37] {
            if value == p {
                return true;
            }
            if value % p == 0 {
                return false;
            }
        }
        let mut divisor = 41u64;
        while divisor <= value / divisor {
            if value % divisor == 0 || value % (divisor + 2) == 0 {
                return false;
            }
            divisor += 6;
        }
        true
    }

    let two_n = 2 * degree as u64;
    let period = two_n / gcd(two_n, 17) * 17;

    let mut candidate = 8_416_769u64;
    candidate += (1 + period - candidate % period) % period;

    let mut moduli = Vec::with_capacity(count);
    while moduli.len() < count {
        if candidate % two_n == 1 && candidate % 17 == 1 && is_prime(candidate) {
            moduli.push(candidate);
        }
        candidate += period;
    }

    moduli
}

#[test]
fn test_encrypted_bpr12_synthesize_nine_limbs_negacyclic_n2() {
    use std::time::Instant;

    use pq_libpep::algebra::ring::PolyRq;
    use pq_libpep::core::bpr12_oblivious::{
        encrypted_radix17_negacyclic_synthesize_nine_limbs_toy, Bpr12HeValue,
    };
    use pq_libpep::core::rlwe_he::RlweHe;
    use pq_libpep::core::rlwr::synthesize;
    use pq_libpep::core::rns::RnsModulusChain;
    use rand::thread_rng;

    const N_TOY: usize = 2;
    const LIMBS: usize = 9;
    const Q: u64 = 17u64.pow(9);

    let started = Instant::now();
    let mut rng = thread_rng();

    eprintln!("[BPR12 SYNTH-9L] 1/8: generating a 41-prime RNS chain for level 40");

    let moduli = bpr12_toy_moduli(41, N_TOY);
    let evaluator = RlweHe::with_chain(RnsModulusChain::new(moduli, N_TOY));

    eprintln!(
        "[BPR12 SYNTH-9L +{:.1}s] 2/8: generating RLWE and relinearization keys",
        started.elapsed().as_secs_f64()
    );

    let keygen = evaluator.keygen(&mut rng, N_TOY);
    let relin_keys = evaluator.generate_relinearization_key_chain(&mut rng, &keygen.sk, 8);

    // Both coefficients are nonzero. The term a[1] * b[1] must wrap
    // through X^2 = -1, so the test exercises the negacyclic sign.
    let lhs_coeffs = [Q - 1_234_567, 17u64.pow(7) + 54_321];
    let rhs_coeffs = [Q - 9_876_543, 17u64.pow(6) + 12_345];

    let lhs_plain = PolyRq::from_coeffs(&lhs_coeffs, N_TOY, Q);
    let rhs_plain = PolyRq::from_coeffs(&rhs_coeffs, N_TOY, Q);

    eprintln!(
        "[BPR12 SYNTH-9L +{:.1}s] 3/8: encrypting nine-limb polynomials",
        started.elapsed().as_secs_f64()
    );

    let lhs = Bpr12HeValue::encrypt(&evaluator, &mut rng, &keygen.pk, &lhs_plain, LIMBS, N_TOY);

    let rhs = Bpr12HeValue::encrypt(&evaluator, &mut rng, &keygen.pk, &rhs_plain, LIMBS, N_TOY);

    eprintln!(
        "[BPR12 SYNTH-9L +{:.1}s] 4/8: evaluating negacyclic product and direct rounding",
        started.elapsed().as_secs_f64()
    );

    let (encrypted_product, encrypted_output) =
        encrypted_radix17_negacyclic_synthesize_nine_limbs_toy(&evaluator, &lhs, &rhs, &relin_keys);

    assert_eq!(
        encrypted_product.level, 33,
        "normalized q=17^9 product should end at level 33"
    );

    assert_eq!(
        encrypted_output.level, 40,
        "direct q=17^9 to p=17 rounding should end at level 40"
    );

    eprintln!(
        "[BPR12 SYNTH-9L +{:.1}s] 5/8: decrypting the unrounded product",
        started.elapsed().as_secs_f64()
    );

    let actual_product = encrypted_product.decrypt(&evaluator, &keygen.sk, N_TOY);

    let expected_product = lhs_plain.mul_negacyclic(&rhs_plain);

    assert_eq!(
        actual_product.modulus(),
        Q,
        "the intermediate product must remain in R_(17^9)"
    );

    assert_eq!(
        &actual_product.coefficients()[..N_TOY],
        &expected_product.coefficients()[..N_TOY],
        "encrypted negacyclic product differs from the clear product"
    );

    eprintln!(
        "[BPR12 SYNTH-9L +{:.1}s] 6/8: decrypting the rounded output",
        started.elapsed().as_secs_f64()
    );

    let actual_output = encrypted_output.decrypt(&evaluator, &keygen.sk, N_TOY);

    eprintln!(
        "[BPR12 SYNTH-9L +{:.1}s] 7/8: comparing with rlwr::synthesize",
        started.elapsed().as_secs_f64()
    );

    let expected_output = synthesize(&lhs_plain, &rhs_plain, 17);

    assert_eq!(
        actual_output.modulus(),
        17,
        "the final output must be in R_17"
    );

    assert_eq!(
        &actual_output.coefficients()[..N_TOY],
        &expected_output.coefficients()[..N_TOY],
        "nine-limb encrypted BPR12 synthesis differs from rlwr::synthesize"
    );

    eprintln!(
        "[BPR12 SYNTH-9L +{:.1}s] 8/8: PASS — product and direct rounding are exact",
        started.elapsed().as_secs_f64()
    );
}

#[test]
fn test_encrypted_bpr12_one_level_synthesis_q9_to_q8_n2() {
    use std::time::Instant;

    use pq_libpep::algebra::ring::PolyRq;
    use pq_libpep::core::bpr12_oblivious::{
        encrypted_radix17_negacyclic_product_nine_limbs_toy, round_one_level_homomorphic,
        Bpr12HeValue,
    };
    use pq_libpep::core::rlwe_he::RlweHe;
    use pq_libpep::core::rlwr::synthesize;
    use pq_libpep::core::rns::RnsModulusChain;
    use rand::thread_rng;

    const N_TOY: usize = 2;
    const LIMBS: usize = 9;
    const Q9: u64 = 17u64.pow(9);
    const Q8: u64 = 17u64.pow(8);

    let started = Instant::now();
    let mut rng = thread_rng();

    eprintln!("[BPR12 Q9->Q8] 1/7: generating 42-prime RNS chain");

    // The product reaches level 33.
    // One-level, nine-limb rounding needs another 8 levels:
    // output level = 33 + 8 = 41.
    // 42 primes provide levels 0..=41.
    let moduli = bpr12_toy_moduli(42, N_TOY);
    let evaluator = RlweHe::with_chain(RnsModulusChain::new(moduli, N_TOY));

    assert_eq!(evaluator.max_level(), 41);

    eprintln!(
        "[BPR12 Q9->Q8 +{:.1}s] 2/7: generating RLWE and relinearization keys",
        started.elapsed().as_secs_f64()
    );

    let keygen = evaluator.keygen(&mut rng, N_TOY);
    let relin_keys = evaluator.generate_relinearization_key_chain(&mut rng, &keygen.sk, 8);

    // Include nonzero coefficients so that the X^2 = -1
    // negacyclic wraparound is exercised.
    let lhs_coeffs = [Q9 - 1_234_567, 17u64.pow(7) + 54_321];
    let rhs_coeffs = [Q9 - 9_876_543, 17u64.pow(6) + 12_345];

    let lhs_plain = PolyRq::from_coeffs(&lhs_coeffs, N_TOY, Q9);
    let rhs_plain = PolyRq::from_coeffs(&rhs_coeffs, N_TOY, Q9);

    eprintln!(
        "[BPR12 Q9->Q8 +{:.1}s] 3/7: encrypting nine-limb inputs",
        started.elapsed().as_secs_f64()
    );

    let lhs = Bpr12HeValue::encrypt(&evaluator, &mut rng, &keygen.pk, &lhs_plain, LIMBS, N_TOY);

    let rhs = Bpr12HeValue::encrypt(&evaluator, &mut rng, &keygen.pk, &rhs_plain, LIMBS, N_TOY);

    eprintln!(
        "[BPR12 Q9->Q8 +{:.1}s] 4/7: evaluating negacyclic product",
        started.elapsed().as_secs_f64()
    );

    let encrypted_product =
        encrypted_radix17_negacyclic_product_nine_limbs_toy(&evaluator, &lhs, &rhs, &relin_keys);

    assert_eq!(
        encrypted_product.level, 33,
        "nine-limb product should finish at HE level 33"
    );
    assert_eq!(encrypted_product.digits(), 9);

    // Validate the product independently before testing rounding.
    let actual_product = encrypted_product.decrypt(&evaluator, &keygen.sk, N_TOY);
    let expected_product = lhs_plain.mul_negacyclic(&rhs_plain);

    assert_eq!(actual_product.modulus(), Q9);
    assert_eq!(
        &actual_product.coefficients()[..N_TOY],
        &expected_product.coefficients()[..N_TOY],
        "homomorphic negacyclic product is incorrect"
    );

    eprintln!(
        "[BPR12 Q9->Q8 +{:.1}s] 5/7: rounding one Ring-LWR level",
        started.elapsed().as_secs_f64()
    );

    let encrypted_output = round_one_level_homomorphic(&evaluator, &encrypted_product, &relin_keys);

    assert_eq!(
        encrypted_output.digits(),
        8,
        "one modulus reduction must leave eight radix-17 limbs"
    );
    assert_eq!(
        encrypted_output.level(),
        41,
        "one-level rounding should finish at HE level 41"
    );
    assert_eq!(encrypted_output.slots_per_ciphertext, 1);

    eprintln!(
        "[BPR12 Q9->Q8 +{:.1}s] 6/7: decrypting rounded output",
        started.elapsed().as_secs_f64()
    );

    let actual_output = encrypted_output.decrypt(&evaluator, &keygen.sk, N_TOY);

    eprintln!(
        "[BPR12 Q9->Q8 +{:.1}s] 7/7: comparing with rlwr::synthesize",
        started.elapsed().as_secs_f64()
    );

    // One BPR12 level: q = 17^9 -> p = 17^8.
    let expected_output = synthesize(&lhs_plain, &rhs_plain, Q8);

    assert_eq!(
        actual_output.modulus(),
        Q8,
        "output must be modulo 17^8 after one level"
    );
    assert_eq!(
        &actual_output.coefficients()[..N_TOY],
        &expected_output.coefficients()[..N_TOY],
        "homomorphic q9-to-q8 synthesis differs from rlwr::synthesize"
    );

    assert_eq!(
        actual_output.coefficients()[N_TOY],
        0,
        "PolyRq padding coefficient must remain zero"
    );

    eprintln!(
        "[BPR12 Q9->Q8 +{:.1}s] PASS — one complete Ring-LWR level is exact",
        started.elapsed().as_secs_f64()
    );
}

#[test]
#[ignore = "slow end-to-end toy PRF test; requires 81 RNS primes for two synthesis layers"]
fn test_encrypted_bpr12_prf_toy_four_bits_matches_clear_reference() {
    use pq_libpep::algebra::ring::PolyRq;
    use pq_libpep::core::bpr12_oblivious::encrypted_bpr12_prf_toy;
    use pq_libpep::core::rlwe_he::RlweHe;
    use pq_libpep::core::rlwr_prf::{RlwrPrf, RlwrPrfBase};
    use pq_libpep::core::rns::RnsModulusChain;
    use rand::thread_rng;

    const N: usize = 2;
    const Q9: u64 = 17u64.pow(9);
    const Q8: u64 = 17u64.pow(8);
    const Q7: u64 = 17u64.pow(7);
    let bits = [0u8, 1, 1, 0];
    let mut rng = thread_rng();

    // Eighty levels are required by the two toy synthesis layers with the
    // current exact circuit: q9 -> q8 -> q7.
    let moduli = bpr12_toy_moduli(81, N);
    let evaluator = RlweHe::with_chain(RnsModulusChain::new(moduli, N));
    assert_eq!(evaluator.max_level(), 80);

    let keygen = evaluator.keygen(&mut rng, N);
    let relin_keys = evaluator.generate_relinearization_key_chain(&mut rng, &keygen.sk, 8);

    let s0 = vec![
        PolyRq::from_coeffs(&[Q9 - 123_457, 17u64.pow(7) + 31], N, Q9),
        PolyRq::from_coeffs(&[17u64.pow(8) + 71, Q9 - 876_543], N, Q9),
        PolyRq::from_coeffs(&[4_321_987, 17u64.pow(6) + 53], N, Q9),
        PolyRq::from_coeffs(&[Q9 - 456_789, Q9 - 234_567], N, Q9),
    ];
    let s1 = vec![
        PolyRq::from_coeffs(&[Q9 - 765_431, 17u64.pow(6) + 97], N, Q9),
        PolyRq::from_coeffs(&[17u64.pow(7) + 111, Q9 - 345_679], N, Q9),
        PolyRq::from_coeffs(&[8_765_431, 17u64.pow(8) + 17], N, Q9),
        PolyRq::from_coeffs(&[Q9 - 987_653, 12_345_678], N, Q9),
    ];

    let encrypted_bits: Vec<_> = bits
        .iter()
        .map(|&bit| {
            let plaintext = PolyRq::from_coeffs(&[bit as u64, 0], N, 17);
            evaluator.encrypt(&mut rng, &keygen.pk, &plaintext, N)
        })
        .collect();

    let encrypted_output =
        encrypted_bpr12_prf_toy(&evaluator, &encrypted_bits, &s0, &s1, &relin_keys);

    assert_eq!(encrypted_output.digits(), 7);
    assert_eq!(encrypted_output.level(), 80);

    let actual = encrypted_output.decrypt(&evaluator, &keygen.sk, N);
    let clear_prf = RlwrPrf::new(RlwrPrfBase { s0, s1 }, vec![Q7, Q8, Q9]);
    let expected = clear_prf.evaluate(&bits);

    assert_eq!(actual.modulus(), Q7);
    assert_eq!(&actual.coefficients()[..N], &expected.coefficients()[..N]);
}

#[test]
fn test_rns_poly_automorphism_matches_negacyclic_reference() {
    use pq_libpep::core::rns::RnsPoly;

    const DEGREE: usize = 256;
    const EXPONENT: usize = 3;

    let moduli = bpr12_toy_moduli(4, DEGREE);
    let chain = RnsModulusChain::new(moduli.clone(), DEGREE);

    let coefficients: Vec<u64> = (0..DEGREE)
        .map(|i| ((i as u64 * 1_234_567 + 987_654) % 7_000_001))
        .collect();

    let input = RnsPoly::from_coeffs(&coefficients, &chain);
    let actual = input.automorphism(EXPONENT);

    assert_eq!(actual.degree, DEGREE);
    assert_eq!(actual.residue_count(), moduli.len());

    // Independently calculate X -> X^3 in every RNS modulus.
    for (residue_index, &q) in moduli.iter().enumerate() {
        let mut expected = vec![0u64; DEGREE];

        for (i, &coefficient) in coefficients.iter().enumerate() {
            let exponent = ((i as u128 * EXPONENT as u128) % (2 * DEGREE) as u128) as usize;

            let destination = exponent % DEGREE;
            let value = coefficient % q;

            if exponent >= DEGREE {
                expected[destination] = (expected[destination] + q - value) % q;
            } else {
                expected[destination] = (expected[destination] + value) % q;
            }
        }

        assert_eq!(
            &actual.residue(residue_index).coefficients()[..DEGREE],
            expected.as_slice(),
            "automorphism mismatch for RNS residue {residue_index}, modulus {q}"
        );
    }
}

#[test]
fn test_rlwe_ciphertext_automorphism_with_key_switch() {
    use pq_libpep::algebra::ring::PolyRq;
    use pq_libpep::core::rlwe_he::RlweHe;
    use rand::thread_rng;

    const N: usize = 256;
    const EXPONENT: usize = 3;
    const P: u64 = 17;

    let mut rng = thread_rng();
    let evaluator = RlweHe::new();
    let keygen = evaluator.keygen(&mut rng, N);

    eprintln!("[AUTO-CT] generating automorphism key for X -> X^3");

    let automorphism_key = evaluator.generate_automorphism_key(&mut rng, &keygen.sk, EXPONENT, 8);

    // Deterministic, nonconstant plaintext across all 256 coefficients.
    let coefficients: Vec<u64> = (0..N).map(|i| ((i * i + 7 * i + 3) as u64) % P).collect();

    let plaintext = PolyRq::from_coeffs(&coefficients, N, P);
    let encrypted = evaluator.encrypt(&mut rng, &keygen.pk, &plaintext, N);

    eprintln!("[AUTO-CT] applying automorphism and key-switching");

    let transformed = evaluator.apply_automorphism(&encrypted, &automorphism_key);

    assert_eq!(transformed.level, 0);

    // Decrypt only after the complete transformation.
    let actual = evaluator.decrypt(&keygen.sk, &transformed, N);

    // Independent plaintext reference for X -> X^3 modulo X^N + 1.
    let mut expected = vec![0u64; N];

    for (i, &coefficient) in coefficients.iter().enumerate() {
        let exponent = (i * EXPONENT) % (2 * N);
        let destination = exponent % N;

        if exponent >= N {
            expected[destination] = (expected[destination] + P - coefficient) % P;
        } else {
            expected[destination] = (expected[destination] + coefficient) % P;
        }
    }

    assert_eq!(
        &actual.coefficients()[..N],
        expected.as_slice(),
        "automorphism ciphertext failed to decrypt to sigma(m)"
    );

    assert_eq!(
        actual.coefficients()[N],
        0,
        "PolyRq padding coefficient must remain zero"
    );

    eprintln!("[AUTO-CT] PASS: ciphertext automorphism preserves the transformed plaintext");
}

#[test]
fn test_rlwe_ciphertext_automorphism_after_modulus_switch() {
    use pq_libpep::algebra::ring::PolyRq;
    use pq_libpep::core::rlwe_he::RlweHe;
    use pq_libpep::core::rns::RnsModulusChain;
    use rand::thread_rng;

    const DEGREE: usize = 256;
    const EXPONENT: usize = 3;
    const P: u64 = 17;

    let mut rng = thread_rng();
    let evaluator = RlweHe::with_chain(RnsModulusChain::new(bpr12_toy_moduli(4, DEGREE), DEGREE));
    let keygen = evaluator.keygen(&mut rng, DEGREE);

    // The chain must contain a key for level 1 as well as level 0.
    let automorphism_keys =
        evaluator.generate_automorphism_key_chain(&mut rng, &keygen.sk, EXPONENT, 8);
    assert_eq!(automorphism_keys.keys.len(), evaluator.max_level() + 1);

    let coefficients: Vec<u64> = (0..DEGREE)
        .map(|i| ((i * i + 7 * i + 3) as u64) % P)
        .collect();
    let plaintext = PolyRq::from_coeffs(&coefficients, DEGREE, P);
    let encrypted = evaluator.encrypt(&mut rng, &keygen.pk, &plaintext, DEGREE);

    // Exercise a nonzero level without introducing an extra multiplication.
    let level_one = evaluator.modulus_switch(&encrypted);
    assert_eq!(level_one.level, 1);
    let transformed = evaluator.apply_automorphism_with_key_chain(&level_one, &automorphism_keys);
    assert_eq!(transformed.level, 1);

    let actual = evaluator.decrypt(&keygen.sk, &transformed, DEGREE);
    let mut expected = vec![0u64; DEGREE];
    for (i, &coefficient) in coefficients.iter().enumerate() {
        let exponent = (i * EXPONENT) % (2 * DEGREE);
        let destination = exponent % DEGREE;
        if exponent >= DEGREE {
            expected[destination] = (expected[destination] + P - coefficient) % P;
        } else {
            expected[destination] = (expected[destination] + coefficient) % P;
        }
    }

    assert_eq!(
        &actual.coefficients()[..DEGREE],
        expected.as_slice(),
        "level-aware automorphism produced the wrong plaintext"
    );
}

#[test]
fn test_rlwe_ciphertext_automorphism_after_ciphertext_multiplication() {
    use pq_libpep::algebra::ring::PolyRq;
    use pq_libpep::core::rlwe_he::RlweHe;
    use pq_libpep::core::rns::RnsModulusChain;
    use rand::thread_rng;

    const N: usize = 256;
    const EXPONENT: usize = 3;
    const P: u64 = 17;

    let mut rng = thread_rng();
    let evaluator = RlweHe::with_chain(RnsModulusChain::new(bpr12_toy_moduli(4, N), N));
    let keygen = evaluator.keygen(&mut rng, N);

    let relin_keys = evaluator.generate_relinearization_key_chain(&mut rng, &keygen.sk, 8);
    let automorphism_keys =
        evaluator.generate_automorphism_key_chain(&mut rng, &keygen.sk, EXPONENT, 8);

    let coefficients: Vec<u64> = (0..N).map(|i| ((i * i + 7 * i + 3) as u64) % P).collect();

    let plaintext = PolyRq::from_coeffs(&coefficients, N, P);
    let encrypted = evaluator.encrypt(&mut rng, &keygen.pk, &plaintext, N);

    // Vera moltiplicazione HE: il risultato passa al livello 1.
    let product = evaluator.mul_ciphertext(&encrypted, &encrypted, &relin_keys);
    assert_eq!(product.level, 1);

    // Automorfismo X -> X^3 al livello 1.
    let transformed = evaluator.apply_automorphism_with_key_chain(&product, &automorphism_keys);
    assert_eq!(transformed.level, 1);

    // Riferimento in chiaro: quadrato negaciclico modulo 17.
    let mut square = vec![0u64; N];

    for i in 0..N {
        for j in 0..N {
            let term = (coefficients[i] * coefficients[j]) % P;
            let k = i + j;
            let destination = k % N;

            if k >= N {
                square[destination] = (square[destination] + P - term) % P;
            } else {
                square[destination] = (square[destination] + term) % P;
            }
        }
    }

    // Riferimento dopo X -> X^3 nel quoziente X^N + 1.
    let mut expected = vec![0u64; N];

    for (i, &coefficient) in square.iter().enumerate() {
        let exponent = (i * EXPONENT) % (2 * N);
        let destination = exponent % N;

        if exponent >= N {
            expected[destination] = (expected[destination] + P - coefficient) % P;
        } else {
            expected[destination] = (expected[destination] + coefficient) % P;
        }
    }

    let actual = evaluator.decrypt(&keygen.sk, &transformed, N);

    assert_eq!(
        &actual.coefficients()[..N],
        expected.as_slice(),
        "automorphism after HE multiplication differs from clear reference"
    );
}

#[test]
fn test_bpr12_crt17_slots_permuted_by_ciphertext_automorphism() {
    use pq_libpep::algebra::ring::PolyRq;
    use pq_libpep::core::bpr12_oblivious::Bpr12HeValue;
    use pq_libpep::core::rlwe_he::RlweHe;
    use rand::thread_rng;

    const N: usize = 256;
    const P: u64 = 17;
    const SLOTS: usize = 8;
    const EXPONENT: usize = 3;

    // These are the CRT17 slot constants used by Bpr12HeValue.
    const SLOT_CONSTANTS: [u64; SLOTS] = [3, 5, 6, 7, 10, 11, 12, 14];

    let mut rng = thread_rng();
    let evaluator = RlweHe::new();
    let keygen = evaluator.keygen(&mut rng, N);

    // Every batch contains eight distinct values modulo 17.
    let coefficients: Vec<u64> = (0..N).map(|i| (i as u64) % P).collect();

    let plaintext = PolyRq::from_coeffs(&coefficients, N, P);

    let packed = Bpr12HeValue::encrypt(&evaluator, &mut rng, &keygen.pk, &plaintext, 1, N);

    assert_eq!(packed.slots_per_ciphertext, SLOTS);
    assert_eq!(packed.limbs.len(), 1);
    assert_eq!(packed.limbs[0].len(), N / SLOTS);

    // First verify the packing order itself.
    let roundtrip = packed.decrypt(&evaluator, &keygen.sk, N);
    assert_eq!(
        &roundtrip.coefficients()[..N],
        coefficients.as_slice(),
        "CRT17 packing roundtrip changed the coefficient order"
    );

    eprintln!("[CRT17 AUTO] generating X -> X^3 automorphism key");

    let automorphism_key = evaluator.generate_automorphism_key(&mut rng, &keygen.sk, EXPONENT, 8);

    // Apply the automorphism to every packed ciphertext.
    // No decryption is performed inside this loop.
    let transformed_batches: Vec<_> = packed.limbs[0]
        .iter()
        .map(|ciphertext| evaluator.apply_automorphism(ciphertext, &automorphism_key))
        .collect();

    let transformed = Bpr12HeValue {
        limbs: vec![transformed_batches],
        level: 0,
        slots_per_ciphertext: SLOTS,
    };

    // Decrypt only after the packed ciphertexts have been transformed.
    let actual = transformed.decrypt(&evaluator, &keygen.sk, N);

    // Under the encoding Y = X^32, slot j corresponds to the root
    // lambda_j = -SLOT_CONSTANTS[j] in F_17.
    // sigma_3(f)(lambda_j) = f(lambda_j^3), so output slot j
    // receives the input slot whose root equals lambda_j^3.
    let roots: [u64; SLOTS] = std::array::from_fn(|j| (P - SLOT_CONSTANTS[j]) % P);

    let mut expected = vec![0u64; N];

    for batch in 0..(N / SLOTS) {
        for output_slot in 0..SLOTS {
            let target_root = mod_pow_test(roots[output_slot], EXPONENT as u32, P);

            let source_slot = roots
                .iter()
                .position(|&root| root == target_root)
                .expect("automorphism must map CRT17 roots to CRT17 roots");

            expected[batch * SLOTS + output_slot] = coefficients[batch * SLOTS + source_slot];
        }
    }

    assert_eq!(
        &actual.coefficients()[..N],
        expected.as_slice(),
        "ciphertext automorphism did not induce the expected CRT17 slot permutation"
    );

    assert_eq!(
        actual.coefficients()[N],
        0,
        "PolyRq padding coefficient must remain zero"
    );

    eprintln!(
        "[CRT17 AUTO] PASS: all {} batches have the expected slot permutation",
        N / SLOTS
    );
}

fn mod_pow_test(mut base: u64, mut exponent: u32, modulus: u64) -> u64 {
    let mut result = 1u64;
    base %= modulus;

    while exponent > 0 {
        if exponent & 1 == 1 {
            result = result * base % modulus;
        }
        base = base * base % modulus;
        exponent >>= 1;
    }

    result
}

#[test]
fn test_encrypted_radix17_scalar_product_nine_limbs_crt8_n256() {
    use std::time::Instant;

    use pq_libpep::algebra::ring::PolyRq;
    use pq_libpep::core::bpr12_oblivious::encrypted_radix17_scalar_product_nine_limbs;
    use pq_libpep::core::rlwe_he::RlweHe;
    use pq_libpep::core::rns::RnsModulusChain;
    use rand::thread_rng;

    const N: usize = 256;
    const SLOTS: usize = 8;
    const Q: u64 = 17u64.pow(9);
    const P: u64 = 17;

    let started = Instant::now();
    let mut rng = thread_rng();

    // Exercise zero, small values, large values, and nontrivial carries.
    let lhs_values: [u64; SLOTS] = [
        0,
        1,
        16,
        17,
        17u64.pow(8) - 1,
        Q - 1_234_567,
        42_123_456_789,
        Q / 2,
    ];

    let rhs_values: [u64; SLOTS] = [
        Q - 1,
        Q - 2,
        2,
        16,
        17u64.pow(7) + 54_321,
        Q - 9_876_543,
        7_654_321,
        Q / 3,
    ];

    eprintln!("[CRT8 MUL-9L] 1/5: generating 24-prime RNS chain");

    let evaluator = RlweHe::with_chain(RnsModulusChain::new(bpr12_toy_moduli(24, N), N));

    let keygen = evaluator.keygen(&mut rng, N);
    let relin_keys = evaluator.generate_relinearization_key_chain(&mut rng, &keygen.sk, 8);

    // Each ciphertext encodes eight independent radix-17 digits.
    // We create just one batch instead of encrypting all 256 coefficients.
    let mut lhs_digits = Vec::with_capacity(9);
    let mut rhs_digits = Vec::with_capacity(9);

    for digit_index in 0..9 {
        let place = P.pow(digit_index as u32);

        let lhs_slots: [u64; SLOTS] = std::array::from_fn(|slot| (lhs_values[slot] / place) % P);

        let rhs_slots: [u64; SLOTS] = std::array::from_fn(|slot| (rhs_values[slot] / place) % P);

        let lhs_encoded = crt17_encode_slots(lhs_slots);
        let rhs_encoded = crt17_encode_slots(rhs_slots);

        let lhs_plain = PolyRq::from_coeffs(&lhs_encoded, N, P);
        let rhs_plain = PolyRq::from_coeffs(&rhs_encoded, N, P);

        lhs_digits.push(evaluator.encrypt(&mut rng, &keygen.pk, &lhs_plain, N));
        rhs_digits.push(evaluator.encrypt(&mut rng, &keygen.pk, &rhs_plain, N));
    }

    let lhs_refs: Vec<_> = lhs_digits.iter().collect();
    let rhs_refs: Vec<_> = rhs_digits.iter().collect();

    eprintln!(
        "[CRT8 MUL-9L +{:.1}s] 2/5: evaluating eight products in parallel",
        started.elapsed().as_secs_f64()
    );

    let encrypted_product =
        encrypted_radix17_scalar_product_nine_limbs(&evaluator, &lhs_refs, &rhs_refs, &relin_keys);

    assert_eq!(encrypted_product.len(), 9);
    assert!(
        encrypted_product.iter().all(|ct| ct.level == 19),
        "all product limbs should finish at level 19"
    );

    eprintln!(
        "[CRT8 MUL-9L +{:.1}s] 3/5: decrypting the nine output limbs",
        started.elapsed().as_secs_f64()
    );

    let decoded_slots: Vec<[u64; SLOTS]> = encrypted_product
        .iter()
        .map(|ct| {
            let plaintext = evaluator.decrypt(&keygen.sk, ct, N);
            crt17_decode_slots(&plaintext.coefficients()[..N])
        })
        .collect();

    let actual: [u64; SLOTS] = std::array::from_fn(|slot| {
        let mut value = 0u128;
        let mut place = 1u128;

        for digit in 0..9 {
            let d = decoded_slots[digit][slot];
            assert!(d < P, "output digit must be in 0..=16");

            value += d as u128 * place;
            place *= P as u128;
        }

        (value % Q as u128) as u64
    });

    let expected: [u64; SLOTS] = std::array::from_fn(|slot| {
        ((lhs_values[slot] as u128 * rhs_values[slot] as u128) % Q as u128) as u64
    });

    eprintln!(
        "[CRT8 MUL-9L +{:.1}s] 4/5: comparing all eight scalar products",
        started.elapsed().as_secs_f64()
    );

    assert_eq!(
        actual, expected,
        "packed nine-limb scalar multiplication differs from the reference"
    );

    eprintln!(
        "[CRT8 MUL-9L +{:.1}s] 5/5: PASS — eight products are exact",
        started.elapsed().as_secs_f64()
    );
}

#[test]
fn test_bpr12_crt17_negacyclic_shift_one_across_batches() {
    use pq_libpep::algebra::ring::PolyRq;
    use pq_libpep::core::bpr12_oblivious::Bpr12HeValue;
    use pq_libpep::core::rlwe_he::RlweHe;
    use rand::thread_rng;

    const N: usize = 256;
    const P: u64 = 17;
    const SLOTS: usize = 8;
    const SLOT_CONSTANTS: [u64; SLOTS] = [3, 5, 6, 7, 10, 11, 12, 14];

    let mut rng = thread_rng();
    let evaluator = RlweHe::new();
    let keygen = evaluator.keygen(&mut rng, N);

    let coefficients: Vec<u64> = (0..N).map(|i| (i as u64 * 7 + 3) % P).collect();

    let plaintext = PolyRq::from_coeffs(&coefficients, N, P);

    let packed = Bpr12HeValue::encrypt(&evaluator, &mut rng, &keygen.pk, &plaintext, 1, N);

    assert_eq!(packed.slots_per_ciphertext, SLOTS);
    assert_eq!(packed.limbs[0].len(), N / SLOTS);

    // Automorfismo per instradare uno slot sorgente
    // verso ciascuno slot di destinazione.
    let roots: [u64; SLOTS] = std::array::from_fn(|i| (P - SLOT_CONSTANTS[i]) % P);

    let exponents: [usize; SLOTS] = std::array::from_fn(|target_slot| {
        let source_slot = (target_slot + SLOTS - 1) % SLOTS;

        (1..(2 * N))
            .step_by(2)
            .find(|&e| mod_pow_test(roots[target_slot], e as u32, P) == roots[source_slot])
            .expect("no automorphism found for slot routing")
    });

    // Genera una sola chiave per ciascun esponente distinto.
    let mut automorphism_keys = Vec::new();

    for &exponent in &exponents {
        if automorphism_keys
            .iter()
            .any(|entry: &(usize, _)| entry.0 == exponent)
        {
            continue;
        }

        let key = evaluator.generate_automorphism_key(&mut rng, &keygen.sk, exponent, 8);

        automorphism_keys.push((exponent, key));
    }

    eprintln!("[SHIFT] Routing 256 coefficients across 32 batches");

    let batch_count = N / SLOTS;
    let mut shifted_batches = Vec::with_capacity(batch_count);

    for batch in 0..batch_count {
        let mut sum = None;

        for target_slot in 0..SLOTS {
            // Multiplication by X:
            // out[i] = in[i-1], with a negative wrap at i=0.
            let source_slot = (target_slot + SLOTS - 1) % SLOTS;

            let source_batch = if target_slot == 0 {
                (batch + batch_count - 1) % batch_count
            } else {
                batch
            };

            // Keep only the source slot we want to route.
            let mut mask_slots = [0u64; SLOTS];
            mask_slots[source_slot] = 1;

            let mask_coefficients = crt17_encode_slots(mask_slots);

            let mask = PolyRq::from_coeffs(&mask_coefficients, N, P);

            let masked = evaluator.mul_plaintext(&packed.limbs[0][source_batch], &mask);

            let exponent = exponents[target_slot];

            let key_index = automorphism_keys
                .iter()
                .position(|entry| entry.0 == exponent)
                .expect("missing automorphism key");

            let transformed =
                evaluator.apply_automorphism(&masked, &automorphism_keys[key_index].1);

            // Only coefficient zero wraps around X^N + 1.
            let term = if batch == 0 && target_slot == 0 {
                evaluator.negate(&transformed)
            } else {
                transformed
            };

            sum = Some(match sum {
                Some(current) => evaluator.add_ciphertexts(&current, &term),
                None => term,
            });
        }

        shifted_batches.push(sum.expect("empty output batch"));
    }

    let shifted = Bpr12HeValue {
        limbs: vec![shifted_batches],
        level: 0,
        slots_per_ciphertext: SLOTS,
    };

    let actual = shifted.decrypt(&evaluator, &keygen.sk, N);

    let expected: Vec<u64> = (0..N)
        .map(|i| {
            if i == 0 {
                (P - coefficients[N - 1]) % P
            } else {
                coefficients[i - 1]
            }
        })
        .collect();

    assert_eq!(
        &actual.coefficients()[..N],
        expected.as_slice(),
        "packed negacyclic shift differs from the clear reference",
    );

    assert_eq!(actual.coefficients()[N], 0);

    eprintln!("[SHIFT] PASS: all 256 coefficients match");
}

#[test]
fn test_bpr12_crt17_negacyclic_shift_eight_by_batch_permutation() {
    use pq_libpep::algebra::ring::PolyRq;
    use pq_libpep::core::bpr12_oblivious::Bpr12HeValue;
    use pq_libpep::core::rlwe_he::RlweHe;
    use rand::thread_rng;

    const N: usize = 256;
    const P: u64 = 17;
    const SLOTS: usize = 8;
    const BATCHES: usize = N / SLOTS;

    let mut rng = thread_rng();
    let evaluator = RlweHe::new();
    let keygen = evaluator.keygen(&mut rng, N);

    let coefficients: Vec<u64> = (0..N).map(|i| (i as u64 * 7 + 3) % P).collect();

    let plaintext = PolyRq::from_coeffs(&coefficients, N, P);
    let packed = Bpr12HeValue::encrypt(&evaluator, &mut rng, &keygen.pk, &plaintext, 1, N);

    // Fresh encryptions of zero let us copy ciphertexts through
    // the public HE API, without consuming a multiplication level.
    let zeros = PolyRq::from_coeffs(&vec![0u64; N], N, P);
    let encrypted_zeros = Bpr12HeValue::encrypt(&evaluator, &mut rng, &keygen.pk, &zeros, 1, N);

    let shifted_batches: Vec<_> = (0..BATCHES)
        .map(|batch| {
            let source_batch = (batch + BATCHES - 1) % BATCHES;

            let copied = evaluator.add_ciphertexts(
                &packed.limbs[0][source_batch],
                &encrypted_zeros.limbs[0][batch],
            );

            // Multiplication by X^8 wraps the last batch with a minus sign.
            if batch == 0 {
                evaluator.negate(&copied)
            } else {
                copied
            }
        })
        .collect();

    let shifted = Bpr12HeValue {
        limbs: vec![shifted_batches],
        level: 0,
        slots_per_ciphertext: SLOTS,
    };

    let actual = shifted.decrypt(&evaluator, &keygen.sk, N);

    let expected: Vec<u64> = (0..N)
        .map(|i| {
            if i < SLOTS {
                (P - coefficients[N - SLOTS + i]) % P
            } else {
                coefficients[i - SLOTS]
            }
        })
        .collect();

    assert_eq!(
        &actual.coefficients()[..N],
        expected.as_slice(),
        "packed negacyclic shift by eight differs from reference",
    );
    assert_eq!(actual.coefficients()[N], 0);

    eprintln!("[SHIFT-8] PASS: all 256 coefficients match");
}

#[test]
fn test_encrypted_radix17_scalar_product_two_limbs_crt8_n256_rank8() {
    use pq_libpep::algebra::ring::PolyRq;
    use pq_libpep::core::bpr12_oblivious::encrypted_radix17_scalar_product;
    use pq_libpep::core::rlwe_he::RlweHe;
    use pq_libpep::core::rns::RnsModulusChain;
    use rand::thread_rng;
    use std::time::Instant;

    const N: usize = 256;
    const SLOTS: usize = 8;
    const P: u64 = 17;
    const Q: u64 = 17 * 17;

    let started = Instant::now();
    let mut rng = thread_rng();

    let lhs_values: [u64; SLOTS] = [0, 1, 16, 17, 288, 34, 255, 272];

    let rhs_values: [u64; SLOTS] = [288, 17, 16, 1, 17, 255, 42, 128];

    eprintln!("[CRT8 MUL-2L] creating N=256 HE context");

    let evaluator = RlweHe::with_chain(RnsModulusChain::new(bpr12_toy_moduli(24, N), N));

    let keygen = evaluator.keygen(&mut rng, N);
    let relin_keys = evaluator.generate_relinearization_key_chain(&mut rng, &keygen.sk, 8);

    let mut lhs_digits = Vec::with_capacity(2);
    let mut rhs_digits = Vec::with_capacity(2);

    for digit_index in 0..2 {
        let place = P.pow(digit_index as u32);

        let lhs_slots: [u64; SLOTS] = std::array::from_fn(|slot| (lhs_values[slot] / place) % P);

        let rhs_slots: [u64; SLOTS] = std::array::from_fn(|slot| (rhs_values[slot] / place) % P);

        let lhs_encoded = crt17_encode_slots(lhs_slots);
        let rhs_encoded = crt17_encode_slots(rhs_slots);

        let lhs_plain = PolyRq::from_coeffs(&lhs_encoded, N, P);
        let rhs_plain = PolyRq::from_coeffs(&rhs_encoded, N, P);

        lhs_digits.push(evaluator.encrypt(&mut rng, &keygen.pk, &lhs_plain, N));

        rhs_digits.push(evaluator.encrypt(&mut rng, &keygen.pk, &rhs_plain, N));
    }

    let lhs_refs: Vec<_> = lhs_digits.iter().collect();
    let rhs_refs: Vec<_> = rhs_digits.iter().collect();

    eprintln!(
        "[CRT8 MUL-2L +{:.1}s] evaluating rank-8 scalar product",
        started.elapsed().as_secs_f64(),
    );

    let encrypted_product =
        encrypted_radix17_scalar_product(&evaluator, &lhs_refs, &rhs_refs, &relin_keys);

    assert_eq!(encrypted_product.len(), 2);

    // For two limbs, the current implementation predicts level 16.
    assert!(
        encrypted_product.iter().all(|ct| ct.level == 16),
        "unexpected output level for the two-limb scalar product",
    );

    let decoded: Vec<[u64; SLOTS]> = encrypted_product
        .iter()
        .map(|ct| {
            let plaintext = evaluator.decrypt(&keygen.sk, ct, N);
            crt17_decode_slots(&plaintext.coefficients()[..N])
        })
        .collect();

    let actual: [u64; SLOTS] =
        std::array::from_fn(|slot| (decoded[0][slot] + P * decoded[1][slot]) % Q);

    let expected: [u64; SLOTS] = std::array::from_fn(|slot| {
        ((lhs_values[slot] as u128 * rhs_values[slot] as u128) % Q as u128) as u64
    });

    assert_eq!(
        actual, expected,
        "N=256 CRT8 rank-8 scalar product is incorrect",
    );

    eprintln!(
        "[CRT8 MUL-2L +{:.1}s] PASS: all eight products are exact",
        started.elapsed().as_secs_f64(),
    );
}

#[test]
fn test_bpr12_crt17_broadcast_coefficient_n256() {
    use pq_libpep::algebra::ring::PolyRq;
    use pq_libpep::core::bpr12_oblivious::{
        bpr12_crt17_broadcast_exponents, encrypted_bpr12_crt17_broadcast_coefficient, Bpr12HeValue,
    };
    use pq_libpep::core::rlwe_he::{HeAutomorphismKeyChain, RlweHe};
    use rand::thread_rng;

    const N: usize = 256;
    const P: u64 = 17;
    const SLOTS: usize = 8;

    let mut rng = thread_rng();
    let evaluator = RlweHe::new();
    let keygen = evaluator.keygen(&mut rng, N);

    let coefficients: Vec<u64> = (0..N).map(|i| ((i * 7 + 3) % P as usize) as u64).collect();

    let plaintext = PolyRq::from_coeffs(&coefficients, N, P);

    let encrypted = Bpr12HeValue::encrypt(&evaluator, &mut rng, &keygen.pk, &plaintext, 1, N);

    // Choose a coefficient that is not at a batch boundary.
    let coefficient_index = 173;
    let source_slot = coefficient_index % SLOTS;
    let expected = coefficients[coefficient_index];

    let exponents = bpr12_crt17_broadcast_exponents(source_slot);

    // This test starts at level 0, so each key chain needs only its
    // level-zero automorphism key. Production calls at higher levels
    // must use complete chains from generate_automorphism_key_chain().
    let mut automorphism_keys: Vec<(usize, HeAutomorphismKeyChain)> = Vec::new();

    for exponent in exponents {
        if automorphism_keys
            .iter()
            .any(|(existing, _)| *existing == exponent)
        {
            continue;
        }

        let key = evaluator.generate_automorphism_key(&mut rng, &keygen.sk, exponent, 8);

        automorphism_keys.push((exponent, HeAutomorphismKeyChain { keys: vec![key] }));
    }

    eprintln!(
        "[CRT17 BROADCAST] extracting coefficient {}",
        coefficient_index
    );

    let broadcast_batches = encrypted_bpr12_crt17_broadcast_coefficient(
        &evaluator,
        &encrypted.limbs[0],
        coefficient_index,
        &automorphism_keys,
    );

    assert_eq!(broadcast_batches.len(), N / SLOTS);

    let broadcast_value = Bpr12HeValue {
        limbs: vec![broadcast_batches],
        level: 0,
        slots_per_ciphertext: SLOTS,
    };

    let recovered = broadcast_value.decrypt(&evaluator, &keygen.sk, N);

    assert_eq!(
        &recovered.coefficients()[..N],
        vec![expected; N].as_slice(),
        "broadcast must replicate the selected coefficient across all slots"
    );
    assert_eq!(
        recovered.coefficients()[N],
        0,
        "broadcast must preserve the trailing padding coefficient"
    );

    eprintln!(
        "[CRT17 BROADCAST] PASS: coefficient {} replicated to all 256 positions",
        coefficient_index
    );
}
