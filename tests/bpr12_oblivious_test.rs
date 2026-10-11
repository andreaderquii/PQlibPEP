use pq_libpep::algebra::ring::{round_poly, PolyRq};
use pq_libpep::core::bpr12_oblivious::{
    compose_radix17,
    decompose_radix17,
    encrypted_carry_ge_9,
    round_one_level_homomorphic,
    round_one_level_radix17,
    Bpr12HeValue,
};
use pq_libpep::core::rlwe_he::RlweHe;
use pq_libpep::core::rns::RnsModulusChain;
use pq_libpep::core::rlwr_prf::RlwrPrfBase;
use rand::thread_rng;

const N: usize = 256;
const N_SMALL: usize = 8;
const PLAINTEXT_MODULUS: u64 = 17;
const Q8: u64 = 17u64.pow(9);
const TEST_RNS_MODULI: [u64; 12] = [
    8_416_769, 8_434_177, 8_573_441, 8_599_553,
    8_782_337, 8_825_857, 8_834_561, 8_860_673,
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
        .map(|i| {
            ((i as u64 + 1) * 987_654_321 + 123_456_789) % Q8
        })
        .collect();

    let value = PolyRq::from_coeffs(&coeffs, N, Q8);
    let expected_digits = decompose_radix17(&value, 9);

    let encrypted =
        Bpr12HeValue::encrypt(&evaluator, &mut rng, &keygen.pk, &value, 9, N);

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
                std::array::from_fn(|i| {
                    expected_digit.coefficients()[start + i]
                });

            assert_eq!(
                actual_slots,
                expected_slots,
                "CRT roundtrip failed for limb {limb_index}, batch {batch_index}"
            );

            // Check that the packed plaintext remains in the expected subring.
            for i in 0..N {
                if i % 32 != 0 {
                    assert_eq!(
                        packed_coeffs[i],
                        0,
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

        let selected = Bpr12HeValue::select_leaf(
            &evaluator, &encrypted_bit, &base.s0[0], &base.s1[0],
        );
        let recovered = selected.decrypt(&evaluator, &keygen.sk, N_SMALL);
        let expected = if bit == 0 { &base.s0[0] } else { &base.s1[0] };
        assert_eq!(
            recovered.to_coeffs_vec(), expected.to_coeffs_vec(),
            "encrypted BPR12 leaf selection failed for bit={}", bit
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
    let low_digits = [
        0u64, 1, 2, 3, 4, 5, 6, 7, 8,
        9, 10, 11, 12, 13, 14, 15, 16,
    ];

    let high_digits = [
        0u64, 1, 2, 3, 4, 5, 6, 7, 8,
        9, 10, 11, 12, 13, 14, 15, 16,
    ];

    let coeffs = (0..N_SMALL)
        .map(|i| low_digits[i] + 17 * high_digits[i])
        .collect::<Vec<_>>();
    let value = PolyRq::from_coeffs(&coeffs, N_SMALL, Q8);
    let mut expected = (0..N_SMALL).map(|i| {
        high_digits[i] + (if low_digits[i] >= 9 { 1 } else { 0 })
    }).collect::<Vec<_>>();
    for coefficient in &mut expected { *coefficient %= PLAINTEXT_MODULUS; }

    let encrypted = Bpr12HeValue::encrypt(
        &evaluator, &mut rng, &keygen.pk, &value, 2, N_SMALL,
    );
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
        assert_eq!(carry.level, 4, "indicator should consume four multiplication levels");

        let mut high_coefficients = vec![0u64; N];
        high_coefficients[0] = high_digits[index];
        let high_plaintext = PolyRq::from_coeffs(&high_coefficients, N, PLAINTEXT_MODULUS);
        let high_ciphertext = evaluator.encrypt(&mut rng, &keygen.pk, &high_plaintext, N);
        let high_at_carry_level = evaluator.modulus_switch_to_level(&high_ciphertext, carry.level);
        let rounded = evaluator.add_ciphertexts(&high_at_carry_level, &carry);
        let recovered = evaluator.decrypt(&keygen.sk, &rounded, N);

        let expected = (high_digits[index] + u64::from(low_digits[index] >= 9))
            % PLAINTEXT_MODULUS;
        assert_eq!(
            recovered.coefficients()[0],
            expected,
            "N=256 carry/rounding failed at vector index {index}"
        );
        assert!(
            recovered.coefficients()[1..N].iter().all(|&coefficient| coefficient == 0),
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
    let relin_keys = evaluator.generate_relinearization_key_chain(
        &mut rng,
        &keygen.sk,
        8,
    );

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
            decoded.coefficients()[1..].iter().all(|&coefficient| coefficient == 0),
            "constant input acquired nonzero plaintext coefficients at level {}",
            expected_level
        );
    }
}

#[test]
#[ignore = "Slow regression: 256 independent encrypted carry circuits at N=256"]
fn test_bpr12_homomorphic_rounding_all_256_coefficients() {
    let mut rng = thread_rng();
    let evaluator = RlweHe::new();

    let keygen = evaluator.keygen(&mut rng, N);
    let relin_keys =
        evaluator.generate_relinearization_key_chain(&mut rng, &keygen.sk, 8);

    // Every coefficient receives a different pair of radix-17 digits.
    let low_digits: Vec<u64> =
        (0..N).map(|i| (i as u64) % PLAINTEXT_MODULUS).collect();

    let high_digits: Vec<u64> = (0..N)
        .map(|i| (i as u64 * 7 + 3) % PLAINTEXT_MODULUS)
        .collect();

    let input_coefficients: Vec<u64> = (0..N)
        .map(|i| low_digits[i] + 17 * high_digits[i])
        .collect();

    let value = PolyRq::from_coeffs(&input_coefficients, N, Q8);

    // Two radix-17 limbs are sufficient because every coefficient is < 17^2.
    let encrypted =
        Bpr12HeValue::encrypt(&evaluator, &mut rng, &keygen.pk, &value, 2, N);

    // Verify that coefficient-wise encryption preserves the input.
    let fresh = encrypted.decrypt(&evaluator, &keygen.sk, N);
    assert_eq!(
        &fresh.coefficients()[..N],
        input_coefficients.as_slice(),
        "coefficient-wise encryption roundtrip failed"
    );
    assert_eq!(
        fresh.coefficients()[N],
        0,
        "PolyRq trailing padding must remain zero"
    );

    // Perform the actual homomorphic rounding on all 256 coefficients.
    let rounded =
        round_one_level_homomorphic(&evaluator, &encrypted, &relin_keys);

    let recovered = rounded.decrypt(&evaluator, &keygen.sk, N);

    let expected: Vec<u64> = (0..N)
        .map(|i| {
            (high_digits[i] + u64::from(low_digits[i] >= 9))
                % PLAINTEXT_MODULUS
        })
        .collect();

    assert_eq!(
        &recovered.coefficients()[..N],
        expected.as_slice(),
        "BPR12 homomorphic rounding failed on the full N=256 coefficient vector"
    );
    assert_eq!(
        recovered.coefficients()[N],
        0,
        "PolyRq trailing padding must remain zero after rounding"
    );

    assert_eq!(rounded.digits(), 1);
    assert_eq!(rounded.level(), 4);
}

/////// prova 256
const CRT17_MODULUS: u64 = 17;
const CRT17_N: usize = 256;
const CRT17_SLOT_CONSTANTS: [u64; 8] =
    [3, 5, 6, 7, 10, 11, 12, 14];

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
                next[k] =
                    (next[k] + coefficient * CRT17_SLOT_CONSTANTS[j]) % 17;
                next[k + 1] =
                    (next[k + 1] + coefficient) % 17;
            }

            h = next;
        }

        // Normalize so that H_i(-c_i) = 1 in slot i.
        let mut denominator = 1u64;
        for j in 0..8 {
            if i != j {
                let difference =
                    (CRT17_SLOT_CONSTANTS[j] + 17
                        - CRT17_SLOT_CONSTANTS[i]) % 17;
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
            actual,
            expected,
            "CRT-batched carry indicator returned incorrect slots"
        );

        for i in 0..CRT17_N {
            if i % 32 != 0 {
                assert_eq!(
                    carry_poly[i],
                    0,
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
    let relin_keys =
        evaluator.generate_relinearization_key_chain(
            &mut rng,
            &keygen.sk,
            8,
        );

    // Eight independent plaintext slots, including threshold cases.
    let slots = [0u64, 1, 8, 9, 10, 16, 4, 12];

    // Pack the eight values into one polynomial in R_17.
    let packed = crt17_encode_slots(slots);
    let plaintext =
        PolyRq::from_coeffs(&packed, CRT17_N, CRT17_MODULUS);

    // Encrypt the entire packed polynomial as ONE ciphertext.
    let ciphertext =
        evaluator.encrypt(&mut rng, &keygen.pk, &plaintext, CRT17_N);

    // First establish that encryption preserves the CRT representation.
    let fresh =
        evaluator.decrypt(&keygen.sk, &ciphertext, CRT17_N);

    assert_eq!(
        crt17_decode_slots(&fresh.coefficients()[..CRT17_N]),
        slots,
        "encrypted CRT-slot roundtrip failed"
    );

    // Evaluate the carry indicator homomorphically.
    // No plaintext decryption occurs inside this evaluation.
    let encrypted_carry =
        encrypted_carry_ge_9(&evaluator, &ciphertext, &relin_keys);

    assert_eq!(encrypted_carry.level, 4);

    // Decrypt only the FINAL ciphertext and decode the eight slots.
    let recovered =
        evaluator.decrypt(&keygen.sk, &encrypted_carry, CRT17_N);

    let actual =
        crt17_decode_slots(&recovered.coefficients()[..CRT17_N]);

    let expected = slots.map(|x| u64::from(x >= 9));

    assert_eq!(
        actual,
        expected,
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
    let relin_keys =
        evaluator.generate_relinearization_key_chain(
            &mut rng,
            &keygen.sk,
            8,
        );

    for batch in 0..(CRT17_N / 8) {
        let start = batch * 8;

        // Eight independent low radix-17 digits.
        let slots: [u64; 8] =
            std::array::from_fn(|j| ((start + j) as u64 * 7 + 3) % 17);

        // Eight independent high radix-17 digits.
        let high_slots: [u64; 8] =
            std::array::from_fn(|j| ((start + j) as u64 * 11 + 4) % 17);

        // Pack the low digits into one polynomial.
        let packed = crt17_encode_slots(slots);
        let plaintext =
            PolyRq::from_coeffs(&packed, CRT17_N, CRT17_MODULUS);

        // Encrypt the entire packed polynomial as one RNS ciphertext.
        let ciphertext =
            evaluator.encrypt(&mut rng, &keygen.pk, &plaintext, CRT17_N);

        // Evaluate the carry indicator without decrypting intermediates.
        let encrypted_carry =
            encrypted_carry_ge_9(&evaluator, &ciphertext, &relin_keys);

        assert_eq!(
            encrypted_carry.level,
            4,
            "unexpected HE level in batch {batch}"
        );

        // Decrypt only the final carry result.
        let recovered_carry =
            evaluator.decrypt(&keygen.sk, &encrypted_carry, CRT17_N);

        let actual_carry =
            crt17_decode_slots(
                &recovered_carry.coefficients()[..CRT17_N]
            );

        let expected_carry = slots.map(|x| u64::from(x >= 9));

        assert_eq!(
            actual_carry,
            expected_carry,
            "carry mismatch in batch {batch}, input slots {slots:?}"
        );

        // Pack and encrypt the high digits.
        let high_packed = crt17_encode_slots(high_slots);
        let high_plaintext =
            PolyRq::from_coeffs(
                &high_packed,
                CRT17_N,
                CRT17_MODULUS,
            );

        let high_ciphertext =
            evaluator.encrypt(
                &mut rng,
                &keygen.pk,
                &high_plaintext,
                CRT17_N,
            );

        // Bring the high digit to the carry's level.
        let high_at_level =
            evaluator.modulus_switch_to_level(
                &high_ciphertext,
                encrypted_carry.level,
            );

        assert_eq!(
            high_at_level.level,
            encrypted_carry.level,
            "high digit and carry must be at the same level"
        );

        // Perform the actual homomorphic rounding step:
        // rounded_digit = high_digit + carry (mod 17).
        let encrypted_rounded =
            evaluator.add_ciphertexts(
                &high_at_level,
                &encrypted_carry,
            );

        // Decrypt only the final rounded ciphertext.
        let decrypted_rounded =
            evaluator.decrypt(
                &keygen.sk,
                &encrypted_rounded,
                CRT17_N,
            );

        let actual_rounded =
            crt17_decode_slots(
                &decrypted_rounded.coefficients()[..CRT17_N]
            );

        let expected_rounded: [u64; 8] =
            std::array::from_fn(|j| {
                (high_slots[j] + u64::from(slots[j] >= 9)) % 17
            });

        assert_eq!(
            actual_rounded,
            expected_rounded,
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