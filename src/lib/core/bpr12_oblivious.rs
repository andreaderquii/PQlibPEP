
use crate::core::rlwe_he::{
    HeCiphertext,
    HePublicKey,
    HeSecretKey,
    HeRelinearizationKeyChain,
    RlweHe,
};

use rand::RngCore;

const RADIX: u64 = 17;

const CRT17_RING_N: usize = 256;
const CRT17_SLOTS: usize = 8;
const CRT17_SLOT_CONSTANTS: [u64; 8] =
    [3, 5, 6, 7, 10, 11, 12, 14];

use crate::algebra::ring::PolyRq;

// A BPR12 ring element represented as radix-17 encrypted limbs.
//
// An element in R_(17^k) is represented coefficient-wise as:
//
//     x = d_0 + 17*d_1 + 17^2*d_2 + ...
//
// where every digit d_i belongs to R_17.
//
// Each limb is encrypted independently with the existing RLWE scheme,
// whose plaintext modulus is 17.
pub struct Bpr12HeValue {
    // Each radix limb stores one scalar-plaintext ciphertext per polynomial
    // coefficient. This prevents nonlinear ring evaluation from mixing
    // coefficient positions through negacyclic multiplication.
    pub limbs: Vec<Vec<HeCiphertext>>,
    pub level: usize,
    pub slots_per_ciphertext: usize,
}

impl Bpr12HeValue {
    // Encrypt coefficient-wise in radix 17. Each individual coefficient is
    // encoded as a constant plaintext polynomial and encrypted separately.
    // This correctness-first representation is more expensive than SIMD.
    pub fn encrypt<R: RngCore>(
        evaluator: &RlweHe,
        rng: &mut R,
        pk: &HePublicKey,
        value: &PolyRq,
        digits: usize,
        n: usize,
    ) -> Self {
        assert!(digits > 0, "BPR12 value must contain at least one limb");
        assert_eq!(
            value.degree_bound(),
            n,
            "BPR12 value has the wrong degree"
        );

        let digit_polys = decompose_radix17(value, digits);

        let slots_per_ciphertext =
            if n == CRT17_RING_N { CRT17_SLOTS } else { 1 };

        let limbs = digit_polys
            .iter()
            .map(|digit| {
                if slots_per_ciphertext == CRT17_SLOTS {
                    digit.coefficients()[..n]
                        .chunks_exact(CRT17_SLOTS)
                        .map(|chunk| {
                            let slots =
                                std::array::from_fn(|i| chunk[i] % RADIX);

                            let packed_coeffs = Self::crt17_encode_slots(slots);
                            let plaintext =
                                PolyRq::from_coeffs(&packed_coeffs, n, RADIX);

                            evaluator.encrypt(rng, pk, &plaintext, n)
                        })
                        .collect::<Vec<_>>()
                } else {
                    digit.coefficients()[..n]
                        .iter()
                        .map(|&coefficient| {
                            let scalar = constant_poly(coefficient, n);
                            evaluator.encrypt(rng, pk, &scalar, n)
                        })
                        .collect::<Vec<_>>()
                }
            })
            .collect::<Vec<_>>();

        Self {
            limbs,
            level: 0,
            slots_per_ciphertext,
        }
    }

    // The encrypted bit must represent a scalar in the constant coefficient.
    // Each coefficient of the selected public leaf is handled independently.
    pub fn select_leaf(
        evaluator: &RlweHe,
        encrypted_bit: &HeCiphertext,
        s0: &PolyRq,
        s1: &PolyRq,
    ) -> Self {
        assert_eq!(s0.modulus(), s1.modulus(), "leaf values must use the same modulus");
        assert_eq!(s0.degree_bound(), s1.degree_bound(), "leaf values must use the same degree");
        assert_eq!(s0.modulus(), RADIX.pow(9), "BPR12 leaf values must use q8 = 17^9");

        let n = s0.degree_bound();
        assert_eq!(encrypted_bit.ciphertext.u.degree, n,
            "encrypted bit and leaf values must use the same degree");

        let s0_digits = decompose_radix17(s0, 9);
        let s1_digits = decompose_radix17(s1, 9);
        let mut selected_limbs = Vec::with_capacity(9);

        for digit_index in 0..9 {
            let mut selected_coefficients = Vec::with_capacity(n);
            for coefficient_index in 0..n {
                let c0 = s0_digits[digit_index].coefficients()[coefficient_index];
                let c1 = s1_digits[digit_index].coefficients()[coefficient_index];
                let difference = constant_poly((c1 + RADIX - c0) % RADIX, n);
                let base = constant_poly(c0, n);
                let selected_difference = evaluator.mul_plaintext(encrypted_bit, &difference);
                selected_coefficients.push(evaluator.add_plaintext(&selected_difference, &base));
            }
            selected_limbs.push(selected_coefficients);
        }

        Self {
            limbs: selected_limbs,
            level: encrypted_bit.level,
            slots_per_ciphertext: 1, 
        }
    }

    pub fn digits(&self) -> usize {
        self.limbs.len()
    }

    pub fn level(&self) -> usize {
        self.level
    }

    pub fn decrypt(
        &self,
        evaluator: &RlweHe,
        sk: &HeSecretKey,
        n: usize,
    ) -> PolyRq {
        let mut digit_polys = Vec::with_capacity(self.limbs.len());

        for limb in &self.limbs {
            let mut coefficients = vec![0u64; n];

            match self.slots_per_ciphertext {
                CRT17_SLOTS => {
                    assert_eq!(n, CRT17_RING_N);
                    assert_eq!(limb.len(), n / CRT17_SLOTS);

                    for (batch_index, ciphertext) in limb.iter().enumerate() {
                        let packed = evaluator.decrypt(sk, ciphertext, n);
                        let packed_coeffs = &packed.coefficients()[..n];

                        // Validate the expected CRT subring representation.
                        for i in 0..n {
                            if i % 32 != 0 {
                                assert_eq!(
                                    packed_coeffs[i],
                                    0,
                                    "unexpected CRT coefficient at index {i}"
                                );
                            }
                        }

                        let slots = Self::crt17_decode_slots(packed_coeffs);
                        let start = batch_index * CRT17_SLOTS;

                        coefficients[start..start + CRT17_SLOTS]
                            .copy_from_slice(&slots);
                    }
                }

                1 => {
                    assert_eq!(
                        limb.len(),
                        n,
                        "coefficient-wise limb must have n ciphertexts"
                    );

                    for (index, scalar_ciphertext) in limb.iter().enumerate() {
                        let scalar = evaluator.decrypt(sk, scalar_ciphertext, n);
                        let scalar_coeffs = scalar.coefficients();

                        assert!(
                            scalar_coeffs[1..].iter().all(|&x| x == 0),
                            "scalar ciphertext has a nonconstant term at index {index}"
                        );

                        coefficients[index] = scalar_coeffs[0];
                    }
                }

                _ => panic!("unsupported BPR12 packing factor"),
            }

            digit_polys.push(PolyRq::from_coeffs(&coefficients, n, RADIX));
        }

        compose_radix17(&digit_polys, n)
    }


    fn crt17_inverse(value: u64) -> u64 {
    (1..RADIX)
        .find(|candidate| value * candidate % RADIX == 1)
        .expect("CRT denominator must be invertible modulo 17")
    }

    fn crt17_encode_slots(slots: [u64; CRT17_SLOTS]) -> Vec<u64> {
        let mut encoded = vec![0u64; CRT17_RING_N];

        for i in 0..CRT17_SLOTS {
            // H_i(Y) = product_{j != i} (Y + c_j).
            let mut h = vec![1u64];

            for j in 0..CRT17_SLOTS {
                if i == j {
                    continue;
                }

                let mut next = vec![0u64; h.len() + 1];

                for (k, &coefficient) in h.iter().enumerate() {
                    next[k] =
                        (next[k] + coefficient * CRT17_SLOT_CONSTANTS[j]) % RADIX;
                    next[k + 1] =
                        (next[k + 1] + coefficient) % RADIX;
                }

                h = next;
            }

            // Normalize H_i(-c_i) to 1.
            let mut denominator = 1u64;

            for j in 0..CRT17_SLOTS {
                if j != i {
                    let difference =
                        (CRT17_SLOT_CONSTANTS[j] + RADIX
                            - CRT17_SLOT_CONSTANTS[i]) % RADIX;

                    denominator = denominator * difference % RADIX;
                }
            }

            let scale = Self::crt17_inverse(denominator);

            // Y = X^32, so only coefficients X^(32*k) are populated.
            for (k, &coefficient) in h.iter().enumerate() {
                let index = 32 * k;
                let term =
                    slots[i] % RADIX * coefficient % RADIX * scale % RADIX;

                encoded[index] = (encoded[index] + term) % RADIX;
            }
        }

        encoded
    }

    fn crt17_decode_slots(poly: &[u64]) -> [u64; CRT17_SLOTS] {
        assert_eq!(poly.len(), CRT17_RING_N);

        let mut slots = [0u64; CRT17_SLOTS];

        for i in 0..CRT17_SLOTS {
            let base = (RADIX - CRT17_SLOT_CONSTANTS[i]) % RADIX;
            let mut power = 1u64;
            let mut value = 0u64;

            for k in 0..CRT17_SLOTS {
                value = (value + poly[32 * k] * power) % RADIX;
                power = power * base % RADIX;
            }

            slots[i] = value;
        }

        slots
    }
}

// Decomposes a polynomial coefficient-wise in base 17.
//
// For example, with k = 3:
//
//     x = d0 + 17*d1 + 17^2*d2
//
// Each returned polynomial belongs to R_17.
pub fn decompose_radix17(
    value: &PolyRq,
    digits: usize,
) -> Vec<PolyRq> {
    assert!(digits > 0);

    let n = value.degree_bound();
    let coeffs = value.coefficients();

    let mut digit_coeffs =
        vec![vec![0u64; n]; digits];

    for i in 0..n {
        let mut x = coeffs[i];

        for d in 0..digits {
            digit_coeffs[d][i] = x % RADIX;
            x /= RADIX;
        }

        assert_eq!(
            x,
            0,
            "value does not fit inside the requested radix-17 representation"
        );
    }

    digit_coeffs
        .into_iter()
        .map(|coeffs| {
            PolyRq::from_coeffs(
                &coeffs,
                n,
                RADIX,
            )
        })
        .collect()
}

// Reconstructs a polynomial from radix-17 limbs.
//
// The resulting polynomial has modulus:
//
//     17^digits
pub fn compose_radix17(
    digits: &[PolyRq],
    n: usize,
) -> PolyRq {
    assert!(
        !digits.is_empty(),
        "at least one radix-17 digit is required"
    );

    for digit in digits {
        assert_eq!(
            digit.modulus(),
            RADIX,
            "radix-17 digit has the wrong modulus"
        );

        assert_eq!(
            digit.degree_bound(),
            n,
            "radix-17 digit has the wrong degree"
        );
    }

    let modulus = RADIX.pow(
        digits.len() as u32
    );

    let mut result =
        vec![0u64; n];

    for i in 0..n {
        let mut value = 0u128;
        let mut power = 1u128;

        for digit in digits {
            value +=
                digit.coefficients()[i] as u128
                * power;

            power *= RADIX as u128;
        }

        result[i] =
            (value % modulus as u128) as u64;
    }

    PolyRq::from_coeffs(
        &result,
        n,
        modulus,
    )
}

// Performs one BPR12 modulus reduction using the radix-17
// representation.
//
// For:
//
//     q = 17 * p
//
// BPR12 rounding:
//
//     round_p(x) = round(x / 17) mod p
//
// can be expressed using the radix-17 digits of x.
//
// If:
//
//     x = d0 + 17*d1 + 17^2*d2 + ...
//
// then:
//
//     round_p(x) = d1 + 17*d2 + ...
//                  + [d0 >= 9]
//
// where [condition] is 1 when the condition is true and 0 otherwise.
//
// This is a plaintext/reference implementation.
// It is NOT homomorphic yet.
pub fn round_one_level_radix17(
    value: &PolyRq,
) -> PolyRq {
    const RADIX: u64 = 17;

    let q = value.modulus();
    let n = value.degree_bound();

    assert!(
        q % RADIX == 0,
        "BPR12 modulus must be divisible by 17"
    );

    let target_modulus =
        q / RADIX;

    let rounded_coeffs: Vec<u64> =
        value
            .coefficients()
            .iter()
            .take(n)
            .map(|&coefficient| {
                let coefficient =
                    coefficient % q;

                let low_digit =
                    coefficient % RADIX;

                let higher_digits =
                    coefficient / RADIX;

                let rounded =
                    if low_digit >= 9 {
                        higher_digits + 1
                    } else {
                        higher_digits
                    };

                rounded % target_modulus
            })
            .collect();

    PolyRq::from_coeffs(
        &rounded_coeffs,
        n,
        target_modulus,
    )
}

// Creates a constant plaintext polynomial in R_17 for BGV operations.
fn constant_poly(value: u64, n: usize) -> PolyRq {
    let mut coeffs = vec![0u64; n];
    coeffs[0] = value % RADIX;
    PolyRq::from_coeffs(&coeffs, n, RADIX)
}

/// Evaluate the BPR12 carry indicator `[x >= 9]` homomorphically for one
/// encrypted scalar represented as a constant plaintext polynomial in R_17.
///
/// This function is coefficient-wise: do not pass a general plaintext
/// polynomial with multiple nonzero coefficients, because ring multiplication
/// is negacyclic and can mix coefficient positions.
pub fn encrypted_carry_ge_9(
    evaluator: &RlweHe,
    value: &HeCiphertext,
    relin_keys: &HeRelinearizationKeyChain,
) -> HeCiphertext {
    let n = value.ciphertext.u.degree;
    let base_level = value.level;

    // ------------------------------------------------------------
    // Compute the powers needed by the indicator polynomial.
    //
    // We keep the multiplicative depth as low as possible:
    //
    // x^2  -> level 1
    // x^3  -> level 2
    // x^4  -> level 2
    // x^5  -> level 3
    // x^7  -> level 3
    // x^8  -> level 3
    // x^11 -> level 4
    // x^13 -> level 4
    // x^15 -> level 4
    // x^16 -> level 4
    // ------------------------------------------------------------

    // x^2
    let x2 = evaluator.mul_ciphertext(
        value,
        value,
        relin_keys,
    );

    // x^3 = x^2 * x
    let x_level_1 =
        lift_ciphertext_level(evaluator, value, base_level + 1);

    let x3 = evaluator.mul_ciphertext(
        &x2,
        &x_level_1,
        relin_keys,
    );

    // x^4 = x^2 * x^2
    let x4 = evaluator.mul_ciphertext(
        &x2,
        &x2,
        relin_keys,
    );

    // x^5 = x^4 * x
    let x_level_2 =
        lift_ciphertext_level(evaluator, value, base_level + 2);

    let x5 = evaluator.mul_ciphertext(
        &x4,
        &x_level_2,
        relin_keys,
    );

    // x^7 = x^4 * x^3. Both ciphertexts are already at level 2.
    // Multiplying x^4 by x^2 would compute x^6 instead.
    let x7 = evaluator.mul_ciphertext(
        &x4,
        &x3,
        relin_keys,
    );

    // x^8 = x^4 * x^4
    let x8 = evaluator.mul_ciphertext(
        &x4,
        &x4,
        relin_keys,
    );

    // x^11 = x^8 * x^3
    let x3_level_3 =
        lift_ciphertext_level(evaluator, &x3, base_level + 3);

    let x11 = evaluator.mul_ciphertext(
        &x8,
        &x3_level_3,
        relin_keys,
    );

    // x^13 = x^8 * x^5
    let x13 = evaluator.mul_ciphertext(
        &x8,
        &x5,
        relin_keys,
    );

    // x^15 = x^8 * x^7
    let x15 = evaluator.mul_ciphertext(
        &x8,
        &x7,
        relin_keys,
    );

    // x^16 = x^8 * x^8
    let x16 = evaluator.mul_ciphertext(
        &x8,
        &x8,
        relin_keys,
    );

    // ------------------------------------------------------------
    // Indicator polynomial for:
    //
    //     [x >= 9]
    //
    // over F_17:
    //
    //     f(x) =
    //       8x
    //     + 9x^3
    //     + 10x^5
    //     + 11x^7
    //     + 15x^11
    //     + 4x^13
    //     + 2x^15
    //     + 9x^16
    // ------------------------------------------------------------

    let term1 = evaluator.mul_plaintext(
        value,
        &constant_poly(8, n)
    );

    let term2 = evaluator.mul_plaintext(
        &x3,
        &constant_poly(9, n),
    );

    let term3 = evaluator.mul_plaintext(
        &x5,
        &constant_poly(10, n),
    );

    let term4 = evaluator.mul_plaintext(
        &x7,
        &constant_poly(11, n),
    );

    let term5 = evaluator.mul_plaintext(
        &x11,
        &constant_poly(15, n),
    );

    let term6 = evaluator.mul_plaintext(
        &x13,
        &constant_poly(4, n),
    );

    let term7 = evaluator.mul_plaintext(
        &x15,
        &constant_poly(2, n),
    );

    let term8 = evaluator.mul_plaintext(
        &x16,
        &constant_poly(9, n),
    );

    // ------------------------------------------------------------
    // The deepest term is at level 4.
    // Lift the lower-level terms so that all additions are valid.
    // ------------------------------------------------------------

    let final_level = base_level + 4;

    let term1 =
        lift_ciphertext_level(evaluator, &term1, final_level);

    let term2 =
        lift_ciphertext_level(evaluator, &term2, final_level);

    let term3 =
        lift_ciphertext_level(evaluator, &term3, final_level);

    let term4 =
        lift_ciphertext_level(evaluator, &term4, final_level);

    let term5 =
        lift_ciphertext_level(evaluator, &term5, final_level);

    let term6 =
        lift_ciphertext_level(evaluator, &term6, final_level);

    let term7 =
        lift_ciphertext_level(evaluator, &term7, final_level);

    let term8 =
        lift_ciphertext_level(evaluator, &term8, final_level);

    // ------------------------------------------------------------
    // Sum the polynomial terms.
    // ------------------------------------------------------------

    let sum12 =
        evaluator.add_ciphertexts(
            &term1,
            &term2,
        );

    let sum34 =
        evaluator.add_ciphertexts(
            &term3,
            &term4,
        );

    let sum56 =
        evaluator.add_ciphertexts(
            &term5,
            &term6,
        );

    let sum78 =
        evaluator.add_ciphertexts(
            &term7,
            &term8,
        );

    let sum1234 =
        evaluator.add_ciphertexts(
            &sum12,
            &sum34,
        );

    let sum5678 =
        evaluator.add_ciphertexts(
            &sum56,
            &sum78,
        );

    evaluator.add_ciphertexts(
        &sum1234,
        &sum5678,
    )
}


// Brings a ciphertext to a deeper level through real BGV modulus switches.
fn lift_ciphertext_level(
    evaluator: &RlweHe,
    ciphertext: &HeCiphertext,
    target_level: usize,
) -> HeCiphertext {
    evaluator.modulus_switch_to_level(ciphertext, target_level)
}

// Homomorphically performs one BPR12 rounding step.
//
// Given an encrypted value:
//
//     x = d0 + 17*d1 + 17^2*d2 + ...
//
// computes:
//
//     round(x / 17)
//
// which is:
//
//     d1 + 17*d2 + ...
//         + [d0 >= 9]
//
// The lowest radix-17 digit is therefore discarded and its rounding carry
// is added to the next digit.
pub fn round_one_level_homomorphic(
    evaluator: &RlweHe,
    value: &Bpr12HeValue,
    relin_keys: &HeRelinearizationKeyChain,
) -> Bpr12HeValue {
    assert!(
        value.limbs.len() >= 2,
        "at least two radix-17 limbs are required for one rounding step"
    );

    let low_digit = &value.limbs[0];
    let first_ciphertext = low_digit
        .first()
        .expect("BPR12 limb must contain at least one ciphertext");

    let ring_n = first_ciphertext.ciphertext.u.degree;

    // Number of ciphertexts in each limb, according to its representation.
    let ciphertexts_per_limb = match value.slots_per_ciphertext {
        1 => ring_n,

        CRT17_SLOTS => {
            assert_eq!(
                ring_n, CRT17_RING_N,
                "CRT-packed representation requires ring dimension 256"
            );
            ring_n / CRT17_SLOTS
        }

        _ => panic!("unsupported BPR12 packing factor"),
    };

    assert_eq!(
        low_digit.len(),
        ciphertexts_per_limb,
        "low limb does not match its packing representation"
    );

    // Evaluate the encrypted carry independently in each batch.
    // In CRT-packed mode, each carry ciphertext contains 8 slots.
    let carries = low_digit
        .iter()
        .map(|ciphertext| {
            encrypted_carry_ge_9(evaluator, ciphertext, relin_keys)
        })
        .collect::<Vec<_>>();

    let target_level = carries[0].level;

    // Drop the low digit and switch the remaining limbs to the carry level.
    let mut output_limbs = Vec::with_capacity(value.limbs.len() - 1);

    for limb in value.limbs.iter().skip(1) {
        assert_eq!(
            limb.len(),
            ciphertexts_per_limb,
            "all radix limbs must use the same packing layout"
        );

        let switched = limb
            .iter()
            .map(|ciphertext| {
                lift_ciphertext_level(evaluator, ciphertext, target_level)
            })
            .collect::<Vec<_>>();

        output_limbs.push(switched);
    }

    // Add each encrypted carry to the corresponding high-digit ciphertext.
    // CRT slot-wise addition handles all 8 values within that ciphertext.
    for batch_index in 0..ciphertexts_per_limb {
        output_limbs[0][batch_index] = evaluator.add_ciphertexts(
            &output_limbs[0][batch_index],
            &carries[batch_index],
        );
    }

    Bpr12HeValue {
        limbs: output_limbs,
        level: target_level,
        slots_per_ciphertext: value.slots_per_ciphertext,
    }
}