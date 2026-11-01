use crate::core::rlwe_he::{
    HeAutomorphismKeyChain, HeCiphertext, HePublicKey, HeRelinearizationKeyChain, HeSecretKey,
    RlweHe,
};
use crate::parameters::bpr12_prototype as parameter_profile;

use rand::RngCore;

const RADIX: u64 = parameter_profile::RADIX;

const CRT17_RING_N: usize = parameter_profile::CRT_PACKED_RING_DIMENSION;
const CRT17_SLOTS: usize = parameter_profile::CRT_PACKED_SLOTS;
const CRT17_SLOT_CONSTANTS: [u64; 8] = [3, 5, 6, 7, 10, 11, 12, 14];

use crate::algebra::ring::PolyRq;

// A BPR12 ring element represented as radix-17 encrypted limbs.
//
// An element in R_(17^k) is represented as:
//
//     x = d_0 + 17*d_1 + 17^2*d_2 + ...
//
// where every digit d_i belongs to R_17. At N=256, each limb uses eight-slot
// CRT packing; other supported ring dimensions use one scalar ciphertext per
// coefficient. Both layouts keep the nonlinear carry circuit pointwise with
// respect to the represented values.
pub struct Bpr12HeValue {
    // Each limb is either coefficient-wise (one scalar ciphertext per
    // coefficient) or CRT-packed (eight slots in each ciphertext).
    pub limbs: Vec<Vec<HeCiphertext>>,
    pub level: usize,
    pub slots_per_ciphertext: usize,
}

impl Bpr12HeValue {
    // Encrypt the radix-17 digits. At N=256, pack eight digit coefficients per
    // ciphertext using the CRT subring; otherwise use scalar ciphertexts.
    pub fn encrypt<R: RngCore>(
        evaluator: &RlweHe,
        rng: &mut R,
        pk: &HePublicKey,
        value: &PolyRq,
        digits: usize,
        n: usize,
    ) -> Self {
        assert!(digits > 0, "BPR12 value must contain at least one limb");
        assert_eq!(value.degree_bound(), n, "BPR12 value has the wrong degree");

        let digit_polys = decompose_radix17(value, digits);

        let slots_per_ciphertext = if n == CRT17_RING_N { CRT17_SLOTS } else { 1 };

        let limbs = digit_polys
            .iter()
            .map(|digit| {
                if slots_per_ciphertext == CRT17_SLOTS {
                    digit.coefficients()[..n]
                        .chunks_exact(CRT17_SLOTS)
                        .map(|chunk| {
                            let slots = std::array::from_fn(|i| chunk[i] % RADIX);

                            let packed_coeffs = Self::crt17_encode_slots(slots);
                            let plaintext = PolyRq::from_coeffs(&packed_coeffs, n, RADIX);

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
        assert_eq!(
            s0.modulus(),
            s1.modulus(),
            "leaf values must use the same modulus"
        );
        assert_eq!(
            s0.degree_bound(),
            s1.degree_bound(),
            "leaf values must use the same degree"
        );
        assert_eq!(
            s0.modulus(),
            RADIX.pow(9),
            "BPR12 leaf values must use q8 = 17^9"
        );

        let n = s0.degree_bound();
        assert_eq!(
            encrypted_bit.ciphertext.u.degree, n,
            "encrypted bit and leaf values must use the same degree"
        );

        // The selector ciphertext is required to encrypt a constant polynomial
        // containing the bit in coefficient zero. Multiplication by a packed
        // plaintext then scales each encoded CRT slot by that same bit, so the
        // eight selected coefficients remain independent.
        let s0_digits = decompose_radix17(s0, 9);
        let s1_digits = decompose_radix17(s1, 9);
        let slots_per_ciphertext = if n == CRT17_RING_N { CRT17_SLOTS } else { 1 };
        let mut selected_limbs = Vec::with_capacity(9);

        for digit_index in 0..9 {
            if slots_per_ciphertext == CRT17_SLOTS {
                let mut selected_batches = Vec::with_capacity(n / CRT17_SLOTS);

                for batch_index in 0..(n / CRT17_SLOTS) {
                    let start = batch_index * CRT17_SLOTS;
                    let base_slots: [u64; CRT17_SLOTS] = std::array::from_fn(|slot| {
                        s0_digits[digit_index].coefficients()[start + slot] % RADIX
                    });
                    let other_slots: [u64; CRT17_SLOTS] = std::array::from_fn(|slot| {
                        s1_digits[digit_index].coefficients()[start + slot] % RADIX
                    });
                    let difference_slots: [u64; CRT17_SLOTS] = std::array::from_fn(|slot| {
                        (other_slots[slot] + RADIX - base_slots[slot]) % RADIX
                    });

                    let base_coefficients = Self::crt17_encode_slots(base_slots);
                    let difference_coefficients = Self::crt17_encode_slots(difference_slots);
                    let base_plaintext = PolyRq::from_coeffs(&base_coefficients, n, RADIX);
                    let difference_plaintext =
                        PolyRq::from_coeffs(&difference_coefficients, n, RADIX);

                    let selected_difference =
                        evaluator.mul_plaintext(encrypted_bit, &difference_plaintext);
                    let selected = evaluator.add_plaintext(&selected_difference, &base_plaintext);
                    selected_batches.push(selected);
                }

                selected_limbs.push(selected_batches);
            } else {
                let mut selected_coefficients = Vec::with_capacity(n);
                for coefficient_index in 0..n {
                    let c0 = s0_digits[digit_index].coefficients()[coefficient_index];
                    let c1 = s1_digits[digit_index].coefficients()[coefficient_index];
                    let difference = constant_poly((c1 + RADIX - c0) % RADIX, n);
                    let base = constant_poly(c0, n);
                    let selected_difference = evaluator.mul_plaintext(encrypted_bit, &difference);
                    selected_coefficients
                        .push(evaluator.add_plaintext(&selected_difference, &base));
                }
                selected_limbs.push(selected_coefficients);
            }
        }

        Self {
            limbs: selected_limbs,
            level: encrypted_bit.level,
            slots_per_ciphertext,
        }
    }

    pub fn digits(&self) -> usize {
        self.limbs.len()
    }

    pub fn level(&self) -> usize {
        self.level
    }

    pub fn decrypt(&self, evaluator: &RlweHe, sk: &HeSecretKey, n: usize) -> PolyRq {
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
                                    packed_coeffs[i], 0,
                                    "unexpected CRT coefficient at index {i}"
                                );
                            }
                        }

                        let slots = Self::crt17_decode_slots(packed_coeffs);
                        let start = batch_index * CRT17_SLOTS;

                        coefficients[start..start + CRT17_SLOTS].copy_from_slice(&slots);
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
                    next[k] = (next[k] + coefficient * CRT17_SLOT_CONSTANTS[j]) % RADIX;
                    next[k + 1] = (next[k + 1] + coefficient) % RADIX;
                }

                h = next;
            }

            // Normalize H_i(-c_i) to 1.
            let mut denominator = 1u64;

            for j in 0..CRT17_SLOTS {
                if j != i {
                    let difference =
                        (CRT17_SLOT_CONSTANTS[j] + RADIX - CRT17_SLOT_CONSTANTS[i]) % RADIX;

                    denominator = denominator * difference % RADIX;
                }
            }

            let scale = Self::crt17_inverse(denominator);

            // Y = X^32, so only coefficients X^(32*k) are populated.
            for (k, &coefficient) in h.iter().enumerate() {
                let index = 32 * k;
                let term = slots[i] % RADIX * coefficient % RADIX * scale % RADIX;

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

/// Return the automorphism exponents needed to copy one CRT17 slot
/// into all eight destination slots.
///
/// The caller must generate an automorphism key for every distinct
/// exponent returned by this function.
pub fn bpr12_crt17_broadcast_exponents(source_slot: usize) -> [usize; CRT17_SLOTS] {
    assert!(
        source_slot < CRT17_SLOTS,
        "CRT17 source slot is out of range"
    );

    let roots: [u64; CRT17_SLOTS] =
        std::array::from_fn(|i| (RADIX - CRT17_SLOT_CONSTANTS[i]) % RADIX);

    std::array::from_fn(|target_slot| {
        (1..(2 * CRT17_RING_N))
            .step_by(2)
            .find(|&exponent| {
                pow_mod_radix17(roots[target_slot], exponent as u32) == roots[source_slot]
            })
            .expect("no automorphism maps the source slot to this target")
    })
}

/// Extract one coefficient from a CRT17-packed radix-17 digit and
/// broadcast it to every slot in all 32 batches.
///
/// Input:
/// - `digit_batches`: one limb, represented by 32 ciphertexts;
/// - `coefficient_index`: coefficient in 0..256;
/// - `automorphism_keys`: exponent/key-chain pairs for the required
///   slot permutations.
///
/// Output:
/// - 32 ciphertexts, each encoding the selected digit in all eight slots.
///
/// The operation preserves the input HE level. For inputs above level 0,
/// each key chain must contain a key for that level.
pub fn encrypted_bpr12_crt17_broadcast_coefficient(
    evaluator: &RlweHe,
    digit_batches: &[HeCiphertext],
    coefficient_index: usize,
    automorphism_keys: &[(usize, HeAutomorphismKeyChain)],
) -> Vec<HeCiphertext> {
    assert_eq!(
        digit_batches.len(),
        CRT17_RING_N / CRT17_SLOTS,
        "expected 32 CRT17 batches"
    );
    assert!(
        coefficient_index < CRT17_RING_N,
        "coefficient index is out of range"
    );

    let base_level = digit_batches[0].level;

    for (batch_index, ciphertext) in digit_batches.iter().enumerate() {
        assert_eq!(
            ciphertext.level, base_level,
            "batch {batch_index} has an inconsistent HE level"
        );
        assert_eq!(
            ciphertext.ciphertext.u.degree, CRT17_RING_N,
            "batch {batch_index} has the wrong ring dimension"
        );
    }

    let source_batch = coefficient_index / CRT17_SLOTS;
    let source_slot = coefficient_index % CRT17_SLOTS;

    let mut mask_slots = [0u64; CRT17_SLOTS];
    mask_slots[source_slot] = 1;

    let mask_coefficients = Bpr12HeValue::crt17_encode_slots(mask_slots);

    let mask = PolyRq::from_coeffs(&mask_coefficients, CRT17_RING_N, RADIX);

    // Isolate the requested coefficient once, before slot routing.
    let masked = evaluator.mul_plaintext(&digit_batches[source_batch], &mask);

    let exponents = bpr12_crt17_broadcast_exponents(source_slot);

    let mut broadcast: Option<HeCiphertext> = None;

    for (target_slot, &exponent) in exponents.iter().enumerate() {
        let (_, key_chain) = automorphism_keys
            .iter()
            .find(|(candidate, _)| *candidate == exponent)
            .expect("missing automorphism key for CRT17 broadcast");

        assert!(
            key_chain.keys.len() > base_level,
            "automorphism key chain does not cover the input level"
        );

        let routed = evaluator.apply_automorphism_with_key_chain(&masked, key_chain);

        assert_eq!(
            routed.level, base_level,
            "automorphism unexpectedly changed the HE level"
        );

        broadcast = Some(match broadcast.take() {
            Some(accumulator) => evaluator.add_ciphertexts(&accumulator, &routed),
            None => routed,
        });

        let _ = target_slot; // The loop index documents destination routing.
    }

    let broadcast = broadcast.expect("broadcast must produce eight routed slots");

    // One encoded scalar is valid for every batch, so reuse its ciphertext
    // payload instead of running the routing circuit 32 additional times.
    (0..CRT17_RING_N / CRT17_SLOTS)
        .map(|_| clone_he_ciphertext(&broadcast))
        .collect()
}

// Alternative representation for the polynomial-multiplication stage.
//
// `Bpr12HeValue` above stores eight coefficients in CRT slots so that carry
// predicates can be evaluated pointwise. That representation intentionally
// does not preserve the ordinary coefficient layout required by negacyclic
// polynomial multiplication. This type keeps each radix-17 digit limb as one
// ordinary plaintext polynomial: coefficient i of `limbs[d]` is digit d of
// coefficient i of the original ring element.
//
// Keep the two types distinct: a CRT-packed limb must not be passed to the
// polynomial-convolution path.
pub struct Bpr12HePolynomialValue {
    pub limbs: Vec<HeCiphertext>,
    pub level: usize,
}

impl Bpr12HePolynomialValue {
    /// Selects one q=17^9 polynomial using an encrypted bit, preserving the
    /// ordinary polynomial coefficient layout needed by negacyclic products.
    /// `encrypted_bit` must encrypt a constant polynomial containing 0 or 1.
    pub fn select_leaf(
        evaluator: &RlweHe,
        encrypted_bit: &HeCiphertext,
        s0: &PolyRq,
        s1: &PolyRq,
    ) -> Self {
        assert_eq!(
            s0.modulus(),
            s1.modulus(),
            "leaf values must use the same modulus"
        );
        assert_eq!(
            s0.degree_bound(),
            s1.degree_bound(),
            "leaf values must use the same degree"
        );
        assert_eq!(
            s0.modulus(),
            RADIX.pow(9),
            "BPR12 leaf values must use q = 17^9"
        );

        let n = s0.degree_bound();
        assert_eq!(
            encrypted_bit.ciphertext.u.degree, n,
            "encrypted bit and leaf values must use the same degree"
        );

        let s0_digits = decompose_radix17(s0, 9);
        let s1_digits = decompose_radix17(s1, 9);
        let mut selected_limbs = Vec::with_capacity(9);

        for digit_index in 0..9 {
            let base_coefficients = &s0_digits[digit_index].coefficients()[..n];
            let other_coefficients = &s1_digits[digit_index].coefficients()[..n];
            let difference_coefficients: Vec<u64> = (0..n)
                .map(|i| (other_coefficients[i] + RADIX - base_coefficients[i]) % RADIX)
                .collect();
            let difference = PolyRq::from_coeffs(&difference_coefficients, n, RADIX);

            // The encrypted selector is a constant polynomial, so multiplying
            // by the whole difference polynomial scales every coefficient by
            // the same hidden bit without mixing coefficient positions.
            let selected_difference = evaluator.mul_plaintext(encrypted_bit, &difference);
            selected_limbs
                .push(evaluator.add_plaintext(&selected_difference, &s0_digits[digit_index]));
        }

        Self {
            limbs: selected_limbs,
            level: encrypted_bit.level,
        }
    }

    pub fn encrypt<R: RngCore>(
        evaluator: &RlweHe,
        rng: &mut R,
        pk: &HePublicKey,
        value: &PolyRq,
        digits: usize,
        n: usize,
    ) -> Self {
        assert!(
            digits > 0,
            "BPR12 polynomial value must have at least one limb"
        );
        assert_eq!(value.degree_bound(), n, "BPR12 value has the wrong degree");
        assert_eq!(
            value.modulus(),
            RADIX.pow(digits as u32),
            "BPR12 polynomial value modulus must equal 17^digits"
        );

        let digit_polys = decompose_radix17(value, digits);
        let limbs = digit_polys
            .iter()
            .map(|digit| evaluator.encrypt(rng, pk, digit, n))
            .collect();

        Self { limbs, level: 0 }
    }

    pub fn digits(&self) -> usize {
        self.limbs.len()
    }

    pub fn decrypt(&self, evaluator: &RlweHe, sk: &HeSecretKey, n: usize) -> PolyRq {
        assert!(
            !self.limbs.is_empty(),
            "BPR12 polynomial value has no limbs"
        );
        let mut digit_polys = Vec::with_capacity(self.limbs.len());
        for (digit_index, limb) in self.limbs.iter().enumerate() {
            assert_eq!(
                limb.level, self.level,
                "BPR12 polynomial limb {digit_index} is not at the value's level"
            );
            digit_polys.push(evaluator.decrypt(sk, limb, n));
        }
        compose_radix17(&digit_polys, n)
    }
}

/// Compute the exact least-significant radix-17 limb of an encrypted ring
/// product. The inputs use the ordinary coefficient basis, so HE ciphertext
/// multiplication performs negacyclic convolution in R_17[X]/(X^n + 1).
///
/// If A = A_0 + 17 A_1 + ... and B = B_0 + 17 B_1 + ..., then
///
///     (A * B) mod 17 = A_0 * B_0 mod 17.
///
/// Thus this returns the correct lowest radix-17 digit polynomial of the
/// product in R_(17^k), at one additional HE level. It is only the first
/// product limb: higher limbs require encrypted accumulation and carry logic.
pub fn encrypted_radix17_low_limb_negacyclic_product(
    evaluator: &RlweHe,
    lhs: &Bpr12HePolynomialValue,
    rhs: &Bpr12HePolynomialValue,
    relin_keys: &HeRelinearizationKeyChain,
) -> HeCiphertext {
    assert!(!lhs.limbs.is_empty(), "lhs BPR12 value has no limbs");
    assert!(!rhs.limbs.is_empty(), "rhs BPR12 value has no limbs");
    assert_eq!(lhs.limbs.len(), rhs.limbs.len(), "BPR12 limb counts differ");
    assert_eq!(
        lhs.level, rhs.level,
        "BPR12 values must be at the same level"
    );
    assert_eq!(
        lhs.limbs[0].level, lhs.level,
        "lhs low limb has inconsistent level"
    );
    assert_eq!(
        rhs.limbs[0].level, rhs.level,
        "rhs low limb has inconsistent level"
    );

    evaluator.mul_ciphertext(&lhs.limbs[0], &rhs.limbs[0], relin_keys)
}

// Decomposes a polynomial coefficient-wise in base 17.
//
// For example, with k = 3:
//
//     x = d0 + 17*d1 + 17^2*d2
//
// Each returned polynomial belongs to R_17.
pub fn decompose_radix17(value: &PolyRq, digits: usize) -> Vec<PolyRq> {
    assert!(digits > 0);

    let n = value.degree_bound();
    let coeffs = value.coefficients();

    let mut digit_coeffs = vec![vec![0u64; n]; digits];

    for i in 0..n {
        let mut x = coeffs[i];

        for d in 0..digits {
            digit_coeffs[d][i] = x % RADIX;
            x /= RADIX;
        }

        assert_eq!(
            x, 0,
            "value does not fit inside the requested radix-17 representation"
        );
    }

    digit_coeffs
        .into_iter()
        .map(|coeffs| PolyRq::from_coeffs(&coeffs, n, RADIX))
        .collect()
}

// Reconstructs a polynomial from radix-17 limbs.
//
// The resulting polynomial has modulus:
//
//     17^digits
pub fn compose_radix17(digits: &[PolyRq], n: usize) -> PolyRq {
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

    let modulus = RADIX.pow(digits.len() as u32);

    let mut result = vec![0u64; n];

    for i in 0..n {
        let mut value = 0u128;
        let mut power = 1u128;

        for digit in digits {
            value += digit.coefficients()[i] as u128 * power;

            power *= RADIX as u128;
        }

        result[i] = (value % modulus as u128) as u64;
    }

    PolyRq::from_coeffs(&result, n, modulus)
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
pub fn round_one_level_radix17(value: &PolyRq) -> PolyRq {
    const RADIX: u64 = parameter_profile::RADIX;

    let q = value.modulus();
    let n = value.degree_bound();

    assert!(q % RADIX == 0, "BPR12 modulus must be divisible by 17");

    let target_modulus = q / RADIX;

    let rounded_coeffs: Vec<u64> = value
        .coefficients()
        .iter()
        .take(n)
        .map(|&coefficient| {
            let coefficient = coefficient % q;

            let low_digit = coefficient % RADIX;

            let higher_digits = coefficient / RADIX;

            let rounded = if low_digit >= 9 {
                higher_digits + 1
            } else {
                higher_digits
            };

            rounded % target_modulus
        })
        .collect();

    PolyRq::from_coeffs(&rounded_coeffs, n, target_modulus)
}

// Creates a constant plaintext polynomial in R_17 for BGV operations.
fn constant_poly(value: u64, n: usize) -> PolyRq {
    let mut coeffs = vec![0u64; n];
    coeffs[0] = value % RADIX;
    PolyRq::from_coeffs(&coeffs, n, RADIX)
}

/// Evaluate the BPR12 carry indicator `[x >= 9]` homomorphically.
///
/// Supported inputs are a scalar encoded as a constant polynomial or the
/// eight-slot CRT subring used by the N=256 BPR12 representation. Do not pass
/// an arbitrary polynomial: negacyclic multiplication can mix its coefficients.
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
    let x2 = evaluator.mul_ciphertext(value, value, relin_keys);

    // x^3 = x^2 * x
    let x_level_1 = lift_ciphertext_level(evaluator, value, base_level + 1);

    let x3 = evaluator.mul_ciphertext(&x2, &x_level_1, relin_keys);

    // x^4 = x^2 * x^2
    let x4 = evaluator.mul_ciphertext(&x2, &x2, relin_keys);

    // x^5 = x^4 * x
    let x_level_2 = lift_ciphertext_level(evaluator, value, base_level + 2);

    let x5 = evaluator.mul_ciphertext(&x4, &x_level_2, relin_keys);

    // x^7 = x^4 * x^3. Both ciphertexts are already at level 2.
    // Multiplying x^4 by x^2 would compute x^6 instead.
    let x7 = evaluator.mul_ciphertext(&x4, &x3, relin_keys);

    // x^8 = x^4 * x^4
    let x8 = evaluator.mul_ciphertext(&x4, &x4, relin_keys);

    // x^11 = x^8 * x^3
    let x3_level_3 = lift_ciphertext_level(evaluator, &x3, base_level + 3);

    let x11 = evaluator.mul_ciphertext(&x8, &x3_level_3, relin_keys);

    // x^13 = x^8 * x^5
    let x13 = evaluator.mul_ciphertext(&x8, &x5, relin_keys);

    // x^15 = x^8 * x^7
    let x15 = evaluator.mul_ciphertext(&x8, &x7, relin_keys);

    // x^16 = x^8 * x^8
    let x16 = evaluator.mul_ciphertext(&x8, &x8, relin_keys);

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

    let term1 = evaluator.mul_plaintext(value, &constant_poly(8, n));

    let term2 = evaluator.mul_plaintext(&x3, &constant_poly(9, n));

    let term3 = evaluator.mul_plaintext(&x5, &constant_poly(10, n));

    let term4 = evaluator.mul_plaintext(&x7, &constant_poly(11, n));

    let term5 = evaluator.mul_plaintext(&x11, &constant_poly(15, n));

    let term6 = evaluator.mul_plaintext(&x13, &constant_poly(4, n));

    let term7 = evaluator.mul_plaintext(&x15, &constant_poly(2, n));

    let term8 = evaluator.mul_plaintext(&x16, &constant_poly(9, n));

    // ------------------------------------------------------------
    // The deepest term is at level 4.
    // Lift the lower-level terms so that all additions are valid.
    // ------------------------------------------------------------

    let final_level = base_level + 4;

    let term1 = lift_ciphertext_level(evaluator, &term1, final_level);

    let term2 = lift_ciphertext_level(evaluator, &term2, final_level);

    let term3 = lift_ciphertext_level(evaluator, &term3, final_level);

    let term4 = lift_ciphertext_level(evaluator, &term4, final_level);

    let term5 = lift_ciphertext_level(evaluator, &term5, final_level);

    let term6 = lift_ciphertext_level(evaluator, &term6, final_level);

    let term7 = lift_ciphertext_level(evaluator, &term7, final_level);

    let term8 = lift_ciphertext_level(evaluator, &term8, final_level);

    // ------------------------------------------------------------
    // Sum the polynomial terms.
    // ------------------------------------------------------------

    let sum12 = evaluator.add_ciphertexts(&term1, &term2);

    let sum34 = evaluator.add_ciphertexts(&term3, &term4);

    let sum56 = evaluator.add_ciphertexts(&term5, &term6);

    let sum78 = evaluator.add_ciphertexts(&term7, &term8);

    let sum1234 = evaluator.add_ciphertexts(&sum12, &sum34);

    let sum5678 = evaluator.add_ciphertexts(&sum56, &sum78);

    evaluator.add_ciphertexts(&sum1234, &sum5678)
}

// Brings a ciphertext to a deeper level through real BGV modulus switches.
fn lift_ciphertext_level(
    evaluator: &RlweHe,
    ciphertext: &HeCiphertext,
    target_level: usize,
) -> HeCiphertext {
    evaluator.modulus_switch_to_level(ciphertext, target_level)
}

// Clone the ciphertext payload while preserving its active RNS level.
fn clone_he_ciphertext(ciphertext: &HeCiphertext) -> HeCiphertext {
    HeCiphertext::new(
        crate::core::rlwe_rns::RnsCiphertext {
            u: ciphertext.ciphertext.u.clone(),
            v: ciphertext.ciphertext.v.clone(),
        },
        ciphertext.level,
    )
}

// Evaluate [x == 16] over F_17. By Fermat's little theorem,
// [x == 16] = 1 - (x + 1)^16. The four squarings consume four levels.
fn encrypted_equal_16(
    evaluator: &RlweHe,
    value: &HeCiphertext,
    relin_keys: &HeRelinearizationKeyChain,
) -> HeCiphertext {
    let n = value.ciphertext.u.degree;
    let one = constant_poly(1, n);
    let shifted = evaluator.add_plaintext(value, &one);

    let mut power = shifted;
    for _ in 0..4 {
        power = evaluator.mul_ciphertext(&power, &power, relin_keys);
    }

    evaluator.one_minus(&power, &one)
}

// Multiply encrypted predicates with a balanced tree. All terms are expected
// to have the same plaintext meaning and usually start at the same level.
// Balancing keeps the prefix product depth logarithmic rather than linear.
fn encrypted_product_balanced(
    evaluator: &RlweHe,
    terms: &[&HeCiphertext],
    relin_keys: &HeRelinearizationKeyChain,
) -> HeCiphertext {
    assert!(
        !terms.is_empty(),
        "encrypted product needs at least one term"
    );
    if terms.len() == 1 {
        return clone_he_ciphertext(terms[0]);
    }

    let midpoint = terms.len() / 2;
    let left = encrypted_product_balanced(evaluator, &terms[..midpoint], relin_keys);
    let right = encrypted_product_balanced(evaluator, &terms[midpoint..], relin_keys);
    let target_level = left.level.max(right.level);
    let left = lift_ciphertext_level(evaluator, &left, target_level);
    let right = lift_ciphertext_level(evaluator, &right, target_level);

    evaluator.mul_ciphertext(&left, &right, relin_keys)
}

// Compute the radix-17 digit product of two encrypted scalar values or two
// CRT17-packed SIMD values. The input plaintexts must be constant polynomials
// or use the CRT17 subring encoding; arbitrary ring polynomials are NOT valid
// because the interpolation below is a pointwise finite-field function.
//
// For each slot, returns:
//   low  = (a * b) mod 17
//   high = floor(a * b / 17)
//
// `low` is the ordinary HE product. `high` is evaluated using a bivariate
// lookup polynomial over F_17, written as
//   high(a,b) = sum_i L_i(a) * H_i(b),
// where L_i is the Lagrange selector for i and H_i interpolates
// floor(i*b/17) for all b in F_17. This is a digit-multiplication primitive,
// NOT a complete encrypted RLWR synthesizer: convolution-term accumulation
// and its carries still have to be implemented above this layer.
pub fn encrypted_radix17_digit_product(
    evaluator: &RlweHe,
    lhs: &HeCiphertext,
    rhs: &HeCiphertext,
    relin_keys: &HeRelinearizationKeyChain,
) -> (HeCiphertext, HeCiphertext) {
    let progress_enabled = std::env::var_os("PQBPR12_PROGRESS").is_some();
    let started = std::time::Instant::now();

    macro_rules! progress {
        ($($arg:tt)*) => {
            if progress_enabled {
                eprintln!(
                    "[BPR12 digit-product +{:.1}s] {}",
                    started.elapsed().as_secs_f64(),
                    format_args!($($arg)*)
                );
            }
        };
    }

    assert_eq!(
        lhs.level, rhs.level,
        "digit operands must be at the same HE level"
    );
    assert_eq!(
        lhs.ciphertext.u.degree, rhs.ciphertext.u.degree,
        "digit operands must use the same ring dimension"
    );

    let base_level = lhs.level;
    let output_level = base_level + 5;

    assert!(
        output_level <= evaluator.max_level(),
        "radix-17 digit product needs five remaining HE levels"
    );
    assert!(
        relin_keys.keys.len() > base_level + 4,
        "relinearization keys do not cover the digit-product circuit"
    );

    progress!(
        "starting digit multiplication at level {}; expected output level {}",
        base_level,
        output_level
    );

    progress!("stage 1/4: computing encrypted powers for lhs");
    let lhs_powers = encrypted_powers_through_16(evaluator, lhs, relin_keys);

    progress!("stage 1/4: lhs powers complete");

    progress!("stage 2/4: computing encrypted powers for rhs");
    let rhs_powers = encrypted_powers_through_16(evaluator, rhs, relin_keys);

    progress!("stage 2/4: rhs powers complete");

    // Exact rank-eight decomposition of:
    //
    //     high(a,b) = floor(a*b/17) mod 17
    //
    // high(a,b) = sum_{r=0..7} U_r(a) * V_r(b) mod 17.
    //
    // The factors are public polynomials over F_17.
    // Their evaluations remain encrypted.
    let (u_coefficients, v_coefficients) = high_digit_rank8_coefficients();

    let ring_n = lhs.ciphertext.u.degree;
    let polynomial_level = base_level + 4;

    let mut encrypted_high: Option<HeCiphertext> = None;

    progress!("stage 3/4: evaluating 8 rank-factor terms");

    for rank in 0..8usize {
        let lhs_factor = evaluate_encrypted_radix17_polynomial(
            evaluator,
            &lhs_powers,
            &u_coefficients[rank],
            ring_n,
        );

        let rhs_factor = evaluate_encrypted_radix17_polynomial(
            evaluator,
            &rhs_powers,
            &v_coefficients[rank],
            ring_n,
        );

        assert_eq!(
            lhs_factor.level, polynomial_level,
            "lhs rank factor has unexpected HE level"
        );
        assert_eq!(
            rhs_factor.level, polynomial_level,
            "rhs rank factor has unexpected HE level"
        );

        let term = evaluator.mul_ciphertext(&lhs_factor, &rhs_factor, relin_keys);

        encrypted_high = Some(match encrypted_high.take() {
            Some(accumulator) => evaluator.add_ciphertexts(&accumulator, &term),
            None => term,
        });

        progress!("high-digit rank terms {}/8 complete", rank + 1);
    }

    progress!("stage 3/4 complete");

    // The low digit is the ordinary product modulo 17.
    // Align it with the high digit at base_level + 5.
    progress!("stage 4/4: evaluating low digit and aligning levels");

    let low_product = evaluator.mul_ciphertext(lhs, rhs, relin_keys);

    let low_digit = lift_ciphertext_level(evaluator, &low_product, output_level);

    let high_digit = encrypted_high.expect("rank-eight expansion has 8 terms");

    assert_eq!(low_digit.level, output_level);
    assert_eq!(high_digit.level, output_level);

    progress!("digit multiplication complete at level {}", output_level);

    (low_digit, high_digit)
}

/// Add two encrypted radix-17 digits, independently in each scalar/CRT17 slot.
///
/// Returns `(sum_low, carry)`, where for canonical digits a,b in 0..=16:
///   sum_low = (a + b) mod 17
///   carry   = floor((a + b) / 17)
///
/// `sum_low` is computed by ciphertext addition. The carry is a bivariate
/// lookup over F_17, evaluated with Lagrange interpolation. This operation is
/// a building block for carry-aware accumulation; it is not yet an efficient
/// multi-term accumulator and does not perform polynomial coefficient shuffles.
pub fn encrypted_radix17_digit_add(
    evaluator: &RlweHe,
    lhs: &HeCiphertext,
    rhs: &HeCiphertext,
    relin_keys: &HeRelinearizationKeyChain,
) -> (HeCiphertext, HeCiphertext) {
    assert_eq!(
        lhs.level, rhs.level,
        "digit add operands must be at the same HE level"
    );
    assert_eq!(
        lhs.ciphertext.u.degree, rhs.ciphertext.u.degree,
        "digit add operands must use the same ring dimension"
    );

    let base_level = lhs.level;
    let output_level = base_level + 5;
    assert!(
        output_level <= evaluator.max_level(),
        "radix-17 digit addition with carry needs five remaining HE levels"
    );
    assert!(
        relin_keys.keys.len() > base_level + 4,
        "relinearization keys do not cover the digit-add carry circuit"
    );

    let progress_enabled = std::env::var_os("PQBPR12_PROGRESS").is_some();
    let started = std::time::Instant::now();
    macro_rules! progress {
        ($($arg:tt)*) => {
            if progress_enabled {
                eprintln!(
                    "[BPR12 digit-add +{:.1}s] {}",
                    started.elapsed().as_secs_f64(),
                    format_args!($($arg)*)
                );
            }
        };
    }

    use rayon::prelude::*;
    let ring_n = lhs.ciphertext.u.degree;
    progress!("stage 1/3: computing encrypted powers for lhs and rhs in parallel");
    // The two power tables are independent.
    // When called inside the carry-tree pool, Rayon reuses that pool.
    let (lhs_powers, rhs_powers) = rayon::join(
        || encrypted_powers_through_16(evaluator, lhs, relin_keys),
        || encrypted_powers_through_16(evaluator, rhs, relin_keys),
    );
    let lagrange = lagrange_basis_table_radix17();
    let polynomial_level = base_level + 4;
    progress!("stage 2/3: evaluating 17 carry-interpolation terms in parallel");
    // Every interpolation term is independent. Collecting an indexed
    // parallel iterator preserves the order of the 17 terms.
    let terms: Vec<HeCiphertext> = (0..17usize)
        .into_par_iter()
        .map(|a_value| {
            let selector = evaluate_encrypted_radix17_polynomial(
                evaluator,
                &lhs_powers,
                &lagrange[a_value],
                ring_n,
            );

            let carry_coefficients = carry_coefficients_for_fixed_lhs(a_value, &lagrange);

            let carry_for_fixed_a = evaluate_encrypted_radix17_polynomial(
                evaluator,
                &rhs_powers,
                &carry_coefficients,
                ring_n,
            );

            assert_eq!(selector.level, polynomial_level);
            assert_eq!(carry_for_fixed_a.level, polynomial_level);

            let term = evaluator.mul_ciphertext(&selector, &carry_for_fixed_a, relin_keys);

            assert_eq!(term.level, output_level);
            term
        })
        .collect();

    // Keep the accumulation order unchanged.
    let mut encrypted_carry: Option<HeCiphertext> = None;

    for term in terms {
        encrypted_carry = Some(match encrypted_carry.take() {
            Some(accumulator) => evaluator.add_ciphertexts(&accumulator, &term),
            None => term,
        });
    }

    let carry = encrypted_carry.expect("carry interpolation must produce a result");

    progress!("stage 3/3: computing low digit and aligning output levels");

    let low_sum = evaluator.add_ciphertexts(lhs, rhs);
    let low_sum = lift_ciphertext_level(evaluator, &low_sum, output_level);

    assert_eq!(low_sum.level, output_level);
    assert_eq!(carry.level, output_level);

    progress!("digit addition complete at level {}", output_level);

    (low_sum, carry)
}

/// Compute (a+b) mod 17, the carry generated by a+b,
/// and the carry-propagate flag [a+b == 16].
///
/// All inputs are encrypted radix-17 digits. All three outputs
/// are at input level + 5.
pub fn encrypted_radix17_digit_add_with_propagate(
    evaluator: &RlweHe,
    lhs: &HeCiphertext,
    rhs: &HeCiphertext,
    relin_keys: &HeRelinearizationKeyChain,
) -> (HeCiphertext, HeCiphertext, HeCiphertext) {
    assert_eq!(lhs.level, rhs.level);
    assert_eq!(lhs.ciphertext.u.degree, rhs.ciphertext.u.degree);

    let base_level = lhs.level;
    let output_level = base_level + 5;
    assert!(output_level <= evaluator.max_level());

    let ring_n = lhs.ciphertext.u.degree;
    let lhs_powers = encrypted_powers_through_16(evaluator, lhs, relin_keys);
    let rhs_powers = encrypted_powers_through_16(evaluator, rhs, relin_keys);
    let lagrange = lagrange_basis_table_radix17();

    let mut encrypted_carry: Option<HeCiphertext> = None;
    let mut encrypted_propagate: Option<HeCiphertext> = None;

    for a_value in 0..17usize {
        let selector = evaluate_encrypted_radix17_polynomial(
            evaluator,
            &lhs_powers,
            &lagrange[a_value],
            ring_n,
        );

        let carry_coefficients = carry_coefficients_for_fixed_lhs(a_value, &lagrange);
        let propagate_coefficients = propagate_coefficients_for_fixed_lhs(a_value, &lagrange);

        let carry_for_a = evaluate_encrypted_radix17_polynomial(
            evaluator,
            &rhs_powers,
            &carry_coefficients,
            ring_n,
        );
        let propagate_for_a = evaluate_encrypted_radix17_polynomial(
            evaluator,
            &rhs_powers,
            &propagate_coefficients,
            ring_n,
        );

        let carry_term = evaluator.mul_ciphertext(&selector, &carry_for_a, relin_keys);
        let propagate_term = evaluator.mul_ciphertext(&selector, &propagate_for_a, relin_keys);

        encrypted_carry = Some(match encrypted_carry.take() {
            Some(acc) => evaluator.add_ciphertexts(&acc, &carry_term),
            None => carry_term,
        });
        encrypted_propagate = Some(match encrypted_propagate.take() {
            Some(acc) => evaluator.add_ciphertexts(&acc, &propagate_term),
            None => propagate_term,
        });
    }

    let sum = evaluator.add_ciphertexts(lhs, rhs);
    let sum = lift_ciphertext_level(evaluator, &sum, output_level);

    (
        sum,
        encrypted_carry.expect("carry interpolation must produce a result"),
        encrypted_propagate.expect("propagate interpolation must produce a result"),
    )
}

/// Multiply two two-limb radix-17 values, independently in each CRT17 slot,
/// modulo 17^2. This is an exact scalar/SIMD digit-arithmetic primitive; it
/// is NOT a coefficient-basis negacyclic polynomial product.
///
/// Each input represents `low + 17 * high`, where all four ciphertexts use
/// the same CRT17 slot layout and each slot contains a digit in 0..=16.
/// The output pair `(product_low, product_high)` represents
/// `(lhs * rhs) mod 17^2` slotwise.
///
/// Formulae over the integer representatives are:
///
///   p0 = low(a0*b0)
///   p1 = high(a0*b0) + a0*b1 + a1*b0 (mod 17)
///
/// The first term uses the digit-product lookup to recover the carry from
/// `a0*b0`; cross terms only need their low products because they contribute
/// directly to the second radix digit. All outputs are level-aligned.
pub fn encrypted_radix17_product_two_limbs(
    evaluator: &RlweHe,
    lhs_low: &HeCiphertext,
    lhs_high: &HeCiphertext,
    rhs_low: &HeCiphertext,
    rhs_high: &HeCiphertext,
    relin_keys: &HeRelinearizationKeyChain,
) -> (HeCiphertext, HeCiphertext) {
    let inputs = [lhs_low, lhs_high, rhs_low, rhs_high];
    let base_level = lhs_low.level;
    let degree = lhs_low.ciphertext.u.degree;
    for (index, input) in inputs.iter().enumerate() {
        assert_eq!(
            input.level, base_level,
            "two-limb product input {index} is at a different HE level"
        );
        assert_eq!(
            input.ciphertext.u.degree, degree,
            "two-limb product input {index} uses a different ring degree"
        );
    }
    assert!(
        base_level + 5 <= evaluator.max_level(),
        "two-limb radix-17 product needs five remaining HE levels"
    );

    let progress_enabled = std::env::var_os("PQBPR12_PROGRESS").is_some();
    let started = std::time::Instant::now();
    macro_rules! progress {
        ($($arg:tt)*) => {
            if progress_enabled {
                eprintln!(
                    "[BPR12 TWO-LIMB +{:.1}s] {}",
                    started.elapsed().as_secs_f64(),
                    format_args!($($arg)*)
                );
            }
        };
    }

    progress!("stage 1/4: evaluating low-digit product and its carry");
    let (product_low, carry_00) =
        encrypted_radix17_digit_product(evaluator, lhs_low, rhs_low, relin_keys);
    let output_level = product_low.level;
    assert_eq!(carry_00.level, output_level);

    progress!("stage 2/4: evaluating cross term lhs_low * rhs_high");
    let cross_01 = evaluator.mul_ciphertext(lhs_low, rhs_high, relin_keys);
    let cross_01 = lift_ciphertext_level(evaluator, &cross_01, output_level);

    progress!("stage 3/4: evaluating cross term lhs_high * rhs_low");
    let cross_10 = evaluator.mul_ciphertext(lhs_high, rhs_low, relin_keys);
    let cross_10 = lift_ciphertext_level(evaluator, &cross_10, output_level);

    progress!(
        "stage 4/4: adding second-limb contributions at level {}",
        output_level
    );
    let partial_high = evaluator.add_ciphertexts(&carry_00, &cross_01);
    let product_high = evaluator.add_ciphertexts(&partial_high, &cross_10);
    assert_eq!(product_high.level, output_level);
    progress!("two-limb product complete at level {}", output_level);

    (product_low, product_high)
}

/// Negacyclic product modulo 17^2 using coefficient-wise encrypted digits.
///
/// Each coefficient is represented by two encrypted scalar limbs.
/// This reference implementation is intentionally capped at degree 8:
/// it validates the complete signed convolution and carries before we
/// design a scalable N=256 circuit.
pub fn encrypted_radix17_negacyclic_product_two_limbs_reference(
    evaluator: &RlweHe,
    lhs: &Bpr12HeValue,
    rhs: &Bpr12HeValue,
    relin_keys: &HeRelinearizationKeyChain,
) -> Bpr12HeValue {
    assert_eq!(lhs.digits(), 2, "lhs must have two radix-17 limbs");
    assert_eq!(rhs.digits(), 2, "rhs must have two radix-17 limbs");
    assert_eq!(lhs.level, rhs.level, "input levels must match");
    assert_eq!(
        lhs.slots_per_ciphertext, 1,
        "reference convolution requires coefficient-wise scalar ciphertexts"
    );
    assert_eq!(
        rhs.slots_per_ciphertext, 1,
        "reference convolution requires coefficient-wise scalar ciphertexts"
    );

    let n = lhs.limbs[0].len();
    assert!(
        (1..=8).contains(&n),
        "reference convolution is limited to degrees 1..=8"
    );
    assert_eq!(rhs.limbs[0].len(), n);
    assert_eq!(lhs.limbs[1].len(), n);
    assert_eq!(rhs.limbs[1].len(), n);

    let base_level = lhs.level;
    let output_level = base_level + 10;
    assert!(
        output_level <= evaluator.max_level(),
        "insufficient HE levels for two-limb convolution"
    );

    for value in [lhs, rhs] {
        for limb in &value.limbs {
            assert!(
                limb.iter().all(|ct| ct.level == base_level),
                "input limb contains ciphertexts at inconsistent levels"
            );
        }
    }

    let progress_enabled = std::env::var_os("PQBPR12_PROGRESS").is_some();
    let started = std::time::Instant::now();

    macro_rules! progress {
        ($($arg:tt)*) => {
            if progress_enabled {
                eprintln!(
                    "[BPR12 NEGACYCLIC-289 +{:.1}s] {}",
                    started.elapsed().as_secs_f64(),
                    format_args!($($arg)*)
                );
            }
        };
    }

    // Group the N*N scalar products by their output coefficient.
    // X^N = -1, so wrapped terms must be negated modulo 17^2.
    let mut terms_by_coefficient: Vec<Vec<(HeCiphertext, HeCiphertext)>> =
        (0..n).map(|_| Vec::with_capacity(n)).collect();

    for i in 0..n {
        progress!("product row {}/{}: started", i + 1, n);

        for j in 0..n {
            let (mut low, mut high) = encrypted_radix17_product_two_limbs(
                evaluator,
                &lhs.limbs[0][i],
                &lhs.limbs[1][i],
                &rhs.limbs[0][j],
                &rhs.limbs[1][j],
                relin_keys,
            );

            if i + j >= n {
                (low, high) = encrypted_radix17_negate_two_limb(evaluator, &low, &high, relin_keys);
            }

            terms_by_coefficient[(i + j) % n].push((low, high));
        }

        progress!("product row {}/{}: complete", i + 1, n);
    }

    let mut output_low = Vec::with_capacity(n);
    let mut output_high = Vec::with_capacity(n);

    for coefficient_index in 0..n {
        progress!("accumulating coefficient {}/{}", coefficient_index + 1, n);

        let terms = std::mem::take(&mut terms_by_coefficient[coefficient_index]);
        assert_eq!(terms.len(), n);

        let mut low_nodes = Vec::with_capacity(n);
        let mut high_terms = Vec::with_capacity(n);

        for (low, high) in terms {
            low_nodes.push(low);
            high_terms.push(high);
        }

        // Carry tree: all low-digit nodes stay at base_level + 5.
        // Every node's carry is evaluated from that same level, so
        // the carry depth is +5, not +5 per tree round.
        let mut carries = Vec::with_capacity(n.saturating_sub(1));

        while low_nodes.len() > 1 {
            let mut next_nodes = Vec::with_capacity((low_nodes.len() + 1) / 2);

            for pair in low_nodes.chunks(2) {
                if pair.len() == 1 {
                    next_nodes.push(clone_he_ciphertext(&pair[0]));
                    continue;
                }

                let parent_low = evaluator.add_ciphertexts(&pair[0], &pair[1]);

                let (_, carry) =
                    encrypted_radix17_digit_add(evaluator, &pair[0], &pair[1], relin_keys);

                assert_eq!(parent_low.level, base_level + 5);
                assert_eq!(carry.level, output_level);

                next_nodes.push(parent_low);
                carries.push(carry);
            }

            low_nodes = next_nodes;
        }

        let low_result = lift_ciphertext_level(evaluator, &low_nodes[0], output_level);

        let mut high_result = lift_ciphertext_level(evaluator, &high_terms[0], output_level);

        for high in high_terms.iter().skip(1) {
            let aligned = lift_ciphertext_level(evaluator, high, output_level);
            high_result = evaluator.add_ciphertexts(&high_result, &aligned);
        }

        for carry in &carries {
            high_result = evaluator.add_ciphertexts(&high_result, carry);
        }

        output_low.push(low_result);
        output_high.push(high_result);
    }

    progress!(
        "complete: exact product modulo 289 at level {}",
        output_level
    );

    Bpr12HeValue {
        limbs: vec![output_low, output_high],
        level: output_level,
        slots_per_ciphertext: 1,
    }
}

/// Negate a two-limb radix-17 value modulo 289.
///
/// If x = low + 17*high, then:
/// -low mod 17 is the new low digit;
/// -high - [low != 0] is the new high digit, modulo 17.
fn encrypted_radix17_negate_two_limb(
    evaluator: &RlweHe,
    low: &HeCiphertext,
    high: &HeCiphertext,
    relin_keys: &HeRelinearizationKeyChain,
) -> (HeCiphertext, HeCiphertext) {
    assert_eq!(low.level, high.level);
    let n = low.ciphertext.u.degree;
    let predicate_level = low.level + 4;

    let powers = encrypted_powers_through_16(evaluator, low, relin_keys);
    let lagrange = lagrange_basis_table_radix17();

    // L_0(low) = 1 exactly when low == 0.
    let is_zero = evaluate_encrypted_radix17_polynomial(evaluator, &powers, &lagrange[0], n);

    let one = constant_poly(1, n);
    let is_nonzero = evaluator.one_minus(&is_zero, &one);

    let high_aligned = lift_ciphertext_level(evaluator, high, predicate_level);

    let negative_high = evaluator.negate(&high_aligned);
    let negative_borrow = evaluator.negate(&is_nonzero);

    let new_high = evaluator.add_ciphertexts(&negative_high, &negative_borrow);
    let new_low = evaluator.negate(low);

    (new_low, new_high)
}

/// Accumulate two encrypted digit products modulo 17^2, independently in each CRT17 slot.
///
/// The result represents (a*b + c*d) mod 289, slot by slot.
/// The low digits are added with an encrypted carry circuit;
/// the high digits and carry are then combined linearly.
///
/// Starting from HE level 0, the digit products reach level 5
/// and the carry-aware addition reaches level 10.
pub fn encrypted_radix17_accumulate_two_products(
    evaluator: &RlweHe,
    a: &HeCiphertext,
    b: &HeCiphertext,
    c: &HeCiphertext,
    d: &HeCiphertext,
    relin_keys: &HeRelinearizationKeyChain,
) -> (HeCiphertext, HeCiphertext) {
    let inputs = [a, b, c, d];
    let base_level = a.level;
    let degree = a.ciphertext.u.degree;

    for (index, input) in inputs.iter().enumerate() {
        assert_eq!(
            input.level, base_level,
            "two-product accumulator input {index} is at a different HE level"
        );
        assert_eq!(
            input.ciphertext.u.degree, degree,
            "two-product accumulator input {index} uses a different ring degree"
        );
    }

    assert!(
        base_level + 10 <= evaluator.max_level(),
        "two-product accumulation needs ten remaining HE levels"
    );

    let progress_enabled = std::env::var_os("PQBPR12_PROGRESS").is_some();
    let started = std::time::Instant::now();

    macro_rules! progress {
        ($($arg:tt)*) => {
            if progress_enabled {
                eprintln!(
                    "[BPR12 TWO-PRODUCT-SUM +{:.1}s] {}",
                    started.elapsed().as_secs_f64(),
                    format_args!($($arg)*)
                );
            }
        };
    }

    progress!("stage 1/4: evaluating first digit product");
    let (ab_low, ab_high) = encrypted_radix17_digit_product(evaluator, a, b, relin_keys);

    progress!("stage 2/4: evaluating second digit product");
    let (cd_low, cd_high) = encrypted_radix17_digit_product(evaluator, c, d, relin_keys);

    assert_eq!(ab_low.level, cd_low.level);
    assert_eq!(ab_high.level, cd_high.level);

    progress!("stage 3/4: adding low digits and evaluating their carry");
    let (sum_low, low_carry) = encrypted_radix17_digit_add(evaluator, &ab_low, &cd_low, relin_keys);

    let output_level = sum_low.level;
    assert_eq!(low_carry.level, output_level);

    progress!(
        "stage 4/4: aligning and summing high digits plus carry at level {}",
        output_level
    );

    let ab_high = lift_ciphertext_level(evaluator, &ab_high, output_level);
    let cd_high = lift_ciphertext_level(evaluator, &cd_high, output_level);

    let high_partial = evaluator.add_ciphertexts(&ab_high, &cd_high);
    let sum_high = evaluator.add_ciphertexts(&high_partial, &low_carry);

    assert_eq!(sum_high.level, output_level);

    progress!(
        "two-product accumulation complete at level {}",
        output_level
    );

    (sum_low, sum_high)
}

/// Accumulate three encrypted digit products modulo 17^2,
/// independently in each CRT17 slot.
///
/// Computes (a*b + c*d + e*f) mod 289.
///
/// All three digit products are evaluated from the same input level.
/// Their low digits are combined using two carry circuits that both
/// start at that level. The carries are added linearly, avoiding a
/// sequential chain of three carry-aware additions.
///
/// From level 0, all outputs are aligned at level 10.
pub fn encrypted_radix17_accumulate_three_products(
    evaluator: &RlweHe,
    a: &HeCiphertext,
    b: &HeCiphertext,
    c: &HeCiphertext,
    d: &HeCiphertext,
    e: &HeCiphertext,
    f: &HeCiphertext,
    relin_keys: &HeRelinearizationKeyChain,
) -> (HeCiphertext, HeCiphertext) {
    let inputs = [a, b, c, d, e, f];
    let base_level = a.level;
    let degree = a.ciphertext.u.degree;

    for (index, input) in inputs.iter().enumerate() {
        assert_eq!(
            input.level, base_level,
            "three-product accumulator input {index} is at a different HE level"
        );
        assert_eq!(
            input.ciphertext.u.degree, degree,
            "three-product accumulator input {index} uses a different ring degree"
        );
    }

    let output_level = base_level + 10;
    assert!(
        output_level <= evaluator.max_level(),
        "three-product accumulation needs ten remaining HE levels"
    );

    let progress_enabled = std::env::var_os("PQBPR12_PROGRESS").is_some();
    let started = std::time::Instant::now();

    macro_rules! progress {
        ($($arg:tt)*) => {
            if progress_enabled {
                eprintln!(
                    "[BPR12 THREE-PRODUCT +{:.1}s] {}",
                    started.elapsed().as_secs_f64(),
                    format_args!($($arg)*)
                );
            }
        };
    }

    progress!("stage 1/5: evaluating product a*b");
    let (ab_low, ab_high) = encrypted_radix17_digit_product(evaluator, a, b, relin_keys);

    progress!("stage 2/5: evaluating products c*d and e*f");
    let (cd_low, cd_high) = encrypted_radix17_digit_product(evaluator, c, d, relin_keys);
    let (ef_low, ef_high) = encrypted_radix17_digit_product(evaluator, e, f, relin_keys);

    for product in [&cd_low, &ef_low, &ab_high, &cd_high, &ef_high] {
        assert_eq!(
            product.level,
            base_level + 5,
            "all digit products must end at the same HE level"
        );
    }

    progress!("stage 3/5: preparing the low-digit sum modulo 17");

    // Ordinary ciphertext addition computes the sum modulo 17
    // without introducing another multiplication level.
    let low_ab = evaluator.add_ciphertexts(&ab_low, &cd_low);

    progress!("stage 4/5: evaluating two carry circuits in parallel depth");

    // First carry: floor((ab_low + cd_low) / 17).
    // Second carry: floor((low_ab + ef_low) / 17).
    // Both use inputs at base_level + 5 and therefore end at
    // base_level + 10. Their sum is at most 2, so it cannot wrap mod 17.
    let (_, carry_ab_cd) = encrypted_radix17_digit_add(evaluator, &ab_low, &cd_low, relin_keys);

    let (sum_low, carry_final) =
        encrypted_radix17_digit_add(evaluator, &low_ab, &ef_low, relin_keys);

    assert_eq!(sum_low.level, output_level);
    assert_eq!(carry_ab_cd.level, output_level);
    assert_eq!(carry_final.level, output_level);

    progress!("stage 5/5: summing high digits and both carries");

    let ab_high = lift_ciphertext_level(evaluator, &ab_high, output_level);
    let cd_high = lift_ciphertext_level(evaluator, &cd_high, output_level);
    let ef_high = lift_ciphertext_level(evaluator, &ef_high, output_level);

    let high_1 = evaluator.add_ciphertexts(&ab_high, &cd_high);
    let high_2 = evaluator.add_ciphertexts(&high_1, &ef_high);
    let high_3 = evaluator.add_ciphertexts(&high_2, &carry_ab_cd);
    let sum_high = evaluator.add_ciphertexts(&high_3, &carry_final);

    assert_eq!(sum_high.level, output_level);

    progress!(
        "three-product accumulation complete at level {}",
        output_level
    );

    (sum_low, sum_high)
}

/// Accumulate encrypted digit products modulo 17^2, slot by slot.
///
/// Computes sum(lhs[i] * rhs[i]) mod 289 for all product pairs.
///
/// Every digit product is evaluated from the same input level.
/// A tree of carry circuits then combines the low digits. The
/// intermediate tree sums remain at the product level, so all
/// carry circuits can run at the same multiplicative depth.
///
/// This computes CRT17 slotwise arithmetic, not polynomial convolution.
pub fn encrypted_radix17_accumulate_products(
    evaluator: &RlweHe,
    factors: &[(&HeCiphertext, &HeCiphertext)],
    relin_keys: &HeRelinearizationKeyChain,
) -> (HeCiphertext, HeCiphertext) {
    assert!(!factors.is_empty(), "at least one product is required");

    let base_level = factors[0].0.level;
    let degree = factors[0].0.ciphertext.u.degree;
    let product_level = base_level + 5;
    let output_level = base_level + 10;

    assert!(
        output_level <= evaluator.max_level(),
        "product accumulation needs ten remaining HE levels"
    );

    for (index, &(lhs, rhs)) in factors.iter().enumerate() {
        assert_eq!(
            lhs.level, base_level,
            "lhs of product {index} starts at a different HE level"
        );
        assert_eq!(
            rhs.level, base_level,
            "rhs of product {index} starts at a different HE level"
        );
        assert_eq!(
            lhs.ciphertext.u.degree, degree,
            "lhs of product {index} uses a different ring degree"
        );
        assert_eq!(
            rhs.ciphertext.u.degree, degree,
            "rhs of product {index} uses a different ring degree"
        );
    }

    let progress_enabled = std::env::var_os("PQBPR12_PROGRESS").is_some();
    let started = std::time::Instant::now();

    macro_rules! progress {
        ($($arg:tt)*) => {
            if progress_enabled {
                eprintln!(
                    "[BPR12 PRODUCT TREE +{:.1}s] {}",
                    started.elapsed().as_secs_f64(),
                    format_args!($($arg)*)
                );
            }
        };
    }

    let mut product_lows = Vec::with_capacity(factors.len());
    let mut product_highs = Vec::with_capacity(factors.len());

    // Phase 1: all products start at the same input level and end at +5.
    for (index, &(lhs, rhs)) in factors.iter().enumerate() {
        progress!(
            "phase 1/3: evaluating product {}/{}",
            index + 1,
            factors.len()
        );

        let (low, high) = encrypted_radix17_digit_product(evaluator, lhs, rhs, relin_keys);

        assert_eq!(low.level, product_level);
        assert_eq!(high.level, product_level);

        product_lows.push(low);
        product_highs.push(high);
    }

    // Phase 2: build a tree of low-digit sums. Each parent is computed
    // by ordinary ciphertext addition, so it stays at product_level.
    // The carry circuit for every internal node uses those level-5
    // child values, rather than the level-10 output of another carry.
    let mut nodes: Vec<HeCiphertext> = product_lows.iter().map(clone_he_ciphertext).collect();

    let mut carries = Vec::with_capacity(factors.len() - 1);
    let mut round = 0usize;

    while nodes.len() > 1 {
        round += 1;
        progress!(
            "phase 2/3: carry-tree round {}, {} nodes",
            round,
            nodes.len()
        );

        let mut next_nodes = Vec::with_capacity((nodes.len() + 1) / 2);

        for (node_index, pair) in nodes.chunks(2).enumerate() {
            if pair.len() == 1 {
                // Preserve the final node of an odd-sized layer.
                next_nodes.push(clone_he_ciphertext(&pair[0]));
                continue;
            }

            // This parent sum stays at product_level.
            let parent_sum = evaluator.add_ciphertexts(&pair[0], &pair[1]);
            assert_eq!(parent_sum.level, product_level);

            // Compute the corresponding carry from the same inputs.
            // The returned low digit is redundant here; parent_sum
            // above is intentionally retained at the shallower level.
            progress!(
                "round {}: evaluating carry for node {}",
                round,
                node_index + 1
            );

            let (_aligned_low, carry) =
                encrypted_radix17_digit_add(evaluator, &pair[0], &pair[1], relin_keys);

            assert_eq!(carry.level, output_level);
            carries.push(carry);
            next_nodes.push(parent_sum);
        }

        nodes = next_nodes;
    }

    // Phase 3: sum all product high digits and all tree carries.
    // These are field additions modulo 17, so they do not add
    // multiplicative depth.
    progress!(
        "phase 3/3: combining {} product high digits and {} carries",
        product_highs.len(),
        carries.len()
    );

    let mut high_total = clone_he_ciphertext(&product_highs[0]);

    for high in product_highs.iter().skip(1) {
        high_total = evaluator.add_ciphertexts(&high_total, high);
    }

    high_total = lift_ciphertext_level(evaluator, &high_total, output_level);

    for carry in &carries {
        high_total = evaluator.add_ciphertexts(&high_total, carry);
    }

    let low_total = lift_ciphertext_level(evaluator, &nodes[0], output_level);

    assert_eq!(low_total.level, output_level);
    assert_eq!(high_total.level, output_level);

    progress!(
        "accumulation complete: {} products, output level {}",
        factors.len(),
        output_level
    );

    (low_total, high_total)
}

// Return x^1, ..., x^16, each switched to the same level `x.level + 4`.
// The addition-only interpolation code can then combine them at equal levels.
fn encrypted_powers_through_16(
    evaluator: &RlweHe,
    value: &HeCiphertext,
    relin_keys: &HeRelinearizationKeyChain,
) -> Vec<HeCiphertext> {
    let base_level = value.level;
    assert!(
        base_level + 4 <= evaluator.max_level(),
        "not enough HE levels to compute radix-17 interpolation powers"
    );

    let x1 = clone_he_ciphertext(value);
    let x2 = evaluator.mul_ciphertext(value, value, relin_keys);
    let x1_at_level_1 = lift_ciphertext_level(evaluator, value, base_level + 1);
    let x3 = evaluator.mul_ciphertext(&x2, &x1_at_level_1, relin_keys);
    let x4 = evaluator.mul_ciphertext(&x2, &x2, relin_keys);

    let x1_at_level_2 = lift_ciphertext_level(evaluator, value, base_level + 2);
    let x5 = evaluator.mul_ciphertext(&x4, &x1_at_level_2, relin_keys);
    let x6 = evaluator.mul_ciphertext(&x3, &x3, relin_keys);
    let x7 = evaluator.mul_ciphertext(&x4, &x3, relin_keys);
    let x8 = evaluator.mul_ciphertext(&x4, &x4, relin_keys);

    let mut powers = vec![x1, x2, x3, x4, x5, x6, x7, x8];

    // x^9..x^16 = x^8 * x^1..x^8. At this point each lower power is
    // aligned to base_level + 3, so all eight products have equal depth.
    let lower_powers: Vec<HeCiphertext> = powers
        .iter()
        .map(|power| lift_ciphertext_level(evaluator, power, base_level + 3))
        .collect();
    for lower_power in &lower_powers {
        let next_power = evaluator.mul_ciphertext(&lower_powers[7], lower_power, relin_keys);
        powers.push(next_power);
    }

    let target_level = base_level + 4;
    powers
        .into_iter()
        .map(|power| lift_ciphertext_level(evaluator, &power, target_level))
        .collect()
}

// Build the 17 Lagrange basis polynomials for F_17, with coefficients in
// ascending monomial order. All denominators are nonzero because F_17 is a
// prime field and each basis point is distinct.
fn lagrange_basis_table_radix17() -> [[u64; 17]; 17] {
    let mut table = [[0u64; 17]; 17];
    for point in 0..17usize {
        let mut numerator = [0u64; 17];
        numerator[0] = 1;
        let mut degree = 0usize;
        let mut denominator = 1u64;

        for other in 0..17usize {
            if other == point {
                continue;
            }
            let mut next = [0u64; 17];
            for k in 0..=degree {
                // Multiply by (x - other), modulo 17.
                next[k] = (next[k] + 17 - (other as u64 * numerator[k]) % 17) % 17;
                next[k + 1] = (next[k + 1] + numerator[k]) % 17;
            }
            numerator = next;
            degree += 1;
            denominator = denominator * ((point as u64 + 17 - other as u64) % 17) % 17;
        }

        let inverse = pow_mod_radix17(denominator, 15);
        for k in 0..17 {
            table[point][k] = numerator[k] * inverse % 17;
        }
    }
    table
}

type Radix17HighDigitRank8Tables = ([[u64; 17]; 8], [[u64; 17]; 8]);

fn high_digit_rank8_coefficients() -> &'static Radix17HighDigitRank8Tables {
    use std::sync::OnceLock;

    static TABLES: OnceLock<Radix17HighDigitRank8Tables> = OnceLock::new();

    TABLES.get_or_init(|| {
        let lagrange = lagrange_basis_table_radix17();

        let mut u_coefficients = [[0u64; 17]; 8];
        let mut v_coefficients = [[0u64; 17]; 8];

        for rank in 0..8usize {
            // U_r(a) = floor(a * (r + 2) / 17).
            for a in 0..17usize {
                let value = ((a * (rank + 2)) / 17) as u64;

                for degree in 0..17usize {
                    u_coefficients[rank][degree] =
                        (u_coefficients[rank][degree] + value * lagrange[a][degree]) % 17;
                }
            }

            // V_r(b), tabulato sui rappresentanti canonici.
            for b in 0..17usize {
                let value = match rank {
                    0..=5 => {
                        let positive = u64::from(b == rank + 2);
                        let negative = u64::from(b == 15 - rank);

                        (positive + 17 - negative) % 17
                    }
                    6 => u64::from(b == 8 || b >= 10),
                    7 => u64::from(b >= 9),
                    _ => unreachable!(),
                };

                for degree in 0..17usize {
                    v_coefficients[rank][degree] =
                        (v_coefficients[rank][degree] + value * lagrange[b][degree]) % 17;
                }
            }
        }

        (u_coefficients, v_coefficients)
    })
}

// Coefficients of the unique polynomial H_a(b) over F_17 whose value is
// floor(a*b/17) for each canonical field representative b in 0..=16.
fn high_digit_coefficients_for_fixed_lhs(a_value: usize, lagrange: &[[u64; 17]; 17]) -> [u64; 17] {
    let mut coefficients = [0u64; 17];
    for b_value in 0..17usize {
        let high_value = ((a_value * b_value) / 17) as u64;
        for degree in 0..17 {
            coefficients[degree] =
                (coefficients[degree] + high_value * lagrange[b_value][degree]) % 17;
        }
    }
    coefficients
}

// Coefficients of the unique polynomial C_a(b) over F_17 that is 1 when
// the canonical representatives satisfy a+b >= 17, and 0 otherwise.
fn carry_coefficients_for_fixed_lhs(a_value: usize, lagrange: &[[u64; 17]; 17]) -> [u64; 17] {
    let mut coefficients = [0u64; 17];
    for b_value in 0..17usize {
        let carry_value = if a_value + b_value >= 17 { 1 } else { 0 };
        for degree in 0..17 {
            coefficients[degree] =
                (coefficients[degree] + carry_value * lagrange[b_value][degree]) % 17;
        }
    }
    coefficients
}

fn propagate_coefficients_for_fixed_lhs(a_value: usize, lagrange: &[[u64; 17]; 17]) -> [u64; 17] {
    let mut coefficients = [0u64; 17];

    for b_value in 0..17usize {
        let propagate = u64::from(a_value + b_value == 16);

        for degree in 0..17 {
            coefficients[degree] =
                (coefficients[degree] + propagate * lagrange[b_value][degree]) % 17;
        }
    }

    coefficients
}

/// Add two radix-17 BPR12 values using a parallel-prefix carry network.
///
/// For k limbs, the digit lookups consume five levels and the prefix
/// network consumes ceil(log2(k)) additional levels. Overflow beyond
/// the highest limb is discarded, implementing addition modulo 17^k.
///
/// This is an arithmetic primitive for future product accumulation;
/// it does not itself implement polynomial convolution.
pub fn encrypted_radix17_add_values_prefix(
    evaluator: &RlweHe,
    lhs: &Bpr12HeValue,
    rhs: &Bpr12HeValue,
    relin_keys: &HeRelinearizationKeyChain,
) -> Bpr12HeValue {
    assert!(!lhs.limbs.is_empty());
    assert_eq!(lhs.limbs.len(), rhs.limbs.len());
    assert_eq!(lhs.level, rhs.level);
    assert_eq!(lhs.slots_per_ciphertext, rhs.slots_per_ciphertext);

    let digits = lhs.limbs.len();
    let ciphertexts_per_limb = lhs.limbs[0].len();
    assert!(ciphertexts_per_limb > 0);

    for digit in 0..digits {
        assert_eq!(lhs.limbs[digit].len(), ciphertexts_per_limb);
        assert_eq!(rhs.limbs[digit].len(), ciphertexts_per_limb);

        assert!(lhs.limbs[digit].iter().all(|ct| ct.level == lhs.level));
        assert!(rhs.limbs[digit].iter().all(|ct| ct.level == rhs.level));
    }

    let base_level = lhs.level;

    let mut prefix_rounds = 0usize;
    let mut offset = 1usize;
    while offset < digits {
        prefix_rounds += 1;
        offset *= 2;
    }

    let output_level = base_level + 5 + prefix_rounds;

    assert!(
        output_level <= evaluator.max_level(),
        "parallel-prefix radix-17 addition exceeds the HE level budget"
    );
    assert!(
        relin_keys.keys.len() >= output_level,
        "relinearization-key chain is too short for the prefix network"
    );

    let progress_enabled = std::env::var_os("PQBPR12_PROGRESS").is_some();
    let started = std::time::Instant::now();

    macro_rules! progress {
        ($($arg:tt)*) => {
            if progress_enabled {
                eprintln!(
                    "[BPR12 PREFIX-ADD +{:.1}s] {}",
                    started.elapsed().as_secs_f64(),
                    format_args!($($arg)*)
                );
            }
        };
    }

    let mut result_limbs: Vec<Vec<HeCiphertext>> = (0..digits)
        .map(|_| Vec::with_capacity(ciphertexts_per_limb))
        .collect();

    for batch_index in 0..ciphertexts_per_limb {
        progress!(
            "batch {}/{}: computing digit sums, generate and propagate flags",
            batch_index + 1,
            ciphertexts_per_limb
        );

        let mut sums = Vec::with_capacity(digits);
        let mut generates = Vec::with_capacity(digits);
        let mut propagates = Vec::with_capacity(digits);

        for digit in 0..digits {
            let (sum, generate, propagate) = encrypted_radix17_digit_add_with_propagate(
                evaluator,
                &lhs.limbs[digit][batch_index],
                &rhs.limbs[digit][batch_index],
                relin_keys,
            );

            sums.push(sum);
            generates.push(generate);
            propagates.push(propagate);
        }

        let mut prefix_g = generates;
        let mut prefix_p = propagates;
        let mut prefix_level = base_level + 5;

        let mut offset = 1usize;
        let mut round = 0usize;

        while offset < digits {
            round += 1;
            let next_level = prefix_level + 1;

            progress!(
                "batch {}: prefix round {}/{}",
                batch_index + 1,
                round,
                prefix_rounds
            );

            let old_g: Vec<HeCiphertext> = prefix_g.iter().map(clone_he_ciphertext).collect();
            let old_p: Vec<HeCiphertext> = prefix_p.iter().map(clone_he_ciphertext).collect();

            let mut next_g = Vec::with_capacity(digits);
            let mut next_p = Vec::with_capacity(digits);

            for digit in 0..digits {
                if digit < offset {
                    next_g.push(lift_ciphertext_level(evaluator, &old_g[digit], next_level));
                    next_p.push(lift_ciphertext_level(evaluator, &old_p[digit], next_level));
                    continue;
                }

                // Compose carry-transfer functions:
                // G = G_upper + P_upper * G_lower
                // P = P_upper * P_lower
                let propagated_lower =
                    evaluator.mul_ciphertext(&old_p[digit], &old_g[digit - offset], relin_keys);

                let upper_generate = lift_ciphertext_level(evaluator, &old_g[digit], next_level);

                next_g.push(evaluator.add_ciphertexts(&upper_generate, &propagated_lower));

                next_p.push(evaluator.mul_ciphertext(
                    &old_p[digit],
                    &old_p[digit - offset],
                    relin_keys,
                ));
            }

            prefix_g = next_g;
            prefix_p = next_p;
            prefix_level = next_level;
            offset *= 2;
        }

        // Carry into digit i is the prefix carry out of digit i-1.
        for digit in 0..digits {
            let sum = lift_ciphertext_level(evaluator, &sums[digit], output_level);

            let result = if digit == 0 {
                sum
            } else {
                evaluator.add_ciphertexts(&sum, &prefix_g[digit - 1])
            };

            assert_eq!(result.level, output_level);
            result_limbs[digit].push(result);
        }
    }

    progress!("complete: {} limbs added at level {}", digits, output_level);

    Bpr12HeValue {
        limbs: result_limbs,
        level: output_level,
        slots_per_ciphertext: lhs.slots_per_ciphertext,
    }
}

/// Sum exactly 256 encrypted radix-17 digits.
///
/// Returns the three radix-17 digits of their exact integer sum.
/// The maximum possible sum is 256 * 16 = 4096 < 17^3.
///
/// Output limbs are aligned at input level + 10:
///   output[0] = sum mod 17
///   output[1] = floor(sum / 17) mod 17
///   output[2] = floor(sum / 17^2) mod 17
///
/// This is a many-term accumulator, not a polynomial product.
pub fn encrypted_radix17_sum_256_digits_three_limbs(
    evaluator: &RlweHe,
    digits: &[HeCiphertext],
    relin_keys: &HeRelinearizationKeyChain,
) -> Vec<HeCiphertext> {
    const TERM_COUNT: usize = parameter_profile::INPUT_BITS;
    const GROUP_SIZE: usize = 18;
    const OUTPUT_LEVELS: usize = 10;

    assert_eq!(
        digits.len(),
        TERM_COUNT,
        "this accumulator requires exactly 256 input digits"
    );

    let base_level = digits[0].level;
    let degree = digits[0].ciphertext.u.degree;

    assert!(
        base_level + OUTPUT_LEVELS <= evaluator.max_level(),
        "256-digit accumulation needs ten remaining HE levels"
    );

    for (index, digit) in digits.iter().enumerate() {
        assert_eq!(
            digit.level, base_level,
            "input digit {index} has an inconsistent HE level"
        );
        assert_eq!(
            digit.ciphertext.u.degree, degree,
            "input digit {index} has an inconsistent ring degree"
        );
    }

    use rayon::prelude::*;

    // Stage 1: reduce groups of at most 18 digits.
    // Each group produces residue + 17 * carry.
    let partials: Vec<(HeCiphertext, HeCiphertext)> = bpr12_rayon_pool().install(|| {
        digits
            .par_chunks(GROUP_SIZE)
            .map(|chunk| encrypted_radix17_sum_digits_with_carry(evaluator, chunk, relin_keys))
            .collect()
    });

    assert_eq!(partials.len(), 15);

    let residues: Vec<HeCiphertext> = partials
        .iter()
        .map(|(residue, _)| clone_he_ciphertext(residue))
        .collect();

    let carries: Vec<HeCiphertext> = partials
        .iter()
        .map(|(_, carry)| clone_he_ciphertext(carry))
        .collect();

    // Stage 2: sum the group residues and the group carries separately.
    let (sum_residue, carry_from_residues) =
        encrypted_radix17_sum_digits_with_carry(evaluator, &residues, relin_keys);

    let (sum_carry_residue, carry_from_carries) =
        encrypted_radix17_sum_digits_with_carry(evaluator, &carries, relin_keys);

    // The next digit is carry_from_residues + sum_carry_residue.
    // Their sum is at most 14 + 16 = 30, so its carry is at most one.
    let (digit_one, extra_carry) = encrypted_radix17_digit_add(
        evaluator,
        &carry_from_residues,
        &sum_carry_residue,
        relin_keys,
    );

    // The top digit is at most 14 + 1 = 15, so this addition
    // cannot wrap modulo 17.
    let digit_two = evaluator.add_ciphertexts(&carry_from_carries, &extra_carry);

    let output_level = base_level + OUTPUT_LEVELS;
    let digit_zero = lift_ciphertext_level(evaluator, &sum_residue, output_level);

    assert_eq!(digit_zero.level, output_level);
    assert_eq!(digit_one.level, output_level);
    assert_eq!(digit_two.level, output_level);

    vec![digit_zero, digit_one, digit_two]
}

fn pow_mod_radix17(mut base: u64, mut exponent: u32) -> u64 {
    let mut result = 1u64;
    base %= 17;
    while exponent > 0 {
        if exponent & 1 == 1 {
            result = result * base % 17;
        }
        base = base * base % 17;
        exponent >>= 1;
    }
    result
}

// Evaluate a public polynomial f(x) over an encrypted x using its encrypted
// powers. Every power must already be at the same HE level.
fn evaluate_encrypted_radix17_polynomial(
    evaluator: &RlweHe,
    powers: &[HeCiphertext],
    coefficients: &[u64; 17],
    ring_n: usize,
) -> HeCiphertext {
    assert_eq!(powers.len(), 16);
    let mut accumulator =
        evaluator.mul_plaintext(&powers[0], &constant_poly(coefficients[1], ring_n));

    for exponent in 2..17usize {
        if coefficients[exponent] == 0 {
            continue;
        }
        let term = evaluator.mul_plaintext(
            &powers[exponent - 1],
            &constant_poly(coefficients[exponent], ring_n),
        );
        accumulator = evaluator.add_ciphertexts(&accumulator, &term);
    }

    evaluator.add_plaintext(&accumulator, &constant_poly(coefficients[0], ring_n))
}

fn bpr12_rayon_pool() -> &'static rayon::ThreadPool {
    static POOL: std::sync::OnceLock<rayon::ThreadPool> = std::sync::OnceLock::new();

    POOL.get_or_init(|| {
        let threads = std::env::var("PQBPR12_THREADS")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .filter(|&n| n > 0)
            .unwrap_or_else(|| {
                std::thread::available_parallelism()
                    .map(|n| n.get())
                    .unwrap_or(2)
                    .min(4)
            });

        eprintln!("[BPR12] Rayon pool: {threads} threads");

        rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .expect("failed to create shared BPR12 Rayon pool")
    })
}

/// Sum 2..=18 encrypted radix-17 digits.
///
/// Returns:
/// - sum modulo 17, at the input level
/// - floor(integer_sum / 17), at input level + 5
///
/// The carry is exact because the sum of at most 18 digits is at most
/// 288, so the carry is in 0..=16 and is representable in F_17.
fn encrypted_radix17_sum_digits_with_carry(
    evaluator: &RlweHe,
    digits: &[HeCiphertext],
    relin_keys: &HeRelinearizationKeyChain,
) -> (HeCiphertext, HeCiphertext) {
    assert!(
        (2..=18).contains(&digits.len()),
        "multi-digit sum expects 2..=18 radix-17 digits"
    );

    let base_level = digits[0].level;
    let degree = digits[0].ciphertext.u.degree;

    for (index, digit) in digits.iter().enumerate() {
        assert_eq!(
            digit.level, base_level,
            "digit {index} has a different HE level"
        );
        assert_eq!(
            digit.ciphertext.u.degree, degree,
            "digit {index} has a different ring degree"
        );
    }

    assert!(
        base_level + 5 <= evaluator.max_level(),
        "multi-digit sum needs five remaining HE levels"
    );

    let progress_enabled = std::env::var_os("PQBPR12_PROGRESS").is_some();
    let started = std::time::Instant::now();

    macro_rules! progress {
        ($($arg:tt)*) => {
            if progress_enabled {
                eprintln!(
                    "[BPR12 MULTI-SUM +{:.1}s] {}",
                    started.elapsed().as_secs_f64(),
                    format_args!($($arg)*)
                );
            }
        };
    }

    // `running` is the prefix sum modulo 17. It remains at base_level
    // because ciphertext addition is linear and consumes no HE level.
    // Each partial represents:
    // exact_sum = residue + 17 * carry
    //
    // residue is maintained at base_level.
    // carry is maintained at base_level + 5.
    struct PartialSum {
        residue: HeCiphertext,
        carry: Option<HeCiphertext>,
    }

    use rayon::prelude::*;

    let output_level = base_level + 5;

    let mut partials: Vec<PartialSum> = digits
        .iter()
        .map(|digit| PartialSum {
            residue: clone_he_ciphertext(digit),
            carry: None,
        })
        .collect();

    let pool = bpr12_rayon_pool();

    let mut tree_level = 0usize;

    while partials.len() > 1 {
        tree_level += 1;

        progress!(
            "carry tree level {}: reducing {} partial sums",
            tree_level,
            partials.len()
        );

        let next: Vec<PartialSum> = pool.install(|| {
            partials
                .par_chunks(2)
                .map(|pair| {
                    let left = &pair[0];

                    // Carry an unmatched final node into the next level.
                    if pair.len() == 1 {
                        return PartialSum {
                            residue: clone_he_ciphertext(&left.residue),
                            carry: left.carry.as_ref().map(|c| clone_he_ciphertext(c)),
                        };
                    }

                    let right = &pair[1];

                    // Compute the carry generated by adding the two
                    // canonical radix-17 residues.
                    let (_, generated_carry) = encrypted_radix17_digit_add(
                        evaluator,
                        &left.residue,
                        &right.residue,
                        relin_keys,
                    );

                    assert_eq!(
                        generated_carry.level, output_level,
                        "generated carry has an unexpected level"
                    );

                    // The residue is the sum modulo 17. Ciphertext
                    // addition preserves the input HE level.
                    let residue = evaluator.add_ciphertexts(&left.residue, &right.residue);

                    // Aggregate the carries from the left and right
                    // subtrees with the newly generated carry.
                    let mut carry = generated_carry;

                    if let Some(left_carry) = &left.carry {
                        carry = evaluator.add_ciphertexts(&carry, left_carry);
                    }

                    if let Some(right_carry) = &right.carry {
                        carry = evaluator.add_ciphertexts(&carry, right_carry);
                    }

                    assert_eq!(residue.level, base_level);
                    assert_eq!(carry.level, output_level);

                    PartialSum {
                        residue,
                        carry: Some(carry),
                    }
                })
                .collect()
        });

        partials = next;
    }

    let result = partials
        .pop()
        .expect("carry reduction requires at least one partial sum");

    let carry_total = result
        .carry
        .expect("summing at least two radix-17 digits produces a carry result");

    assert_eq!(result.residue.level, base_level);
    assert_eq!(carry_total.level, output_level);

    progress!(
        "tree reduction complete at level {}; carry at level {}",
        base_level,
        output_level
    );

    (result.residue, carry_total)
}

/// Computes one radix-17 digit product using precomputed lookup tables.
///
/// `lhs_selectors[a]` encrypts L_a(lhs).
/// `rhs_high_terms[a]` encrypts H_a(rhs), where
/// H_a(b) = floor(a*b/17) for canonical representatives in F_17.
///
/// Both tables must be at input level + 4.
/// The returned low and high digits are aligned at input level + 5.
fn encrypted_radix17_digit_product_from_precomputed_tables(
    evaluator: &RlweHe,
    lhs: &HeCiphertext,
    rhs: &HeCiphertext,
    lhs_selectors: &[HeCiphertext],
    rhs_high_terms: &[HeCiphertext],
    relin_keys: &HeRelinearizationKeyChain,
) -> (HeCiphertext, HeCiphertext) {
    const TABLE_SIZE: usize = parameter_profile::RADIX as usize;

    assert_eq!(lhs.level, rhs.level, "digit input levels differ");
    assert_eq!(lhs_selectors.len(), TABLE_SIZE);
    assert_eq!(rhs_high_terms.len(), TABLE_SIZE);

    let base_level = lhs.level;
    let polynomial_level = base_level + 4;
    let output_level = base_level + 5;

    assert!(
        output_level <= evaluator.max_level(),
        "not enough HE levels for digit multiplication"
    );

    for selector in lhs_selectors {
        assert_eq!(selector.level, polynomial_level);
    }

    for high_term in rhs_high_terms {
        assert_eq!(high_term.level, polynomial_level);
    }

    // High digit = sum_a L_a(lhs) * H_a(rhs).
    let mut high_digit: Option<HeCiphertext> = None;

    for a in 0..TABLE_SIZE {
        let term = evaluator.mul_ciphertext(&lhs_selectors[a], &rhs_high_terms[a], relin_keys);

        assert_eq!(term.level, output_level);

        high_digit = Some(match high_digit.take() {
            Some(accumulator) => evaluator.add_ciphertexts(&accumulator, &term),
            None => term,
        });
    }

    // The ordinary product modulo 17 gives the low digit.
    let low_product = evaluator.mul_ciphertext(lhs, rhs, relin_keys);
    let low_digit = lift_ciphertext_level(evaluator, &low_product, output_level);

    let high_digit = high_digit.expect("17 interpolation terms must exist");

    assert_eq!(low_digit.level, output_level);
    assert_eq!(high_digit.level, output_level);

    (low_digit, high_digit)
}

fn encrypted_radix17_digit_product_from_precomputed_rank8_tables(
    evaluator: &RlweHe,
    lhs: &HeCiphertext,
    rhs: &HeCiphertext,
    lhs_factors: &[HeCiphertext],
    rhs_factors: &[HeCiphertext],
    relin_keys: &HeRelinearizationKeyChain,
) -> (HeCiphertext, HeCiphertext) {
    const RANKS: usize = 8;

    assert_eq!(lhs.level, rhs.level, "digit input levels differ");
    assert_eq!(lhs_factors.len(), RANKS);
    assert_eq!(rhs_factors.len(), RANKS);

    let base_level = lhs.level;
    let polynomial_level = base_level + 4;
    let output_level = base_level + 5;

    assert!(
        output_level <= evaluator.max_level(),
        "not enough HE levels for rank-eight digit multiplication"
    );

    for factor in lhs_factors.iter().chain(rhs_factors.iter()) {
        assert_eq!(
            factor.level, polynomial_level,
            "rank-eight factor has an unexpected HE level"
        );
    }

    let mut high_digit: Option<HeCiphertext> = None;

    for rank in 0..RANKS {
        let term = evaluator.mul_ciphertext(&lhs_factors[rank], &rhs_factors[rank], relin_keys);

        assert_eq!(term.level, output_level);

        high_digit = Some(match high_digit.take() {
            Some(accumulator) => evaluator.add_ciphertexts(&accumulator, &term),
            None => term,
        });
    }

    let low_product = evaluator.mul_ciphertext(lhs, rhs, relin_keys);

    let low_digit = lift_ciphertext_level(evaluator, &low_product, output_level);

    let high_digit = high_digit.expect("rank-eight expansion requires eight terms");

    assert_eq!(low_digit.level, output_level);
    assert_eq!(high_digit.level, output_level);

    (low_digit, high_digit)
}

/// Multiply two encrypted radix-17 integers represented by nine digits.
///
/// Computes lhs * rhs modulo 17^9. Each input digit must encrypt a
/// scalar represented by a constant polynomial, not an arbitrary ring
/// polynomial.
///
/// The 45 relevant digit products are evaluated at a common input level.
/// Diagonal sums then propagate carries across the nine product digits.
/// The most significant carry is discarded, as required modulo 17^9.
///
/// Output: nine encrypted digits, all aligned at input level + 40.
///
/// This is a scalar-coefficient multiplication primitive. It is not yet
/// the complete negacyclic polynomial convolution.
pub fn encrypted_radix17_scalar_product_nine_limbs_serial_reference(
    evaluator: &RlweHe,
    lhs_digits: &[&HeCiphertext],
    rhs_digits: &[&HeCiphertext],
    relin_keys: &HeRelinearizationKeyChain,
) -> Vec<HeCiphertext> {
    const LIMBS: usize = 9;

    assert_eq!(lhs_digits.len(), LIMBS, "lhs needs nine radix-17 digits");
    assert_eq!(rhs_digits.len(), LIMBS, "rhs needs nine radix-17 digits");

    let base_level = lhs_digits[0].level;
    let degree = lhs_digits[0].ciphertext.u.degree;
    let product_level = base_level + 5;
    let final_level = base_level + 40;

    assert!(
        final_level <= evaluator.max_level(),
        "nine-limb multiplication needs at least 40 remaining HE levels"
    );

    for (index, digit) in lhs_digits.iter().chain(rhs_digits.iter()).enumerate() {
        assert_eq!(
            digit.level, base_level,
            "input digit {index} is at a different HE level"
        );
        assert_eq!(
            digit.ciphertext.u.degree, degree,
            "input digit {index} uses a different ring degree"
        );
    }

    let progress_enabled = std::env::var_os("PQBPR12_PROGRESS").is_some();
    let started = std::time::Instant::now();

    macro_rules! progress {
        ($($arg:tt)*) => {
            if progress_enabled {
                eprintln!(
                    "[BPR12 SCALAR-MUL +{:.1}s] {}",
                    started.elapsed().as_secs_f64(),
                    format_args!($($arg)*)
                );
            }
        };
    }

    // Store low/high parts of each digit product whose radix position
    // can contribute modulo 17^9. Products with i+j >= 9 overflow q
    // and are intentionally omitted.
    let mut low_products: Vec<Vec<Option<HeCiphertext>>> = (0..LIMBS)
        .map(|_| (0..LIMBS).map(|_| None).collect())
        .collect();

    let mut high_products: Vec<Vec<Option<HeCiphertext>>> = (0..LIMBS)
        .map(|_| (0..LIMBS).map(|_| None).collect())
        .collect();

    progress!("stage 1/3: computing 45 digit-pair products");

    let mut product_count = 0usize;
    for i in 0..LIMBS {
        for j in 0..(LIMBS - i) {
            let (low, high) = encrypted_radix17_digit_product(
                evaluator,
                lhs_digits[i],
                rhs_digits[j],
                relin_keys,
            );

            assert_eq!(low.level, product_level);
            assert_eq!(high.level, product_level);

            low_products[i][j] = Some(low);
            high_products[i][j] = Some(high);
            product_count += 1;

            if product_count % 5 == 0 || product_count == 45 {
                progress!("digit products {}/45 complete", product_count);
            }
        }
    }
    assert_eq!(product_count, 45);

    progress!("stage 2/3: accumulating product diagonals and carries");

    // Digit zero has a single contribution, low(a_0*b_0), so its
    // outgoing carry is zero. The high part of that product is included
    // in diagonal one.
    let mut result_digits = Vec::with_capacity(LIMBS);
    result_digits.push(clone_he_ciphertext(
        low_products[0][0].as_ref().expect("product (0,0) exists"),
    ));

    let mut carry_in: Option<HeCiphertext> = None;

    for k in 1..LIMBS {
        // At diagonal k, sum:
        //   low(a_i*b_j) for i+j=k
        //   high(a_i*b_j) for i+j=k-1
        //   carry from diagonal k-1, when k >= 2
        //
        // This diagonal's output digit stays at base+5*k, except
        // k=1, which starts and ends at base+5.
        let target_level = base_level + 5 * k;
        let mut terms = Vec::with_capacity(2 * k + 2);

        for i in 0..=k {
            let j = k - i;
            terms.push(clone_he_ciphertext(
                low_products[i][j].as_ref().expect("low product exists"),
            ));
        }

        for i in 0..k {
            let j = k - 1 - i;
            terms.push(clone_he_ciphertext(
                high_products[i][j].as_ref().expect("high product exists"),
            ));
        }

        if k >= 2 {
            terms.push(clone_he_ciphertext(
                carry_in
                    .as_ref()
                    .expect("previous diagonal produced a carry"),
            ));
        }

        // Product digits were produced at base+5. Align them with the
        // carry from the previous diagonal before summing.
        let terms: Vec<HeCiphertext> = terms
            .into_iter()
            .map(|term| {
                if term.level < target_level {
                    lift_ciphertext_level(evaluator, &term, target_level)
                } else {
                    term
                }
            })
            .collect();

        progress!(
            "diagonal {}/{}: summing {} digits at level {}",
            k + 1,
            LIMBS,
            terms.len(),
            target_level
        );

        if k == LIMBS - 1 {
            // Top digit only: overflow beyond the highest limb is discarded
            // modulo 17^k, so no additional carry circuit is needed.
            let mut top = clone_he_ciphertext(&terms[0]);
            for term in terms.iter().skip(1) {
                top = evaluator.add_ciphertexts(&top, term);
            }
            result_digits.push(top);
        } else {
            let (digit, carry_out) =
                encrypted_radix17_sum_digits_with_carry(evaluator, &terms, relin_keys);

            assert_eq!(digit.level, target_level);
            assert_eq!(carry_out.level, target_level + 5);

            result_digits.push(digit);
            carry_in = Some(carry_out);
        }
    }

    progress!("stage 3/3: aligning all nine output digits");

    let aligned: Vec<HeCiphertext> = result_digits
        .into_iter()
        .map(|digit| {
            if digit.level < final_level {
                lift_ciphertext_level(evaluator, &digit, final_level)
            } else {
                digit
            }
        })
        .collect();

    assert_eq!(aligned.len(), LIMBS);
    assert!(aligned.iter().all(|digit| digit.level == final_level));

    progress!(
        "complete: exact scalar product modulo 17^9 at level {}",
        final_level
    );

    aligned
}

/// Multiply two encrypted radix-17 integers modulo 17^k, where k is the
/// number of input limbs (k >= 2).
///
/// Encrypted powers and interpolation tables are cached once per input digit.
/// Product diagonals are then combined with a parallel-prefix carry network.
/// Inputs may be scalar digits or CRT17-packed digit ciphertexts. Output is
/// aligned at input level + 15 + ceil(log2(k)).
pub fn encrypted_radix17_scalar_product(
    evaluator: &RlweHe,
    lhs_digits: &[&HeCiphertext],
    rhs_digits: &[&HeCiphertext],
    relin_keys: &HeRelinearizationKeyChain,
) -> Vec<HeCiphertext> {
    use rayon::prelude::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    assert!(
        !lhs_digits.is_empty(),
        "scalar product needs at least one digit"
    );
    assert_eq!(lhs_digits.len(), rhs_digits.len());
    let limb_count = lhs_digits.len();
    assert!(
        limb_count >= 2,
        "scalar product used in BPR12 synthesis needs at least two digits"
    );

    let base_level = lhs_digits[0].level;
    let degree = lhs_digits[0].ciphertext.u.degree;
    let product_level = base_level + 5;
    let diagonal_level = base_level + 10;
    let mut prefix_rounds = 0usize;
    let mut prefix_capacity = 1usize;
    while prefix_capacity < limb_count {
        prefix_rounds += 1;
        prefix_capacity *= 2;
    }
    let final_level = diagonal_level + 5 + prefix_rounds;

    assert!(
        final_level <= evaluator.max_level(),
        "parallel scalar multiplication exceeds the HE level budget"
    );

    for (index, digit) in lhs_digits.iter().chain(rhs_digits.iter()).enumerate() {
        assert_eq!(
            digit.level, base_level,
            "input digit {index}: level mismatch"
        );
        assert_eq!(
            digit.ciphertext.u.degree, degree,
            "input digit {index}: ring degree mismatch"
        );
    }

    let progress_enabled = std::env::var_os("PQBPR12_PROGRESS").is_some();
    let started = std::time::Instant::now();

    macro_rules! progress {
        ($($arg:tt)*) => {
            if progress_enabled {
                eprintln!(
                    "[BPR12 SCALAR-CACHED +{:.1}s] {}",
                    started.elapsed().as_secs_f64(),
                    format_args!($($arg)*)
                );
            }
        };
    }

    // ------------------------------------------------------------
    // Phase 1: precompute encrypted powers for each input digit.
    // Each digit's powers are shared by all products involving it.
    // ------------------------------------------------------------

    progress!("phase 1/5: precomputing powers for lhs digits");

    let lhs_powers: Vec<Vec<HeCiphertext>> = lhs_digits
        .iter()
        .enumerate()
        .map(|(i, digit)| {
            progress!("lhs powers {}/{}", i + 1, limb_count);
            encrypted_powers_through_16(evaluator, digit, relin_keys)
        })
        .collect();

    progress!("phase 2/5: precomputing powers for rhs digits");

    let rhs_powers: Vec<Vec<HeCiphertext>> = rhs_digits
        .iter()
        .enumerate()
        .map(|(i, digit)| {
            progress!("rhs powers {}/{}", i + 1, limb_count);
            encrypted_powers_through_16(evaluator, digit, relin_keys)
        })
        .collect();

    // Rank-eight factorization for the encrypted high digit.
    let (u_coefficients, v_coefficients) = high_digit_rank8_coefficients();

    // ------------------------------------------------------------
    // Phase 3: cache eight U_r(lhs_i) factors per input limb.
    // ------------------------------------------------------------

    progress!("phase 3/5: caching lhs rank-eight factors");

    let lhs_rank_factors: Vec<Vec<HeCiphertext>> = lhs_powers
        .iter()
        .enumerate()
        .map(|(i, powers)| {
            let factors: Vec<HeCiphertext> = u_coefficients
                .iter()
                .map(|coefficients| {
                    evaluate_encrypted_radix17_polynomial(evaluator, powers, coefficients, degree)
                })
                .collect();

            assert_eq!(factors.len(), 8);
            assert!(
                factors.iter().all(|ct| ct.level == base_level + 4),
                "lhs rank-factor table {i} has inconsistent levels"
            );

            progress!("lhs rank-factor table {}/{} complete", i + 1, limb_count);

            factors
        })
        .collect();

    // ------------------------------------------------------------
    // Phase 4: cache eight V_r(rhs_j) factors per input limb.
    // ------------------------------------------------------------

    progress!("phase 4/5: caching rhs rank-eight factors");

    let rhs_rank_factors: Vec<Vec<HeCiphertext>> = rhs_powers
        .iter()
        .enumerate()
        .map(|(j, powers)| {
            let factors: Vec<HeCiphertext> = v_coefficients
                .iter()
                .map(|coefficients| {
                    evaluate_encrypted_radix17_polynomial(evaluator, powers, coefficients, degree)
                })
                .collect();

            assert_eq!(factors.len(), 8);
            assert!(
                factors.iter().all(|ct| ct.level == base_level + 4),
                "rhs rank-factor table {j} has inconsistent levels"
            );

            progress!("rhs rank-factor table {}/{} complete", j + 1, limb_count);

            factors
        })
        .collect();

    // ------------------------------------------------------------
    // Phase 5: compute each relevant digit-pair product.
    // The power computations and polynomial evaluations above are
    // cached; only the pair-specific encrypted products remain.
    // ------------------------------------------------------------

    let mut low_products: Vec<Vec<Option<HeCiphertext>>> = (0..limb_count)
        .map(|_| (0..limb_count).map(|_| None).collect())
        .collect();

    let mut high_products: Vec<Vec<Option<HeCiphertext>>> = (0..limb_count)
        .map(|_| (0..limb_count).map(|_| None).collect())
        .collect();

    progress!(
        "phase 5/5: computing {} cached digit products",
        limb_count * (limb_count + 1) / 2
    );

    let digit_pairs: Vec<(usize, usize)> = (0..limb_count)
        .flat_map(|i| (0..(limb_count - i)).map(move |j| (i, j)))
        .collect();
    let expected_pair_count = digit_pairs.len();

    let pool = bpr12_rayon_pool();

    let completed = AtomicUsize::new(0);

    let products: Vec<(usize, usize, HeCiphertext, HeCiphertext)> = pool.install(|| {
        digit_pairs
            .par_iter()
            .map(|&(i, j)| {
                let (low, high) = encrypted_radix17_digit_product_from_precomputed_rank8_tables(
                    evaluator,
                    lhs_digits[i],
                    rhs_digits[j],
                    &lhs_rank_factors[i],
                    &rhs_rank_factors[j],
                    relin_keys,
                );

                assert_eq!(low.level, product_level);
                assert_eq!(high.level, product_level);

                let done = completed.fetch_add(1, Ordering::Relaxed) + 1;

                if done % 5 == 0 || done == expected_pair_count {
                    progress!("digit products {}/{} complete", done, expected_pair_count);
                }

                (i, j, low, high)
            })
            .collect()
    });

    // Inseriamo i risultati nelle stesse posizioni usate
    // dalla successiva fase di riduzione delle diagonali.
    for (i, j, low, high) in products {
        low_products[i][j] = Some(low);
        high_products[i][j] = Some(high);
    }

    // For each diagonal k:
    // S_k = sum(low products where i+j=k)
    //     + sum(high products where i+j=k-1).
    //
    // S_k = residue_k + 17 * carry_k.

    progress!("reducing product diagonals independently");

    let mut residues = Vec::with_capacity(limb_count);
    let mut diagonal_carries: Vec<Option<HeCiphertext>> = (0..limb_count).map(|_| None).collect();

    residues.push(clone_he_ciphertext(
        low_products[0][0].as_ref().expect("product (0,0) exists"),
    ));

    for k in 1..limb_count {
        progress!("diagonal {}/{}: assembling terms", k + 1, limb_count);

        let mut terms = Vec::with_capacity(2 * k + 1);

        // Low parts: i+j=k.
        for i in 0..=k {
            let j = k - i;
            terms.push(clone_he_ciphertext(
                low_products[i][j].as_ref().expect("low product exists"),
            ));
        }

        // High parts: i+j=k-1.
        for i in 0..k {
            let j = k - 1 - i;
            terms.push(clone_he_ciphertext(
                high_products[i][j].as_ref().expect("high product exists"),
            ));
        }

        assert!(terms.iter().all(|term| term.level == product_level));

        if k < limb_count - 1 {
            let (residue, carry) =
                encrypted_radix17_sum_digits_with_carry(evaluator, &terms, relin_keys);

            assert_eq!(residue.level, product_level);
            assert_eq!(carry.level, diagonal_level);

            residues.push(residue);
            diagonal_carries[k] = Some(carry);
        } else {
            // The carry beyond the highest limb is discarded modulo 17^k.
            let mut residue = terms.remove(0);
            for term in &terms {
                residue = evaluator.add_ciphertexts(&residue, term);
            }

            assert_eq!(residue.level, product_level);
            residues.push(residue);
        }
    }

    // Recombine all diagonal residues and shifted carries.
    progress!("combining residues and shifted carries");

    let u_digits: Vec<HeCiphertext> = residues
        .iter()
        .map(|digit| lift_ciphertext_level(evaluator, digit, diagonal_level))
        .collect();

    let negative_u0 = evaluator.negate(&u_digits[0]);
    let zero = evaluator.add_ciphertexts(&u_digits[0], &negative_u0);

    let mut v_digits = Vec::with_capacity(limb_count);
    v_digits.push(clone_he_ciphertext(&zero));
    v_digits.push(clone_he_ciphertext(&zero));

    for k in 1..(limb_count - 1) {
        v_digits.push(clone_he_ciphertext(
            diagonal_carries[k].as_ref().expect("diagonal carry exists"),
        ));
    }

    assert_eq!(u_digits.len(), limb_count);
    assert_eq!(v_digits.len(), limb_count);
    assert!(u_digits.iter().all(|d| d.level == diagonal_level));
    assert!(v_digits.iter().all(|d| d.level == diagonal_level));

    let u_value = Bpr12HeValue {
        limbs: u_digits.into_iter().map(|digit| vec![digit]).collect(),
        level: diagonal_level,
        slots_per_ciphertext: 1,
    };

    let v_value = Bpr12HeValue {
        limbs: v_digits.into_iter().map(|digit| vec![digit]).collect(),
        level: diagonal_level,
        slots_per_ciphertext: 1,
    };

    let result = encrypted_radix17_add_values_prefix(evaluator, &u_value, &v_value, relin_keys);

    assert_eq!(result.level, final_level);
    assert_eq!(result.limbs.len(), limb_count);

    let mut output_digits = Vec::with_capacity(limb_count);

    for (index, mut limb) in result.limbs.into_iter().enumerate() {
        assert_eq!(limb.len(), 1, "output limb {index} must be scalar");
        output_digits.push(limb.remove(0));
    }

    assert!(output_digits.iter().all(|d| d.level == final_level));

    progress!(
        "PASS candidate: cached {}-limb scalar product at level {}",
        limb_count,
        final_level
    );

    output_digits
}

/// Backward-compatible nine-limb entry point.
/// Prefer `encrypted_radix17_scalar_product` for recursive BPR12 levels,
/// where the radix-17 digit count shrinks after each synthesis node.
pub fn encrypted_radix17_scalar_product_nine_limbs(
    evaluator: &RlweHe,
    lhs_digits: &[&HeCiphertext],
    rhs_digits: &[&HeCiphertext],
    relin_keys: &HeRelinearizationKeyChain,
) -> Vec<HeCiphertext> {
    assert_eq!(lhs_digits.len(), 9, "lhs needs nine radix-17 digits");
    assert_eq!(rhs_digits.len(), 9, "rhs needs nine radix-17 digits");
    encrypted_radix17_scalar_product(evaluator, lhs_digits, rhs_digits, relin_keys)
}

// Homomorphically performs one BPR12 rounding step.
//
// For x = d0 + 17*d1 + 17^2*d2 + ..., the rounded result is
// d1 + 17*d2 + ... + [d0 >= 9]. The carry must propagate: if d1 is 16,
// adding the first carry wraps d1 to zero and increments d2, and so on.
//
// The carry into output digit j is therefore [d0 >= 9] AND [d1 == 16] AND
// ... AND [d(j) == 16]. Prefix products are evaluated in a balanced tree to
// keep the full 9-limb N=256 path within eight additional multiplication levels.
pub fn round_one_level_homomorphic(
    evaluator: &RlweHe,
    value: &Bpr12HeValue,
    relin_keys: &HeRelinearizationKeyChain,
) -> Bpr12HeValue {
    let progress_enabled = std::env::var_os("PQBPR12_PROGRESS").is_some();
    let progress_started = std::time::Instant::now();
    macro_rules! progress {
        ($($arg:tt)*) => {
            if progress_enabled {
                eprintln!(
                    "[BPR12 +{:.1}s] {}",
                    progress_started.elapsed().as_secs_f64(),
                    format_args!($($arg)*)
                );
            }
        };
    }

    assert!(
        value.limbs.len() >= 2,
        "at least two radix-17 limbs are required for one rounding step"
    );

    let low_digit = &value.limbs[0];
    let first_ciphertext = low_digit
        .first()
        .expect("BPR12 limb must contain at least one ciphertext");
    let ring_n = first_ciphertext.ciphertext.u.degree;
    let base_level = first_ciphertext.level;

    assert_eq!(
        base_level, value.level,
        "BPR12 value level must match the ciphertext level"
    );

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

    progress!(
        "start rounding: ring_n={}, limbs={}, slots_per_ciphertext={}, ciphertexts_per_limb={}, base_level={}",
        ring_n,
        value.limbs.len(),
        value.slots_per_ciphertext,
        ciphertexts_per_limb,
        base_level
    );

    for limb in &value.limbs {
        assert_eq!(
            limb.len(),
            ciphertexts_per_limb,
            "all radix limbs must use the same packing layout"
        );
        assert!(
            limb.iter().all(|ciphertext| ciphertext.level == base_level),
            "all ciphertexts in a BPR12 value must have the same level"
        );
    }

    let output_limb_count = value.limbs.len() - 1;
    let max_prefix_terms = output_limb_count.saturating_sub(1);
    let mut prefix_depth = 0usize;
    let mut prefix_capacity = 1usize;
    while prefix_capacity < max_prefix_terms {
        prefix_capacity *= 2;
        prefix_depth += 1;
    }
    let additional_depth = if max_prefix_terms == 0 {
        4
    } else {
        5 + prefix_depth
    };
    assert!(
        base_level + additional_depth <= evaluator.max_level(),
        "insufficient RNS levels for BPR12 carry propagation: need level {}, maximum is {}",
        base_level + additional_depth,
        evaluator.max_level()
    );

    let progress_stride = (ciphertexts_per_limb / 8).max(1);

    // c0 = [d0 >= 9], evaluated independently in each ciphertext batch.
    progress!("stage 1/4: evaluating low-digit carry [d0 >= 9]");
    let mut low_carries = Vec::with_capacity(ciphertexts_per_limb);
    for (batch_index, ciphertext) in low_digit.iter().enumerate() {
        progress!(
            "low carry batch {}/{}: started",
            batch_index + 1,
            ciphertexts_per_limb
        );
        low_carries.push(encrypted_carry_ge_9(evaluator, ciphertext, relin_keys));
        if (batch_index + 1) % progress_stride == 0 || batch_index + 1 == ciphertexts_per_limb {
            progress!(
                "low carry batch {}/{}: complete",
                batch_index + 1,
                ciphertexts_per_limb
            );
        }
    }
    progress!("stage 1/4 complete");

    // Equality predicates for d1 through the penultimate output digit. The
    // topmost carry beyond the output modulus is intentionally discarded.
    progress!(
        "stage 2/4: evaluating [d_j == 16] for {} higher limbs",
        max_prefix_terms
    );
    let mut equal_16_by_limb = Vec::with_capacity(max_prefix_terms);
    for (higher_limb_index, limb) in value
        .limbs
        .iter()
        .skip(1)
        .take(max_prefix_terms)
        .enumerate()
    {
        progress!(
            "equality predicate for input limb d{}: started",
            higher_limb_index + 1
        );
        let mut predicates = Vec::with_capacity(ciphertexts_per_limb);
        for (batch_index, ciphertext) in limb.iter().enumerate() {
            progress!(
                "d{} == 16, batch {}/{}: started",
                higher_limb_index + 1,
                batch_index + 1,
                ciphertexts_per_limb
            );
            predicates.push(encrypted_equal_16(evaluator, ciphertext, relin_keys));
            if (batch_index + 1) % progress_stride == 0 || batch_index + 1 == ciphertexts_per_limb {
                progress!(
                    "d{} == 16, batch {}/{}: complete",
                    higher_limb_index + 1,
                    batch_index + 1,
                    ciphertexts_per_limb
                );
            }
        }
        equal_16_by_limb.push(predicates);
        progress!(
            "equality predicate for input limb d{}: complete",
            higher_limb_index + 1
        );
    }
    progress!("stage 2/4 complete");

    // carries_by_output_limb[j] is the carry added to output digit j.
    // For j > 0, it is c0 multiplied by the prefix product of [d1==16] ..
    // [dj==16]. Products are balanced to limit their multiplicative depth.
    let mut carries_by_output_limb = Vec::with_capacity(output_limb_count);
    carries_by_output_limb.push(low_carries);

    progress!(
        "stage 3/4: composing propagated carries for {} output limbs",
        output_limb_count
    );
    for output_index in 1..output_limb_count {
        progress!(
            "propagated carry into output digit {}: started",
            output_index
        );
        let mut batch_carries = Vec::with_capacity(ciphertexts_per_limb);
        for batch_index in 0..ciphertexts_per_limb {
            progress!(
                "output digit {}, batch {}/{}: prefix product started",
                output_index,
                batch_index + 1,
                ciphertexts_per_limb
            );
            let factors = equal_16_by_limb[..output_index]
                .iter()
                .map(|limb| &limb[batch_index])
                .collect::<Vec<_>>();
            let prefix_product = encrypted_product_balanced(evaluator, &factors, relin_keys);
            let first_carry = lift_ciphertext_level(
                evaluator,
                &carries_by_output_limb[0][batch_index],
                prefix_product.level,
            );
            batch_carries.push(evaluator.mul_ciphertext(&first_carry, &prefix_product, relin_keys));
            if (batch_index + 1) % progress_stride == 0 || batch_index + 1 == ciphertexts_per_limb {
                progress!(
                    "output digit {}, batch {}/{}: carry complete",
                    output_index,
                    batch_index + 1,
                    ciphertexts_per_limb
                );
            }
        }
        carries_by_output_limb.push(batch_carries);
        progress!(
            "propagated carry into output digit {}: complete",
            output_index
        );
    }
    progress!("stage 3/4 complete");

    let target_level = carries_by_output_limb
        .iter()
        .flatten()
        .map(|carry| carry.level)
        .max()
        .expect("at least one output carry is required");

    progress!(
        "carry circuits complete; target level={}, switching remaining limbs",
        target_level
    );

    // Drop d0 and switch every remaining digit to the deepest carry level.
    let mut output_limbs = Vec::with_capacity(output_limb_count);
    for (limb_index, limb) in value.limbs.iter().skip(1).enumerate() {
        let switched = limb
            .iter()
            .map(|ciphertext| lift_ciphertext_level(evaluator, ciphertext, target_level))
            .collect::<Vec<_>>();
        output_limbs.push(switched);
        progress!(
            "level switch for output limb {} of {} complete",
            limb_index + 1,
            output_limb_count
        );
    }

    // Add the correctly propagated carry to each radix digit. Ciphertext
    // addition is slot-wise in CRT mode and scalar-wise in coefficient mode.
    progress!("stage 4/4: adding propagated carries to output limbs");
    for output_index in 0..output_limb_count {
        for batch_index in 0..ciphertexts_per_limb {
            let carry = lift_ciphertext_level(
                evaluator,
                &carries_by_output_limb[output_index][batch_index],
                target_level,
            );
            output_limbs[output_index][batch_index] =
                evaluator.add_ciphertexts(&output_limbs[output_index][batch_index], &carry);
        }
        progress!(
            "carry additions for output limb {} of {} complete",
            output_index + 1,
            output_limb_count
        );
    }
    progress!(
        "rounding complete at level {} in {:.1}s",
        target_level,
        progress_started.elapsed().as_secs_f64()
    );

    Bpr12HeValue {
        limbs: output_limbs,
        level: target_level,
        slots_per_ciphertext: value.slots_per_ciphertext,
    }
}

#[cfg(test)]
mod radix17_digit_product_tests {
    use super::{
        carry_coefficients_for_fixed_lhs, high_digit_coefficients_for_fixed_lhs,
        high_digit_rank8_coefficients, lagrange_basis_table_radix17,
    };

    fn evaluate(coefficients: &[u64; 17], x: u64) -> u64 {
        let mut result = 0u64;
        let mut power = 1u64;
        for &coefficient in coefficients {
            result = (result + coefficient * power) % 17;
            power = power * x % 17;
        }
        result
    }

    #[test]
    fn lagrange_interpolation_covers_all_289_radix17_digit_products() {
        let lagrange = lagrange_basis_table_radix17();

        for a in 0..17usize {
            for b in 0..17usize {
                assert_eq!(
                    evaluate(&lagrange[a], b as u64),
                    if a == b { 1 } else { 0 },
                    "Lagrange selector L_{a}({b}) is incorrect"
                );
            }

            let high_coefficients = high_digit_coefficients_for_fixed_lhs(a, &lagrange);
            for b in 0..17usize {
                assert_eq!(
                    evaluate(&high_coefficients, b as u64),
                    ((a * b) / 17) as u64,
                    "high digit for {a} * {b} is incorrect"
                );
            }
        }
    }

    #[test]
    fn lagrange_interpolation_covers_all_289_radix17_digit_additions() {
        let lagrange = lagrange_basis_table_radix17();
        for a in 0..17usize {
            let carry_coefficients = carry_coefficients_for_fixed_lhs(a, &lagrange);
            for b in 0..17usize {
                assert_eq!(
                    evaluate(&carry_coefficients, b as u64),
                    (if a + b >= 17 { 1 } else { 0 }),
                    "addition carry for {a} + {b} is incorrect"
                );
            }
        }
    }

    #[test]
    fn rank8_high_digit_factorization_covers_all_289_digit_products() {
        let (u_coefficients, v_coefficients) = high_digit_rank8_coefficients();

        for a in 0..17u64 {
            for b in 0..17u64 {
                let reconstructed = (0..8usize).fold(0u64, |sum, rank| {
                    (sum + evaluate(&u_coefficients[rank], a) * evaluate(&v_coefficients[rank], b))
                        % 17
                });

                assert_eq!(
                    reconstructed,
                    (a * b / 17) % 17,
                    "incorrect high digit for {a} * {b}"
                );
            }
        }
    }
}

/// Carry-save accumulation of up to four signed radix-17 products modulo 17^k.
/// `negative == true` means that the product contributes with a minus sign
/// (negacyclic wraparound). Complementing every digit and adding the public
/// number of negative terms at digit zero implements subtraction modulo 17^k.
/// The result is normalized to k radix-17 digits at input level
/// `L + 10 + ceil(log2(k))`.
fn encrypted_radix17_sum_products_carry_save(
    evaluator: &RlweHe,
    terms: &[(Vec<HeCiphertext>, bool)],
    relin_keys: &HeRelinearizationKeyChain,
) -> Vec<HeCiphertext> {
    const MAX_TERMS: usize = 4;

    assert!(!terms.is_empty() && terms.len() <= MAX_TERMS);
    let limb_count = terms[0].0.len();
    assert!(
        limb_count >= 2,
        "carry-save product sum needs at least two limbs"
    );
    assert!(terms.iter().all(|(digits, _)| digits.len() == limb_count));

    let base_level = terms[0].0[0].level;
    let ring_n = terms[0].0[0].ciphertext.u.degree;
    let mut prefix_rounds = 0usize;
    let mut prefix_capacity = 1usize;
    while prefix_capacity < limb_count {
        prefix_rounds += 1;
        prefix_capacity *= 2;
    }
    let output_level = base_level + 10 + prefix_rounds;
    let negative_count = terms.iter().filter(|term| term.1).count();

    assert!(
        output_level <= evaluator.max_level(),
        "carry-save accumulation exceeds the HE level budget"
    );

    for (term_index, (digits, _)) in terms.iter().enumerate() {
        for (digit_index, digit) in digits.iter().enumerate() {
            assert_eq!(
                digit.level, base_level,
                "term {term_index}, digit {digit_index}: level mismatch"
            );
            assert_eq!(
                digit.ciphertext.u.degree, ring_n,
                "term {term_index}, digit {digit_index}: ring degree mismatch"
            );
        }
    }

    let progress_enabled = std::env::var_os("PQBPR12_PROGRESS").is_some();
    let started = std::time::Instant::now();

    macro_rules! progress {
        ($($arg:tt)*) => {
            if progress_enabled {
                eprintln!(
                    "[BPR12 CSA-SUM +{:.1}s] {}",
                    started.elapsed().as_secs_f64(),
                    format_args!($($arg)*)
                );
            }
        };
    }

    progress!(
        "starting with {} products at level {}; {} negative terms",
        terms.len(),
        base_level,
        negative_count
    );

    // Replace every negative operand x by (17^k - 1 - x).
    // The missing +1 for each negative term is accounted for at digit zero.
    let mut operands: Vec<Vec<HeCiphertext>> = Vec::with_capacity(MAX_TERMS);

    for (term_index, (digits, negative)) in terms.iter().enumerate() {
        let mut transformed = Vec::with_capacity(limb_count);

        for (_digit_index, digit) in digits.iter().enumerate() {
            let output_digit = if *negative {
                let negated = evaluator.negate(digit);
                evaluator.add_plaintext(&negated, &constant_poly(16, ring_n))
            } else {
                clone_he_ciphertext(digit)
            };

            assert_eq!(output_digit.level, base_level);
            transformed.push(output_digit);
        }

        operands.push(transformed);

        progress!(
            "term {}/{}: sign representation ready",
            term_index + 1,
            terms.len()
        );
        debug_assert_eq!(operands[term_index].len(), limb_count);
    }

    // Pad to four operands with encrypted zeroes. This keeps the carry-save
    // network structurally identical when N=2 or N=3.
    let zero_seed = evaluator.add_ciphertexts(&operands[0][0], &evaluator.negate(&operands[0][0]));

    while operands.len() < MAX_TERMS {
        operands.push(
            (0..limb_count)
                .map(|_| clone_he_ciphertext(&zero_seed))
                .collect(),
        );
    }

    let mut residues = Vec::with_capacity(limb_count);
    let mut diagonal_carries = Vec::with_capacity(limb_count - 1);

    progress!("phase 1/2: reducing each radix column");

    for digit_index in 0..limb_count {
        let a = &operands[0][digit_index];
        let b = &operands[1][digit_index];
        let c = &operands[2][digit_index];
        let d = &operands[3][digit_index];

        // Pair residues remain at base_level because addition is linear
        // over the plaintext field F_17.
        let residue_ab = evaluator.add_ciphertexts(a, b);
        let residue_cd = evaluator.add_ciphertexts(c, d);

        let mut residue = evaluator.add_ciphertexts(&residue_ab, &residue_cd);

        if digit_index == 0 && negative_count > 0 {
            // Add one for every complemented negative product.
            residue =
                evaluator.add_plaintext(&residue, &constant_poly(negative_count as u64, ring_n));
        }

        residues.push(residue);

        // The final carry beyond the highest limb is discarded modulo 17^k.
        if digit_index == limb_count - 1 {
            continue;
        }

        // Carry from each pair: floor((a+b)/17) and floor((c+d)/17).
        let carry_ab = encrypted_radix17_digit_add(evaluator, a, b, relin_keys).1;

        let carry_cd = encrypted_radix17_digit_add(evaluator, c, d, relin_keys).1;

        // Carry from combining the pair residues. At digit zero, include
        // the public correction for negative terms in this same addition.
        let carry_join = if digit_index == 0 {
            let zero_at_base =
                evaluator.add_ciphertexts(&residue_ab, &evaluator.negate(&residue_ab));

            let correction = evaluator
                .add_plaintext(&zero_at_base, &constant_poly(negative_count as u64, ring_n));

            let join_terms = vec![
                clone_he_ciphertext(&residue_ab),
                clone_he_ciphertext(&residue_cd),
                correction,
            ];

            encrypted_radix17_sum_digits_with_carry(evaluator, &join_terms, relin_keys).1
        } else {
            encrypted_radix17_digit_add(evaluator, &residue_ab, &residue_cd, relin_keys).1
        };

        // These are ordinary small integers in 0..=4, so their sum does
        // not wrap in F_17.
        let pair_carries = evaluator.add_ciphertexts(&carry_ab, &carry_cd);
        let total_carry = evaluator.add_ciphertexts(&pair_carries, &carry_join);

        assert_eq!(total_carry.level, base_level + 5);
        diagonal_carries.push(total_carry);
    }

    progress!("phase 2/2: normalizing residues and shifted carries");

    let carry_level = base_level + 5;

    let residue_value = Bpr12HeValue {
        limbs: residues
            .iter()
            .map(|digit| vec![lift_ciphertext_level(evaluator, digit, carry_level)])
            .collect(),
        level: carry_level,
        slots_per_ciphertext: 1,
    };

    // The shifted carry vector is (0, k0, k1, ..., k7).
    let zero_at_carry_level = evaluator.add_ciphertexts(
        &diagonal_carries[0],
        &evaluator.negate(&diagonal_carries[0]),
    );

    let mut shifted_carries = Vec::with_capacity(limb_count);
    shifted_carries.push(vec![zero_at_carry_level]);

    for carry in diagonal_carries {
        shifted_carries.push(vec![carry]);
    }

    let carry_value = Bpr12HeValue {
        limbs: shifted_carries,
        level: carry_level,
        slots_per_ciphertext: 1,
    };

    let normalized =
        encrypted_radix17_add_values_prefix(evaluator, &residue_value, &carry_value, relin_keys);

    assert_eq!(normalized.level, output_level);
    assert_eq!(normalized.limbs.len(), limb_count);
    assert!(normalized.limbs.iter().all(|limb| limb.len() == 1));

    progress!(
        "complete: signed product sum normalized at level {}",
        output_level
    );

    normalized
        .limbs
        .into_iter()
        .map(|mut limb| limb.remove(0))
        .collect()
}

/// Compute the complete negacyclic product in R_(17^k), coefficient-wise,
/// for a k-limb input. This correctness-first implementation is limited to
/// N <= 4 and uses one scalar radix-17 product per coefficient pair.
/// Terms with i+j >= N are complemented and corrected during carry-save
/// accumulation to implement X^N = -1.
pub fn encrypted_radix17_negacyclic_product_toy(
    evaluator: &RlweHe,
    lhs: &Bpr12HeValue,
    rhs: &Bpr12HeValue,
    relin_keys: &HeRelinearizationKeyChain,
) -> Bpr12HeValue {
    assert!(!lhs.limbs.is_empty(), "lhs BPR12 value has no limbs");
    assert_eq!(lhs.limbs.len(), rhs.limbs.len());
    let limb_count = lhs.limbs.len();
    assert!(
        limb_count >= 2,
        "toy synthesis needs at least two radix-17 limbs"
    );
    assert_eq!(lhs.level, rhs.level);
    assert_eq!(lhs.slots_per_ciphertext, 1);
    assert_eq!(rhs.slots_per_ciphertext, 1);

    let n = lhs.limbs[0].len();
    let base_level = lhs.level;
    let mut prefix_rounds = 0usize;
    let mut prefix_capacity = 1usize;
    while prefix_capacity < limb_count {
        prefix_rounds += 1;
        prefix_capacity *= 2;
    }
    let product_level = base_level + 15 + prefix_rounds;
    let output_level = product_level + 10 + prefix_rounds;

    assert!(
        (2..=4).contains(&n),
        "toy convolution supports degrees N=2..=4"
    );
    assert!(
        output_level <= evaluator.max_level(),
        "insufficient HE levels for toy negacyclic product"
    );

    for value in [lhs, rhs] {
        assert!(value.limbs.iter().all(|limb| limb.len() == n));
        assert!(value
            .limbs
            .iter()
            .flatten()
            .all(|ct| ct.level == base_level));
        assert!(value
            .limbs
            .iter()
            .flatten()
            .all(|ct| ct.ciphertext.u.degree == n));
    }

    let progress_enabled = std::env::var_os("PQBPR12_PROGRESS").is_some();
    let started = std::time::Instant::now();

    macro_rules! progress {
        ($($arg:tt)*) => {
            if progress_enabled {
                eprintln!(
                    "[BPR12 NEGACYCLIC +{:.1}s] {}",
                    started.elapsed().as_secs_f64(),
                    format_args!($($arg)*)
                );
            }
        };
    }

    let mut terms_by_coefficient: Vec<Vec<(Vec<HeCiphertext>, bool)>> =
        (0..n).map(|_| Vec::with_capacity(n)).collect();

    progress!(
        "phase 1/2: evaluating {} scalar coefficient products",
        n * n
    );

    let mut product_count = 0usize;

    for i in 0..n {
        for j in 0..n {
            let lhs_digits: Vec<&HeCiphertext> =
                (0..limb_count).map(|digit| &lhs.limbs[digit][i]).collect();

            let rhs_digits: Vec<&HeCiphertext> =
                (0..limb_count).map(|digit| &rhs.limbs[digit][j]).collect();

            let product_digits =
                encrypted_radix17_scalar_product(evaluator, &lhs_digits, &rhs_digits, relin_keys);

            assert_eq!(product_digits.len(), limb_count);
            assert!(product_digits
                .iter()
                .all(|digit| digit.level == product_level));

            let output_coefficient = (i + j) % n;
            let wrapped_negative = i + j >= n;

            terms_by_coefficient[output_coefficient].push((product_digits, wrapped_negative));

            product_count += 1;
            progress!("scalar products {}/{} complete", product_count, n * n);
        }
    }

    progress!("phase 2/2: carry-save accumulation for each output coefficient");

    let mut output_limbs: Vec<Vec<HeCiphertext>> =
        (0..limb_count).map(|_| Vec::with_capacity(n)).collect();

    for coefficient_index in 0..n {
        let terms = std::mem::take(&mut terms_by_coefficient[coefficient_index]);

        assert_eq!(terms.len(), n);

        progress!(
            "coefficient {}/{}: reducing {} signed products",
            coefficient_index + 1,
            n,
            terms.len()
        );

        let coefficient_digits =
            encrypted_radix17_sum_products_carry_save(evaluator, &terms, relin_keys);

        assert_eq!(coefficient_digits.len(), limb_count);

        for (digit_index, digit) in coefficient_digits.into_iter().enumerate() {
            output_limbs[digit_index].push(digit);
        }
    }

    let result = Bpr12HeValue {
        limbs: output_limbs,
        level: output_level,
        slots_per_ciphertext: 1,
    };

    progress!(
        "complete: {}-limb negacyclic product at level {}",
        limb_count,
        result.level
    );

    result
}

/// Backward-compatible nine-limb wrapper for the original toy tests.
pub fn encrypted_radix17_negacyclic_product_nine_limbs_toy(
    evaluator: &RlweHe,
    lhs: &Bpr12HeValue,
    rhs: &Bpr12HeValue,
    relin_keys: &HeRelinearizationKeyChain,
) -> Bpr12HeValue {
    assert_eq!(lhs.limbs.len(), 9, "lhs needs nine radix-17 limbs");
    assert_eq!(rhs.limbs.len(), 9, "rhs needs nine radix-17 limbs");
    encrypted_radix17_negacyclic_product_toy(evaluator, lhs, rhs, relin_keys)
}

/// Evaluate the BPR12 binary synthesis tree for encrypted input bits on a
/// small ring (N=2..=4). This is an end-to-end correctness prototype, not the
/// N=256 implementation: the current polynomial convolution still evaluates
/// every coefficient pair individually.
///
/// `s0` and `s1` contain one q=17^9 leaf polynomial per input bit. Each
/// encrypted bit must encrypt the constant polynomial 0 or 1. At every tree
/// layer, the product is computed in the current radix modulus and rounded
/// once, so the number of limbs decreases by one per layer.
pub fn encrypted_bpr12_prf_toy(
    evaluator: &RlweHe,
    encrypted_bits: &[HeCiphertext],
    s0: &[PolyRq],
    s1: &[PolyRq],
    relin_keys: &HeRelinearizationKeyChain,
) -> Bpr12HeValue {
    assert!(!encrypted_bits.is_empty(), "PRF input must not be empty");
    assert!(
        encrypted_bits.len().is_power_of_two(),
        "PRF input size must be a power of two"
    );
    assert_eq!(
        encrypted_bits.len(),
        s0.len(),
        "s0 leaf count must match input bits"
    );
    assert_eq!(
        encrypted_bits.len(),
        s1.len(),
        "s1 leaf count must match input bits"
    );

    let n = s0[0].degree_bound();
    assert!((2..=4).contains(&n), "toy PRF supports ring degree N=2..=4");
    assert_eq!(
        s0[0].modulus(),
        RADIX.pow(9),
        "PRF leaves must be modulo 17^9"
    );
    assert!(s0
        .iter()
        .chain(s1.iter())
        .all(|leaf| leaf.degree_bound() == n));
    assert!(s0
        .iter()
        .chain(s1.iter())
        .all(|leaf| leaf.modulus() == RADIX.pow(9)));

    for (i, bit) in encrypted_bits.iter().enumerate() {
        assert_eq!(
            bit.level, encrypted_bits[0].level,
            "encrypted bit {i} level mismatch"
        );
        assert_eq!(
            bit.ciphertext.u.degree, n,
            "encrypted bit {i} ring degree mismatch"
        );
    }

    let mut layer: Vec<Bpr12HeValue> = encrypted_bits
        .iter()
        .zip(s0.iter().zip(s1.iter()))
        .map(|(bit, (zero_leaf, one_leaf))| {
            Bpr12HeValue::select_leaf(evaluator, bit, zero_leaf, one_leaf)
        })
        .collect();

    while layer.len() > 1 {
        assert_eq!(
            layer.len() % 2,
            0,
            "each PRF tree layer must have an even number of nodes"
        );
        let mut next_layer = Vec::with_capacity(layer.len() / 2);

        for pair in layer.chunks_exact(2) {
            let product =
                encrypted_radix17_negacyclic_product_toy(evaluator, &pair[0], &pair[1], relin_keys);
            let rounded = round_one_level_homomorphic(evaluator, &product, relin_keys);
            next_layer.push(rounded);
        }

        layer = next_layer;
    }

    layer.pop().expect("PRF tree must produce one root value")
}

/// Exact direct rounding from q=17^9 to p=17.
///
/// For x = d0 + 17*d1 + ... + 17^8*d8,
/// round(17*x / 17^9) equals d8 + carry modulo 17.
///
/// The carry is one precisely when the lower eight digits are at least
/// (17^8+1)/2, whose radix-17 digits are [9,8,8,8,8,8,8,8].
/// The comparison is evaluated in parallel: the first digit from the top
/// that is >= 9, after only 8s, determines the carry.
///
/// This is a direct q-to-p rounding circuit, not one q-to-q/17 digit drop.
/// Input level L -> output level L+7.
pub fn encrypted_radix17_round_nine_limbs_to_17(
    evaluator: &RlweHe,
    product: &Bpr12HeValue,
    relin_keys: &HeRelinearizationKeyChain,
) -> Bpr12HeValue {
    const LIMBS: usize = 9;
    const LOW_LIMBS: usize = 8;

    assert_eq!(product.limbs.len(), LIMBS);
    assert_eq!(product.slots_per_ciphertext, 1);

    let n = product.limbs[0].len();
    let base_level = product.level;
    let predicate_level = base_level + 4;
    let output_level = base_level + 7;

    assert!(product.limbs.iter().all(|limb| limb.len() == n));
    assert!(product
        .limbs
        .iter()
        .flatten()
        .all(|ct| ct.level == base_level));
    assert!(
        output_level <= evaluator.max_level(),
        "insufficient HE levels for direct nine-limb rounding"
    );

    let progress_enabled = std::env::var_os("PQBPR12_PROGRESS").is_some();
    let started = std::time::Instant::now();

    macro_rules! progress {
        ($($arg:tt)*) => {
            if progress_enabled {
                eprintln!(
                    "[BPR12 DIRECT-ROUND +{:.1}s] {}",
                    started.elapsed().as_secs_f64(),
                    format_args!($($arg)*)
                );
            }
        };
    }

    let mut rounded_coefficients = Vec::with_capacity(n);

    for coefficient_index in 0..n {
        progress!(
            "coefficient {}/{}: evaluating [digit >= 9] and [digit == 8]",
            coefficient_index + 1,
            n
        );

        let ge9: Vec<HeCiphertext> = (0..LOW_LIMBS)
            .map(|digit_index| {
                encrypted_carry_ge_9(
                    evaluator,
                    &product.limbs[digit_index][coefficient_index],
                    relin_keys,
                )
            })
            .collect();

        let eq8: Vec<HeCiphertext> = (0..LOW_LIMBS)
            .map(|digit_index| {
                encrypted_radix17_equal_8(
                    evaluator,
                    &product.limbs[digit_index][coefficient_index],
                    relin_keys,
                )
            })
            .collect();

        assert!(ge9.iter().all(|ct| ct.level == predicate_level));
        assert!(eq8.iter().all(|ct| ct.level == predicate_level));

        let mut carry_terms = Vec::with_capacity(LOW_LIMBS);

        // Terms are mutually exclusive:
        // [d7 >= 9]
        // + [d7 == 8] [d6 >= 9]
        // + ...
        // + [d7 == 8] ... [d1 == 8] [d0 >= 9].
        // Their sum is therefore the carry bit without a final OR circuit.
        for digit_index in (0..LOW_LIMBS).rev() {
            let mut factors: Vec<&HeCiphertext> = Vec::with_capacity(LOW_LIMBS);

            for higher_digit in (digit_index + 1..LOW_LIMBS).rev() {
                factors.push(&eq8[higher_digit]);
            }
            factors.push(&ge9[digit_index]);

            let term = encrypted_product_balanced(evaluator, &factors, relin_keys);

            assert!(term.level <= output_level);
            carry_terms.push(lift_ciphertext_level(evaluator, &term, output_level));
        }

        let mut carry = clone_he_ciphertext(&carry_terms[0]);
        for term in carry_terms.iter().skip(1) {
            carry = evaluator.add_ciphertexts(&carry, term);
        }

        assert_eq!(carry.level, output_level);

        // d8 is the quotient digit. Adding the exact rounding carry
        // directly produces the one-limb result modulo 17.
        let top_digit = lift_ciphertext_level(
            evaluator,
            &product.limbs[8][coefficient_index],
            output_level,
        );

        let rounded = evaluator.add_ciphertexts(&top_digit, &carry);

        assert_eq!(rounded.level, output_level);
        rounded_coefficients.push(rounded);

        progress!(
            "coefficient {}/{}: rounding complete",
            coefficient_index + 1,
            n
        );
    }

    progress!(
        "complete: direct q=17^9 -> p=17 rounding at level {}",
        output_level
    );

    Bpr12HeValue {
        limbs: vec![rounded_coefficients],
        level: output_level,
        slots_per_ciphertext: 1,
    }
}

/// Full toy BPR12 synthesis: nine-limb negacyclic product followed by
/// direct rounding to p=17. Returns both the unrounded product and output
/// so the test can validate each phase independently.
pub fn encrypted_radix17_negacyclic_synthesize_nine_limbs_toy(
    evaluator: &RlweHe,
    lhs: &Bpr12HeValue,
    rhs: &Bpr12HeValue,
    relin_keys: &HeRelinearizationKeyChain,
) -> (Bpr12HeValue, Bpr12HeValue) {
    let product =
        encrypted_radix17_negacyclic_product_nine_limbs_toy(evaluator, lhs, rhs, relin_keys);

    let rounded = encrypted_radix17_round_nine_limbs_to_17(evaluator, &product, relin_keys);

    (product, rounded)
}

/// Encrypted equality predicate [x == 8] over F_17.
///
/// Fermat's theorem gives [x == 8] = 1 - (x - 8)^16.
/// Four squarings consume exactly four HE levels.
fn encrypted_radix17_equal_8(
    evaluator: &RlweHe,
    value: &HeCiphertext,
    relin_keys: &HeRelinearizationKeyChain,
) -> HeCiphertext {
    let ring_n = value.ciphertext.u.degree;
    let shifted = evaluator.add_plaintext(value, &constant_poly(9, ring_n));

    let mut power = shifted;
    for _ in 0..4 {
        power = evaluator.mul_ciphertext(&power, &power, relin_keys);
    }

    evaluator.one_minus(&power, &constant_poly(1, ring_n))
}

#[cfg(test)]
mod cached_crt17_digit_product_tests {
    use super::{
        encrypted_powers_through_16, encrypted_radix17_digit_product_from_precomputed_tables,
        evaluate_encrypted_radix17_polynomial, high_digit_coefficients_for_fixed_lhs,
        lagrange_basis_table_radix17, Bpr12HeValue,
    };
    use crate::algebra::ring::PolyRq;
    use crate::core::rlwe_he::RlweHe;
    use rand::thread_rng;
    use std::time::Instant;

    #[test]
    fn cached_crt17_digit_product_matches_reference() {
        const N: usize = 256;
        const P: u64 = 17;
        const SLOTS: usize = 8;

        let started = Instant::now();
        let mut rng = thread_rng();
        let evaluator = RlweHe::new();
        let keygen = evaluator.keygen(&mut rng, N);
        let relin_keys = evaluator.generate_relinearization_key_chain(&mut rng, &keygen.sk, 8);

        let lhs_values: [u64; SLOTS] = [0, 1, 2, 4, 8, 9, 15, 16];
        let rhs_values: [u64; SLOTS] = [16, 15, 8, 4, 2, 1, 9, 16];

        eprintln!("[CACHED CRT17] encoding eight input pairs");

        let lhs_encoded = Bpr12HeValue::crt17_encode_slots(lhs_values);
        let rhs_encoded = Bpr12HeValue::crt17_encode_slots(rhs_values);

        let lhs_plain = PolyRq::from_coeffs(&lhs_encoded, N, P);
        let rhs_plain = PolyRq::from_coeffs(&rhs_encoded, N, P);

        let lhs = evaluator.encrypt(&mut rng, &keygen.pk, &lhs_plain, N);
        let rhs = evaluator.encrypt(&mut rng, &keygen.pk, &rhs_plain, N);

        eprintln!(
            "[CACHED CRT17 +{:.1}s] precomputing encrypted powers",
            started.elapsed().as_secs_f64()
        );

        let lhs_powers = encrypted_powers_through_16(&evaluator, &lhs, &relin_keys);
        let rhs_powers = encrypted_powers_through_16(&evaluator, &rhs, &relin_keys);

        let lagrange = lagrange_basis_table_radix17();

        eprintln!(
            "[CACHED CRT17 +{:.1}s] caching interpolation tables",
            started.elapsed().as_secs_f64()
        );

        let lhs_selectors: Vec<_> = lagrange
            .iter()
            .map(|coefficients| {
                evaluate_encrypted_radix17_polynomial(&evaluator, &lhs_powers, coefficients, N)
            })
            .collect();

        let rhs_high_terms: Vec<_> = (0..17)
            .map(|a| {
                let coefficients = high_digit_coefficients_for_fixed_lhs(a, &lagrange);

                evaluate_encrypted_radix17_polynomial(&evaluator, &rhs_powers, &coefficients, N)
            })
            .collect();

        eprintln!(
            "[CACHED CRT17 +{:.1}s] evaluating cached digit product",
            started.elapsed().as_secs_f64()
        );

        let (low, high) = encrypted_radix17_digit_product_from_precomputed_tables(
            &evaluator,
            &lhs,
            &rhs,
            &lhs_selectors,
            &rhs_high_terms,
            &relin_keys,
        );

        assert_eq!(low.level, 5);
        assert_eq!(high.level, 5);

        // Decrypt only after the complete homomorphic operation.
        let actual_low = evaluator.decrypt(&keygen.sk, &low, N);
        let actual_high = evaluator.decrypt(&keygen.sk, &high, N);

        let low_slots = Bpr12HeValue::crt17_decode_slots(&actual_low.coefficients()[..N]);
        let high_slots = Bpr12HeValue::crt17_decode_slots(&actual_high.coefficients()[..N]);

        let expected_low: [u64; SLOTS] = std::array::from_fn(|i| lhs_values[i] * rhs_values[i] % P);
        let expected_high: [u64; SLOTS] =
            std::array::from_fn(|i| lhs_values[i] * rhs_values[i] / P);

        assert_eq!(low_slots, expected_low, "incorrect low digits");
        assert_eq!(high_slots, expected_high, "incorrect high digits");

        eprintln!(
            "[CACHED CRT17 +{:.1}s] PASS — eight low/high digit pairs are exact",
            started.elapsed().as_secs_f64()
        );
    }

    pub(super) fn benchmark_rns_moduli(count: usize, degree: usize) -> Vec<u64> {
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
    fn cached_crt17_digit_product_n256_24_primes() {
        use crate::algebra::ring::PolyRq;
        use crate::core::rlwe_he::RlweHe;
        use crate::core::rns::RnsModulusChain;
        use rand::thread_rng;
        use std::time::Instant;

        const N: usize = 256;
        const P: u64 = 17;
        const SLOTS: usize = 8;

        let started = Instant::now();
        let mut rng = thread_rng();

        eprintln!("[CRT8 SINGLE +0.0s] 1/6: creating 24-prime RNS chain");

        let evaluator = RlweHe::with_chain(RnsModulusChain::new(
            crate::core::bpr12_oblivious::cached_crt17_digit_product_tests::benchmark_rns_moduli(
                24, N,
            ),
            N,
        ));

        let keygen = evaluator.keygen(&mut rng, N);
        let relin_keys = evaluator.generate_relinearization_key_chain(&mut rng, &keygen.sk, 8);

        let lhs_slots = [0u64, 1, 2, 8, 9, 12, 16, 16];
        let rhs_slots = [0u64, 16, 9, 8, 9, 16, 16, 9];

        eprintln!(
            "[CRT8 SINGLE +{:.1}s] 2/6: encrypting eight CRT17 slots",
            started.elapsed().as_secs_f64()
        );

        let lhs_plain = PolyRq::from_coeffs(&Bpr12HeValue::crt17_encode_slots(lhs_slots), N, P);
        let rhs_plain = PolyRq::from_coeffs(&Bpr12HeValue::crt17_encode_slots(rhs_slots), N, P);

        let lhs = evaluator.encrypt(&mut rng, &keygen.pk, &lhs_plain, N);
        let rhs = evaluator.encrypt(&mut rng, &keygen.pk, &rhs_plain, N);

        eprintln!(
            "[CRT8 SINGLE +{:.1}s] 3/6: precomputing encrypted powers",
            started.elapsed().as_secs_f64()
        );

        let lhs_powers = encrypted_powers_through_16(&evaluator, &lhs, &relin_keys);
        let rhs_powers = encrypted_powers_through_16(&evaluator, &rhs, &relin_keys);

        let lagrange = lagrange_basis_table_radix17();

        eprintln!(
            "[CRT8 SINGLE +{:.1}s] 4/6: building interpolation tables",
            started.elapsed().as_secs_f64()
        );

        let lhs_selectors: Vec<_> = lagrange
            .iter()
            .map(|coefficients| {
                evaluate_encrypted_radix17_polynomial(&evaluator, &lhs_powers, coefficients, N)
            })
            .collect();

        let high_coefficients: Vec<[u64; 17]> = (0..17usize)
            .map(|a| high_digit_coefficients_for_fixed_lhs(a, &lagrange))
            .collect();

        let rhs_high_terms: Vec<_> = high_coefficients
            .iter()
            .map(|coefficients| {
                evaluate_encrypted_radix17_polynomial(&evaluator, &rhs_powers, coefficients, N)
            })
            .collect();

        eprintln!(
            "[CRT8 SINGLE +{:.1}s] 5/6: evaluating one cached digit product",
            started.elapsed().as_secs_f64()
        );

        let (low, high) = encrypted_radix17_digit_product_from_precomputed_tables(
            &evaluator,
            &lhs,
            &rhs,
            &lhs_selectors,
            &rhs_high_terms,
            &relin_keys,
        );

        assert_eq!(low.level, 5);
        assert_eq!(high.level, 5);

        eprintln!(
            "[CRT8 SINGLE +{:.1}s] 6/6: decrypting and checking reference",
            started.elapsed().as_secs_f64()
        );

        let low_plain = evaluator.decrypt(&keygen.sk, &low, N);
        let high_plain = evaluator.decrypt(&keygen.sk, &high, N);

        let actual_low = Bpr12HeValue::crt17_decode_slots(&low_plain.coefficients()[..N]);
        let actual_high = Bpr12HeValue::crt17_decode_slots(&high_plain.coefficients()[..N]);

        let expected_low: [u64; SLOTS] = std::array::from_fn(|i| lhs_slots[i] * rhs_slots[i] % P);
        let expected_high: [u64; SLOTS] = std::array::from_fn(|i| lhs_slots[i] * rhs_slots[i] / P);

        assert_eq!(actual_low, expected_low, "incorrect low digits");
        assert_eq!(actual_high, expected_high, "incorrect high digits");

        eprintln!(
            "[CRT8 SINGLE +{:.1}s] PASS — one cached product is exact",
            started.elapsed().as_secs_f64()
        );
    }

    #[test]
    fn sum_256_radix17_digits_three_limbs_exact_n256() {
        use super::encrypted_radix17_sum_256_digits_three_limbs;
        use super::Bpr12HeValue;

        use crate::algebra::ring::PolyRq;
        use crate::core::rlwe_he::RlweHe;
        use crate::core::rns::RnsModulusChain;
        use rand::thread_rng;

        const N: usize = 256;
        const P: u64 = 17;
        const SLOTS: usize = 8;

        let mut rng = thread_rng();

        eprintln!("[SUM 256] creating N=256 HE context");

        let evaluator = RlweHe::with_chain(RnsModulusChain::new(benchmark_rns_moduli(24, N), N));

        let keygen = evaluator.keygen(&mut rng, N);
        let relin_keys = evaluator.generate_relinearization_key_chain(&mut rng, &keygen.sk, 8);

        // 256 different encrypted radix-17 digits, each with eight SIMD slots.
        let clear_values: Vec<[u64; SLOTS]> = (0..256usize)
            .map(|term| {
                std::array::from_fn(|slot| ((term * 13 + slot * 7 + term * slot) % 17) as u64)
            })
            .collect();

        let encrypted_digits: Vec<_> = clear_values
            .iter()
            .map(|slots| {
                let encoded = Bpr12HeValue::crt17_encode_slots(*slots);
                let plaintext = PolyRq::from_coeffs(&encoded, N, P);

                evaluator.encrypt(&mut rng, &keygen.pk, &plaintext, N)
            })
            .collect();

        eprintln!("[SUM 256] reducing 256 encrypted digits");

        let result = encrypted_radix17_sum_256_digits_three_limbs(
            &evaluator,
            &encrypted_digits,
            &relin_keys,
        );

        assert_eq!(result.len(), 3);
        assert!(result.iter().all(|digit| digit.level == 10));

        let decoded: Vec<[u64; SLOTS]> = result
            .iter()
            .map(|digit| {
                let plaintext = evaluator.decrypt(&keygen.sk, digit, N);
                Bpr12HeValue::crt17_decode_slots(&plaintext.coefficients()[..N])
            })
            .collect();

        let actual: [u64; SLOTS] = std::array::from_fn(|slot| {
            decoded[0][slot] + P * decoded[1][slot] + P * P * decoded[2][slot]
        });

        let expected: [u64; SLOTS] =
            std::array::from_fn(|slot| clear_values.iter().map(|values| values[slot]).sum());

        assert_eq!(
            actual, expected,
            "256-digit sum or its propagated carries are incorrect"
        );

        eprintln!("[SUM 256] PASS: all eight three-limb sums are exact");
    }

    #[test]
    fn carry_tree_sum_digits_n256_24_primes_exact() {
        use crate::algebra::ring::PolyRq;
        use crate::core::rlwe_he::RlweHe;
        use crate::core::rns::RnsModulusChain;
        use rand::thread_rng;
        use std::time::Instant;

        const N: usize = 256;
        const P: u64 = 17;
        const SLOTS: usize = 8;

        let started = Instant::now();
        let mut rng = thread_rng();

        eprintln!("[CARRY TREE N256] creating HE context");

        let evaluator = RlweHe::with_chain(RnsModulusChain::new(benchmark_rns_moduli(24, N), N));

        let keygen = evaluator.keygen(&mut rng, N);
        let relin_keys = evaluator.generate_relinearization_key_chain(&mut rng, &keygen.sk, 8);

        let digit_values: [[u64; SLOTS]; 3] = [
            [16, 16, 0, 3, 5, 8, 10, 16],
            [16, 1, 16, 14, 12, 8, 7, 16],
            [16, 0, 16, 16, 16, 16, 16, 16],
        ];

        eprintln!("[CARRY TREE N256] encrypting three radix-17 digits");

        let encrypted_digits: Vec<_> = digit_values
            .iter()
            .map(|slots| {
                let encoded = Bpr12HeValue::crt17_encode_slots(*slots);
                let plaintext = PolyRq::from_coeffs(&encoded, N, P);

                evaluator.encrypt(&mut rng, &keygen.pk, &plaintext, N)
            })
            .collect();

        eprintln!("[CARRY TREE N256] evaluating tree reduction");

        let (residue, carry) = super::encrypted_radix17_sum_digits_with_carry(
            &evaluator,
            &encrypted_digits,
            &relin_keys,
        );

        assert_eq!(residue.level, 0);
        assert_eq!(carry.level, 5);

        eprintln!(
            "[CARRY TREE N256 +{:.1}s] decrypting and checking",
            started.elapsed().as_secs_f64()
        );

        let residue_plain = evaluator.decrypt(&keygen.sk, &residue, N);
        let carry_plain = evaluator.decrypt(&keygen.sk, &carry, N);

        let actual_residue = Bpr12HeValue::crt17_decode_slots(&residue_plain.coefficients()[..N]);

        let actual_carry = Bpr12HeValue::crt17_decode_slots(&carry_plain.coefficients()[..N]);

        let sums: [u64; SLOTS] =
            std::array::from_fn(|slot| digit_values.iter().map(|digits| digits[slot]).sum());

        let expected_residue = std::array::from_fn(|slot| sums[slot] % P);

        let expected_carry = std::array::from_fn(|slot| sums[slot] / P);

        assert_eq!(
            actual_residue, expected_residue,
            "incorrect radix-17 residues"
        );

        assert_eq!(actual_carry, expected_carry, "incorrect radix-17 carries");

        eprintln!(
            "[CARRY TREE N256 +{:.1}s] PASS — all eight residues and carries are exact",
            started.elapsed().as_secs_f64()
        );
    }
}
