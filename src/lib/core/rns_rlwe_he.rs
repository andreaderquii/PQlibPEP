use num_bigint::{BigInt, BigUint, Sign};
use rand::RngCore;

use crate::algebra::ring::PolyRq;
use crate::core::rns::{RnsModulusChain, RnsPoly};

use crate::core::rlwe_rns::{
    sample_small_rns_poly,
    sample_uniform_rns_poly,
    RnsCiphertext,
    RnsSecretKey,
};

const PLAINTEXT_MODULUS: u64 = 17;

// Three-component ciphertext produced by ciphertext x ciphertext
// multiplication:
//
//     c0 = v1 * v2
//     c1 = -(v1*u2 + u1*v2)
//     c2 = u1 * u2
//
// The decryption relation is:
//
//     c0 + c1*s + c2*s^2.
pub struct RnsMulCiphertext {
    pub c0: RnsPoly,
    pub c1: RnsPoly,
    pub c2: RnsPoly,
}

// One RNS relinearization-key entry.
//
//     k1 - k0*s = 17*e + B^i*s^2
//
// modulo every RNS modulus.
pub struct RnsRelinearizationKeyEntry {
    pub k0: RnsPoly,
    pub k1: RnsPoly,
}

// RNS relinearization key.
pub struct RnsRelinearizationKey {
    pub entries: Vec<RnsRelinearizationKeyEntry>,
    pub base_bits: usize,
}

// RNS RLWE homomorphic evaluator.
pub struct RnsRlweHe;

impl RnsRlweHe {
    pub fn new() -> Self {
        Self
    }

    // Raw ciphertext x ciphertext multiplication.
    //
    // If:
    //
    //     ct_i = (u_i, v_i)
    //
    // then the product is:
    //
    //     c0 = v1*v2
    //     c1 = -(v1*u2 + u1*v2)
    //     c2 = u1*u2
    //
    // and:
    //
    //     c0 + c1*s + c2*s^2
    //
    // is the product phase before relinearization.
    pub fn mul_raw(
        &self,
        lhs: &RnsCiphertext,
        rhs: &RnsCiphertext,
    ) -> RnsMulCiphertext {
        assert_compatible_ciphertexts(lhs, rhs);

        let c0 = lhs.v.mul_negacyclic(&rhs.v);

        let c1 = lhs
            .v
            .mul_negacyclic(&rhs.u)
            .add(&lhs.u.mul_negacyclic(&rhs.v))
            .neg();

        let c2 = lhs.u.mul_negacyclic(&rhs.u);

        RnsMulCiphertext {
            c0,
            c1,
            c2,
        }
    }

    // Generate an RNS relinearization key.
    //
    // We use:
    //
    //     k1 = k0*s + 17*e + B^i*s^2
    //
    // so that:
    //
    //     k1 - k0*s = 17*e + B^i*s^2
    //
    // With base_bits = 8 and our current ~23-24 bit RNS primes,
    // three decomposition digits are sufficient.
    pub fn generate_relinearization_key<R: RngCore>(
    &self,
    rng: &mut R,
    sk: &RnsSecretKey,
    base_bits: usize,
) -> RnsRelinearizationKey {
    assert!(
        base_bits > 0 && base_bits < 32,
        "base_bits must be in 1..31"
    );

    let base = 1u64
        .checked_shl(base_bits as u32)
        .expect("base_bits too large");

    // Reconstruct the RNS modulus chain from the secret key.
    let chain = RnsModulusChain::new(
        sk.s
            .residues
            .iter()
            .map(PolyRq::modulus)
            .collect(),
        sk.s.degree,
    );

    // Full CRT modulus Q = q0 * q1 * ... * q(k-1).
    let full_modulus = chain
        .moduli
        .iter()
        .fold(
            BigUint::from(1u64),
            |acc, &q| acc * BigUint::from(q),
        );

    // Number of digits required to represent an element modulo Q
    // in base B = 2^base_bits.
    //
    // For the current ~208-bit Q and B = 2^8:
    //
    //     ceil(208 / 8) = 26 digits.
    let digits_count =
        ((full_modulus.bits() as usize)
            + base_bits
            - 1)
        / base_bits;

    assert!(
        digits_count > 0,
        "relinearization key must contain at least one digit"
    );

    let secret_squared =
        sk.s.mul_negacyclic(&sk.s);

    let mut entries =
        Vec::with_capacity(digits_count);

    for digit_index in 0..digits_count {
        // Fresh uniform RLWE masking polynomial.
        let a =
            sample_uniform_rns_poly(rng, &chain);

        // IMPORTANT:
        // This samples one small integer polynomial and
        // represents the SAME polynomial in every RNS limb.
        let e =
            sample_small_rns_poly(rng, &chain);

        // Compute B^i * s^2 separately modulo each RNS prime.
        //
        // We cannot use RnsPoly::mul_scalar() here because
        // B^i becomes different modulo each q_i.
        let mut gadget_s2_residues =
            Vec::with_capacity(chain.moduli.len());

        for residue_index in 0..chain.moduli.len() {
            let q =
                chain.modulus(residue_index);

            let gadget =
                mod_pow_u64(
                    base % q,
                    digit_index as u64,
                    q,
                );

            let scaled =
                secret_squared
                    .residue(residue_index)
                    .mul_scalar(gadget);

            gadget_s2_residues.push(scaled);
        }

        let gadget_s2 =
            RnsPoly {
                residues: gadget_s2_residues,
                degree: chain.degree,
            };

        // k1 = k0*s + 17*e + B^i*s^2
        let as_product =
            a.mul_negacyclic(&sk.s);

        let scaled_error =
            e.mul_scalar(
                PLAINTEXT_MODULUS,
            );

        let k1 =
            as_product
                .add(&scaled_error)
                .add(&gadget_s2);

        entries.push(
            RnsRelinearizationKeyEntry {
                k0: a,
                k1,
            },
        );
    }

    RnsRelinearizationKey {
        entries,
        base_bits,
    }
}

    // Relinearize a three-component ciphertext.
    //
    // Starting from:
    //
    //     c0 + c1*s + c2*s^2
    //
    // decompose each RNS residue coefficient-wise:
    //
    //     c2 = d0 + B*d1 + B^2*d2
    //
    // and use:
    //
    //     k1_i - k0_i*s
    //         = 17*e_i + B^i*s^2
    //
    // We construct:
    //
    //     u' = -c1 + sum_i d_i*k0_i
    //     v' =  c0 + sum_i d_i*k1_i
    //
    // so that:
    //
    //     v' - u'*s
    //
    // equals the original product phase plus additional
    // relinearization noise.
    pub fn relinearize(
    &self,
    product: &RnsMulCiphertext,
    key: &RnsRelinearizationKey,
) -> RnsCiphertext {
    assert!(
        !key.entries.is_empty(),
        "relinearization key must not be empty"
    );

    assert_eq!(
        product.c2.residue_count(),
        key.entries[0].k0.residue_count(),
        "product and relinearization key use different RNS bases"
    );

    // IMPORTANT:
    //
    // Decompose c2 ONCE over the FULL CRT modulus Q.
    //
    // Every RNS limb receives the SAME digit polynomial.
    let digits =
        global_decompose_rns_poly(
            &product.c2,
            key.base_bits,
        );

    assert_eq!(
        digits.len(),
        key.entries.len(),
        "global ciphertext decomposition and relinearization key have different lengths"
    );

    // Start from:
    //
    //     c0 + c1*s + c2*s^2
    //
    // and replace c2*s^2 with the gadget decomposition.
    //
    // u' = -c1 + sum_i d_i*k0_i
    // v' =  c0 + sum_i d_i*k1_i
    //
    // Since:
    //
    //     k1_i - k0_i*s
    //       = 17*e_i + B^i*s^2
    //
    // and:
    //
    //     c2 = sum_i d_i*B^i   (mod Q)
    //
    // we obtain the original phase plus
    // plaintext-modulus-scaled relinearization noise.

    let mut u =
        product.c1.neg();

    let mut v =
        product.c0.clone();

    for (digit, entry) in
        digits.iter().zip(
            key.entries.iter()
        )
    {
        let digit_k0 =
            digit.mul_negacyclic(
                &entry.k0
            );

        let digit_k1 =
            digit.mul_negacyclic(
                &entry.k1
            );

        u =
            u.add(&digit_k0);

        v =
            v.add(&digit_k1);
    }

    RnsCiphertext {
        u,
        v,
    }
}

    // Full ciphertext x ciphertext multiplication:
    //
    //     raw multiplication
    //          ↓
    //     degree-2 ciphertext
    //          ↓
    //     relinearization
    //          ↓
    //     normal RLWE ciphertext
    pub fn mul_ciphertext(
        &self,
        lhs: &RnsCiphertext,
        rhs: &RnsCiphertext,
        relin_key: &RnsRelinearizationKey,
    ) -> RnsCiphertext {
        let product =
            self.mul_raw(lhs, rhs);

        self.relinearize(
            &product,
            relin_key,
        )
    }


    // BGV-style modulus switch from the current RNS base
    // to the same base with its final modulus removed.
    //
    // The target must contain exactly the prefix of source moduli.
    // Each coefficient is reconstructed in the full CRT modulus,
    // corrected to be divisible by the dropped modulus, and divided
    // by that modulus while preserving its value modulo 17.
    pub fn modulus_switch(
        &self,
        ciphertext: &RnsCiphertext,
        target_chain: &RnsModulusChain,
    ) -> RnsCiphertext {
        let source_moduli: Vec<u64> = ciphertext
            .u
            .residues
            .iter()
            .map(PolyRq::modulus)
            .collect();

        assert_eq!(
            ciphertext.v.residue_count(),
            source_moduli.len(),
            "ciphertext components use different RNS bases"
        );

        assert_eq!(
            target_chain.degree,
            ciphertext.u.degree,
            "source and target polynomial degrees differ"
        );

        assert!(
            source_moduli.len() >= 2,
            "cannot switch an RNS base containing fewer than two moduli"
        );

        assert_eq!(
            target_chain.moduli.len() + 1,
            source_moduli.len(),
            "one modulus must be removed per switch"
        );

        assert_eq!(
            target_chain.moduli.as_slice(),
            &source_moduli[..source_moduli.len() - 1],
            "target RNS base must be the source base without its final modulus"
        );

        let u = bgv_modswitch_rns_poly(&ciphertext.u, target_chain);
        let v = bgv_modswitch_rns_poly(&ciphertext.v, target_chain);

        RnsCiphertext { u, v }
    }
}

fn assert_compatible_ciphertexts(
    lhs: &RnsCiphertext,
    rhs: &RnsCiphertext,
) {
    assert_eq!(
        lhs.u.degree,
        rhs.u.degree,
        "ciphertexts must use the same polynomial degree"
    );

    assert_eq!(
        lhs.u.residue_count(),
        rhs.u.residue_count(),
        "ciphertexts must use the same number of RNS residues"
    );

    assert_eq!(
        lhs.v.residue_count(),
        rhs.v.residue_count(),
        "ciphertexts must use the same number of RNS residues"
    );

    for i in 0..lhs.u.residue_count() {
        assert_eq!(
            lhs.u.residue(i).modulus(),
            rhs.u.residue(i).modulus(),
            "ciphertexts have different RNS modulus at u residue {}",
            i
        );

        assert_eq!(
            lhs.v.residue(i).modulus(),
            rhs.v.residue(i).modulus(),
            "ciphertexts have different RNS modulus at v residue {}",
            i
        );
    }
}

fn mod_inverse_u64(
    a: u64,
    modulus: u64,
) -> u64 {
    assert!(
        a != 0,
        "modular inverse does not exist for zero"
    );

    let mut t: i128 = 0;
    let mut new_t: i128 = 1;

    let mut r =
        modulus as i128;
    let mut new_r =
        a as i128;

    while new_r != 0 {
        let quotient =
            r / new_r;

        let next_t =
            t - quotient * new_t;

        t = new_t;
        new_t = next_t;

        let next_r =
            r - quotient * new_r;

        r = new_r;
        new_r = next_r;
    }

    assert_eq!(
        r,
        1,
        "value is not invertible modulo modulus"
    );

    t.rem_euclid(modulus as i128) as u64
}

fn mod_pow_u64(
    mut base: u64,
    mut exponent: u64,
    modulus: u64,
) -> u64 {
    if modulus == 1 {
        return 0;
    }

    let mut result = 1u64;

    base %= modulus;

    while exponent > 0 {
        if exponent & 1 == 1 {
            result =
                ((result as u128
                    * base as u128)
                    % modulus as u128)
                    as u64;
        }

        base =
            ((base as u128
                * base as u128)
                % modulus as u128)
                as u64;

        exponent >>= 1;
    }

    result
}

fn biguint_to_u64(
    value: &BigUint,
) -> u64 {
    value
        .to_u64_digits()
        .first()
        .copied()
        .unwrap_or(0)
}

// Decompose an RNS polynomial using the FULL CRT modulus.
//
// For every coefficient:
//
//     x = d0 + B*d1 + B^2*d2 + ...
//
// where x is reconstructed from ALL RNS residues.
//
// The returned digit polynomials have identical integer
// coefficients across every RNS limb.
fn global_decompose_rns_poly(
    input: &RnsPoly,
    base_bits: usize,
) -> Vec<RnsPoly> {
    assert!(
        base_bits > 0 && base_bits < 32,
        "base_bits must be in 1..31"
    );

    let residue_count =
        input.residue_count();

    assert!(
        residue_count > 0,
        "RNS polynomial must contain at least one residue"
    );

    let degree =
        input.degree;

    let moduli: Vec<u64> =
        (0..residue_count)
            .map(|i| {
                input
                    .residue(i)
                    .modulus()
            })
            .collect();

    // Full CRT modulus:
    //
    //     Q = q0*q1*...*q(k-1)
    let full_modulus =
        moduli.iter().fold(
            BigUint::from(1u64),
            |acc, &q| {
                acc * BigUint::from(q)
            },
        );

    // CRT constants:
    //
    //     M_i = Q / q_i
    //     inv_i = M_i^{-1} mod q_i
    //
    // so:
    //
    //     x = sum_i r_i*M_i*inv_i mod Q
    let mut crt_constants =
        Vec::with_capacity(residue_count);

    for &q_i in &moduli {
        let q_i_big =
            BigUint::from(q_i);

        let m_i =
            &full_modulus / &q_i_big;

        let m_i_mod_q =
            (&m_i % q_i)
                .to_u64_digits()
                .first()
                .copied()
                .unwrap_or(0);

        let inverse =
            mod_inverse_u64(
                m_i_mod_q,
                q_i,
            );

        crt_constants.push(
            (m_i, inverse)
        );
    }

    let base =
        1u64
            .checked_shl(
                base_bits as u32
            )
            .expect("base_bits too large");

    let base_big =
        BigUint::from(base);

    // ceil(log_B(Q))
    let digits_count =
        ((full_modulus.bits() as usize)
            + base_bits
            - 1)
        / base_bits;

    let mut digit_coefficients =
        vec![
            vec![0u64; degree];
            digits_count
        ];

    for coefficient_index in 0..degree {
        // Reconstruct this coefficient modulo the full Q.
        let mut value =
            BigUint::from(0u64);

        for residue_index in 0..residue_count {
            let residue =
                input
                    .residue(residue_index)
                    .coefficients()
                    [coefficient_index];

            let (ref m_i, inverse) =
                crt_constants[residue_index];

            value +=
                BigUint::from(residue)
                    * m_i
                    * BigUint::from(
                        inverse
                    );
        }

        value %= &full_modulus;

        // Extract common base-B digits.
        for digit_index in 0..digits_count {
            let digit =
                &value % &base_big;

            digit_coefficients
                [digit_index]
                [coefficient_index] =
                biguint_to_u64(&digit);

            value /= &base_big;
        }

        debug_assert!(
            value == BigUint::from(0u64)
        );
    }

    // Lift every GLOBAL digit into all RNS limbs.
    digit_coefficients
        .into_iter()
        .map(|coeffs| {
            let residues =
                moduli
                    .iter()
                    .map(|&q| {
                        PolyRq::from_coeffs(
                            &coeffs,
                            degree,
                            q,
                        )
                    })
                    .collect();

            RnsPoly {
                residues,
                degree,
            }
        })
        .collect()
}

fn bgv_modswitch_rns_poly(
    input: &RnsPoly,
    target_chain: &RnsModulusChain,
) -> RnsPoly {
    const P: u64 = 17;

    let source_moduli: Vec<u64> = input
        .residues
        .iter()
        .map(PolyRq::modulus)
        .collect();

    assert_eq!(input.degree, target_chain.degree);

    assert_eq!(
        source_moduli.len(),
        target_chain.moduli.len() + 1,
        "modulus switching must drop exactly one RNS modulus"
    );

    assert_eq!(
        target_chain.moduli.as_slice(),
        &source_moduli[..source_moduli.len() - 1],
        "target must be the source modulus prefix"
    );

    let source_q = source_moduli.iter().fold(
        BigUint::from(1u64),
        |acc, &q| acc * BigUint::from(q),
    );

    let target_q = target_chain.moduli.iter().fold(
        BigUint::from(1u64),
        |acc, &q| acc * BigUint::from(q),
    );

    assert_eq!(
        &source_q % &target_q,
        BigUint::from(0u64),
        "target modulus must divide source modulus"
    );

    assert_eq!(
        rns_bgv_biguint_to_u64(
            &(&source_q % BigUint::from(P))
        ),
        1,
        "source CRT modulus must equal 1 modulo 17"
    );

    assert_eq!(
        rns_bgv_biguint_to_u64(
            &(&target_q % BigUint::from(P))
        ),
        1,
        "target CRT modulus must equal 1 modulo 17"
    );

    let dropped_big = &source_q / &target_q;
    let dropped = rns_bgv_biguint_to_u64(&dropped_big);

    assert!(dropped > 1);

    assert_eq!(
        BigUint::from(dropped),
        dropped_big,
        "dropped modulus must fit in u64"
    );

    assert_eq!(
        dropped % P,
        1,
        "dropped modulus must equal 1 modulo 17"
    );

    let inverse_p = rns_bgv_mod_inverse_u64(P, dropped);
    let dropped_bigint = BigInt::from(dropped);

    let half_q = &source_q / BigUint::from(2u64);

    let source_q_bigint = BigInt::from_biguint(
        Sign::Plus,
        source_q.clone(),
    );

    // CRT reconstruction constants:
    // M_i = Q / q_i and inv_i = M_i^(-1) mod q_i.
    let mut crt_constants: Vec<(BigUint, u64)> =
        Vec::with_capacity(source_moduli.len());

    for &q_i in &source_moduli {
        let q_i_big = BigUint::from(q_i);
        let m_i = &source_q / &q_i_big;

        let m_i_mod_q =
            rns_bgv_biguint_to_u64(&(&m_i % &q_i_big));

        let inverse =
            rns_bgv_mod_inverse_u64(m_i_mod_q, q_i);

        crt_constants.push((m_i, inverse));
    }

    let mut switched_coefficients: Vec<BigInt> =
        Vec::with_capacity(input.degree);

    for coefficient_index in 0..input.degree {
        // Reconstruct the source coefficient in [0, Q).
        let mut value = BigUint::from(0u64);

        for residue_index in 0..source_moduli.len() {
            let residue = input
                .residue(residue_index)
                .coefficients()[coefficient_index];

            let (m_i, inverse) =
                &crt_constants[residue_index];

            value += BigUint::from(residue)
                * m_i
                * BigUint::from(*inverse);
        }

        value %= &source_q;

        // Center the CRT representative.
        let centered = if value > half_q {
            BigInt::from_biguint(Sign::Plus, value)
                - source_q_bigint.clone()
        } else {
            BigInt::from_biguint(Sign::Plus, value)
        };

        // Choose k so that centered + 17*k is divisible by dropped.
        let mut remainder =
            (-centered.clone()) % &dropped_bigint;

        if remainder.sign() == Sign::Minus {
            remainder += &dropped_bigint;
        }

        let remainder_u64 =
            rns_bgv_bigint_to_u64(&remainder);

        let mut k = (
            (remainder_u64 as u128 * inverse_p as u128)
                % dropped as u128
        ) as i128;

        // Use the balanced representative of k.
        if k > (dropped / 2) as i128 {
            k -= dropped as i128;
        }

        let corrected =
            centered + BigInt::from(P) * BigInt::from(k);

        assert_eq!(
            &corrected % &dropped_bigint,
            BigInt::from(0u64),
            "BGV correction did not make the coefficient divisible"
        );

        switched_coefficients.push(corrected / &dropped_bigint);
    }

    // Encode the switched coefficients in every remaining RNS modulus.
    let residues = target_chain
        .moduli
        .iter()
        .map(|&q| {
            let q_bigint = BigInt::from(q);

            let coefficients: Vec<u64> = switched_coefficients
                .iter()
                .map(|coefficient| {
                    let mut remainder = coefficient % &q_bigint;

                    if remainder.sign() == Sign::Minus {
                        remainder += &q_bigint;
                    }

                    rns_bgv_bigint_to_u64(&remainder)
                })
                .collect();

            PolyRq::from_coeffs(
                &coefficients,
                input.degree,
                q,
            )
        })
        .collect();

    RnsPoly {
        residues,
        degree: input.degree,
    }
}

fn rns_bgv_mod_inverse_u64(
    a: u64,
    modulus: u64,
) -> u64 {
    assert!(modulus > 1);
    assert!(a > 0);

    let mut t: i128 = 0;
    let mut new_t: i128 = 1;
    let mut r = modulus as i128;
    let mut new_r = a as i128;

    while new_r != 0 {
        let quotient = r / new_r;

        let next_t = t - quotient * new_t;
        t = new_t;
        new_t = next_t;

        let next_r = r - quotient * new_r;
        r = new_r;
        new_r = next_r;
    }

    assert_eq!(
        r, 1,
        "modular inverse does not exist"
    );

    t.rem_euclid(modulus as i128) as u64
}

fn rns_bgv_biguint_to_u64(
    value: &BigUint,
) -> u64 {
    let digits = value.to_u64_digits();

    assert!(
        digits.len() <= 1,
        "integer does not fit in u64"
    );

    digits.first().copied().unwrap_or(0)
}

fn rns_bgv_bigint_to_u64(
    value: &BigInt,
) -> u64 {
    assert_ne!(
        value.sign(),
        Sign::Minus,
        "expected a nonnegative integer"
    );

    let unsigned = value
        .to_biguint()
        .expect("BigInt conversion failed");

    rns_bgv_biguint_to_u64(&unsigned)
}