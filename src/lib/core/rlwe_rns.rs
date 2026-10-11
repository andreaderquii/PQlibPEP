use num_bigint::BigUint;
use rand::RngCore;

use crate::algebra::ring::PolyRq;
use crate::core::rns::{RnsModulusChain, RnsPoly};

const PLAINTEXT_MODULUS: u64 = 17;

// RNS RLWE secret key.
//
// The same small polynomial s is represented across all RNS limbs.
pub struct RnsSecretKey {
    pub s: RnsPoly,
}

// RNS RLWE public key:
//
//     b = a*s + 17*e
//
// The factor 17 is intentional: it makes the encryption noise
// vanish modulo the plaintext modulus.
pub struct RnsPublicKey {
    pub a: RnsPoly,
    pub b: RnsPoly,
}

// RNS RLWE key-generation result.
pub struct RnsKeyGenResult {
    pub sk: RnsSecretKey,
    pub pk: RnsPublicKey,
}

// RNS RLWE ciphertext:
//
//     u = a*r + 17*e1
//     v = b*r + 17*e2 + m
//
// Therefore:
//
//     v - u*s
//       = m + 17*(e*r + e2 - e1*s)
//
// and reducing modulo 17 recovers the plaintext.
pub struct RnsCiphertext {
    pub u: RnsPoly,
    pub v: RnsPoly,
}

pub struct RnsRlwe;

impl RnsRlwe {
    pub fn new() -> Self {
        Self
    }

    // Generate an RNS RLWE key pair.
    pub fn keygen<R: RngCore>(
        &self,
        rng: &mut R,
        chain: &RnsModulusChain,
    ) -> RnsKeyGenResult {
        let a = sample_uniform_rns_poly(rng, chain);
        let s = sample_small_rns_poly(rng, chain);
        let e = sample_small_rns_poly(rng, chain);

        let as_product = a.mul_negacyclic(&s);
        let scaled_error = e.mul_scalar(PLAINTEXT_MODULUS);
        let b = as_product.add(&scaled_error);

        RnsKeyGenResult {
            sk: RnsSecretKey { s },
            pk: RnsPublicKey { a, b },
        }
    }

    // Encrypt a plaintext polynomial with coefficients in Z_17.
    pub fn encrypt<R: RngCore>(
        &self,
        rng: &mut R,
        pk: &RnsPublicKey,
        message: &[u64],
    ) -> RnsCiphertext {
        let n = pk.a.degree;

        let chain = RnsModulusChain::new(
            pk.a
                .residues
                .iter()
                .map(PolyRq::modulus)
                .collect(),
            n,
        );

        assert_eq!(
            message.len(),
            n,
            "RNS RLWE plaintext must contain exactly n coefficients"
        );

        for &m in message {
            assert!(
                m < PLAINTEXT_MODULUS,
                "plaintext coefficients must be in Z_17"
            );
        }

        let r = sample_small_rns_poly(rng, &chain);
        let e1 = sample_small_rns_poly(rng, &chain);
        let e2 = sample_small_rns_poly(rng, &chain);

        let u = pk
            .a
            .mul_negacyclic(&r)
            .add(&e1.mul_scalar(PLAINTEXT_MODULUS));

        let message_rns = RnsPoly::from_coeffs(message, &chain);

        let v = pk
            .b
            .mul_negacyclic(&r)
            .add(&e2.mul_scalar(PLAINTEXT_MODULUS))
            .add(&message_rns);

        RnsCiphertext { u, v }
    }

    // Decrypt an RNS RLWE ciphertext.
    //
    // IMPORTANT:
    //
    // We must reconstruct the phase modulo the FULL CRT modulus
    //
    //     Q = q0 * q1 * ... * q(L-1)
    //
    // rather than decoding using only one RNS limb.
    //
    // The phase satisfies:
    //
    //     phase = m + 17 * noise  (mod Q)
    //
    // so after centered reconstruction, reducing modulo 17
    // recovers the plaintext.
    pub fn decrypt(
        &self,
        sk: &RnsSecretKey,
        ciphertext: &RnsCiphertext,
    ) -> Vec<u64> {
        let n = sk.s.degree;

        assert_eq!(
            sk.s.residue_count(),
            ciphertext.u.residue_count(),
            "secret key and ciphertext must use the same RNS basis"
        );

        assert_eq!(
            ciphertext.u.residue_count(),
            ciphertext.v.residue_count(),
            "ciphertext components must use the same RNS basis"
        );

        let phase = ciphertext
            .v
            .sub(&ciphertext.u.mul_negacyclic(&sk.s));

        let residue_count = phase.residue_count();

        let moduli: Vec<u64> = (0..residue_count)
            .map(|i| phase.residue(i).modulus())
            .collect();

        // Full CRT modulus:
        //
        // Q = q0 * q1 * ... * q(L-1)
        let full_modulus = moduli.iter().fold(
            BigUint::from(1u64),
            |acc, &q| acc * BigUint::from(q),
        );

        let half_modulus = &full_modulus >> 1usize;

        // For each q_i:
        //
        // M_i = Q / q_i
        // inv_i = M_i^{-1} mod q_i
        //
        // CRT:
        //
        // x = sum_i r_i * M_i * inv_i  (mod Q)
        let mut crt_constants = Vec::with_capacity(residue_count);

        for &q_i in &moduli {
            let q_i_big = BigUint::from(q_i);

            let m_i = &full_modulus / &q_i_big;

            let m_i_mod_q = (&m_i % q_i)
                .to_u64_digits()
                .first()
                .copied()
                .unwrap_or(0);

            let inverse = mod_inverse_u64(
                m_i_mod_q,
                q_i,
            );

            crt_constants.push((m_i, inverse));
        }

        let full_modulus_mod_plaintext = (
            &full_modulus % PLAINTEXT_MODULUS
        )
            .to_u64_digits()
            .first()
            .copied()
            .unwrap_or(0);

        let mut message = Vec::with_capacity(n);

        for coeff_index in 0..n {
            let mut x = BigUint::from(0u64);

            // CRT reconstruction.
            for residue_index in 0..residue_count {
                let residue = phase
                    .residue(residue_index)
                    .coefficients()[coeff_index];

                let (ref m_i, inverse) =
                    crt_constants[residue_index];

                let term =
                    BigUint::from(residue)
                        * m_i
                        * BigUint::from(inverse);

                x += term;
            }

            x %= &full_modulus;

            // Center x into (-Q/2, Q/2].
            let x_mod_plaintext = (
                &x % PLAINTEXT_MODULUS
            )
                .to_u64_digits()
                .first()
                .copied()
                .unwrap_or(0);

            let decoded = if x > half_modulus {
                (
                    x_mod_plaintext
                        + PLAINTEXT_MODULUS
                        - full_modulus_mod_plaintext
                ) % PLAINTEXT_MODULUS
            } else {
                x_mod_plaintext
            };

            message.push(decoded);
        }

        message
    }
}

// Samples an independent uniform polynomial in every RNS limb.
pub(crate) fn sample_uniform_rns_poly<R: RngCore>(
    rng: &mut R,
    chain: &RnsModulusChain,
) -> RnsPoly {
    let residues = chain
        .moduli
        .iter()
        .map(|&q| {
            let coeffs: Vec<u64> = (0..chain.degree)
                .map(|_| rng.next_u64() % q)
                .collect();

            PolyRq::from_coeffs(
                &coeffs,
                chain.degree,
                q,
            )
        })
        .collect();

    RnsPoly {
        residues,
        degree: chain.degree,
    }
}

// Samples one small integer polynomial and represents it in every RNS limb.
//
// Distribution:
//
//     coefficient = (a0 + a1) - (b0 + b1)
//
// giving values in {-2,-1,0,1,2}.
pub(crate) fn sample_small_rns_poly<R: RngCore>(
    rng: &mut R,
    chain: &RnsModulusChain,
) -> RnsPoly {
    let degree = chain.degree;

    // Sample ONE small integer polynomial in Z.
    //
    // These coefficients are then represented consistently
    // across every RNS modulus.
    let small_coeffs: Vec<i64> = (0..degree)
        .map(|_| {
            match rng.next_u32() % 5 {
                0 => -2,
                1 => -1,
                2 => 0,
                3 => 1,
                _ => 2,
            }
        })
        .collect();

    // Lift the same integer polynomial into every RNS limb.
    let residues = chain
        .moduli
        .iter()
        .map(|&q| {
            let coeffs: Vec<u64> = small_coeffs
                .iter()
                .map(|&x| {
                    if x < 0 {
                        q - (-x as u64)
                    } else {
                        x as u64
                    }
                })
                .collect();

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
}

// Modular inverse using the extended Euclidean algorithm.
fn mod_inverse_u64(
    value: u64,
    modulus: u64,
) -> u64 {
    assert!(
        value != 0,
        "CRT inverse does not exist for zero"
    );

    let mut t: i128 = 0;
    let mut new_t: i128 = 1;

    let mut r: i128 = modulus as i128;
    let mut new_r: i128 = value as i128;

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
        r,
        1,
        "value is not invertible modulo modulus"
    );

    if t < 0 {
        t += modulus as i128;
    }

    t as u64
}