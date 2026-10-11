use crate::algebra::ring::PolyRq;
use crate::core::rlwe_pke::Ciphertext;

use rand_core::RngCore;

use crate::algebra::sampling::{
    sample_small_poly,
    sample_uniform_poly,
};

const PLAINTEXT_MODULUS: u64 = 17;

pub struct BgvSecretKey {
    pub s: PolyRq,
}

pub struct BgvPublicKey {
    pub a: PolyRq,
    pub b: PolyRq,
}

pub struct BgvKeyGenResult {
    pub sk: BgvSecretKey,
    pub pk: BgvPublicKey,
}

pub struct BgvCiphertext {
    pub ciphertext: Ciphertext,
    pub level: usize,
}

pub struct BgvRelinearizationKeyEntry {
    pub k0: PolyRq,
    pub k1: PolyRq,
}

pub struct BgvRelinearizationKey {
    pub entries: Vec<BgvRelinearizationKeyEntry>,
    pub base_bits: usize,
}


/// Prototype BGV modulus chain.
///
/// Each level uses a ciphertext modulus q_i such that:
/// - q_{i+1} divides q_i
/// - gcd(q_i, 17) = 1
/// - q_i = 1 (mod 17)
///
/// The default chain is intentionally simple and uses powers of two.
/// Because these moduli are composite, the leveled prototype below uses
/// direct negacyclic multiplication instead of the NTT implementation.
#[derive(Clone, Debug)]
pub struct BgvModulusChain {
    pub moduli: Vec<u64>,
}

impl BgvModulusChain {
    pub fn new(moduli: Vec<u64>) -> Self {
        assert!(
            !moduli.is_empty(),
            "BGV modulus chain must not be empty"
        );

        for q in &moduli {
            assert!(*q >= 2, "ciphertext moduli must be >= 2");
            assert_eq!(
                *q % PLAINTEXT_MODULUS,
                1,
                "BGV modulus must be 1 modulo the plaintext modulus"
            );
        }

        for i in 0..moduli.len().saturating_sub(1) {
            assert!(
                moduli[i] > moduli[i + 1],
                "BGV modulus chain must be strictly decreasing"
            );
            assert_eq!(
                moduli[i] % moduli[i + 1],
                0,
                "each BGV modulus must be divisible by the next one"
            );

            let d = moduli[i] / moduli[i + 1];
            assert_eq!(
                num_gcd(d, PLAINTEXT_MODULUS),
                1,
                "modulus-switching factor must be coprime with plaintext modulus"
            );
        }

        Self { moduli }
    }

  pub fn default_chain() -> Self {
    // Five levels support four consecutive ciphertext-ciphertext
    // multiplications.
    //
    // q0 -> q1 uses D = 256
    // q1 -> q2 uses D = 256
    // q2 -> q3 uses D = 137
    // q3 -> q4 uses D = 528
    //
    // Every switching factor is 1 (mod 17), so every q_i is also
    // 1 (mod 17).
    //
    // The moduli are chosen for this correctness/noise prototype;
    // they are not production cryptographic parameters.

    const Q4: u64 = 3_500_000_002;

    const D1: u64 = 256;
    const D2: u64 = 256;
    const D3: u64 = 137;
    const D4: u64 = 528;

    let q3 = Q4 * D4;
    let q2 = q3 * D3;
    let q1 = q2 * D2;
    let q0 = q1 * D1;

    Self::new(vec![
        q0,
        q1,
        q2,
        q3,
        Q4,
    ])
}

    pub fn modulus(&self, level: usize) -> u64 {
        *self
            .moduli
            .get(level)
            .expect("BGV level is outside the modulus chain")
    }

    pub fn len(&self) -> usize {
        self.moduli.len()
    }

    pub fn last_level(&self) -> usize {
        self.moduli.len() - 1
    }
}

impl Default for BgvModulusChain {
    fn default() -> Self {
        Self::default_chain()
    }
}

/// One relinearization key for one modulus level.
///
/// A leveled BGV ciphertext changes modulus after each multiplication, so
/// its relinearization key has to be generated at the corresponding level.
pub struct BgvRelinearizationKeyChain {
    pub keys: Vec<BgvRelinearizationKey>,
}


pub struct RlweBgvHe;

impl RlweBgvHe {
    pub fn new() -> Self {
        Self
    }

    /// Key generation for the leveled BGV prototype.
    pub fn keygen_leveled<R: RngCore>(
        &self,
        rng: &mut R,
        n: usize,
        chain: &BgvModulusChain,
    ) -> BgvKeyGenResult {
        let q = chain.modulus(0);

        let a = sample_uniform_poly(rng, n, q);
        let s = sample_small_poly(rng, n, q);
        let e = sample_small_poly(rng, n, q);

        let as_product = a.mul_negacyclic(&s);
        let scaled_error = e.mul_scalar(PLAINTEXT_MODULUS);
        let b = as_product.add(&scaled_error);

        BgvKeyGenResult {
            sk: BgvSecretKey { s },
            pk: BgvPublicKey { a, b },
        }
    }

    /// Encrypt a plaintext at level 0.
    pub fn encrypt_leveled<R: RngCore>(
        &self,
        rng: &mut R,
        pk: &BgvPublicKey,
        message: &PolyRq,
        n: usize,
    ) -> BgvCiphertext {
        assert_eq!(message.modulus(), PLAINTEXT_MODULUS);
        assert_eq!(message.degree_bound(), n);
        assert_eq!(pk.a.degree_bound(), n);
        assert_eq!(pk.b.degree_bound(), n);
        assert_eq!(pk.a.modulus(), pk.b.modulus());

        encrypt_negacyclic(rng, pk, message, n)
    }

    /// Add two ciphertexts at the same level.
    pub fn add(
        &self,
        lhs: &BgvCiphertext,
        rhs: &BgvCiphertext,
    ) -> BgvCiphertext {
        assert_eq!(
            lhs.level,
            rhs.level,
            "ciphertexts must be at the same level"
        );

        let ciphertext = Ciphertext {
            u: lhs.ciphertext.u.add(&rhs.ciphertext.u),
            v: lhs.ciphertext.v.add(&rhs.ciphertext.v),
        };

        BgvCiphertext {
            ciphertext,
            level: lhs.level,
        }
    }

    /// Add an unencrypted plaintext polynomial without consuming a level.
    pub fn add_plaintext(
        &self,
        ciphertext: &BgvCiphertext,
        plaintext: &PolyRq,
    ) -> BgvCiphertext {
        assert_eq!(
            plaintext.modulus(),
            PLAINTEXT_MODULUS,
            "plaintext must use modulus 17"
        );
        assert_eq!(
            plaintext.degree_bound(),
            ciphertext.ciphertext.v.degree_bound(),
            "plaintext and ciphertext must have the same degree"
        );

        let q = ciphertext.ciphertext.v.modulus();
        let plaintext_q =
            PolyRq::from_coeffs(plaintext.coefficients(), plaintext.degree_bound(), q);

        BgvCiphertext {
            ciphertext: Ciphertext {
                u: ciphertext.ciphertext.u.clone(),
                v: ciphertext.ciphertext.v.add(&plaintext_q),
            },
            level: ciphertext.level,
        }
    }

    /// Multiply a ciphertext by an unencrypted plaintext polynomial.
    ///
    /// This does not consume a ciphertext-ciphertext multiplication level.
    pub fn mul_plaintext(
        &self,
        ciphertext: &BgvCiphertext,
        plaintext: &PolyRq,
    ) -> BgvCiphertext {
        assert_eq!(
            plaintext.modulus(),
            PLAINTEXT_MODULUS,
            "plaintext must use modulus 17"
        );
        assert_eq!(
            plaintext.degree_bound(),
            ciphertext.ciphertext.u.degree_bound(),
            "plaintext and ciphertext must have the same degree"
        );

        let q = ciphertext.ciphertext.u.modulus();
        let plaintext_q =
            PolyRq::from_coeffs(plaintext.coefficients(), plaintext.degree_bound(), q);

        BgvCiphertext {
            ciphertext: Ciphertext {
                u: ciphertext.ciphertext.u.mul_negacyclic(&plaintext_q),
                v: ciphertext.ciphertext.v.mul_negacyclic(&plaintext_q),
            },
            level: ciphertext.level,
        }
    }

    /// Generate one relinearization key for every multiplication level.
    pub fn generate_relinearization_key_chain<R: RngCore>(
        &self,
        rng: &mut R,
        sk: &BgvSecretKey,
        chain: &BgvModulusChain,
        base_bits: usize,
    ) -> BgvRelinearizationKeyChain {
        assert_eq!(
            sk.s.modulus(),
            chain.modulus(0),
            "base secret key must use the first chain modulus"
        );

        let keys = (0..chain.last_level())
            .map(|level| {
                let sk_level = reduce_secret_to_modulus(sk, chain.modulus(level));
                relin_key_negacyclic(rng, &sk_level, base_bits)
            })
            .collect();

        BgvRelinearizationKeyChain { keys }
    }

    /// Switch a ciphertext from q_l to q_{l+1}.
    pub fn modulus_switch(
        &self,
        ciphertext: &BgvCiphertext,
        chain: &BgvModulusChain,
    ) -> BgvCiphertext {
        let level = ciphertext.level;
        assert!(
            level < chain.last_level(),
            "cannot modulus-switch the final BGV level"
        );

        let q = chain.modulus(level);
        let q_next = chain.modulus(level + 1);

        assert_eq!(
            ciphertext.ciphertext.u.modulus(),
            q,
            "ciphertext u modulus does not match its BGV level"
        );
        assert_eq!(
            ciphertext.ciphertext.v.modulus(),
            q,
            "ciphertext v modulus does not match its BGV level"
        );

        // Internal RLWE form is (u, v) with phase v - u*s.
        // Standard BGV form is (c0, c1) = (v, -u).
        let c0_next = bgv_modswitch_poly(&ciphertext.ciphertext.v, q_next);
        let c1_next = bgv_modswitch_poly(&ciphertext.ciphertext.u.neg(), q_next);

        BgvCiphertext {
            ciphertext: Ciphertext {
                u: c1_next.neg(),
                v: c0_next,
            },
            level: level + 1,
        }
    }

    /// One leveled ciphertext-ciphertext multiplication:
    ///
    /// raw multiplication
    ///     -> relinearization
    ///     -> modulus switching
    ///
    /// The result is placed at the next chain level.
    pub fn mul_ciphertext_leveled(
        &self,
        lhs: &BgvCiphertext,
        rhs: &BgvCiphertext,
        relin_keys: &BgvRelinearizationKeyChain,
        chain: &BgvModulusChain,
    ) -> BgvCiphertext {
        assert_eq!(
            lhs.level,
            rhs.level,
            "ciphertexts must be at the same level"
        );

        let level = lhs.level;
        assert!(
            level < chain.last_level(),
            "no remaining modulus-switch level"
        );

        let key = relin_keys
            .keys
            .get(level)
            .expect("missing relinearization key for current level");

        let product = mul_raw_negacyclic(lhs, rhs);
        let relinearized = relinearize_negacyclic(&product, key, level);

        self.modulus_switch(&relinearized, chain)
    }

    /// Decrypt a ciphertext at any level using the corresponding reduced
    /// representation of the original secret key.
    pub fn decrypt_leveled(
        &self,
        sk: &BgvSecretKey,
        ciphertext: &BgvCiphertext,
        chain: &BgvModulusChain,
        n: usize,
    ) -> PolyRq {
        assert!(ciphertext.level < chain.len());
        let q = chain.modulus(ciphertext.level);

        assert_eq!(ciphertext.ciphertext.u.modulus(), q);
        assert_eq!(ciphertext.ciphertext.v.modulus(), q);

        let sk_level = reduce_secret_to_modulus(sk, q);
        let phase = ciphertext
            .ciphertext
            .v
            .sub(&ciphertext.ciphertext.u.mul_negacyclic(&sk_level.s));

        let mut plaintext_coeffs = Vec::with_capacity(n);
        for &coefficient in phase.coefficients().iter().take(n) {
            let centered = centered_i128(coefficient, q);
            plaintext_coeffs.push(
                centered.rem_euclid(PLAINTEXT_MODULUS as i128) as u64
            );
        }

        PolyRq::from_coeffs(
            &plaintext_coeffs,
            n,
            PLAINTEXT_MODULUS,
        )
    }
}

// ============================================================
// LEVELED BGV HELPERS
// ============================================================
//
// This module intentionally contains only the leveled prototype.
// The old single-modulus BGV-like API has been removed:
//
//   keygen()
//   encrypt()
//   decrypt()
//   generate_relinearization_key()
//   relinearize()
//   mul_ciphertext()
//
// They were useful during exploration, but are now obsolete because the
// actual direction of the project is leveled evaluation with a modulus
// chain and modulus switching.

fn num_gcd(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        let r = a % b;
        a = b;
        b = r;
    }
    a
}

fn mod_inverse(a: u64, modulus: u64) -> u64 {
    assert!(modulus > 1, "modulus must be > 1");
    assert_eq!(num_gcd(a, modulus), 1);

    let mut old_r = a as i128;
    let mut r = modulus as i128;
    let mut old_t = 1i128;
    let mut t = 0i128;

    while r != 0 {
        let quotient = old_r / r;

        let next_r = old_r - quotient * r;
        old_r = r;
        r = next_r;

        let next_t = old_t - quotient * t;
        old_t = t;
        t = next_t;
    }

    old_t.rem_euclid(modulus as i128) as u64
}

fn centered_i128(value: u64, modulus: u64) -> i128 {
    if value > modulus / 2 {
        value as i128 - modulus as i128
    } else {
        value as i128
    }
}

fn bgv_switch_coefficient(
    coefficient: u64,
    q: u64,
    q_next: u64,
) -> u64 {
    assert_eq!(q % q_next, 0);

    let d = q / q_next;
    assert_eq!(q % PLAINTEXT_MODULUS, 1);
    assert_eq!(q_next % PLAINTEXT_MODULUS, 1);

    let inverse_p = mod_inverse(PLAINTEXT_MODULUS, d);
    let centered = centered_i128(coefficient, q);

    // Choose k such that:
    //   centered + 17*k == 0 (mod d)
    // while keeping k balanced around zero.
    let mut k = (
        (((-centered).rem_euclid(d as i128) as u128)
            * inverse_p as u128)
            % d as u128
    ) as i128;

    if k > (d / 2) as i128 {
        k -= d as i128;
    }

    let corrected = centered + PLAINTEXT_MODULUS as i128 * k;
    assert_eq!(corrected.rem_euclid(d as i128), 0);

    (corrected / d as i128).rem_euclid(q_next as i128) as u64
}

fn bgv_modswitch_poly(
    polynomial: &PolyRq,
    q_next: u64,
) -> PolyRq {
    let q = polynomial.modulus();
    let n = polynomial.degree_bound();

    let coefficients = polynomial
        .coefficients()
        .iter()
        .take(n)
        .map(|&coefficient| bgv_switch_coefficient(coefficient, q, q_next))
        .collect::<Vec<_>>();

    PolyRq::from_coeffs(&coefficients, n, q_next)
}

fn reduce_secret_to_modulus(
    secret: &BgvSecretKey,
    modulus: u64,
) -> BgvSecretKey {
    let source_modulus = secret.s.modulus();
    let n = secret.s.degree_bound();

    let coefficients = secret
        .s
        .coefficients()
        .iter()
        .take(n)
        .map(|&coefficient| {
            centered_i128(coefficient, source_modulus)
                .rem_euclid(modulus as i128) as u64
        })
        .collect::<Vec<_>>();

    BgvSecretKey {
        s: PolyRq::from_coeffs(&coefficients, n, modulus),
    }
}

fn encrypt_negacyclic<R: RngCore>(
    rng: &mut R,
    pk: &BgvPublicKey,
    message: &PolyRq,
    n: usize,
) -> BgvCiphertext {
    let q = pk.a.modulus();

    let r = sample_small_poly(rng, n, q);
    let e1 = sample_small_poly(rng, n, q);
    let e2 = sample_small_poly(rng, n, q);

    let u = pk
        .a
        .mul_negacyclic(&r)
        .add(&e1.mul_scalar(PLAINTEXT_MODULUS));

    let message_q =
        PolyRq::from_coeffs(message.coefficients(), n, q);

    let v = pk
        .b
        .mul_negacyclic(&r)
        .add(&e2.mul_scalar(PLAINTEXT_MODULUS))
        .add(&message_q);

    BgvCiphertext {
        ciphertext: Ciphertext { u, v },
        level: 0,
    }
}

fn relin_key_negacyclic<R: RngCore>(
    rng: &mut R,
    secret: &BgvSecretKey,
    base_bits: usize,
) -> BgvRelinearizationKey {
    assert!(
        base_bits > 0 && base_bits < 64,
        "base_bits must be in 1..64"
    );

    let q = secret.s.modulus();
    let base = 1u64 << base_bits;
    let secret_squared =
        secret.s.mul_negacyclic(&secret.s);

    let mut entries = Vec::new();
    let mut gadget = 1u64;

    while gadget < q {
        let a =
            sample_uniform_poly(
                rng,
                secret.s.degree_bound(),
                q,
            );

        let e =
            sample_small_poly(
                rng,
                secret.s.degree_bound(),
                q,
            );

        let k1 = a
            .mul_negacyclic(&secret.s)
            .add(&e.mul_scalar(PLAINTEXT_MODULUS))
            .add(&secret_squared.mul_scalar(gadget));

        entries.push(BgvRelinearizationKeyEntry { k0: a, k1 });

        if gadget > q / base {
            break;
        }

        gadget *= base;
    }

    BgvRelinearizationKey {
        entries,
        base_bits,
    }
}

fn relinearize_negacyclic(
    product: &crate::core::rlwe_pke::MulCiphertext,
    key: &BgvRelinearizationKey,
    level: usize,
) -> BgvCiphertext {
    let digits =
        crate::core::rlwe_pre::decompose_poly(
            &product.c2,
            key.base_bits,
        );

    assert_eq!(
        digits.len(),
        key.entries.len(),
        "ciphertext decomposition and relinearization key lengths differ"
    );

    let mut u = product.c1.neg();
    let mut v = product.c0.clone();

    for (digit, entry) in digits.iter().zip(key.entries.iter()) {
        u = u.add(&digit.mul_negacyclic(&entry.k0));
        v = v.add(&digit.mul_negacyclic(&entry.k1));
    }

    BgvCiphertext {
        ciphertext: Ciphertext { u, v },
        level,
    }
}

fn mul_raw_negacyclic(
    lhs: &BgvCiphertext,
    rhs: &BgvCiphertext,
) -> crate::core::rlwe_pke::MulCiphertext {
    let c0 = lhs.ciphertext.v.mul_negacyclic(&rhs.ciphertext.v);

    let c1 = lhs
        .ciphertext
        .v
        .mul_negacyclic(&rhs.ciphertext.u)
        .add(
            &lhs
                .ciphertext
                .u
                .mul_negacyclic(&rhs.ciphertext.v),
        )
        .neg();

    let c2 = lhs.ciphertext.u.mul_negacyclic(&rhs.ciphertext.u);

    crate::core::rlwe_pke::MulCiphertext { c0, c1, c2 }
}
