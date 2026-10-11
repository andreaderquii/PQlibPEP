use rand::RngCore;

use crate::algebra::ring::PolyRq;
use crate::algebra::sampling::sample_small_poly;
use crate::core::rlwe::{PublicKey, SecretKey};

use crate::core::rlwe_pke::Ciphertext; //reencrypt()

pub struct ReEncryptionKey {
    pub entries: Vec<KeySwitchEntry>,
}

pub struct KeySwitchEntry {
    pub k0: PolyRq,
    pub k1: PolyRq,
}

/// Decomposes a polynomial coefficient-wise in base B = 2^base_bits.
///
/// For an input polynomial
/// ```text
/// u = sum_i u_i X^i
/// ```
/// the function returns polynomials d_0, ..., d_{L-1} such that
/// ```text
/// u = d_0 + B*d_1 + ... + B^(L-1)*d_(L-1)
/// ```
/// modulo q.
///
/// The decomposition is performed on the canonical coefficient
/// representatives in [0, q).
pub fn decompose_poly(
    input: &PolyRq,
    base_bits: usize,
) -> Vec<PolyRq> {
    assert!(base_bits > 0, "base_bits must be greater than zero");

    let base = 1u64
        .checked_shl(base_bits as u32)
        .expect("base_bits is too large");

    let q = input.modulus();
    let n = input.degree_bound();
    let coeffs = input.to_coeffs_vec();

    // Number of digits required to represent all coefficients in [0, q).
    let mut digits_count = 0usize;
    let mut modulus_bound = q;

    while modulus_bound > 1 {
        modulus_bound = (modulus_bound + base - 1) / base;
        digits_count += 1;
    }

    let mut digits = vec![vec![0u64; n]; digits_count];

    for coeff_index in 0..n {
        let mut value = coeffs[coeff_index];

        for digit_index in 0..digits_count {
            digits[digit_index][coeff_index] = value % base;
            value /= base;
        }

        debug_assert_eq!(value, 0);
    }

    digits
        .into_iter()
        .map(|coeffs| PolyRq::from_coeffs(&coeffs, n, q))
        .collect()
}

fn number_of_digits(q: u64, base: u64) -> usize {
    let mut count = 0usize;
    let mut value = q;

    while value > 1 {
        value = (value + base - 1) / base;
        count += 1;
    }

    count
}

pub fn generate_rekey<R: RngCore>(
    rng: &mut R,
    sk_a: &SecretKey,
    pk_b: &PublicKey,
    base_bits: usize,
) -> ReEncryptionKey {
    assert!(base_bits > 0, "base_bits must be greater than zero");

    let q = sk_a.s.modulus();
    let n = sk_a.s.degree_bound();

    assert_eq!(
        pk_b.a.modulus(),
        q,
        "Alice and Bob must use the same modulus"
    );

    assert_eq!(
        pk_b.b.modulus(),
        q,
        "Alice and Bob must use the same modulus"
    );

    assert_eq!(
        pk_b.a.degree_bound(),
        n,
        "Alice and Bob must use the same degree bound"
    );

    let base = 1u64
        .checked_shl(base_bits as u32)
        .expect("base_bits is too large");

    let digits_count = number_of_digits(q, base);

    let mut entries = Vec::with_capacity(digits_count);

    // Current power of B modulo q.
    //
    // i = 0 -> B^0 = 1
    // i = 1 -> B^1
    // i = 2 -> B^2
    // ...
    let mut power = 1u64;

    for _ in 0..digits_count {
        // Fresh small randomness for this switching entry.
        let rho = sample_small_poly(rng, n, q);
        let e0 = sample_small_poly(rng, n, q);
        let e1 = sample_small_poly(rng, n, q);

        // k0 = a_B * rho + e0
        let a_rho = pk_b.a.mul_ntt(&rho);
        let k0 = a_rho.add(&e0);

        // s_A * B^i
        let scaled_secret = sk_a.s.mul_scalar(power);

        // k1 = b_B * rho + e1 + s_A * B^i
        let b_rho = pk_b.b.mul_ntt(&rho);
        let k1 = b_rho
            .add(&e1)
            .add(&scaled_secret);

        entries.push(KeySwitchEntry { k0, k1 });

        // power <- power * B mod q
        power = ((power as u128 * base as u128) % q as u128) as u64;
    }

    ReEncryptionKey { entries }
}

pub fn reencrypt(
    ciphertext: &Ciphertext,
    rekey: &ReEncryptionKey,
    base_bits: usize,
) -> Ciphertext {
    assert!(
        base_bits > 0,
        "base_bits must be greater than zero"
    );

    let q = ciphertext.u.modulus();
    let n = ciphertext.u.degree_bound();

    assert_eq!(
        ciphertext.v.modulus(),
        q,
        "ciphertext components must use the same modulus"
    );

    assert_eq!(
        ciphertext.v.degree_bound(),
        n,
        "ciphertext components must use the same degree bound"
    );

    let digits = decompose_poly(
        &ciphertext.u,
        base_bits,
    );

    assert_eq!(
        digits.len(),
        rekey.entries.len(),
        "re-encryption key has an incompatible number of entries"
    );

    let zero_coeffs = vec![0u64; n];

    let mut sum_u_k0 = PolyRq::from_coeffs(
        &zero_coeffs,
        n,
        q,
    );

    let mut sum_u_k1 = PolyRq::from_coeffs(
        &zero_coeffs,
        n,
        q,
    );

    for (digit, entry) in
        digits.iter().zip(rekey.entries.iter())
    {
        //println!(
            //"[REENCRYPT] Processing digit {}",
            //digit_index
        //);

        let product_k0 = digit.mul_ntt(&entry.k0);
        let product_k1 = digit.mul_ntt(&entry.k1);

        sum_u_k0 = sum_u_k0.add(&product_k0);
        sum_u_k1 = sum_u_k1.add(&product_k1);
    }

    let u_prime = sum_u_k0.mul_scalar(q - 1);
    let v_prime = ciphertext.v.sub(&sum_u_k1);

    Ciphertext {
        u: u_prime,
        v: v_prime,
    }
}