/*rlwe_pke.rs
    RLWE encryption/decryption
    + addition
    + raw multiplication
    + relinearization
        ↓
    reference/prototype PKE
*/

use rand::RngCore;
use crate::algebra::ring::{PolyRq, Q};
use crate::algebra::sampling::{
    sample_small_poly,
    sample_uniform_poly,
};
use crate::core::rlwe::{PublicKey, SecretKey};

/// Ciphertext della RLWE-PKE:
///
/// c = (u, v)
///
/// u = a*r + e1
/// v = b*r + e2 + Delta*m
pub struct Ciphertext {
    pub u: PolyRq,
    pub v: PolyRq,
}

pub struct MulCiphertext {
    pub c0: PolyRq,
    pub c1: PolyRq,
    pub c2: PolyRq,
}

pub struct RelinearizationKeyEntry {
    pub k0: PolyRq,
    pub k1: PolyRq,
}

pub struct RelinearizationKey {
    pub entries: Vec<RelinearizationKeyEntry>,
    pub base_bits: usize,
}




/// Encoding del messaggio:
///
/// 0 -> 0
/// 1 -> Delta
///
/// Usiamo q/2 come distanza tra i due simboli.
fn delta() -> u64 {
    Q / 2
}

/// Convert a binary message into a polynomial in Z_q[X]/(X^n + 1).
/// Each byte must be 0 or 1.
fn encode_message(message: &[u8], n: usize) -> PolyRq {
    assert!(
        message.len() <= n,
        "message length must be <= polynomial degree"
    );

    let d = delta();
    let mut coeffs = vec![0u64; n];
    for (i, &bit) in message.iter().enumerate() {
        assert!(bit == 0 || bit == 1, "message must contain only 0/1 values");
        coeffs[i] = if bit == 0 { 0 } else { d };
    }
    PolyRq::from_coeffs(&coeffs, n, Q)
}

/// Encrypt a binary message using the RLWE public key.
/// r, e1, e2 <- CBD_2
/// u = a*r + e1
/// v = b*r + e2 + Delta*m
pub fn encrypt<R: RngCore>(
    rng: &mut R,
    pk: &PublicKey, //pk = (a, b)       b = a * s + e
    message: &[u8],
    n: usize,
) -> Ciphertext {
    assert!(
        message.len() <= n,
        "message length must be <= polynomial degree"
    );

    // Fresh ephemeral randomness and noise.
    let r = sample_small_poly(rng, n, Q); //nonce for encryption
    let e1 = sample_small_poly(rng, n, Q); //for u
    let e2 = sample_small_poly(rng, n, Q); //for v

    // u = a*r + e1
    let ar = pk.a.mul_ntt(&r);
    let u = ar.add(&e1);

    // v = b*r + e2 + Delta*m
    let br = pk.b.mul_ntt(&r);
    let encoded_message = encode_message(message, n);

    let v = br.add(&e2).add(&encoded_message);

    Ciphertext { u, v }
}

/// Converts a coefficient from its representation in Z_q
/// to a centered integer.
///
/// Example:
///
/// 0       -> 0
/// 1       -> 1
/// Q - 1   -> -1
/// Q - 2   -> -2
fn center_mod_q(x: u64) -> i64 {
    let x = x % Q;

    if x <= Q / 2 {
        x as i64
    } else {
        x as i64 - Q as i64
    }
}

/// Decode one coefficient into a message bit.
///
/// Values close to 0  -> 0
/// Values close to q/2 -> 1
fn decode_coefficient(x: u64) -> u8 {
    let d = delta();

    // Distance from x to 0 modulo Q.
    let distance_to_zero = center_mod_q(x).abs();

    // Distance from x to Delta modulo Q.
    let distance_to_one = center_mod_q((x + Q - d) % Q).abs();

    if distance_to_one < distance_to_zero {
        1
    } else {
        0
    }
}

/// Decrypt a ciphertext using the RLWE secret key.
///
/// x = v - u*s
///
/// Ideally:
///
/// x = Delta*m + noise
pub fn decrypt(sk: &SecretKey, ciphertext: &Ciphertext, n: usize, message_len: usize) -> Vec<u8> {
    assert!(
        message_len <= n,
        "message length must be <= polynomial degree"
    );

    // u*s
    let us = ciphertext.u.mul_ntt(&sk.s);

    // v - u*s
    let decoded_poly = ciphertext.v.sub(&us);

    // DensePolynomial removes trailing zero coefficients,
    // so restore the expected fixed length.
    let mut coeffs = decoded_poly.to_coeffs_vec();
    coeffs.resize(n, 0);

    // Decode only the number of coefficients belonging to
    // the original message.
    coeffs[..message_len]
        .iter()
        .map(|&coeff| decode_coefficient(coeff))
        .collect()
}

    pub fn generate_relinearization_key<R: RngCore>(
    rng: &mut R,
    sk: &SecretKey,
    base_bits: usize,
) -> RelinearizationKey {
    assert!(
        base_bits > 0,
        "base_bits must be greater than zero"
    );

    let q =
        sk.s.modulus();

    let base =
        1u64
            .checked_shl(base_bits as u32)
            .expect(
                "base_bits is too large"
            );

    let mut entries =
        Vec::new();

    let secret_squared =
        sk.s.mul_ntt(&sk.s);

    let mut gadget =
        1u64;

    while gadget < q {
        let a =
            sample_uniform_poly(
                rng,
                sk.s.degree_bound(),
                q,
            );

        let e =
            sample_small_poly(
                rng,
                sk.s.degree_bound(),
                q,
            );

        // k1 = a*s + e + gadget*s^2
        let as_product =
            a.mul_ntt(&sk.s);

        let gadget_s2 =
            secret_squared.mul_scalar(
                gadget,
            );

        let k1 =
            as_product
                .add(&e)
                .add(&gadget_s2);

        entries.push(
            RelinearizationKeyEntry {
                k0: a,
                k1,
            }
        );

        if gadget > q / base {
            break;
        }

        gadget *= base;
    }

    RelinearizationKey {
        entries,
        base_bits,
    }
}    

    pub fn relinearize(
        product: &MulCiphertext,
        key: &RelinearizationKey,
    ) -> Ciphertext {
        assert!(
            !key.entries.is_empty(),
            "relinearization key must not be empty"
        );

        let digits = crate::core::rlwe_pre::decompose_poly(
            &product.c2,
            key.base_bits,
        );

        assert_eq!(
            digits.len(),
            key.entries.len(),
            "ciphertext decomposition and relinearization key have different lengths"
        );

        // We want:
        //
        // v' - u'*s
        //
        // = c0 + c1*s + c2*s^2
        //
        // Therefore u' starts as -c1.
        let mut u = product.c1.neg();
        let mut v = product.c0.clone();

        for (digit, entry) in digits.iter().zip(key.entries.iter()) {
            let digit_k0 = digit.mul_ntt(&entry.k0);
            let digit_k1 = digit.mul_ntt(&entry.k1);

            u = u.add(&digit_k0);
            v = v.add(&digit_k1);
        }

        Ciphertext {
            u,
            v,
        }
    }







impl Ciphertext {
    pub fn add(&self, other: &Ciphertext) -> Ciphertext {
        assert_eq!(
            self.u.modulus(),
            other.u.modulus(),
            "ciphertexts must use the same modulus"
        );

        assert_eq!(
            self.u.degree_bound(),
            other.u.degree_bound(),
            "ciphertexts must use the same degree"
        );

        Ciphertext {
            u: self.u.add(&other.u),
            v: self.v.add(&other.v),
        }
    }

    pub fn mul_scalar(&self, scalar: u64) -> Ciphertext {
        Ciphertext {
            u: self.u.mul_scalar(scalar),
            v: self.v.mul_scalar(scalar),
        }
    }

    pub fn mul_raw(&self, other: &Ciphertext) -> MulCiphertext {
        let c0 = self.v.mul_ntt(&other.v);

        let c1 = self.v
            .mul_ntt(&other.u)
            .add(&self.u.mul_ntt(&other.v))
            .neg();

        let c2 = self.u.mul_ntt(&other.u);

        MulCiphertext {
            c0,
            c1,
            c2,
        }
    }
}
//////////////////////////////////////////////////////////////////////////////// binary function end


//////////////////////////////////////////////////////////////////////////////// generalization of encrypt() and decrypt() from binary to poly representation
/// Encrypts a polynomial plaintext M in R_q.
///
/// Each plaintext coefficient m in {0, ..., p-1} is encoded as:
///     m * Delta
/// where Delta = floor(q / p).
///
/// The ciphertext is:
///     u = a*r + e1
///     v = b*r + e2 + Delta*M
pub fn encrypt_poly<R: rand_core::RngCore>(
    rng: &mut R,
    pk: &PublicKey,
    message: &PolyRq,
    n: usize,
) -> Ciphertext {
    assert_eq!(message.degree_bound(), n);
    assert_eq!(message.modulus(), pk.a.modulus());
    assert_eq!(pk.a.degree_bound(), n);
    assert_eq!(pk.b.degree_bound(), n);

    const PLAINTEXT_MODULUS: u64 = 17;

    let q = pk.a.modulus();
    let delta = q / PLAINTEXT_MODULUS;

    // Random ephemeral secret and encryption noise.
    let r = sample_small_poly(rng, n, q);
    let e1 = sample_small_poly(rng, n, q);
    let e2 = sample_small_poly(rng, n, q);

    // u = a*r + e1
    let u = pk.a.mul_ntt(&r).add(&e1);

    // Encode plaintext polynomial:
    // Delta * M
    let encoded_message = message.mul_scalar(delta);

    // v = b*r + e2 + Delta*M
    let v = pk
        .b
        .mul_ntt(&r)
        .add(&e2)
        .add(&encoded_message);

    Ciphertext { u, v }
}

/// Decrypts a polynomial plaintext from an RLWE ciphertext.
///
/// The decrypted polynomial is:
///     v - u*s = Delta*M + noise
///
/// Each coefficient is then decoded back to {0, ..., 16}.
pub fn decrypt_poly(
    sk: &SecretKey,
    ciphertext: &Ciphertext,
    n: usize,
) -> PolyRq {
    const PLAINTEXT_MODULUS: u64 = 17;

    let q = sk.s.modulus();

    assert_eq!(sk.s.degree_bound(), n);
    assert_eq!(ciphertext.u.degree_bound(), n);
    assert_eq!(ciphertext.v.degree_bound(), n);
    assert_eq!(ciphertext.u.modulus(), q);
    assert_eq!(ciphertext.v.modulus(), q);

    let decrypted = ciphertext
        .v
        .sub(&ciphertext.u.mul_ntt(&sk.s));

    let coeffs = decrypted.coefficients();

    let mut message_coeffs = Vec::with_capacity(n);

    for &c in coeffs.iter().take(n) {
        // Convert coefficient to centered representative in
        // [-q/2, q/2).
        // Use i128 throughout: `q` is u64 and may exceed i64::MAX.
        let centered: i128 = if c > q / 2 {
            c as i128 - q as i128
        } else {
            c as i128
        };

        // Decode the nearest plaintext level:
        //
        // centered ~= m * q / p
        //
        // => m ~= centered * p / q
        let numerator = centered * PLAINTEXT_MODULUS as i128;

        let rounded = if numerator >= 0 {
            (numerator + (q as i128 / 2)) / q as i128
        } else {
            (numerator - (q as i128 / 2)) / q as i128
        };

        let m = rounded.rem_euclid(PLAINTEXT_MODULUS as i128) as u64;
        message_coeffs.push(m);
    }

    PolyRq::from_coeffs(&message_coeffs, n, q)
}

/// Compatibility wrapper for the HE polynomial API.
///
/// The plaintext coefficients must belong to `{0, ..., 16}`. This wrapper
/// converts the input into the ciphertext modulus and then delegates to the
/// Delta-scaled encoding used by `encrypt_poly`. Keeping a second unscaled
/// encoding here would make ordinary RLWE noise incompatible with reduction
/// modulo 17.
pub fn encrypt_he_poly<R: rand_core::RngCore>(
    rng: &mut R,
    pk: &PublicKey,
    message: &PolyRq,
    n: usize,
) -> Ciphertext {
    assert_eq!(message.degree_bound(), n, "message degree must match n");
    assert_eq!(pk.a.degree_bound(), n, "public key degree must match n");
    assert_eq!(pk.b.degree_bound(), n, "public key degree must match n");

    let q = pk.a.modulus();
    let plaintext_coeffs: Vec<u64> = message
        .coefficients()
        .iter()
        .take(n)
        .map(|&coefficient| {
            assert!(coefficient < 17, "HE plaintext coefficient must be in 0..=16");
            coefficient
        })
        .collect();
    let message_q = PolyRq::from_coeffs(&plaintext_coeffs, n, q);
    encrypt_poly(rng, pk, &message_q, n)
}

/// Decrypts a ciphertext created by `encrypt_he_poly()`.
///
/// The result is represented in `Z_17[X]/(X^n + 1)`. This is intentionally a
/// thin wrapper around the matching Delta-scaled decoder.
pub fn decrypt_he_poly(
    sk: &SecretKey,
    ciphertext: &Ciphertext,
    n: usize,
) -> PolyRq {
    let decoded = decrypt_poly(sk, ciphertext, n);
    PolyRq::from_coeffs(decoded.coefficients(), n, 17)
}
