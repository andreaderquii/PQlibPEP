use rand::RngCore;

use crate::algebra::ring::{PolyRq, Q};
use crate::algebra::sampling::sample_small_poly;
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
