use rand::RngCore;
use crate::algebra::ring::PolyRq;

pub fn sample_uniform_poly<R: RngCore>(
    rng: &mut R,
    n: usize,
    q: u64,
) -> PolyRq {
    let coeffs: Vec<u64> = (0..n)
        .map(|_| (rng.next_u64() as u128 % q as u128) as u64)
        .collect();

    PolyRq::from_coeffs(&coeffs, n, q)
}

pub fn sample_small_poly<R: RngCore>(
    rng: &mut R,
    n: usize,
    q: u64,
) -> PolyRq {
    let mut coeffs = Vec::with_capacity(n);
    let mut byte_buf = [0u8; 1];

    for _ in 0..n {
        rng.fill_bytes(&mut byte_buf);
        let b = byte_buf[0];

        let a0 = (b >> 0) & 1;
        let a1 = (b >> 1) & 1;
        let b0 = (b >> 2) & 1;
        let b1 = (b >> 3) & 1;

        let pos = (a0 + a1) as i32;
        let neg = (b0 + b1) as i32;

        let val = pos - neg;

        let coeff = if val < 0 {
            (q as i64 + val as i64) as u64
        } else {
            val as u64
        };

        coeffs.push(coeff);
    }

    PolyRq::from_coeffs(&coeffs, n, q)
}