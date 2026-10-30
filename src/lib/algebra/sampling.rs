use crate::algebra::ring::PolyRq;
use crate::parameters::rlwe_prototype as parameter_profile;
use rand::RngCore;

pub fn sample_uniform_poly<R: RngCore>(rng: &mut R, n: usize, q: u64) -> PolyRq {
    let coeffs: Vec<u64> = (0..n)
        .map(|_| (rng.next_u64() as u128 % q as u128) as u64)
        .collect();

    PolyRq::from_coeffs(&coeffs, n, q)
}

/// Samples the current centered-binomial RLWE noise/secret distribution.
/// The eta value is declared in [`crate::parameters::rlwe_prototype`].
pub fn sample_small_poly<R: RngCore>(rng: &mut R, n: usize, q: u64) -> PolyRq {
    let mut coeffs = Vec::with_capacity(n);
    let mut byte_buf = [0u8; 1];

    for _ in 0..n {
        rng.fill_bytes(&mut byte_buf);
        let b = byte_buf[0];

        let eta = parameter_profile::SMALL_NOISE_ETA;
        assert!(eta > 0 && 2 * eta <= 8, "CBD eta must fit the sampled byte");
        let pos: i32 = (0..eta).map(|i| ((b >> i) & 1) as i32).sum();
        let neg: i32 = (0..eta).map(|i| ((b >> (eta + i)) & 1) as i32).sum();

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
