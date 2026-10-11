use rand::RngCore;

use crate::algebra::ring::{PolyRq, Q};
use crate::algebra::sampling::{sample_small_poly, sample_uniform_poly};

pub struct SecretKey {
    pub s: PolyRq,
}

pub struct PublicKey {
    pub a: PolyRq,
    pub b: PolyRq,
}

pub struct KeyGenResult {
    pub sk: SecretKey,
    pub pk: PublicKey,
    pub error: PolyRq,
}

impl KeyGenResult {
    pub fn keygen<R: RngCore>(rng: &mut R, n: usize) -> Self {
        let a = sample_uniform_poly(rng, n, Q);
        let s = sample_small_poly(rng, n, Q);
        let e = sample_small_poly(rng, n, Q);

        // Use the same NTT multiplication path as RLWE encryption
        // and decryption.
        let as_prod = a.mul_ntt(&s);
        let b = as_prod.add(&e);

        Self {
            sk: SecretKey { s },
            pk: PublicKey { a, b },
            error: e,
        }
    }

    pub fn keygen_with_modulus<R: RngCore>(
        rng: &mut R,
        n: usize,
        q: u64,
    ) -> Self {
        assert!(
            q >= 2,
            "RLWE modulus must be at least 2"
        );

        let a =
            sample_uniform_poly(
                rng,
                n,
                q,
            );

        let s =
            sample_small_poly(
                rng,
                n,
                q,
            );

        let e =
            sample_small_poly(
                rng,
                n,
                q,
            );

        let as_prod =
            a.mul_negacyclic(&s);

        let b =
            as_prod.add(&e);

        Self {
            sk: SecretKey { s },
            pk: PublicKey { a, b },
            error: e,
        }
    }
}