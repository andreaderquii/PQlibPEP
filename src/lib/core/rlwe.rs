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

        let as_prod = a.mul_negacyclic(&s);
        let b = as_prod.add(&e);

        Self {
            sk: SecretKey { s },
            pk: PublicKey { a, b },
            error: e,
        }
    }
}