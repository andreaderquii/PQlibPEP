use rand::RngCore;

use crate::algebra::ring::PolyRq;
use crate::algebra::sampling::sample_uniform_poly;
use crate::core::rlwr::synthesize;

pub struct RlwrPrfBase {
    pub s0: Vec<PolyRq>,
    pub s1: Vec<PolyRq>,
}

impl RlwrPrfBase {
    pub fn sample<R: RngCore>(
        rng: &mut R,
        n: usize,
        q: u64,
        input_len: usize,
    ) -> Self {
        let s0 = (0..input_len)
            .map(|_| sample_uniform_poly(rng, n, q))
            .collect();

        let s1 = (0..input_len)
            .map(|_| sample_uniform_poly(rng, n, q))
            .collect();

        Self { s0, s1 }
    }

    pub fn evaluate_at(
        &self,
        position: usize,
        bit: u8,
    ) -> &PolyRq {
        assert!(
            position < self.s0.len(),
            "PRF leaf position out of range"
        );

        match bit {
            0 => &self.s0[position],
            1 => &self.s1[position],
            _ => panic!("PRF input must contain only 0 or 1"),
        }
    }
}

pub struct RlwrPrf {
    pub base: RlwrPrfBase,
    pub moduli: Vec<u64>,
}

impl RlwrPrf {
    pub fn new(
        base: RlwrPrfBase,
        moduli: Vec<u64>,
    ) -> Self {
        assert!(
            moduli.len() >= 2,
            "the modulus chain must contain at least q_0 and q_1"
        );

        assert!(
            moduli.windows(2).all(|w| w[0] < w[1]),
            "BPR12 modulus chain must satisfy q_0 < q_1 < ... < q_d"
        );

        let highest_modulus =
            *moduli.last().unwrap();

        assert_eq!(
            base.s0.len(),
            base.s1.len(),
            "s0 and s1 must contain the same number of leaves"
        );

        assert!(
            base.s0.len().is_power_of_two(),
            "number of PRF leaves must be a power of two"
        );

        let expected_leaves =
            1usize << (moduli.len() - 1);

        assert_eq!(
            base.s0.len(),
            expected_leaves,
            "base key size must match the modulus-chain depth"
        );

        assert!(
            base.s0
                .iter()
                .all(|p| p.modulus() == highest_modulus),
            "all base polynomials in s0 must use q_d"
        );

        assert!(
            base.s1
                .iter()
                .all(|p| p.modulus() == highest_modulus),
            "all base polynomials in s1 must use q_d"
        );

        Self {
            base,
            moduli,
        }
    }

    pub fn evaluate(
        &self,
        input: &[u8],
    ) -> PolyRq {
        assert!(
            !input.is_empty(),
            "PRF input must not be empty"
        );

        assert!(
            input.len().is_power_of_two(),
            "PRF input length must be a power of two"
        );

        let depth =
            input.len().ilog2() as usize;

        assert!(
            depth < self.moduli.len(),
            "input is too deep for the provided modulus chain"
        );

        assert_eq!(
            self.base.s0.len(),
            input.len(),
            "PRF base key size must match the input length"
        );

        self.evaluate_recursive(
            input,
            depth,
            0,
        )
    }

    fn evaluate_recursive(
        &self,
        input: &[u8],
        level: usize,
        start_position: usize,
    ) -> PolyRq {
        if level == 0 {
            return self
                .base
                .evaluate_at(
                    start_position,
                    input[0],
                )
                .clone();
        }

        let midpoint =
            input.len() / 2;

        let left =
            self.evaluate_recursive(
                &input[..midpoint],
                level - 1,
                start_position,
            );

        let right =
            self.evaluate_recursive(
                &input[midpoint..],
                level - 1,
                start_position + midpoint,
            );

        let target_modulus =
            self.moduli[
                self.moduli.len() - 1 - level
            ];

        synthesize(
            &left,
            &right,
            target_modulus,
        )
    }
}