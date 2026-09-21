use rand::RngCore;

use crate::algebra::ring::PolyRq;
use crate::algebra::sampling::sample_uniform_poly;
use crate::core::rlwr::synthesize;

pub struct RlwrPrfBase {
    pub s0: PolyRq,
    pub s1: PolyRq,
}

impl RlwrPrfBase {
    pub fn sample<R: RngCore>(
        rng: &mut R,
        n: usize,
        q: u64,
    ) -> Self {
        let s0 = sample_uniform_poly(rng, n, q);
        let s1 = sample_uniform_poly(rng, n, q);

        Self { s0, s1 }
    }

    pub fn evaluate(&self, bit: u8) -> &PolyRq {
        match bit {
            0 => &self.s0,
            1 => &self.s1,
            _ => panic!("RF^(0) input must be either 0 or 1"),
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

        let highest_modulus = *moduli.last().unwrap();

        assert_eq!(
            base.s0.modulus(),
            highest_modulus,
            "base modulus must equal the highest modulus q_d"
        );

        assert_eq!(
            base.s1.modulus(),
            highest_modulus,
            "base modulus must equal the highest modulus q_d"
        );

        Self {
            base,
            moduli,
        }
    }

    pub fn evaluate(&self, input: &[u8]) -> PolyRq {
        assert!(
            !input.is_empty(),
            "PRF input must not be empty"
        );

        assert!(
            input.len().is_power_of_two(),
            "PRF input length must be a power of two"
        );

        let depth = input.len().ilog2() as usize;

        assert!(
            depth < self.moduli.len(),
            "input is too deep for the provided modulus chain"
        );

        self.evaluate_recursive(input, depth)
    }

    fn evaluate_recursive(
        &self,
        input: &[u8],
        level: usize,
    ) -> PolyRq {
        if level == 0 {
            return self.base.evaluate(input[0]).clone();
        }

        let midpoint = input.len() / 2;

        let left = self.evaluate_recursive(
            &input[..midpoint],
            level - 1,
        );

        let right = self.evaluate_recursive(
            &input[midpoint..],
            level - 1,
        );

        // The recursion starts at q_d and descends one modulus per level until q_0.:
        // q_d -> q_(d-1) -> ... -> q_0
        let target_modulus =
            self.moduli[self.moduli.len() - 1 - level];
        synthesize(
            &left,
            &right,
            target_modulus,
        )
    }
}