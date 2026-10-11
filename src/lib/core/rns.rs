use crate::algebra::ring::PolyRq;

// Plaintext modulus used by the current BGV prototype.
pub const RNS_PLAINTEXT_MODULUS: u64 = 17;

// Ring dimension used by the current project prototype.
pub const RNS_RING_DIMENSION: usize = 256;

// RNS primes.
//
// Requirements for N = 256:
//
//     q_i ≡ 1 mod 2N
//     q_i ≡ 1 mod 17
//
// Since 2N = 512, every modulus satisfies:
//
//     q_i ≡ 1 mod 512
//     q_i ≡ 1 mod 17
//
// Therefore each modulus is also:
//
//     q_i ≡ 1 mod 8704
//
// These moduli are intended for the first RNS arithmetic
// prototype. They are NOT cryptographic security parameters.
pub const DEFAULT_RNS_MODULI: [u64; 9] = [
    8_416_769,
    8_434_177,
    8_573_441,
    8_599_553,
    8_782_337,
    8_825_857,
    8_834_561,
    8_860_673,
    8_904_193,
];

// Collection of pairwise-coprime RNS moduli.
pub struct RnsModulusChain {
    pub moduli: Vec<u64>,
    pub degree: usize,
}

impl RnsModulusChain {
    pub fn new(
        moduli: Vec<u64>,
        degree: usize,
    ) -> Self {
        assert!(
            !moduli.is_empty(),
            "RNS modulus chain must not be empty"
        );

        assert!(
            degree > 0,
            "RNS polynomial degree must be positive"
        );

        for &q in &moduli {
            assert!(
                q > 2,
                "RNS modulus must be greater than 2"
            );

            assert_eq!(
                q % (2 * degree as u64),
                1,
                "each RNS modulus must satisfy q ≡ 1 mod 2N"
            );

            assert_eq!(
                q % RNS_PLAINTEXT_MODULUS,
                1,
                "each RNS modulus must satisfy q ≡ 1 mod plaintext modulus"
            );
        }

        for i in 0..moduli.len() {
            for j in (i + 1)..moduli.len() {
                assert_ne!(
                    moduli[i],
                    moduli[j],
                    "RNS moduli must be distinct"
                );
            }
        }

        Self {
            moduli,
            degree,
        }
    }

    pub fn default_for_degree(
        degree: usize,
    ) -> Self {
        Self::new(
            DEFAULT_RNS_MODULI.to_vec(),
            degree,
        )
    }

    pub fn len(&self) -> usize {
        self.moduli.len()
    }

    pub fn is_empty(&self) -> bool {
        self.moduli.is_empty()
    }

    pub fn modulus(
        &self,
        index: usize,
    ) -> u64 {
        self.moduli[index]
    }
}

impl Default for RnsModulusChain {
    fn default() -> Self {
        Self::default_for_degree(
            RNS_RING_DIMENSION,
        )
    }
}

// A polynomial represented in RNS/CRT form.
//
// One logical polynomial is represented by one PolyRq
// for every RNS modulus:
//
//     f
//       -> f mod q_0
//       -> f mod q_1
//       -> ...
//       -> f mod q_{k-1}
//
// All residues represent the same polynomial over the
// product modulus.
#[derive(Clone)]
pub struct RnsPoly {
    pub residues: Vec<PolyRq>,
    pub degree: usize,
}

impl RnsPoly {
    // Creates an RNS polynomial from ordinary integer
    // coefficients.
    //
    // The input coefficients are independently reduced
    // modulo every RNS modulus.
    pub fn from_coeffs(
        coefficients: &[u64],
        chain: &RnsModulusChain,
    ) -> Self {
        assert!(
            coefficients.len() <= chain.degree,
            "too many polynomial coefficients"
        );

        let mut padded =
            vec![0u64; chain.degree];

        for (i, &coefficient)
            in coefficients.iter().enumerate()
        {
            padded[i] = coefficient;
        }

        let residues = chain
            .moduli
            .iter()
            .map(|&q| {
                PolyRq::from_coeffs(
                    &padded,
                    chain.degree,
                    q,
                )
            })
            .collect();

        Self {
            residues,
            degree: chain.degree,
        }
    }

    // Creates a constant polynomial.
    pub fn constant(
        value: u64,
        chain: &RnsModulusChain,
    ) -> Self {
        let mut coefficients =
            vec![0u64; chain.degree];

        coefficients[0] = value;

        Self::from_coeffs(
            &coefficients,
            chain,
        )
    }

    // Creates the zero polynomial.
    pub fn zero(
        chain: &RnsModulusChain,
    ) -> Self {
        Self::from_coeffs(
            &vec![0u64; chain.degree],
            chain,
        )
    }

    // Creates the multiplicative identity.
    pub fn one(
        chain: &RnsModulusChain,
    ) -> Self {
        Self::constant(1, chain)
    }

    fn assert_compatible(
        &self,
        other: &Self,
    ) {
        assert_eq!(
            self.degree,
            other.degree,
            "RNS polynomials must use the same degree"
        );

        assert_eq!(
            self.residues.len(),
            other.residues.len(),
            "RNS polynomials must use the same number of residues"
        );

        for (lhs, rhs) in self
            .residues
            .iter()
            .zip(other.residues.iter())
        {
            assert_eq!(
                lhs.modulus(),
                rhs.modulus(),
                "RNS residue moduli must match"
            );

            assert_eq!(
                lhs.degree_bound(),
                rhs.degree_bound(),
                "RNS residue degrees must match"
            );
        }
    }

    // Coefficient-wise addition in RNS.
    pub fn add(
        &self,
        other: &Self,
    ) -> Self {
        self.assert_compatible(other);

        let residues = self
            .residues
            .iter()
            .zip(other.residues.iter())
            .map(|(lhs, rhs)| lhs.add(rhs))
            .collect();

        Self {
            residues,
            degree: self.degree,
        }
    }

    // Coefficient-wise subtraction in RNS.
    pub fn sub(
        &self,
        other: &Self,
    ) -> Self {
        self.assert_compatible(other);

        let residues = self
            .residues
            .iter()
            .zip(other.residues.iter())
            .map(|(lhs, rhs)| lhs.sub(rhs))
            .collect();

        Self {
            residues,
            degree: self.degree,
        }
    }

    // Negation in RNS.
    pub fn neg(&self) -> Self {
        let residues = self
            .residues
            .iter()
            .map(|poly| poly.neg())
            .collect();

        Self {
            residues,
            degree: self.degree,
        }
    }

    // Scalar multiplication in RNS.
    pub fn mul_scalar(
        &self,
        scalar: u64,
    ) -> Self {
        let residues = self
            .residues
            .iter()
            .map(|poly| poly.mul_scalar(scalar))
            .collect();

        Self {
            residues,
            degree: self.degree,
        }
    }

    // Negacyclic polynomial multiplication in RNS.
    //
    // Each residue is multiplied independently.
    //
    // Since the chosen RNS moduli are NTT-friendly,
    // multiplication uses the existing NTT implementation.
    pub fn mul_negacyclic(
        &self,
        other: &Self,
    ) -> Self {
        self.assert_compatible(other);

        let residues = self
            .residues
            .iter()
            .zip(other.residues.iter())
            .map(|(lhs, rhs)| {
                lhs.mul_ntt(rhs)
            })
            .collect();

        Self {
            residues,
            degree: self.degree,
        }
    }

    // Returns one residue polynomial.
    pub fn residue(
        &self,
        index: usize,
    ) -> &PolyRq {
        &self.residues[index]
    }

    // Number of RNS residues.
    pub fn residue_count(&self) -> usize {
        self.residues.len()
    }

    // Checks that every residue agrees with the given
    // ordinary coefficient vector modulo its modulus.
    pub fn assert_matches_coefficients(
        &self,
        coefficients: &[u64],
    ) {
        assert!(
            coefficients.len() <= self.degree,
            "too many coefficients"
        );

        for residue in &self.residues {
            let q = residue.modulus();

            let actual =
                residue.coefficients();

            for i in 0..self.degree {
                let expected =
                    if i < coefficients.len() {
                        coefficients[i] % q
                    } else {
                        0
                    };

                assert_eq!(
                    actual[i],
                    expected,
                    "RNS residue mismatch at coefficient {} modulo {}",
                    i,
                    q
                );
            }
        }
    }
}