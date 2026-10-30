//! Reference implementation of the depth-1 LWR PRF from Section 5 of
//! "Fast Homomorphic Evaluation of LWR-based PRFs".
//!
//! This module deliberately implements the *cleartext definition* first. It is
//! the reference against which the TFHE programmable-bootstrap implementation
//! must be checked. It does not perform homomorphic evaluation yet.
//!
//! IMPORTANT: the paper provides an efficient depth-1 evaluation of this PRF,
//! not the cross-key conversion law required by PEP RS2. The LWR rounding is
//! generally many-to-one, so this API must not be presented as RS2-capable.
//!
//! The paper's modified PRF is not the same function as `rlwr_prf::RlwrPrf`:
//! it hashes a public input to a vector in Z_(2N), takes an inner product with
//! a binary secret vector, and applies the paper's signed floor-rounding map.

use crate::parameters::fast_lwr_prf as parameter_profile;
use core::fmt;

use rand::RngCore;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

const HASH_DOMAIN: &[u8] = parameter_profile::HASH_DOMAIN;

/// Parameters for the modified LWR PRF in the paper's Section 5.
///
/// `lwr_dimension` is the length of the secret vector; `ring_dimension` is N
/// from the paper (and must be a power of two); `output_modulus` is p.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "pep-role-lab", derive(serde::Serialize, serde::Deserialize))]
pub struct FastLwrPrfParameters {
    pub lwr_dimension: usize,
    pub ring_dimension: usize,
    pub output_modulus: u64,
}

impl FastLwrPrfParameters {
    /// The paper's practical baseline for its optimized 5-bit-output setting:
    /// N = 2048, p = 32, and LWR dimension n = 445.
    ///
    /// The paper reports a lattice-estimator-based 128-bit security estimate
    /// for this setting; that estimate is not independently re-established by
    /// this library. Re-run a current estimator before treating it as a
    /// production parameter set.
    pub const fn paper_default() -> Self {
        Self {
            lwr_dimension: parameter_profile::LWR_DIMENSION,
            ring_dimension: parameter_profile::RING_DIMENSION,
            output_modulus: parameter_profile::OUTPUT_MODULUS,
        }
    }

    pub fn validate(self) -> Result<(), FastLwrPrfError> {
        if self.lwr_dimension == 0 {
            return Err(FastLwrPrfError::ZeroDimension);
        }
        if self.ring_dimension < 2 || !self.ring_dimension.is_power_of_two() {
            return Err(FastLwrPrfError::RingDimensionNotPowerOfTwo);
        }
        let n = u64::try_from(self.ring_dimension)
            .map_err(|_| FastLwrPrfError::RingDimensionTooLarge)?;
        if n.checked_mul(2).is_none() {
            return Err(FastLwrPrfError::RingDimensionTooLarge);
        }
        // Section 5 uses power-of-two moduli with p < N. The TFHE output
        // decoder relies on p being a power of two.
        if self.output_modulus < 2
            || self.output_modulus >= n
            || !self.output_modulus.is_power_of_two()
            || n % self.output_modulus != 0
        {
            return Err(FastLwrPrfError::InvalidOutputModulus);
        }
        Ok(())
    }

    #[inline]
    fn q(self) -> u64 {
        // `validate` guarantees this multiplication cannot overflow.
        if self.ring_dimension == parameter_profile::RING_DIMENSION {
            parameter_profile::LWR_MODULUS
        } else {
            (self.ring_dimension as u64) * 2
        }
    }
}

impl Default for FastLwrPrfParameters {
    fn default() -> Self {
        Self::paper_default()
    }
}

/// Error cases raised while constructing the cleartext reference PRF.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FastLwrPrfError {
    ZeroDimension,
    RingDimensionNotPowerOfTwo,
    RingDimensionTooLarge,
    InvalidOutputModulus,
    WrongKeyLength { expected: usize, actual: usize },
    NonBinarySecretKey { index: usize, value: u8 },
}

impl fmt::Display for FastLwrPrfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroDimension => write!(f, "LWR dimension must be non-zero"),
            Self::RingDimensionNotPowerOfTwo => {
                write!(f, "ring dimension N must be a power of two and at least 2")
            }
            Self::RingDimensionTooLarge => write!(f, "ring dimension is too large"),
            Self::InvalidOutputModulus => {
                write!(f, "output modulus p must be a power of two with 2 <= p < N")
            }
            Self::WrongKeyLength { expected, actual } => write!(
                f,
                "secret-key length mismatch: expected {expected} bits, got {actual}"
            ),
            Self::NonBinarySecretKey { index, value } => write!(
                f,
                "secret-key entry at index {index} is {value}, but entries must be 0 or 1"
            ),
        }
    }
}

impl std::error::Error for FastLwrPrfError {}

/// Binary secret vector `s` for the modified LWR PRF.
///
/// The secret bits are intentionally not public and the `Debug` implementation
/// redacts them. A caller must provide a cryptographically secure RNG when
/// generating a key for real use.
#[derive(Clone)]
pub struct FastLwrPrfSecretKey {
    parameters: FastLwrPrfParameters,
    bits: Vec<u8>,
}

impl fmt::Debug for FastLwrPrfSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FastLwrPrfSecretKey")
            .field("parameters", &self.parameters)
            .field("bit_count", &self.bits.len())
            .field("bits", &"[REDACTED]")
            .finish()
    }
}

impl FastLwrPrfSecretKey {
    /// Samples a uniform binary secret vector using the caller-supplied RNG.
    pub fn generate<R: RngCore + ?Sized>(
        parameters: FastLwrPrfParameters,
        rng: &mut R,
    ) -> Result<Self, FastLwrPrfError> {
        parameters.validate()?;
        let bits = (0..parameters.lwr_dimension)
            .map(|_| (rng.next_u32() & 1) as u8)
            .collect();
        Ok(Self { parameters, bits })
    }

    /// Builds a key from bits, mainly useful for importing a key or writing
    /// deterministic tests. Keep the supplied bits secret.
    pub fn from_bits(
        parameters: FastLwrPrfParameters,
        bits: Vec<u8>,
    ) -> Result<Self, FastLwrPrfError> {
        parameters.validate()?;
        if bits.len() != parameters.lwr_dimension {
            return Err(FastLwrPrfError::WrongKeyLength {
                expected: parameters.lwr_dimension,
                actual: bits.len(),
            });
        }
        for (index, &value) in bits.iter().enumerate() {
            if value > 1 {
                return Err(FastLwrPrfError::NonBinarySecretKey { index, value });
            }
        }
        Ok(Self { parameters, bits })
    }

    pub fn parameters(&self) -> FastLwrPrfParameters {
        self.parameters
    }

    /// Internal read-only access for constructing the TFHE evaluation key.
    /// The bits remain private to the crate and are never exposed by Debug.
    #[cfg(feature = "fast-prf-tfhe")]
    pub(super) fn bits(&self) -> &[u8] {
        &self.bits
    }
}

/// Cleartext reference evaluator for the paper's modified LWR PRF.
///
/// In the intended homomorphic setting, `input` is public and the secret key
/// is encrypted in a TFHE evaluation key. This type deliberately keeps the
/// cleartext reference separate from the existing encrypted-input BPR12 API.
#[derive(Clone)]
pub struct FastLwrPrf {
    secret_key: FastLwrPrfSecretKey,
}

impl FastLwrPrf {
    pub fn new(secret_key: FastLwrPrfSecretKey) -> Self {
        Self { secret_key }
    }

    pub fn parameters(&self) -> FastLwrPrfParameters {
        self.secret_key.parameters
    }

    /// Evaluates the first component of the paper's vector PRF, H(x, 1).
    /// By construction, this is exactly `evaluate_many(input, 1)[0]`.
    pub fn evaluate(&self, input: &[u8]) -> u64 {
        let parameters = self.secret_key.parameters;
        let a = hash_to_ring_vector(parameters, input, 1);
        evaluate_from_vector(parameters, &self.secret_key.bits, &a)
    }

    /// Evaluates `count` components in Z_p using the paper's indexed hashes
    /// H(x, i), with component indices i starting at one.
    pub fn evaluate_many(&self, input: &[u8], count: usize) -> Vec<u64> {
        let parameters = self.secret_key.parameters;
        (1..=count)
            .map(|index| {
                let a = hash_to_ring_vector(parameters, input, index as u64);
                evaluate_from_vector(parameters, &self.secret_key.bits, &a)
            })
            .collect()
    }
}

/// Computes the exact scalar function described in Section 5, Equation (7):
///
/// `(-1)^MSB(z) * floor(p * (z mod N) / N) mod p`, where
/// `z = <a, s> mod 2N`.
fn evaluate_from_vector(parameters: FastLwrPrfParameters, secret_bits: &[u8], a: &[u64]) -> u64 {
    debug_assert_eq!(secret_bits.len(), parameters.lwr_dimension);
    debug_assert_eq!(a.len(), parameters.lwr_dimension);

    let dot_product: u128 = a
        .iter()
        .zip(secret_bits.iter())
        .map(|(&coefficient, &bit)| (coefficient as u128) * (bit as u128))
        .sum();
    let phase = (dot_product % (parameters.q() as u128)) as u64;
    round_phase(parameters, phase)
}

fn round_phase(parameters: FastLwrPrfParameters, phase: u64) -> u64 {
    let n = parameters.ring_dimension as u64;
    let phase = phase % (2 * n);
    let negative = phase >= n;
    let x = phase % n;

    // Use integer arithmetic for floor(p*x/N); this avoids floating-point
    // discrepancies at rounding boundaries.
    let rounded = ((parameters.output_modulus as u128) * (x as u128) / (n as u128)) as u64;
    if negative && rounded != 0 {
        parameters.output_modulus - rounded
    } else {
        rounded
    }
}

/// Deterministically expands H(x, output_index) to a vector in Z_(2N)^n.
/// The paper defines vector-output slots through indexed hashes H(x, i), so
/// the scalar `evaluate(x)` API uses slot 1 rather than a separate H(x) domain.
/// SHAKE256 is used as the domain-separated XOF instantiation.
pub(super) fn hash_to_ring_vector(
    parameters: FastLwrPrfParameters,
    input: &[u8],
    output_index: u64,
) -> Vec<u64> {
    assert!(output_index > 0, "PRF output indices start at one");
    let mut hasher = Shake256::default();
    hasher.update(HASH_DOMAIN);
    hasher.update(&(parameters.lwr_dimension as u64).to_le_bytes());
    hasher.update(&(parameters.ring_dimension as u64).to_le_bytes());
    hasher.update(&parameters.output_modulus.to_le_bytes());
    hasher.update(&(input.len() as u64).to_le_bytes());
    hasher.update(input);
    hasher.update(&output_index.to_le_bytes());

    let mut reader = hasher.finalize_xof();
    (0..parameters.lwr_dimension)
        .map(|_| sample_uniform_below(&mut reader, parameters.q()))
        .collect()
}

/// Samples uniformly from 0..modulus using rejection sampling on SHAKE output.
/// This avoids introducing modulo-reduction bias into the hash expansion.
fn sample_uniform_below(reader: &mut impl XofReader, modulus: u64) -> u64 {
    // `modulus` is in [4, 2^64), due to parameter validation.
    let limit = u64::MAX - (u64::MAX % modulus);
    loop {
        let mut bytes = [0u8; 8];
        reader.read(&mut bytes);
        let value = u64::from_le_bytes(bytes);
        if value < limit {
            return value % modulus;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};

    fn small_parameters() -> FastLwrPrfParameters {
        FastLwrPrfParameters {
            lwr_dimension: 8,
            ring_dimension: 16,
            output_modulus: 4,
        }
    }

    #[test]
    fn paper_rounding_map_matches_signed_floor_formula() {
        let parameters = FastLwrPrfParameters {
            lwr_dimension: 1,
            ring_dimension: 8,
            output_modulus: 4,
        };
        assert_eq!(round_phase(parameters, 0), 0);
        assert_eq!(round_phase(parameters, 1), 0);
        assert_eq!(round_phase(parameters, 2), 1);
        assert_eq!(round_phase(parameters, 7), 3);
        assert_eq!(round_phase(parameters, 8), 0);
        assert_eq!(round_phase(parameters, 10), 3);
        assert_eq!(round_phase(parameters, 15), 1);
    }

    #[test]
    fn signed_floor_rounding_matches_equation_for_every_phase() {
        // Exhaustively check the paper's Eq. (7) on small power-of-two
        // parameter sets, including the sign boundary at phase N and the
        // wraparound at 2N. This is independent of the TFHE implementation.
        for (n, p) in [(8_u64, 2_u64), (8, 4), (16, 2), (16, 8), (64, 16)] {
            let parameters = FastLwrPrfParameters {
                lwr_dimension: 1,
                ring_dimension: n as usize,
                output_modulus: p,
            };
            parameters.validate().unwrap();

            for phase in 0..(2 * n) {
                let magnitude = phase % n;
                let rounded = (p * magnitude) / n;
                let expected = if phase >= n {
                    (p - rounded) % p
                } else {
                    rounded
                };
                assert_eq!(
                    round_phase(parameters, phase),
                    expected,
                    "N={n}, p={p}, phase={phase}"
                );
            }
        }
    }

    #[test]
    fn validates_parameters_and_binary_key() {
        let bad_n = FastLwrPrfParameters {
            ring_dimension: 12,
            ..small_parameters()
        };
        assert_eq!(
            bad_n.validate(),
            Err(FastLwrPrfError::RingDimensionNotPowerOfTwo)
        );

        assert!(matches!(
            FastLwrPrfSecretKey::from_bits(small_parameters(), vec![0; 7]),
            Err(FastLwrPrfError::WrongKeyLength { .. })
        ));
        let mut non_binary = vec![0; small_parameters().lwr_dimension];
        non_binary[3] = 2;
        assert!(matches!(
            FastLwrPrfSecretKey::from_bits(small_parameters(), non_binary),
            Err(FastLwrPrfError::NonBinarySecretKey { index: 3, value: 2 })
        ));
    }

    #[test]
    fn deterministic_key_and_evaluation_for_reproducible_tests() {
        let mut rng1 = StdRng::seed_from_u64(0xFA57_1A2);
        let mut rng2 = StdRng::seed_from_u64(0xFA57_1A2);
        let key1 = FastLwrPrfSecretKey::generate(small_parameters(), &mut rng1).unwrap();
        let key2 = FastLwrPrfSecretKey::generate(small_parameters(), &mut rng2).unwrap();
        let prf1 = FastLwrPrf::new(key1);
        let prf2 = FastLwrPrf::new(key2);

        assert_eq!(prf1.evaluate(b"example-id"), prf2.evaluate(b"example-id"));
        assert_eq!(
            prf1.evaluate_many(b"example-id", 12),
            prf2.evaluate_many(b"example-id", 12)
        );
    }

    #[test]
    fn outputs_are_in_the_requested_modulus_and_multi_output_is_stable() {
        let parameters = small_parameters();
        let key = FastLwrPrfSecretKey::from_bits(parameters, vec![1, 0, 1, 1, 0, 1, 0, 1]).unwrap();
        let prf = FastLwrPrf::new(key);
        let out = prf.evaluate_many(b"id-123", 64);

        assert_eq!(out.len(), 64);
        assert!(out.iter().all(|&value| value < parameters.output_modulus));
        assert_eq!(out, prf.evaluate_many(b"id-123", 64));
        assert!(prf.evaluate(b"id-123") < parameters.output_modulus);
    }

    #[test]
    fn scalar_output_matches_first_vector_component_and_indices_are_separated() {
        let parameters = small_parameters();
        let key = FastLwrPrfSecretKey::from_bits(parameters, vec![1, 0, 1, 1, 0, 1, 0, 1]).unwrap();
        let prf = FastLwrPrf::new(key);
        let input = b"same-input";
        assert_eq!(prf.evaluate(input), prf.evaluate_many(input, 1)[0]);

        let component_1 = hash_to_ring_vector(parameters, input, 1);
        let component_2 = hash_to_ring_vector(parameters, input, 2);
        assert_ne!(component_1, component_2);
    }
}
