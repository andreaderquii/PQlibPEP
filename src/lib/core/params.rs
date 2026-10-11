/// Prototype parameters for the BPR12 Ring-LWR PRF.
///
/// The PRF uses a modulus chain of the form
///
///q_j = Q_BASE^(j + 1)
///
/// as suggested in the BPR12 construction.
///
/// These parameters are intended for functional validation and
/// benchmarking. They do NOT constitute a claimed security level.

pub const RING_DIMENSION: usize = 256;

/// Base modulus used to construct the BPR12 modulus chain.
///
/// Since sqrt(256) = 16, we choose the smallest integer > sqrt(n).
pub const Q_BASE: u64 = 17;

/// Output modulus q_0.
pub const Q0: u64 = 17;

/// Input size of the PRF in bits.
///
/// 32-byte ID = 256 bits = 2^8.
pub const PRF_INPUT_BITS: usize = 256;

/// BPR12 recursion depth.
pub const PRF_DEPTH: usize = 8;

/// Number of moduli in the chain:
///
/// q_0, q_1, ..., q_d
pub const PRF_MODULUS_COUNT: usize = PRF_DEPTH + 1;

/// The PRF uses a modulus chain based on increasing powers of Q_BASE.
pub fn prf_modulus_chain() -> Vec<u64> {
    (0..=PRF_DEPTH)
        .map(|j| Q_BASE.pow((j + 1) as u32))
        .collect()
}

pub const PLAINTEXT_MODULUS: u64 = 17;