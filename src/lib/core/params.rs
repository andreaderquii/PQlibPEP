//! Backward-compatible re-exports for the legacy BPR12 profile.
//! Canonical parameter declarations live in [`crate::parameters::bpr12_prototype`].

pub use crate::parameters::bpr12_prototype::{DEPTH as PRF_DEPTH, INPUT_BITS as PRF_INPUT_BITS,
    MODULUS_COUNT as PRF_MODULUS_COUNT, RADIX as Q_BASE, RING_DIMENSION};
pub const Q0: u64 = Q_BASE;
pub const PLAINTEXT_MODULUS: u64 = Q_BASE;

pub fn prf_modulus_chain() -> Vec<u64> {
    (0..=PRF_DEPTH).map(|j| Q_BASE.pow((j + 1) as u32)).collect()
}
