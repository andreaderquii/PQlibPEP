use crate::algebra::ring::PolyRq;
use crate::core::id_encoding::bytes_to_bits;
use crate::core::rlwr_prf::RlwrPrf;

/// Applies the RLWR PRF to a 32-byte identifier.
/// A 32-byte identifier is converted to exactly 256 bits,
/// which matches a BPR12 Ring-LWR PRF of depth d = 8.
pub fn pseudonymize_32(prf: &RlwrPrf, id: &[u8; 32]) -> PolyRq {
    let bits = bytes_to_bits(id);
    assert_eq!(bits.len(), 256);
    prf.evaluate(&bits)
}