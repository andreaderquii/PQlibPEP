use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

use crate::algebra::ring::PolyRq;

const PID_DOMAIN: &[u8] = b"PQ-LIBPEP-PID-v1";

/// Serializes a polynomial into a canonical byte representation.
///
/// Each coefficient is encoded as a little-endian u64.
/// The modulus and ring degree are included to make the encoding
/// unambiguous across parameter sets.
fn encode_poly(poly: &PolyRq) -> Vec<u8> {
    let mut encoded = Vec::new();

    encoded.extend_from_slice(b"PolyRq-v1");

    encoded.extend_from_slice(&(poly.degree_bound() as u64).to_le_bytes());
    encoded.extend_from_slice(&poly.modulus().to_le_bytes());

    for &coefficient in poly.coefficients() {
        encoded.extend_from_slice(&coefficient.to_le_bytes());
    }

    encoded
}

/// Derives the fixed-size 64-byte PID from the RLWR PRF output.
///
/// The polynomial itself may be much larger than 64 bytes.
/// SHAKE256 is used as an XOF to derive a fixed-size application-level PID.
pub fn derive_pid(poly: &PolyRq) -> [u8; 64] {
    let encoded = encode_poly(poly);

    let mut hasher = Shake256::default();
    hasher.update(PID_DOMAIN);
    hasher.update(&encoded);

    let mut pid = [0u8; 64];
    let mut reader = hasher.finalize_xof();
    reader.read(&mut pid);

    pid
}