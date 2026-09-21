/// Converts a byte slice into a binary vector.
/// Each byte is expanded into 8 bits, from the most significant
/// bit to the least significant bit.
pub fn bytes_to_bits(bytes: &[u8]) -> Vec<u8> {
    let mut bits = Vec::with_capacity(bytes.len() * 8);
    for &byte in bytes {
        for shift in (0..8).rev() {
            bits.push((byte >> shift) & 1);
        }
    }

    bits
}

pub fn string_to_id(input: &str) -> [u8; 32] {
    let bytes = input.as_bytes();
    assert!(
        bytes.len() <= 32,
        "string is too long for a 32-byte ID"
    );
    let mut id = [0u8; 32];
    id[..bytes.len()].copy_from_slice(bytes);
    id
}