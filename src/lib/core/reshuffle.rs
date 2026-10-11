use crate::algebra::ring::PolyRq;
use crate::core::rlwe_pke::Ciphertext;

use crate::core::id_encoding::string_to_id;
use crate::core::pseudonym::pseudonymize_32;
use crate::core::rlwr_prf::RlwrPrf;

/// Converts a Ring-LWR PRF output from R_17 into a polynomial
/// in R_q by preserving the integer coefficient values.
///
/// This is a prototype coefficient-wise lift:
///
///
/// No scaling is applied.
pub fn lift_prf_output_to_q(
    prf_output: &PolyRq,
    q: u64,
) -> PolyRq {
    let n = prf_output.degree_bound();

    assert_eq!(
        prf_output.modulus(),
        17,
        "PRF output must have modulus 17"
    );

    let coefficients: Vec<u64> = prf_output
        .coefficients()
        .iter()
        .take(n)
        .map(|&c| c % 17)
        .collect();

    PolyRq::from_coeffs(
        &coefficients,
        n,
        q,
    )
}

/// Derives a domain-specific reshuffling factor.
///
/// The domain is encoded as a 32-byte identifier, evaluated by the
/// Ring-LWR PRF, and then lifted from R_17 to R_q.
///
/// This is a prototype construction.
pub fn derive_reshuffle_factor(
    prf: &RlwrPrf,
    domain: &str,
    n: usize,
    q: u64,
) -> PolyRq {
    let domain_id = string_to_id(domain);

    let prf_output = pseudonymize_32(
        prf,
        &domain_id,
    );

    assert_eq!(
        prf_output.degree_bound(),
        n,
        "PRF output has unexpected degree"
    );

    lift_prf_output_to_q(
        &prf_output,
        q,
    )
}

/// Applies a polynomial reshuffling factor to an RLWE ciphertext.
pub fn reshuffle(
    ciphertext: &Ciphertext,
    factor: &PolyRq,
) -> Ciphertext {
    assert_eq!(
        ciphertext.u.modulus(),
        factor.modulus(),
        "ciphertext and reshuffling factor must have the same modulus"
    );

    assert_eq!(
        ciphertext.u.degree_bound(),
        factor.degree_bound(),
        "ciphertext and reshuffling factor must have the same degree"
    );

    let u_new = ciphertext.u.mul_ntt(factor);
    let v_new = ciphertext.v.mul_ntt(factor);

    Ciphertext {
        u: u_new,
        v: v_new,
    }
}