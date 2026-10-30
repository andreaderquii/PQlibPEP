use sha3::{Digest, Sha3_256};

use crate::algebra::ring::PolyRq;
use crate::core::id_encoding::string_to_id;
use crate::core::pseudonym::pseudonymize_32;
use crate::core::rlwe_pke::Ciphertext;
use crate::core::rlwr_prf::RlwrPrf;
use crate::parameters::reshuffle_prototype as parameter_profile;

pub const RESHUFFLE_PLAINTEXT_MODULUS: u64 = parameter_profile::PLAINTEXT_MODULUS;
const MAX_FACTOR_RETRIES: u32 = 1024;
const FACTOR_DOMAIN_TAG: &[u8] = b"PQlibPEP/reshuffle-factor/v1";

/// A domain-specific PRF factor that is invertible in
/// R_17 = F_17[X]/(X^N + 1), together with its coefficient-wise lift to R_Q.
///
/// NOTE: the lift from R_17 to R_Q is not an exact ring homomorphism.
/// Its correctness in the encrypted path relies on the RLWE Delta encoding,
/// bounded noise and successful rounding during decryption.
#[derive(Clone, Debug)]
pub struct InvertibleReshuffleFactor {
    pub factor_mod_p: PolyRq,
    pub inverse_mod_p: PolyRq,
    pub factor_mod_q: PolyRq,
    pub retry_counter: u32,
}

/// Converts the coefficient representatives of an RLWR output in R_17 into
/// the same integer representatives in R_Q. This is a coefficient-wise lift,
/// not a ring homomorphism between R_17 and R_Q.
pub fn lift_prf_output_to_q(prf_output: &PolyRq, q: u64) -> PolyRq {
    let n = prf_output.degree_bound();
    assert_eq!(
        prf_output.modulus(),
        RESHUFFLE_PLAINTEXT_MODULUS,
        "PRF output must have modulus 17"
    );
    assert!(q >= 2, "ciphertext modulus must be >= 2");

    let coefficients: Vec<u64> = prf_output
        .coefficients()
        .iter()
        .take(n)
        .map(|&c| c % RESHUFFLE_PLAINTEXT_MODULUS)
        .collect();

    PolyRq::from_coeffs(&coefficients, n, q)
}

/// Legacy API retained for compatibility with the existing reshuffle tests.
/// The returned factor is not guaranteed to be invertible.
pub fn derive_reshuffle_factor(
    prf: &RlwrPrf,
    domain: &str,
    n: usize,
    q: u64,
) -> PolyRq {
    let domain_id = string_to_id(domain);
    let prf_output = pseudonymize_32(prf, &domain_id);

    assert_eq!(
        prf_output.degree_bound(),
        n,
        "PRF output has unexpected degree"
    );
    lift_prf_output_to_q(&prf_output, q)
}

fn inverse_scalar_mod_17(value: u64) -> Option<u64> {
    const P: u64 = RESHUFFLE_PLAINTEXT_MODULUS;
    let value = value % P;
    if value == 0 {
        return None;
    }

    // Fermat: value^(-1) = value^(P-2) mod P; P=17 is prime.
    let mut base = value;
    let mut exponent = P - 2;
    let mut result = 1u64;

    while exponent > 0 {
        if exponent & 1 == 1 {
            result = (result * base) % P;
        }
        base = (base * base) % P;
        exponent >>= 1;
    }

    Some(result)
}

fn is_one_mod_17(poly: &PolyRq) -> bool {
    let n = poly.degree_bound();
    let c = poly.coefficients();
    poly.modulus() == RESHUFFLE_PLAINTEXT_MODULUS
        && c[0] == 1
        && c[1..n].iter().all(|&value| value == 0)
}

/// Compute the multiplicative inverse in R_17 = F_17[X]/(X^N + 1).
/// Returns None exactly when the multiplication-by-g matrix is singular.
/// The dense Gaussian-elimination implementation is O(N^3), suitable for
/// deriving a domain factor once during setup, not once per payload.
pub fn invert_polynomial_mod_17(poly: &PolyRq) -> Option<PolyRq> {
    const P: u64 = RESHUFFLE_PLAINTEXT_MODULUS;
    if poly.modulus() != P {
        return None;
    }

    let n = poly.degree_bound();
    if n == 0 {
        return None;
    }

    let g: Vec<u64> = poly.coefficients()[..n]
        .iter()
        .map(|&coefficient| coefficient % P)
        .collect();

    // Matrix of the linear map h -> g*h in F_17[X]/(X^N+1).
    // If row >= column: g[row-column]. Otherwise wrap via X^N = -1.
    let mut matrix = vec![vec![0u64; n + 1]; n];
    for row in 0..n {
        for col in 0..n {
            matrix[row][col] = if row >= col {
                g[row - col]
            } else {
                let value = g[row + n - col];
                if value == 0 { 0 } else { P - value }
            };
        }
        matrix[row][n] = if row == 0 { 1 } else { 0 };
    }

    for pivot_col in 0..n {
        let pivot_row = (pivot_col..n)
            .find(|&row| matrix[row][pivot_col] != 0)?;
        matrix.swap(pivot_col, pivot_row);

        let inverse = inverse_scalar_mod_17(matrix[pivot_col][pivot_col])?;
        for col in pivot_col..=n {
            matrix[pivot_col][col] =
                (matrix[pivot_col][col] * inverse) % P;
        }

        for row in 0..n {
            if row == pivot_col {
                continue;
            }
            let multiplier = matrix[row][pivot_col];
            if multiplier == 0 {
                continue;
            }
            for col in pivot_col..=n {
                let subtract = (multiplier * matrix[pivot_col][col]) % P;
                matrix[row][col] = (matrix[row][col] + P - subtract) % P;
            }
        }
    }

    let inverse_coefficients: Vec<u64> =
        (0..n).map(|row| matrix[row][n]).collect();
    let inverse = PolyRq::from_coeffs(&inverse_coefficients, n, P);

    let product = poly.mul_negacyclic(&inverse);
    if is_one_mod_17(&product) {
        Some(inverse)
    } else {
        None
    }
}

fn domain_factor_input(domain: &str, counter: u32) -> [u8; 32] {
    if counter == 0 {
        // Preserve the current factor derivation when its output is invertible.
        return string_to_id(domain);
    }

    // On a non-invertible candidate, use a deterministic, domain-separated
    // retry input. The same domain, PRF key and retry sequence always agree.
    let mut hasher = Sha3_256::new();
    hasher.update(FACTOR_DOMAIN_TAG);
    hasher.update((domain.len() as u64).to_le_bytes());
    hasher.update(domain.as_bytes());
    hasher.update(counter.to_le_bytes());
    let digest = hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&digest);
    output
}

/// Derive a deterministic domain-specific factor guaranteed to be invertible
/// in R_17. The retry counter changes only the PRF input, not the PRF key.
pub fn derive_invertible_reshuffle_factor(
    prf: &RlwrPrf,
    domain: &str,
    n: usize,
    q: u64,
) -> Result<InvertibleReshuffleFactor, String> {
    if domain.is_empty() {
        return Err("reshuffle domain must not be empty".to_string());
    }
    if domain.len() > 32 {
        return Err("reshuffle domain must be at most 32 UTF-8 bytes".to_string());
    }
    if n == 0 {
        return Err("reshuffle ring dimension must be non-zero".to_string());
    }
    if q < 2 {
        return Err("ciphertext modulus must be at least 2".to_string());
    }

    for counter in 0..MAX_FACTOR_RETRIES {
        let input = domain_factor_input(domain, counter);
        let factor_mod_p = pseudonymize_32(prf, &input);

        if factor_mod_p.degree_bound() != n {
            return Err(format!(
                "RLWR PRF output degree is {}, expected {n}",
                factor_mod_p.degree_bound()
            ));
        }
        if factor_mod_p.modulus() != RESHUFFLE_PLAINTEXT_MODULUS {
            return Err(format!(
                "RLWR PRF output modulus is {}, expected 17",
                factor_mod_p.modulus()
            ));
        }

        if let Some(inverse_mod_p) = invert_polynomial_mod_17(&factor_mod_p) {
            let factor_mod_q = lift_prf_output_to_q(&factor_mod_p, q);
            return Ok(InvertibleReshuffleFactor {
                factor_mod_p,
                inverse_mod_p,
                factor_mod_q,
                retry_counter: counter,
            });
        }
    }

    Err(format!(
        "failed to derive an invertible reshuffle factor after {MAX_FACTOR_RETRIES} candidates"
    ))
}

/// Derive the relative factor for a source-domain to target-domain transition.
/// If the source plaintext is M*g_source, multiplying by this factor yields
/// M*g_target in R_17, subject to the RLWE lift/rounding noise bound.
pub fn derive_domain_transform_factor(
    prf: &RlwrPrf,
    source_domain: &str,
    target_domain: &str,
    n: usize,
    q: u64,
) -> Result<PolyRq, String> {
    let source = derive_invertible_reshuffle_factor(prf, source_domain, n, q)?;
    let target = derive_invertible_reshuffle_factor(prf, target_domain, n, q)?;

    let relative_mod_p = source
        .inverse_mod_p
        .mul_negacyclic(&target.factor_mod_p);

    // Sanity check that the relative factor implements source^-1 * target.
    let check = source.factor_mod_p.mul_negacyclic(&relative_mod_p);
    if check != target.factor_mod_p {
        return Err("derived domain-transition factor failed its R_17 check".to_string());
    }

    Ok(lift_prf_output_to_q(&relative_mod_p, q))
}

/// Apply multiplication by g to both RLWE ciphertext components.
/// At the plaintext level, the intended transform is M -> M*g mod 17.
/// The coefficient-wise lift is approximate across moduli, so tests must
/// check the decrypted result and noise margin.
pub fn reshuffle(ciphertext: &Ciphertext, factor: &PolyRq) -> Ciphertext {
    assert_eq!(
        ciphertext.u.modulus(),
        factor.modulus(),
        "ciphertext and reshuffling factor must have the same modulus"
    );
    assert_eq!(
        ciphertext.v.modulus(),
        factor.modulus(),
        "ciphertext v and reshuffling factor must have the same modulus"
    );
    assert_eq!(
        ciphertext.u.degree_bound(),
        factor.degree_bound(),
        "ciphertext and reshuffling factor must have the same degree"
    );
    assert_eq!(
        ciphertext.v.degree_bound(),
        factor.degree_bound(),
        "ciphertext v and reshuffling factor must have the same degree"
    );

    Ciphertext {
        u: ciphertext.u.mul_ntt(factor),
        v: ciphertext.v.mul_ntt(factor),
    }
}
