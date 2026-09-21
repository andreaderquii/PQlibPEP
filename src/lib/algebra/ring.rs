use crate::algebra::ntt::{mod_inverse, ConcreteNttContext};
use nc_polynomial::{RingContext, RingElem};

/// Default modulus used by the current RLWE tests.
pub const Q: u64 = 998_244_353;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolyRq {
    /// Coefficients of the polynomial.
    ///
    /// We keep n coefficients plus one trailing zero in order to preserve
    /// the representation previously returned by nc-polynomial::RingElem.
    coeffs: Vec<u64>,

    modulus: u64,
    degree: usize,
}

impl PolyRq {
    /// Creates an element of
    /// without requiring q to be NTT-friendly.
    ///
    /// This is important for the Ring-LWR/BPR12 path, whose modulus chain
    /// does not need to satisfy the constraints imposed by RingContext.
    pub fn from_coeffs(coeffs: &[u64], n: usize, q: u64) -> Self {
        assert!(n > 0, "polynomial degree must be greater than zero");
        assert!(q >= 2, "modulus q must be >= 2");
        assert!(
            coeffs.len() <= n + 1,
            "too many coefficients for PolyRq"
        );

        // nc-polynomial historically exposes n+1 coefficients, with the
        // coefficient of X^n equal to zero after reduction modulo X^n + 1.
        if coeffs.len() == n + 1 {
            assert_eq!(
                coeffs[n] % q,
                0,
                "coefficient of X^n must be zero in canonical PolyRq representation"
            );
        }

        let mut stored = vec![0u64; n + 1];

        for i in 0..n.min(coeffs.len()) {
            stored[i] = coeffs[i] % q;
        }

        Self {
            coeffs: stored,
            modulus: q,
            degree: n,
        }
    }

    /// Converts an nc-polynomial RingElem into PolyRq.
    ///
    /// This function is kept for compatibility with code that already works
    /// with RingElem. PolyRq itself does not depend on RingContext anymore.
    pub fn from_element(elem: RingElem, modulus: u64, degree: usize) -> Self {
        assert!(degree > 0, "polynomial degree must be greater than zero");
        assert!(modulus >= 2, "modulus q must be >= 2");

        let raw = elem.coefficients();

        let mut coeffs = vec![0u64; degree + 1];

        for i in 0..degree.min(raw.len()) {
            coeffs[i] = raw[i] % modulus;
        }

        Self {
            coeffs,
            modulus,
            degree,
        }
    }

    /// Returns the stored coefficient representation.
    /// The returned vector contains n+1 entries, with the last coefficient
    /// normally equal to zero.
    pub fn to_coeffs_vec(&self) -> Vec<u64> {
        self.coeffs.clone()
    }

    /// Returns the coefficient slice.
    /// The slice contains n+1 entries, preserving the old RingElem-based API.
    pub fn coefficients(&self) -> &[u64] {
        &self.coeffs
    }

    /// Polynomial addition modulo q.
    pub fn add(&self, other: &Self) -> Self {
        assert_compatible(self, other);

        let n = self.degree;
        let q = self.modulus;

        let mut result = vec![0u64; n + 1];

        for i in 0..n {
            result[i] = ((self.coeffs[i] as u128 + other.coeffs[i] as u128)
                % q as u128) as u64;
        }

        Self {
            coeffs: result,
            modulus: q,
            degree: n,
        }
    }

    /// Polynomial subtraction modulo q.
    pub fn sub(&self, other: &Self) -> Self {
        assert_compatible(self, other);

        let n = self.degree;
        let q = self.modulus;

        let mut result = vec![0u64; n + 1];

        for i in 0..n {
            let a = self.coeffs[i];
            let b = other.coeffs[i];

            result[i] = if a >= b {
                a - b
            } else {
                q - (b - a)
            };
        }

        Self {
            coeffs: result,
            modulus: q,
            degree: n,
        }
    }

    /// Scalar multiplication modulo q.
    pub fn mul_scalar(&self, scalar: u64) -> Self {
        let n = self.degree;
        let q = self.modulus;
        let scalar = scalar % q;

        let mut result = vec![0u64; n + 1];

        for i in 0..n {
            result[i] =
                ((self.coeffs[i] as u128 * scalar as u128) % q as u128) as u64;
        }

        Self {
            coeffs: result,
            modulus: q,
            degree: n,
        }
    }

    /// Direct negacyclic multiplication:
    ///(X^n = -1)
    /// This implementation does NOT require an NTT-friendly modulus.
    /// It is therefore the multiplication used by the Ring-LWR/BPR12 path.
    pub fn mul_negacyclic(&self, other: &Self) -> Self {
        assert_compatible(self, other);

        let n = self.degree;
        let q = self.modulus;

        let mut result = vec![0u64; n + 1];

        for i in 0..n {
            for j in 0..n {
                let product =
                    (self.coeffs[i] as u128 * other.coeffs[j] as u128)
                        % q as u128;

                let index = i + j;

                if index < n {
                    result[index] =
                        ((result[index] as u128 + product) % q as u128) as u64;
                } else {
                    // X^n = -1, therefore terms with degree >= n
                    // wrap around with a minus sign.
                    let wrapped = index - n;

                    result[wrapped] = (
                        (result[wrapped] as u128 + q as u128 - product)
                            % q as u128
                    ) as u64;
                }
            }
        }

        Self {
            coeffs: result,
            modulus: q,
            degree: n,
        }
    }

    /// NTT-based multiplication.
    /// Unlike mul_negacyclic(), this operation requires q and n to be
    /// supported by ConcreteNttContext.
    /// This path is intended for RLWE/PKE, not for the generic BPR12
    /// Ring-LWR modulus chain.
    pub fn mul_ntt(&self, other: &Self) -> Self {
        assert_compatible(self, other);

        let n = self.degree;
        let q = self.modulus;

        let mut a = self.coeffs[..n].to_vec();
        let mut b = other.coeffs[..n].to_vec();

        let ctx = ConcreteNttContext::new(n, q);

        ctx.forward(&mut a);
        ctx.forward(&mut b);

        for i in 0..n {
            a[i] =
                ((a[i] as u128 * b[i] as u128) % q as u128) as u64;
        }

        ctx.inverse(&mut a);

        let n_inv = mod_inverse(n as u64, q);

        for x in &mut a {
            *x =
                ((*x as u128 * n_inv as u128) % q as u128) as u64;
        }

        Self::from_coeffs(&a, n, q)
    }

    pub fn modulus(&self) -> u64 {
        self.modulus
    }

    pub fn degree_bound(&self) -> usize {
        self.degree
    }
}

/// Creates the ring
///R_q = Z_q[X] / (X^n + 1)
/// using nc-polynomial.
/// This helper is kept for the existing RLWE code/tests.
/// IMPORTANT:
/// This function is NOT used anymore by PolyRq::from_coeffs().
/// Therefore BPR12 Ring-LWR parameters are not constrained by RingContext.
pub fn context(n: usize, q: u64) -> RingContext {
    let mut modulus_poly = vec![0u64; n + 1];

    // X^n + 1
    modulus_poly[0] = 1;
    modulus_poly[n] = 1;

    RingContext::from_parts(n, q, &modulus_poly, 3)
        .expect("invalid RLWE ring parameters")
}

/// Backward-compatible helper for the current RLWE implementation.
pub fn fixed_context(n: usize) -> RingContext {
    context(n, Q)
}

/// Rounds an element from R_q to R_p coefficient-wise.
/// For every coefficient x:
///round(p * x / q) mod p
/// This operation does not require p or q to be NTT-friendly.
pub fn round_poly(poly: &PolyRq, p: u64) -> PolyRq {
    let q = poly.modulus();
    let n = poly.degree_bound();

    assert!(p >= 2, "target modulus p must be >= 2");
    assert!(q >= p, "rounding expects q >= p");

    let rounded_coeffs: Vec<u64> = poly
        .coefficients()
        .iter()
        .take(n)
        .map(|&x| {
            let numerator = x as u128 * p as u128;

            let rounded =
                (numerator + (q as u128 / 2)) / q as u128;

            (rounded % p as u128) as u64
        })
        .collect();

    PolyRq::from_coeffs(&rounded_coeffs, n, p)
}

fn assert_compatible(a: &PolyRq, b: &PolyRq) {
    assert_eq!(
        a.modulus, b.modulus,
        "PolyRq elements have different moduli"
    );

    assert_eq!(
        a.degree, b.degree,
        "PolyRq elements have different degree bounds"
    );
}