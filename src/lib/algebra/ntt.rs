// src/lib/algebra/ntt.rs
// NTT fundamental to convert polynomials in R_q = Z_q[X] / (X^n + 1) to their NTT representation and back.
// Very useful for polynomial multiplication that becomes point-wise in the NTT domain,
// allowing O(n log n) multiplication instead of O(n^2).
//
// a(X) ──NTT──> A
// b(X) ──NTT──> B
// A * B = C
// C ──INTT──> c(X) = a(X) * b(X) mod (X^n + 1, q)

// ============================================================================
// 1. Custom NTT Implementation (Reference Implementation)
// ============================================================================

/// Handles the context and precomputed tables for the custom Number Theoretic Transform (NTT)
/// into R_q = Z_q[X] / (X^n + 1).
#[derive(Debug, Clone)]
pub struct CustomNttContext {
    pub n: usize,
    pub q: u64,
    pub psi: u64,               // 2n-th primitive root of unity mod q (psi^n ≡ -1 mod q)
    pub psi_inv: u64,           // Inverse of psi mod q
    pub n_inv: u64,             // Inverse of n mod q
    pub twiddles: Vec<u64>,     // Precomputed powers of psi for Forward NTT
    pub twiddles_inv: Vec<u64>, // Precomputed powers of psi_inv for Inverse NTT
}

impl CustomNttContext {
    /// Finds a primitive 2n-th root of unity modulo q.
    pub fn find_primitive_root(n: usize, q: u64) -> u64 {
        assert_eq!(q % (2 * n as u64), 1, "q must satisfy q ≡ 1 mod 2n");
        let k = (q - 1) / (2 * n as u64);

        for g in 2..q {
            let psi = mod_pow(g, k, q);
            // Check if psi^n ≡ -1 mod q (i.e., q - 1)
            if mod_pow(psi, n as u64, q) == q - 1 {
                return psi;
            }
        }
        panic!("Impossible to find a primitive root for n={}, q={}", n, q);
    }

    /// Initializes the NTT context and precomputes root tables (twiddle factors).
    ///
    /// # Requirements
    /// - `n` must be a power of 2.
    /// - `q` must be prime and satisfy `q ≡ 1 mod 2n`.
    pub fn new(n: usize, q: u64) -> Self {
        let psi = Self::find_primitive_root(n, q);
        let psi_inv = mod_inverse(psi, q);
        let n_inv = mod_inverse(n as u64, q);

        let mut twiddles = vec![0u64; n];
        let mut twiddles_inv = vec![0u64; n];
        let bits = n.trailing_zeros() as usize;

        for i in 0..n {
            let rev_i = bit_reverse(i, bits);
            twiddles[i] = mod_pow(psi, rev_i as u64, q);
            twiddles_inv[i] = mod_pow(psi_inv, rev_i as u64, q);
        }

        Self {
            n,
            q,
            psi,
            psi_inv,
            n_inv,
            twiddles,
            twiddles_inv,
        }
    }

    /// Executes the forward NTT in-place using the Cooley-Tukey butterfly algorithm.
    /// Transforms the vector from coefficient representation to NTT domain.
    pub fn forward(&self, a: &mut [u64]) {
        assert_eq!(a.len(), self.n);
        let n = self.n;
        let q = self.q as u128;

        let mut t = n / 2;
        let mut m = 1;

        while m < n {
            let mut k = 0;
            for i in 0..m {
                let w = self.twiddles[m + i] as u128;
                for j in k..(k + t) {
                    let u = a[j] as u128;
                    let v = (a[j + t] as u128 * w) % q;

                    a[j] = ((u + v) % q) as u64;
                    a[j + t] = ((u + q - v) % q) as u64;
                }
                k += 2 * t;
            }
            t /= 2;
            m *= 2;
        }
    }

    /// Executes the inverse NTT in-place using the Gentleman-Sande butterfly algorithm.
    /// Converts values from NTT domain back to standard coefficient representation.
    pub fn inverse(&self, a: &mut [u64]) {
        assert_eq!(a.len(), self.n);
        let n = self.n;
        let q = self.q as u128;

        let mut t = 1;
        let mut m = n / 2;

        while m > 0 {
            let mut k = 0;
            for i in 0..m {
                let w = self.twiddles_inv[m + i] as u128;
                for j in k..(k + t) {
                    let u = a[j] as u128;
                    let v = a[j + t] as u128;

                    a[j] = ((u + v) % q) as u64;
                    let diff = (u + q - v) % q;
                    a[j + t] = ((diff * w) % q) as u64;
                }
                k += 2 * t;
            }
            t *= 2;
            m /= 2;
        }

        // Final scaling by n^-1 mod q
        let n_inv = self.n_inv as u128;
        for x in a.iter_mut() {
            *x = ((*x as u128 * n_inv) % q) as u64;
        }
    }
}

// ============================================================================
// 3. Mathematical Helper Functions
// ============================================================================

/// Reverses the order of the first `bits` bits of `val`.
fn bit_reverse(val: usize, bits: usize) -> usize {
    val.reverse_bits() >> (usize::BITS as usize - bits)
}

/// Modular exponentiation: `(base^exp) % modulus`
fn mod_pow(base: u64, mut exp: u64, modulus: u64) -> u64 {
    let mut result = 1u128;
    let mut b = (base % modulus) as u128;
    let m = modulus as u128;

    while exp > 0 {
        if exp % 2 == 1 {
            result = (result * b) % m;
        }
        b = (b * b) % m;
        exp /= 2;
    }
    result as u64
}

/// Computes modular inverse using Fermat's Little Theorem: `a^(q-2) ≡ a^-1 mod q`
pub fn mod_inverse(a: u64, q: u64) -> u64 {
    mod_pow(a, q - 2, q)
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

use concrete_ntt::prime64::Plan;
// ============================================================================
// 2. Concrete-NTT Wrapper (High-Performance Library Integration)
// ============================================================================

/// High-performance NTT engine backed by Zama's `concrete-ntt`.
pub struct ConcreteNttContext {
    pub n: usize,
    pub q: u64,
    plan: Plan,
}

impl ConcreteNttContext {
    /// Creates a new `ConcreteNttContext`.
    /// Panics if `q` is not a prime satisfying `q ≡ 1 mod 2n`.
    pub fn new(n: usize, q: u64) -> Self {
        let plan = Plan::try_new(n, q).unwrap_or_else(|| {
            panic!(
                "concrete-ntt failed to initialize Plan for n={}, q={}",
                n, q
            )
        });

        Self { n, q, plan }
    }

    /// Executes forward NTT in-place using `concrete-ntt`.
    pub fn forward(&self, a: &mut [u64]) {
        assert_eq!(a.len(), self.n);
        self.plan.fwd(a);
    }

    /// Executes inverse NTT in-place using `concrete-ntt`.
    /// Note: `concrete-ntt::Plan::inv` does not apply the `N^-1`
    /// normalization. The result is therefore `N * a` modulo `q`
    /// after a `fwd` followed by `inv`.
    pub fn inverse(&self, a: &mut [u64]) {
        assert_eq!(a.len(), self.n);
        self.plan.inv(a);
    }
}
