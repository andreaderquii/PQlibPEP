use pq_libpep::algebra::ntt::{ConcreteNttContext, CustomNttContext};

fn mod_pow(base: u64, mut exp: u64, modulus: u64) -> u64 {
    let mut result = 1u128;
    let mut b = base as u128;
    let m = modulus as u128;

    while exp > 0 {
        if exp & 1 == 1 {
            result = (result * b) % m;
        }

        b = (b * b) % m;
        exp >>= 1;
    }
    result as u64
}

fn mod_inverse(a: u64, q: u64) -> u64 {
    mod_pow(a, q - 2, q)
}

fn negacyclic_mul_naive(a: &[u64], b: &[u64], q: u64) -> Vec<u64> {
    let n = a.len();
    let mut result = vec![0u64; n];

    for i in 0..n {
        for j in 0..n {
            let product = (a[i] as u128 * b[j] as u128) % q as u128;
            let k = i + j;

            if k < n {
                result[k] = ((result[k] as u128 + product) % q as u128) as u64;
            } else {
                // X^n = -1
                let index = k - n;
                result[index] = ((result[index] as u128 + q as u128 - product) % q as u128) as u64;
            }
        }
    }
    result
}

#[test]
fn compare_negacyclic_multiplication() {
    let n = 64;
    let q = 998_244_353u64;

    let custom = CustomNttContext::new(n, q);
    let concrete = ConcreteNttContext::new(n, q);

    let a: Vec<u64> = (0..n).map(|i| (7 * i as u64 + 13) % q).collect();

    let b: Vec<u64> = (0..n).map(|i| (11 * i as u64 + 5) % q).collect();

    // ============================================================
    // Naive reference
    // ============================================================

    let expected = negacyclic_mul_naive(&a, &b, q);

    // ============================================================
    // Custom NTT
    // ============================================================

    let mut a_custom = a.clone();
    let mut b_custom = b.clone();
    custom.forward(&mut a_custom);
    custom.forward(&mut b_custom);

    for i in 0..n {
        a_custom[i] = ((a_custom[i] as u128 * b_custom[i] as u128) % q as u128) as u64;
    }
    custom.inverse(&mut a_custom);

    // ============================================================
    // Concrete NTT
    // ============================================================

    let mut a_concrete = a.clone();
    let mut b_concrete = b.clone();
    concrete.forward(&mut a_concrete);
    concrete.forward(&mut b_concrete);

    for i in 0..n {
        a_concrete[i] = ((a_concrete[i] as u128 * b_concrete[i] as u128) % q as u128) as u64;
    }
    concrete.inverse(&mut a_concrete);

    // concrete inverse is unnormalized
    let n_inv = mod_inverse(n as u64, q);
    for x in a_concrete.iter_mut() {
        *x = ((*x as u128 * n_inv as u128) % q as u128) as u64;
    }

    // ============================================================
    // Compare everything
    // ============================================================

    assert_eq!(
        a_custom, expected,
        "Custom NTT multiplication != naive negacyclic multiplication"
    );

    assert_eq!(
        a_concrete, expected,
        "Concrete NTT multiplication != naive negacyclic multiplication"
    );

    assert_eq!(a_custom, a_concrete, "Custom NTT and Concrete NTT disagree");
}
