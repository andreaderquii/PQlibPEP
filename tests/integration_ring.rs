use pq_libpep::algebra::ring::{PolyRq, Q};
use rand::{thread_rng, Rng};

/// Reference implementation of multiplication in
/// Z_q[X] / (X^n + 1).
///
/// This is intentionally simple and slow:
/// it is used only as a correctness reference for mul_ntt().
fn naive_negacyclic_mul(a: &[u64], b: &[u64], n: usize) -> Vec<u64> {
    assert_eq!(a.len(), n);
    assert_eq!(b.len(), n);

    let mut result = vec![0u64; n];

    for i in 0..n {
        for j in 0..n {
            let product = (a[i] as u128 * b[j] as u128) % Q as u128;
            let k = i + j;

            if k < n {
                result[k] =
                    ((result[k] as u128 + product) % Q as u128) as u64;
            } else {
                // X^n = -1 in Z_q[X] / (X^n + 1).
                let index = k - n;

                result[index] = if result[index] >= product as u64 {
                    result[index] - product as u64
                } else {
                    Q - (product as u64 - result[index])
                };
            }
        }
    }

    result
}

/// Test 1:
/// X^(n-1) * X = X^n = -1 mod (X^n + 1).
#[test]
fn test_negacyclic_x_n() {
    let n = 256;

    let mut a = vec![0u64; n];
    let mut b = vec![0u64; n];

    a[n - 1] = 1;
    b[1] = 1;

    let poly_a = PolyRq::from_coeffs(&a, n, Q);
    let poly_b = PolyRq::from_coeffs(&b, n, Q);

    let result = poly_a.mul_ntt(&poly_b);

    let mut result_coeffs = result.to_coeffs_vec();
    result_coeffs.resize(n, 0);

    let mut expected = vec![0u64; n];
    expected[0] = Q - 1;

    assert_eq!(
        result_coeffs, expected,
        "X^(n-1) * X should be -1 in Z_q[X]/(X^n + 1)"
    );
}

/// Test 2:
/// X^(n-1) * X^2 = X^(n+1) = -X mod (X^n + 1).
#[test]
fn test_negacyclic_x_n_plus_one() {
    let n = 256;

    let mut a = vec![0u64; n];
    let mut b = vec![0u64; n];

    a[n - 1] = 1;
    b[2] = 1;

    let poly_a = PolyRq::from_coeffs(&a, n, Q);
    let poly_b = PolyRq::from_coeffs(&b, n, Q);

    let result = poly_a.mul_ntt(&poly_b);

    let mut result_coeffs = result.to_coeffs_vec();
    result_coeffs.resize(n, 0);

    let mut expected = vec![0u64; n];
    expected[1] = Q - 1;

    assert_eq!(
        result_coeffs, expected,
        "X^(n-1) * X^2 should be -X in Z_q[X]/(X^n + 1)"
    );
}

/// Test 3:
/// Compare the NTT-based multiplication against
/// a simple reference implementation for random polynomials.
#[test]
fn test_ntt_matches_naive_negacyclic() {
    let n = 256;
    let mut rng = thread_rng();

    for iteration in 0..200 {
        let a: Vec<u64> = (0..n).map(|_| rng.gen_range(0..Q)).collect();
        let b: Vec<u64> = (0..n).map(|_| rng.gen_range(0..Q)).collect();

        let poly_a = PolyRq::from_coeffs(&a, n, Q);
        let poly_b = PolyRq::from_coeffs(&b, n, Q);

        let ntt_result = poly_a.mul_ntt(&poly_b);

        let mut ntt_coeffs = ntt_result.to_coeffs_vec();
        ntt_coeffs.resize(n, 0);

        let naive_result = naive_negacyclic_mul(&a, &b, n);

        assert_eq!(
            ntt_coeffs,
            naive_result,
            "NTT multiplication differs from naive negacyclic multiplication \
             at random test iteration {}",
            iteration
        );
    }
}

/// Test 4a:
/// 1 * a = a.
#[test]
fn test_multiplication_by_one() {
    let n = 256;
    let mut rng = thread_rng();

    let a: Vec<u64> = (0..n).map(|_| rng.gen_range(0..Q)).collect();

    let mut one = vec![0u64; n];
    one[0] = 1;

    let poly_a = PolyRq::from_coeffs(&a, n, Q);
    let poly_one = PolyRq::from_coeffs(&one, n, Q);

    let result = poly_one.mul_ntt(&poly_a);

    let mut result_coeffs = result.to_coeffs_vec();
    result_coeffs.resize(n, 0);

    assert_eq!(result_coeffs, a, "1 * a should be equal to a");
}

/// Test 4b:
/// 0 * a = 0.
#[test]
fn test_multiplication_by_zero() {
    let n = 256;
    let mut rng = thread_rng();

    let a: Vec<u64> = (0..n).map(|_| rng.gen_range(0..Q)).collect();

    let zero = vec![0u64; n];

    let poly_a = PolyRq::from_coeffs(&a, n, Q);
    let poly_zero = PolyRq::from_coeffs(&zero, n, Q);

    let result = poly_zero.mul_ntt(&poly_a);

    let mut result_coeffs = result.to_coeffs_vec();
    result_coeffs.resize(n, 0);

    let expected = vec![0u64; n];

    assert_eq!(result_coeffs, expected, "0 * a should be equal to 0");
}

/// Test 5:
/// Verify that nc-polynomial uses the negacyclic relation
/// X^n = -1 modulo X^n + 1.
#[test]
fn nc_polynomial_is_negacyclic() {
    let n = 8;

    let mut a = vec![0u64; n];
    let mut b = vec![0u64; n];

    // X^(n-1)
    a[n - 1] = 1;

    // X
    b[1] = 1;

    let poly_a = PolyRq::from_coeffs(&a, n, Q);
    let poly_b = PolyRq::from_coeffs(&b, n, Q);

    let result = poly_a.mul_negacyclic(&poly_b);
    let coeffs = result.to_coeffs_vec();

    // X^(n-1) * X = X^n = -1 mod (X^n + 1)
    assert_eq!(coeffs[0], Q - 1);

    // Tutti gli altri coefficienti devono essere zero.
    for &coeff in &coeffs[1..] {
        assert_eq!(coeff, 0);
    }
}

#[test]
fn test_round_poly() {
    use pq_libpep::algebra::ring::{round_poly, PolyRq};

    let n = 4;
    let q = 998_244_353;
    let p = 469_762_049;

    let coeffs = vec![0, 37, 82, 15];

    let poly = PolyRq::from_coeffs(&coeffs, n, q);
    let rounded = round_poly(&poly, p);

    assert_eq!(rounded.modulus(), p);
    assert_eq!(rounded.degree_bound(), n);

    let result = rounded.to_coeffs_vec();

    assert!(result.len() >= coeffs.len());

    let expected = [0, 17, 39, 7];

    for (actual, expected) in result.iter().zip(expected.iter()) {
        assert_eq!(actual, expected);
    }

    assert!(
        result[expected.len()..]
            .iter()
            .all(|&x| x == 0),
        "coefficients beyond the input degree must be zero"
    );
}

#[test]
fn test_rlwr_synthesizer() {
    use pq_libpep::algebra::ring::PolyRq;
    use pq_libpep::core::rlwr::synthesize;

    let n = 4;
    let q = 998_244_353;
    let p = 469_762_049;

    let x = PolyRq::from_coeffs(
        &[1, 2, 0, 0],
        n,
        q,
    );

    let y = PolyRq::from_coeffs(
        &[3, 4, 0, 0],
        n,
        q,
    );

    let result = synthesize(&x, &y, p);

    assert_eq!(result.modulus(), p);
    assert_eq!(result.degree_bound(), n);
}

#[test]
fn test_rlwr_synthesizer_known_answer() {
    use pq_libpep::algebra::ring::PolyRq;
    use pq_libpep::core::rlwr::synthesize;

    let n = 4;
    let q = 998_244_353;
    let p = 469_762_049;

    // x = 1 + 2X
    let x = PolyRq::from_coeffs(
        &[1, 2, 0, 0],
        n,
        q,
    );

    // y = 3 + 4X
    let y = PolyRq::from_coeffs(
        &[3, 4, 0, 0],
        n,
        q,
    );

    // (1 + 2X)(3 + 4X)
    // = 3 + 10X + 8X^2
    //
    // After rounding q -> p:
    // round(p * 3 / q)  = 1
    // round(p * 10 / q) = 5
    // round(p * 8 / q)  = 4
    let result = synthesize(&x, &y, p);

    let coeffs = result.to_coeffs_vec();

    assert_eq!(result.modulus(), p);
    assert_eq!(result.degree_bound(), n);

    assert_eq!(&coeffs[..3], &[1, 5, 4]);
    assert!(coeffs[3..].iter().all(|&x| x == 0));
}

#[test]
fn test_rlwr_synthesizer_negacyclic_wrap() {
    use pq_libpep::algebra::ring::PolyRq;
    use pq_libpep::core::rlwr::synthesize;

    let n = 4;
    let q = 998_244_353;
    let p = 469_762_049;

    // x = X^3
    let x = PolyRq::from_coeffs(
        &[0, 0, 0, 1],
        n,
        q,
    );

    // y = X
    let y = PolyRq::from_coeffs(
        &[0, 1, 0, 0],
        n,
        q,
    );

    // X^3 * X = X^4 = -1 mod (X^4 + 1)
    let result = synthesize(&x, &y, p);

    let coeffs = result.to_coeffs_vec();

    assert_eq!(result.modulus(), p);
    assert_eq!(result.degree_bound(), n);

    // -1 in R_q is q - 1.
    // Rounding q - 1 from q to p gives p,
    // which is 0 modulo p.
    assert_eq!(coeffs[0], 0);
    assert!(coeffs[1..].iter().all(|&x| x == 0));
}

#[test]
fn test_rlwr_prf_base() {
    use pq_libpep::core::rlwr_prf::RlwrPrfBase;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    let n = 4;
    let q = 998_244_353;

    let mut rng = StdRng::seed_from_u64(42);

    let base = RlwrPrfBase::sample(
        &mut rng,
        n,
        q,
        2,
    );

    assert_eq!(base.s0.len(), 2);
    assert_eq!(base.s1.len(), 2);

    for i in 0..2 {
        assert_eq!(base.s0[i].modulus(), q);
        assert_eq!(base.s1[i].modulus(), q);

        assert_eq!(base.s0[i].degree_bound(), n);
        assert_eq!(base.s1[i].degree_bound(), n);

        assert_ne!(
            base.s0[i].to_coeffs_vec(),
            base.s1[i].to_coeffs_vec()
        );
    }

    assert_eq!(
        base.evaluate_at(0, 0).to_coeffs_vec(),
        base.s0[0].to_coeffs_vec()
    );

    assert_eq!(
        base.evaluate_at(0, 1).to_coeffs_vec(),
        base.s1[0].to_coeffs_vec()
    );

    assert_eq!(
        base.evaluate_at(1, 0).to_coeffs_vec(),
        base.s0[1].to_coeffs_vec()
    );

    assert_eq!(
        base.evaluate_at(1, 1).to_coeffs_vec(),
        base.s1[1].to_coeffs_vec()
    );
}

#[test]
fn test_rlwr_prf_two_bits() {
    use pq_libpep::core::rlwr_prf::{RlwrPrf, RlwrPrfBase};
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    let n = 4;

    let q0 = 469_762_049;
    let q1 = 998_244_353;

    let mut rng = StdRng::seed_from_u64(42);

    let base = RlwrPrfBase::sample(
    &mut rng,
    n,
    q1,
    2,
    );

    let prf = RlwrPrf::new(base, vec![q0, q1]);

    let result = prf.evaluate(&[0, 1]);

    assert_eq!(result.modulus(), q0);
    assert_eq!(result.degree_bound(), n);
}

#[test]
fn test_rlwr_prf_four_bits() {
    use pq_libpep::core::rlwr_prf::{RlwrPrf, RlwrPrfBase};
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    let n = 4;

    let q0 = 17;
    let q1 = 289;
    let q2 = 4_913;

    let mut rng = StdRng::seed_from_u64(42);

    let base = RlwrPrfBase::sample(&mut rng, n, q2, 4);

    let prf = RlwrPrf::new(base, vec![q0, q1, q2]);

    let result = prf.evaluate(&[0, 1, 1, 0]);

    assert_eq!(result.modulus(), q0);
    assert_eq!(result.degree_bound(), n);
}

#[test]
fn test_rlwr_prf_eight_bits() {
    use pq_libpep::core::rlwr_prf::{RlwrPrf, RlwrPrfBase};
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    let n = 4;

    let q0 = 17;
    let q1 = 289;
    let q2 = 4_913;
    let q3 = 83_521;

    let mut rng = StdRng::seed_from_u64(42);

    let base = RlwrPrfBase::sample(&mut rng, n, q3, 8);

    let prf = RlwrPrf::new(
        base,
        vec![q0, q1, q2, q3],
    );

    let result = prf.evaluate(&[1, 0, 1, 1, 0, 0, 1, 0]);

    assert_eq!(result.modulus(), q0);
    assert_eq!(result.degree_bound(), n);
}

#[test]
#[should_panic(expected = "PRF input length must be a power of two")]
fn test_rlwr_prf_invalid_input_length() {
    use pq_libpep::core::rlwr_prf::{RlwrPrf, RlwrPrfBase};
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    let n = 4;
    let q0 = 469_762_049;
    let q1 = 998_244_353;

    let mut rng = StdRng::seed_from_u64(42);

    let base = RlwrPrfBase::sample(
    &mut rng,
    n,
    q1,
    2,
    );

    let prf = RlwrPrf::new(base, vec![q0, q1]);

    prf.evaluate(&[0, 1, 1]);
}

#[test]
#[should_panic(expected = "PRF input must not be empty")]
fn test_rlwr_prf_empty_input() {
    use pq_libpep::core::rlwr_prf::{RlwrPrf, RlwrPrfBase};
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    let n = 4;
    let q0 = 469_762_049;
    let q1 = 998_244_353;

    let mut rng = StdRng::seed_from_u64(42);

    let base = RlwrPrfBase::sample(&mut rng, n, q1, 2);
    let prf = RlwrPrf::new(base, vec![q0, q1]);

    prf.evaluate(&[]);
}

#[test]
#[should_panic(expected = "input is too deep for the provided modulus chain")]
fn test_rlwr_prf_insufficient_modulus_chain() {
    use pq_libpep::core::rlwr_prf::{RlwrPrf, RlwrPrfBase};
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    let n = 4;
    let q0 = 469_762_049;
    let q1 = 998_244_353;

    let mut rng = StdRng::seed_from_u64(42);

    let base = RlwrPrfBase::sample(&mut rng, n, q1, 2);
    let prf = RlwrPrf::new(base, vec![q0, q1]);

    // 8 bit => depth 3, ma abbiamo solo q0, q1.
   prf.evaluate(&[1, 0, 1, 1, 0, 0, 1, 0]);
}

#[test]
fn test_rlwr_prf_deterministic() {
    use pq_libpep::core::rlwr_prf::{RlwrPrf, RlwrPrfBase};
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    let n = 4;

    let q0 = 17;
    let q1 = 289;
    let q2 = 4_913;
    let q3 = 83_521;

    let mut rng = StdRng::seed_from_u64(42);

    let base = RlwrPrfBase::sample(&mut rng, n, q3, 8);

    let prf = RlwrPrf::new(
        base,
        vec![q0, q1, q2, q3],
    );

    let input = [1, 0, 1, 1, 0, 0, 1, 0];

    let result1 = prf.evaluate(&input);
    let result2 = prf.evaluate(&input);

    assert_eq!(result1, result2);
}

#[test]
fn test_rlwr_prf_different_inputs() {
    use pq_libpep::core::rlwr_prf::{RlwrPrf, RlwrPrfBase};
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    let n = 4;

    let q0 = 17;
    let q1 = 289;
    let q2 = 4_913;
    let q3 = 83_521;

    let mut rng = StdRng::seed_from_u64(42);

    let base = RlwrPrfBase::sample(&mut rng, n, q3, 8);

    let prf = RlwrPrf::new(
        base,
        vec![q0, q1, q2, q3],
    );

    let input1 = [0, 0, 0, 0, 0, 0, 0, 0];
    let input2 = [1, 0, 0, 0, 0, 0, 0, 0];
    let input3 = [1, 1, 1, 1, 1, 1, 1, 1];

    let output1 = prf.evaluate(&input1);
    let output2 = prf.evaluate(&input2);
    let output3 = prf.evaluate(&input3);

    assert!(
        output1 != output2 ||
        output1 != output3 ||
        output2 != output3
    );
}

#[test]
fn test_bytes_to_bits() {
    use pq_libpep::core::id_encoding::bytes_to_bits;

    let bits = bytes_to_bits(&[0xA5]);

    assert_eq!(
        bits,
        vec![1, 0, 1, 0, 0, 1, 0, 1]
    );
}

#[test]
fn test_prf_input_position_sensitivity() {
    use pq_libpep::core::rlwr_prf::{
        RlwrPrf,
        RlwrPrfBase,
    };
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    let n = 4;

    let q0 = 17;
    let q1 = 289;
    let q2 = 4_913;
    let q3 = 83_521;

    let mut rng = StdRng::seed_from_u64(42);

    let base = RlwrPrfBase::sample(
        &mut rng,
        n,
        q3,
        8,
    );

    let prf = RlwrPrf::new(
        base,
        vec![q0, q1, q2, q3],
    );

    let p0 = prf.evaluate(&[
        0, 0, 0, 0, 0, 0, 0, 0
    ]);

    let p1 = prf.evaluate(&[
        1, 0, 0, 0, 0, 0, 0, 0
    ]);

    let p2 = prf.evaluate(&[
        0, 1, 0, 0, 0, 0, 0, 0
    ]);

    let p3 = prf.evaluate(&[
        0, 0, 0, 0, 0, 0, 0, 1
    ]);

    assert_ne!(p0, p1);
    assert_ne!(p0, p2);
    assert_ne!(p0, p3);

    assert_ne!(p1, p2);
    assert_ne!(p1, p3);
    assert_ne!(p2, p3);
}