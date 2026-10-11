use pq_libpep::algebra::ring::PolyRq;
use pq_libpep::core::rns::{
    RnsModulusChain,
    RnsPoly,
    DEFAULT_RNS_MODULI,
    RNS_RING_DIMENSION,
};

const N: usize = RNS_RING_DIMENSION;

fn test_coefficients_a() -> Vec<u64> {
    let mut coefficients =
        vec![0u64; N];

    for i in 0..N {
        coefficients[i] =
            (37 * i as u64 * i as u64
                + 19 * i as u64
                + 7)
                % 1_000_000;
    }

    coefficients
}

fn test_coefficients_b() -> Vec<u64> {
    let mut coefficients =
        vec![0u64; N];

    for i in 0..N {
        coefficients[i] =
            (91 * i as u64 * i as u64
                + 13 * i as u64
                + 23)
                % 1_000_000;
    }

    coefficients
}

fn assert_poly_equal(
    lhs: &PolyRq,
    rhs: &PolyRq,
) {
    assert_eq!(
        lhs.modulus(),
        rhs.modulus()
    );

    assert_eq!(
        lhs.degree_bound(),
        rhs.degree_bound()
    );

    assert_eq!(
        lhs.coefficients(),
        rhs.coefficients(),
        "polynomials differ modulo q={}",
        lhs.modulus()
    );
}

#[test]
fn test_rns_modulus_chain() {
    let chain =
        RnsModulusChain::default();

    assert_eq!(
        chain.len(),
        DEFAULT_RNS_MODULI.len()
    );

    assert_eq!(
        chain.degree,
        N
    );

    println!();
    println!("==============================================");
    println!("             RNS MODULUS CHAIN");
    println!("==============================================");

    let mut estimated_bits = 0.0f64;

    for (index, &q)
        in chain.moduli.iter().enumerate()
    {
        assert_eq!(
            q % 512,
            1,
            "q_{} is not NTT-friendly for N=256",
            index
        );

        assert_eq!(
            q % 17,
            1,
            "q_{} is not compatible with P=17",
            index
        );

        println!(
            "q[{}] = {}",
            index,
            q
        );

        println!(
            "      q mod 512 = {}",
            q % 512
        );

        println!(
            "      q mod 17  = {}",
            q % 17
        );

        estimated_bits +=
            (q as f64).log2();
    }

    println!();
    println!(
        "Estimated total CRT modulus size ≈ {:.2} bits",
        estimated_bits
    );

    println!(
        "Residues = {}",
        chain.len()
    );

    assert!(
        estimated_bits > 200.0,
        "RNS product is unexpectedly small"
    );
}

#[test]
fn test_rns_representation() {
    let chain =
        RnsModulusChain::default();

    let coefficients =
        test_coefficients_a();

    let rns =
        RnsPoly::from_coeffs(
            &coefficients,
            &chain,
        );

    assert_eq!(
        rns.residue_count(),
        chain.len()
    );

    assert_eq!(
        rns.degree,
        N
    );

    rns.assert_matches_coefficients(
        &coefficients
    );

    println!();
    println!(
        "RNS representation test passed:"
    );
    println!(
        "  polynomial degree = {}",
        rns.degree
    );
    println!(
        "  residue count     = {}",
        rns.residue_count()
    );
}

#[test]
fn test_rns_addition_matches_each_modulus() {
    let chain =
        RnsModulusChain::default();

    let coefficients_a =
        test_coefficients_a();

    let coefficients_b =
        test_coefficients_b();

    let a =
        RnsPoly::from_coeffs(
            &coefficients_a,
            &chain,
        );

    let b =
        RnsPoly::from_coeffs(
            &coefficients_b,
            &chain,
        );

    let result =
        a.add(&b);

    let expected_coefficients =
        coefficients_a
            .iter()
            .zip(coefficients_b.iter())
            .map(|(&x, &y)| {
                x.wrapping_add(y)
            })
            .collect::<Vec<_>>();

    result.assert_matches_coefficients(
        &expected_coefficients
    );

    for i in 0..chain.len() {
        let q =
            chain.modulus(i);

        let expected =
            PolyRq::from_coeffs(
                &expected_coefficients,
                N,
                q,
            );

        assert_poly_equal(
            result.residue(i),
            &expected,
        );
    }

    println!(
        "RNS addition matches all {} residues.",
        chain.len()
    );
}

#[test]
fn test_rns_multiplication_matches_each_modulus() {
    let chain =
        RnsModulusChain::default();

    let coefficients_a =
        test_coefficients_a();

    let coefficients_b =
        test_coefficients_b();

    let a =
        RnsPoly::from_coeffs(
            &coefficients_a,
            &chain,
        );

    let b =
        RnsPoly::from_coeffs(
            &coefficients_b,
            &chain,
        );

    let result =
        a.mul_negacyclic(&b);

    println!();
    println!(
        "Testing RNS negacyclic multiplication..."
    );

    for i in 0..chain.len() {
        let q =
            chain.modulus(i);

        let lhs =
            PolyRq::from_coeffs(
                &coefficients_a,
                N,
                q,
            );

        let rhs =
            PolyRq::from_coeffs(
                &coefficients_b,
                N,
                q,
            );

        let expected =
            lhs.mul_ntt(&rhs);

        assert_poly_equal(
            result.residue(i),
            &expected,
        );

        println!(
            "  residue {} modulo {}: OK",
            i,
            q
        );
    }

    println!(
        "RNS multiplication matches all {} residues.",
        chain.len()
    );
}

#[test]
fn test_rns_negacyclic_wrap() {
    let chain =
        RnsModulusChain::default();

    let mut x_n_minus_1 =
        vec![0u64; N];

    let mut x =
        vec![0u64; N];

    x_n_minus_1[N - 1] = 1;
    x[1] = 1;

    let a =
        RnsPoly::from_coeffs(
            &x_n_minus_1,
            &chain,
        );

    let b =
        RnsPoly::from_coeffs(
            &x,
            &chain,
        );

    let result =
        a.mul_negacyclic(&b);

    /*
     * X^(N-1) * X
     *
     * = X^N
     *
     * = -1
     *
     * in R_q = Z_q[X] / (X^N + 1).
     */

    for i in 0..chain.len() {
        let q =
            chain.modulus(i);

        let expected =
            PolyRq::from_coeffs(
                &{
                    let mut coeffs =
                        vec![0u64; N];

                    coeffs[0] = q - 1;

                    coeffs
                },
                N,
                q,
            );

        assert_poly_equal(
            result.residue(i),
            &expected,
        );
    }

    println!(
        "RNS negacyclic wrap X^(N-1)*X = -1: OK"
    );
}