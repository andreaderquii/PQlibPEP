use rand::thread_rng;

use pq_libpep::core::rlwe::KeyGenResult;

#[test]
fn test_rlwe_keygen_relation() {
    let mut rng = thread_rng();
    let n = 256;

    let result = KeyGenResult::keygen(&mut rng, n);

    let sk = result.sk;
    let pk = result.pk;
    let error = result.error;

    // Compute a * s independently from the stored public key.
    let as_prod = pk.a.mul_ntt(&sk.s);

    // Compute b - a*s.
    let recovered_error = pk.b.sub(&as_prod);

    let mut recovered_error_coeffs = recovered_error.to_coeffs_vec();
    recovered_error_coeffs.resize(n, 0);

    let mut error_coeffs = error.to_coeffs_vec();
    error_coeffs.resize(n, 0);

    assert_eq!(
        recovered_error_coeffs, error_coeffs,
        "RLWE relation b - a*s = e does not hold"
    );
}