use pq_libpep::algebra::ntt::ConcreteNttContext;
use pq_libpep::algebra::ring::PolyRq; // Assicurati che il percorso della NTT sia corretto

/// Moltiplicazione negaciclica di riferimento (naive O(n^2)) per validare il test
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
                let index = k - n;
                result[index] = ((result[index] as u128 + q as u128 - product) % q as u128) as u64;
            }
        }
    }
    result
}

#[test]
fn test_ark_poly_with_ntt_multiplication() {
    let n = 16;
    let q = 998_244_353u64;

    // 1. Creazione di due polinomi di test tramite la nostra struct PolyRq
    let raw_a = vec![3, 2, 1, 6, 7, 8, 9, 1, 8, 0, 0, 0, 0, 0, 0, 0];
    let raw_b = vec![1, 5, 4, 6, 7, 9, 2, 1, 4, 0, 0, 0, 0, 0, 0, 0];

    let poly_a = PolyRq::from_coeffs(&raw_a, n, q);
    let poly_b = PolyRq::from_coeffs(&raw_b, n, q);

    // 2. Calcolo del risultato atteso con la moltiplicazione naive negaciclica
    let expected_coeffs = negacyclic_mul_naive(&raw_a, &raw_b, q);

    // 3. Esecuzione della NTT tramite concrete-ntt bridge
    let ntt_ctx = ConcreteNttContext::new(n, q);

    let mut coeffs_a = poly_a.to_coeffs_vec();
    let mut coeffs_b = poly_b.to_coeffs_vec();
    coeffs_a.resize(n, 0);
    coeffs_b.resize(n, 0);

    ntt_ctx.forward(&mut coeffs_a);
    ntt_ctx.forward(&mut coeffs_b);

    let mut coeffs_res = vec![0u64; n];
    for i in 0..n {
        coeffs_res[i] = ((coeffs_a[i] as u128 * coeffs_b[i] as u128) % q as u128) as u64;
    }

    ntt_ctx.inverse(&mut coeffs_res);

    // Normalizzazione per N^-1
    let n_inv = {
        let base = n as u64;
        let mut exp = q - 2;
        let mut res = 1u128;
        let mut b = base as u128;
        let m = q as u128;
        while exp > 0 {
            if exp & 1 == 1 {
                res = (res * b) % m;
            }
            b = (b * b) % m;
            exp >>= 1;
        }
        res as u64
    };

    for x in coeffs_res.iter_mut() {
        *x = ((*x as u128 * n_inv as u128) % q as u128) as u64;
    }

    // 4. Wrapping del risultato finale in un PolyRq basato su arkworks
    let result_poly = PolyRq::from_coeffs(&coeffs_res, n, q);
    let mut final_vector = result_poly.to_coeffs_vec();

    // Riportiamo il vettore alla dimensione n aggiungendo gli zeri di padding trimmati da arkworks
    final_vector.resize(n, 0);

    // 5. Assert di verifica
    assert_eq!(
        final_vector, expected_coeffs,
        "La moltiplicazione NTT con arkworks non coincide con il riferimento negaciclico!"
    );

    println!(
        "Test superato con successo! Risultato NTT: {:?}",
        final_vector
    );
}
