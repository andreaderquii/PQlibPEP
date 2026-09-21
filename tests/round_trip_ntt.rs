use pq_libpep::algebra::ntt::{ConcreteNttContext, CustomNttContext};

fn mod_pow(mut base: u64, mut exp: u64, modulus: u64) -> u64 {
    let mut result = 1u128;
    let mut b = base as u128;
    let m = modulus as u128;

    while exp > 0 {
        if exp & 1 == 1 {
            result = result * b % m;
        }

        b = b * b % m;
        exp >>= 1;
    }
    result as u64
}

fn mod_inverse(a: u64, q: u64) -> u64 {
    mod_pow(a, q - 2, q)
}

#[test]
fn compare_custom_and_concrete_roundtrip() {
    //q = 1 mod{2n}
    let n = 16;
    let q = 998_244_353u64;

    let custom = CustomNttContext::new(n, q);
    let concrete = ConcreteNttContext::new(n, q);

    let input: Vec<u64> = (0..n).map(|i| (7 * i as u64 + 13) % q).collect();

    // Custom
    let mut custom_result = input.clone();
    custom.forward(&mut custom_result);
    custom.inverse(&mut custom_result);
    assert_eq!(custom_result, input);

    // Concrete
    let mut concrete_result = input.clone();
    concrete.forward(&mut concrete_result);
    concrete.inverse(&mut concrete_result);

    // concrete-ntt gives N * input, a different convention than custom-ntt, so we need to scale down by N to compare results
    // must normalize the result by multiplying by N^-1 mod q
    let expected_concrete: Vec<u64> = input
        .iter()
        .map(|&x| ((x as u128 * n as u128) % q as u128) as u64)
        .collect();

    assert_eq!(concrete_result, expected_concrete);

    // Normalize
    let n_inv = mod_inverse(n as u64, q);
    for x in concrete_result.iter_mut() {
        *x = ((*x as u128 * n_inv as u128) % q as u128) as u64;
    }
    assert_eq!(concrete_result, input);

    // Compare
    assert_eq!(custom_result, concrete_result);
}
