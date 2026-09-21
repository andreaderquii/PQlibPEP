use pq_libpep::core::params::{
    prf_modulus_chain,
    Q0,
    Q_BASE,
    RING_DIMENSION,
};
use pq_libpep::core::pid::derive_pid;
use pq_libpep::core::pseudonym::pseudonymize_32;
use pq_libpep::core::rlwr_prf::{
    RlwrPrf,
    RlwrPrfBase,
};

use rand::rngs::StdRng;
use rand::SeedableRng;

fn test_prf() -> RlwrPrf {
    let mut rng = StdRng::seed_from_u64(42);

    let chain = prf_modulus_chain();

    let highest_modulus = *chain.last().unwrap();

    let base = RlwrPrfBase::sample(
        &mut rng,
        RING_DIMENSION,
        highest_modulus,
    );

    RlwrPrf::new(
        base,
        chain,
    )
}

#[test]
fn test_modulus_chain() {
    let chain = prf_modulus_chain();

    assert_eq!(chain.len(), 9);

    assert_eq!(chain[0], 17);
    assert_eq!(chain[1], 289);
    assert_eq!(chain[2], 4_913);
    assert_eq!(chain[3], 83_521);
    assert_eq!(chain[4], 1_419_857);
    assert_eq!(chain[5], 24_137_569);
    assert_eq!(chain[6], 410_338_673);
    assert_eq!(chain[7], 6_975_757_441);
    assert_eq!(chain[8], 118_587_876_497);

    assert!(
        chain.windows(2).all(|w| w[0] < w[1])
    );

    assert_eq!(chain[0], Q0);
    assert_eq!(Q_BASE, 17);
}

#[test]
fn test_id_to_64_byte_pid() {
    let prf = test_prf();

    let id = [0x42u8; 32];

    let poly = pseudonymize_32(&prf, &id);
    let pid = derive_pid(&poly);

    assert_eq!(pid.len(), 64);
    assert_eq!(poly.modulus(), Q0);
    assert_eq!(poly.degree_bound(), RING_DIMENSION);
}

#[test]
fn test_same_id_same_prf_same_pid() {
    let prf = test_prf();

    let id = [0x42u8; 32];

    let pid1 =
        derive_pid(&pseudonymize_32(&prf, &id));

    let pid2 =
        derive_pid(&pseudonymize_32(&prf, &id));

    assert_eq!(pid1, pid2);
}

#[test]
fn test_different_ids_produce_different_pids() {
    let prf = test_prf();

    let id1 = [0x42u8; 32];
    let id2 = [0x43u8; 32];

    let pid1 =
        derive_pid(&pseudonymize_32(&prf, &id1));

    let pid2 =
        derive_pid(&pseudonymize_32(&prf, &id2));

    assert_ne!(pid1, pid2);
}

#[test]
fn test_complete_id_to_pid_pipeline() {
    let prf = test_prf();

    let id = [0xA5u8; 32];

    let poly = pseudonymize_32(&prf, &id);
    let pid = derive_pid(&poly);

    assert_eq!(
        poly.degree_bound(),
        RING_DIMENSION
    );

    assert_eq!(
        poly.modulus(),
        Q0
    );

    assert_eq!(
        pid.len(),
        64
    );
}

#[test]
fn test_string_to_pid() {
    use pq_libpep::core::id_encoding::string_to_id;

    let prf = test_prf();

    let input = "andrea.derqui@ru.nl";

    let id = string_to_id(input);
    let poly = pseudonymize_32(&prf, &id);
    let pid = derive_pid(&poly);

    println!("STRINGA : {}", input);
    println!("ID      : {:02x?}", id);
    println!("POLY    : {:?}", poly.coefficients());
    println!("PID     : {:02x?}", pid);

    assert_eq!(id.len(), 32);
    assert_eq!(pid.len(), 64);
    assert_eq!(poly.modulus(), Q0);
    assert_eq!(poly.degree_bound(), RING_DIMENSION);
}