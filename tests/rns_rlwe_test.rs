use pq_libpep::core::rns::RnsModulusChain;
use pq_libpep::core::rlwe_rns::RnsRlwe;
use rand::{rngs::StdRng, SeedableRng};

#[test]
fn test_rns_rlwe_encrypt_decrypt_roundtrip() {
    let n = 256;
    let chain = RnsModulusChain::default_for_degree(n);

    let mut rng = StdRng::seed_from_u64(0x52534E5F524C5745);

    let rlwe = RnsRlwe::new();
    let keys = rlwe.keygen(&mut rng, &chain);

    let message: Vec<u64> = (0..n)
        .map(|i| ((7 * i + 3) % 17) as u64)
        .collect();

    let ciphertext = rlwe.encrypt(&mut rng, &keys.pk, &message);
    let decrypted = rlwe.decrypt(&keys.sk, &ciphertext);

    assert_eq!(decrypted, message);

    println!("RNS RLWE round-trip: OK");
    println!("  degree       = {}", n);
    println!("  RNS residues = {}", chain.len());
    println!("  plaintext q  = 17");
}

#[test]
fn test_rns_rlwe_zero_plaintext() {
    let n = 256;
    let chain = RnsModulusChain::default_for_degree(n);

    let mut rng = StdRng::seed_from_u64(0x5A45524F);

    let rlwe = RnsRlwe::new();
    let keys = rlwe.keygen(&mut rng, &chain);

    let message = vec![0u64; n];
    let ciphertext = rlwe.encrypt(&mut rng, &keys.pk, &message);
    let decrypted = rlwe.decrypt(&keys.sk, &ciphertext);

    assert_eq!(decrypted, message);
}

#[test]
fn test_rns_rlwe_full_plaintext_range() {
    let n = 256;
    let chain = RnsModulusChain::default_for_degree(n);

    let mut rng = StdRng::seed_from_u64(0x17171717);

    let rlwe = RnsRlwe::new();
    let keys = rlwe.keygen(&mut rng, &chain);

    let message: Vec<u64> = (0..n)
        .map(|i| (i % 17) as u64)
        .collect();

    let ciphertext = rlwe.encrypt(&mut rng, &keys.pk, &message);
    let decrypted = rlwe.decrypt(&keys.sk, &ciphertext);

    assert_eq!(decrypted, message);
}

