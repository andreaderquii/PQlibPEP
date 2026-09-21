use pq_libpep::core::rlwe::KeyGenResult;
use pq_libpep::core::rlwe_pke::{decrypt, encrypt};
use rand::thread_rng;

#[test]
fn test_encrypt_decrypt() {
    let mut rng = thread_rng();
    let n = 256;

    let message = vec![0, 1, 1, 0, 1, 0, 1, 1];

    let keygen = KeyGenResult::keygen(&mut rng, n);

    let ciphertext = encrypt(&mut rng, &keygen.pk, &message, n);

    let recovered = decrypt(&keygen.sk, &ciphertext, n, message.len());

    assert_eq!(
        recovered, message,
        "decrypted message does not match the original message"
    );
}


#[test]
fn test_encrypt_decrypt_all_zero() {
    let mut rng = thread_rng();
    let n = 256;

    let message = vec![0u8; 64];

    let keygen = KeyGenResult::keygen(&mut rng, n);
    let ciphertext = encrypt(&mut rng, &keygen.pk, &message, n);

    let recovered = decrypt(&keygen.sk, &ciphertext, n, message.len());

    assert_eq!(recovered, message);
}

#[test]
fn test_encrypt_decrypt_all_one() {
    let mut rng = thread_rng();
    let n = 256;

    let message = vec![1u8; 64];

    let keygen = KeyGenResult::keygen(&mut rng, n);
    let ciphertext = encrypt(&mut rng, &keygen.pk, &message, n);

    let recovered = decrypt(&keygen.sk, &ciphertext, n, message.len());

    assert_eq!(recovered, message);
}

#[test]
fn test_encrypt_decrypt_empty_message() {
    let mut rng = thread_rng();
    let n = 256;

    let message = Vec::<u8>::new();

    let keygen = KeyGenResult::keygen(&mut rng, n);
    let ciphertext = encrypt(&mut rng, &keygen.pk, &message, n);

    let recovered = decrypt(&keygen.sk, &ciphertext, n, message.len());

    assert_eq!(recovered, message);
}

#[test]
fn test_encrypt_decrypt_message_of_degree_n() {
    let mut rng = thread_rng();
    let n = 256;

    let message: Vec<u8> = (0..n)
        .map(|i| (i % 2) as u8)
        .collect();

    let keygen = KeyGenResult::keygen(&mut rng, n);
    let ciphertext = encrypt(&mut rng, &keygen.pk, &message, n);

    let recovered = decrypt(&keygen.sk, &ciphertext, n, message.len());

    assert_eq!(recovered, message);
}

