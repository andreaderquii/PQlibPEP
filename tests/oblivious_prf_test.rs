use pq_libpep::core::id_encoding::{
    bytes_to_bits,
    string_to_id,
};

use pq_libpep::core::oblivious_prf::{
    EncryptedInput,
    ObliviousPrf,
};

use pq_libpep::core::rlwe::KeyGenResult;
use pq_libpep::core::rlwe_pke::encrypt;
use pq_libpep::core::transcryptor::Transcryptor;

use rand::thread_rng;

const N: usize = 256;

#[test]
fn test_oblivious_prf_encrypted_input() {
    let mut rng = thread_rng();

    // 1. Encode an identifier as exactly 256 bits.
    let input = "patient-001";
    let id = string_to_id(input);
    let bits = bytes_to_bits(&id);

    assert_eq!(id.len(), 32);
    assert_eq!(bits.len(), N);

    assert!(
        bits.iter().all(|&bit| bit == 0 || bit == 1),
        "identifier encoding must produce only binary values"
    );

    // 2. Generate the RLWE key pair.
    let keygen = KeyGenResult::keygen(
        &mut rng,
        N,
    );

    // 3. Encrypt each bit independently.
    let encrypted_bits = bits
        .iter()
        .map(|&bit| {
            encrypt(
                &mut rng,
                &keygen.pk,
                &[bit],
                N,
            )
        })
        .collect::<Vec<_>>();

    // 4. Assemble the encrypted input.
    let encrypted_input = EncryptedInput {
        bits: encrypted_bits,
    };

    assert_eq!(
        encrypted_input.bits.len(),
        N,
        "encrypted input must contain 256 ciphertexts"
    );

    // 5. Construct the current PRF interface.
    //
    // The actual oblivious PRF evaluation is not implemented yet.
    let oblivious_prf = ObliviousPrf::new();
    let _transcryptor = Transcryptor::new(oblivious_prf);

    // 6. Verify each encrypted bit locally.
    for (index, ciphertext) in
        encrypted_input.bits.iter().enumerate()
    {
        let recovered = pq_libpep::core::rlwe_pke::decrypt(
            &keygen.sk,
            ciphertext,
            N,
            1,
        );

        assert_eq!(
            recovered[0],
            bits[index],
            "encrypted bit {} did not decrypt correctly",
            index
        );
    }

    println!("Identifier bytes = {}", id.len());
    println!("Input bits = {}", bits.len());
    println!(
        "Encrypted bits = {}",
        encrypted_input.bits.len()
    );
    println!("Encrypted input round-trip: OK");
}