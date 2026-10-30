use pq_libpep::core::fast_lwr_prf::{FastLwrPrf, FastLwrPrfParameters, FastLwrPrfSecretKey};
use pq_libpep::core::fast_lwr_prf_private_tfhe::{
    FastLwrPrfPrivateInputClient, FastLwrPrfPrivateInputEvaluationKey,
};

fn small_fixture() -> (FastLwrPrfParameters, FastLwrPrfSecretKey) {
    let parameters = FastLwrPrfParameters {
        lwr_dimension: 8,
        ring_dimension: 64,
        output_modulus: 4,
    };
    let key = FastLwrPrfSecretKey::from_bits(parameters, vec![1, 0, 1, 1, 0, 1, 0, 1])
        .expect("valid toy key");
    (parameters, key)
}

#[test]
fn private_input_encrypted_prf_matches_cleartext_reference_for_several_slots() {
    // Tiny parameters test functionality only. They are not secure parameters.
    let (parameters, prf_key) = small_fixture();
    let reference = FastLwrPrf::new(prf_key.clone());
    let (client, server_key) =
        FastLwrPrfPrivateInputClient::generate(parameters).expect("generate TFHE recipient keys");
    let evaluation_key =
        FastLwrPrfPrivateInputEvaluationKey::new(&prf_key, client.public_key(), server_key)
            .expect("encrypt the PRF key under recipient public key");

    let input = b"pqpep-private-input-smoke";
    let expected = reference.evaluate_many(input, 3);

    for (offset, expected_symbol) in expected.into_iter().enumerate() {
        let slot = (offset + 1) as u64;
        let encrypted_input = client
            .encrypt_input(input, slot)
            .expect("encrypt indexed H(x, i) vector");
        assert_eq!(
            encrypted_input.coefficient_count(),
            parameters.lwr_dimension
        );
        let encrypted_output = evaluation_key
            .evaluate(&encrypted_input)
            .expect("evaluate with encrypted input and encrypted PRF key");
        assert_eq!(encrypted_output.output_index(), slot);
        let actual = client
            .decrypt_output(&encrypted_output)
            .expect("decrypt output as recipient");
        assert_eq!(actual as u64, expected_symbol, "slot {slot}");
    }
}

#[test]
fn private_input_api_rejects_zero_output_index() {
    let (parameters, prf_key) = small_fixture();
    let (client, server_key) =
        FastLwrPrfPrivateInputClient::generate(parameters).expect("generate TFHE recipient keys");
    let _evaluation_key =
        FastLwrPrfPrivateInputEvaluationKey::new(&prf_key, client.public_key(), server_key)
            .expect("encrypt the PRF key");
    assert!(client.encrypt_input(b"x", 0).is_err());
}
