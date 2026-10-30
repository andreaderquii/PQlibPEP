//! TFHE programmable-bootstrap evaluator for the modified PRF in Section 5.
//!
//! This module is intentionally separate from `oblivious_prf`: the paper's
//! construction takes a public input x and an evaluation key derived from the
//! encrypted PRF key. It does not provide private-input evaluation.
//! It also does not provide PEP RS2: the key-dependent LWR rounding does not
//! define a conversion from an existing F_{s_A}(x) to F_{s_B}(x).
//!
//! The backend uses TFHE-rs core_crypto APIs and a single PBS with a negacyclic
//! LUT. Parameter and noise choices are an implementation baseline, not a new
//! security proof; do not label a deployment production-secure without running
//! a current estimator and reviewing the complete key-generation setup.

use super::fast_lwr_prf::{hash_to_ring_vector, FastLwrPrfParameters, FastLwrPrfSecretKey};
use rayon::prelude::*;
use tfhe::core_crypto::algorithms::lwe_programmable_bootstrapping::fft128_pbs::programmable_bootstrap_f128_lwe_ciphertext;
use tfhe::core_crypto::fft_impl::fft128::crypto::bootstrap::Fourier128LweBootstrapKeyOwned;
use tfhe::core_crypto::prelude::*;

const PBS_BASE_LOG: usize = 23;
const PBS_LEVEL_COUNT: usize = 1;
const OUTPUT_GLWE_DIMENSION: usize = 1;

/// A TFHE ciphertext of one output symbol. It is encrypted under the output
/// LWE key derived from the GLWE key used by the bootstrap key.
pub struct FastLwrPrfCiphertext {
    parameters: FastLwrPrfParameters,
    ciphertext: LweCiphertext<Vec<u128>>,
}

impl FastLwrPrfCiphertext {
    /// Parameters associated with this ciphertext.
    pub fn parameters(&self) -> FastLwrPrfParameters {
        self.parameters
    }

    /// Borrows the underlying TFHE LWE ciphertext.
    ///
    /// This is useful for a later key-switch or for composing this PRF with
    /// another low-level TFHE operation. The ciphertext is under the output
    /// LWE key associated with the client key returned by `setup_tfhe`.
    pub fn lwe_ciphertext(&self) -> &LweCiphertext<Vec<u128>> {
        &self.ciphertext
    }

    /// Consumes the wrapper and returns the underlying TFHE LWE ciphertext.
    pub fn into_lwe_ciphertext(self) -> LweCiphertext<Vec<u128>> {
        self.ciphertext
    }
}

/// Client-side decryption material. The PRF key is not included in this object;
/// the caller may erase its cleartext key after evaluation-key generation.
pub struct FastLwrPrfTfheClientKey {
    parameters: FastLwrPrfParameters,
    output_secret_key: LweSecretKey<Vec<u128>>,
}

/// Server-side evaluation material: the Fourier-domain GGSW evaluation key
/// and the public test polynomial used by the depth-1 PBS construction.
pub struct FastLwrPrfTfheEvaluationKey {
    parameters: FastLwrPrfParameters,
    bootstrapping_key: Fourier128LweBootstrapKeyOwned,
    accumulator: GlweCiphertext<Vec<u128>>,
}

/// Creates client and evaluation keys from the clear binary PRF key.
///
/// The source LWE key is exactly the PRF secret vector `s`; TFHE encrypts its
/// bits into the GGSW entries of the bootstrap key. The returned evaluation
/// key contains no cleartext PRF key or output secret key.
pub fn setup_tfhe(
    prf_secret_key: &FastLwrPrfSecretKey,
) -> (FastLwrPrfTfheClientKey, FastLwrPrfTfheEvaluationKey) {
    let parameters = prf_secret_key.parameters();
    parameters
        .validate()
        .expect("FastLwrPrfSecretKey must contain valid parameters");

    let polynomial_size = PolynomialSize(parameters.ring_dimension);
    let glwe_dimension = GlweDimension(OUTPUT_GLWE_DIMENSION);
    let glwe_size = glwe_dimension.to_glwe_size();
    let source_lwe_dimension = LweDimension(parameters.lwr_dimension);
    let base_log = DecompositionBaseLog(PBS_BASE_LOG);
    let level_count = DecompositionLevelCount(PBS_LEVEL_COUNT);
    let ciphertext_modulus = CiphertextModulus::new_native();

    // TFHE-rs uses a 128-bit torus here so that the LUT scale q/(2N) is exact.
    // The normalized standard deviation matches the core_crypto example for
    // this 128-bit PBS path; these values still require a parameter/security
    // audit before production use.
    let glwe_sigma = 2.940_360_153_543_253_3e-16_f64;
    let glwe_noise_distribution = Gaussian::from_dispersion_parameter(StandardDev(glwe_sigma), 0.0);

    let mut boxed_seeder = new_seeder();
    let seeder = boxed_seeder.as_mut();
    let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

    // The PRF key is a binary LWR vector. Wrap those same bits as the input LWE
    // secret key; do not sample a different key here.
    let source_secret_key = LweSecretKey::from_container(
        prf_secret_key
            .bits()
            .iter()
            .map(|&bit| bit as u128)
            .collect::<Vec<_>>(),
    );

    // Independent output key. Section 5 explicitly permits a different TFHE
    // output key to preserve key separation from the PRF key.
    let output_glwe_secret_key =
        GlweSecretKey::generate_new_binary(glwe_dimension, polynomial_size, &mut secret_generator);
    let output_secret_key = output_glwe_secret_key.clone().into_lwe_secret_key();

    // This is the evaluation-key construction bsk[j] = GGSW_{s'}(s_j).
    let seeded_bootstrapping_key = par_allocate_and_generate_new_seeded_lwe_bootstrap_key(
        &source_secret_key,
        &output_glwe_secret_key,
        base_log,
        level_count,
        glwe_noise_distribution,
        ciphertext_modulus,
        seeder,
    );
    let standard_bootstrapping_key: LweBootstrapKeyOwned<u128> =
        seeded_bootstrapping_key.decompress_into_lwe_bootstrap_key();

    let mut fourier_bootstrapping_key = Fourier128LweBootstrapKey::new(
        source_lwe_dimension,
        glwe_size,
        polynomial_size,
        base_log,
        level_count,
    );
    convert_standard_lwe_bootstrap_key_to_fourier_128(
        &standard_bootstrapping_key,
        &mut fourier_bootstrapping_key,
    );
    drop(standard_bootstrapping_key);

    // Keep TFHE-rs' owned aligned representation. Fourier128LweBootstrapKey
    // stores four separate aligned buffers; `.data()` returns a tuple, not a
    // flat slice, so rebuilding it as `Vec<f64>` is invalid.
    let bootstrapping_key: Fourier128LweBootstrapKeyOwned = fourier_bootstrapping_key;

    // The Section 5 test polynomial is v_i = floor(i*p/N) mod p. The LUT's
    // *output* encoding uses delta_out = q/(2p), while the input LWE mask uses
    // delta_in = q/(2N). The negacyclic extension supplies the sign for phases
    // in [N, 2N).
    let output_delta = (1_u128 << 127) / (parameters.output_modulus as u128);
    let accumulator: GlweCiphertext<Vec<u128>> = generate_programmable_bootstrap_glwe_lut(
        polynomial_size,
        glwe_size,
        parameters.ring_dimension,
        ciphertext_modulus,
        output_delta,
        |x: u128| {
            ((parameters.output_modulus as u128) * x / (parameters.ring_dimension as u128))
                % (parameters.output_modulus as u128)
        },
    );

    (
        FastLwrPrfTfheClientKey {
            parameters,
            output_secret_key,
        },
        FastLwrPrfTfheEvaluationKey {
            parameters,
            bootstrapping_key,
            accumulator,
        },
    )
}

impl FastLwrPrfTfheEvaluationKey {
    pub fn parameters(&self) -> FastLwrPrfParameters {
        self.parameters
    }

    /// Evaluates the first component of the paper's vector PRF, H(x, 1),
    /// using exactly one PBS.
    pub fn evaluate(&self, input: &[u8]) -> FastLwrPrfCiphertext {
        self.evaluate_component(input, 1)
    }

    /// Evaluates the indexed output H(x, i), matching the cleartext reference.
    pub fn evaluate_component(&self, input: &[u8], output_index: u64) -> FastLwrPrfCiphertext {
        assert!(output_index > 0, "PRF output indices start at one");
        self.evaluate_with_output_index(input, output_index)
    }

    /// Evaluates `count` output components for the same public input. Each
    /// component uses one PBS. Four or more slots are evaluated in parallel;
    /// Rayon preserves indexed collection order, so slot i remains at i - 1.
    ///
    /// The returned values are encrypted. Decryption belongs on the client.
    pub fn evaluate_many(&self, input: &[u8], count: usize) -> Vec<FastLwrPrfCiphertext> {
        if count == 0 {
            return Vec::new();
        }
        if count < 4 {
            return (1..=count)
                .map(|index| self.evaluate_component(input, index as u64))
                .collect();
        }
        (1..=count)
            .into_par_iter()
            .map(|index| self.evaluate_component(input, index as u64))
            .collect()
    }

    fn evaluate_with_output_index(&self, input: &[u8], output_index: u64) -> FastLwrPrfCiphertext {
        let a = hash_to_ring_vector(self.parameters, input, output_index);
        let n = self.parameters.lwr_dimension;
        let delta = (1_u128 << 127) / (self.parameters.ring_dimension as u128);

        // The input LWE encoding has delta_in = q/(2N). The LWE mask is -a*
        // delta_in and the body is zero, so its phase under s is
        // <a,s>*delta_in modulo q. The LUT separately uses delta_out = q/(2p).
        let mut raw_input = vec![0_u128; n + 1];
        for (mask, coefficient) in raw_input[..n].iter_mut().zip(a.iter()) {
            *mask = 0_u128.wrapping_sub((*coefficient as u128) * delta);
        }
        let input_ciphertext =
            LweCiphertext::from_container(raw_input, CiphertextModulus::new_native());

        let output_lwe_dimension = self.parameters.ring_dimension * OUTPUT_GLWE_DIMENSION;
        let mut output_ciphertext = LweCiphertext::new(
            0_u128,
            LweDimension(output_lwe_dimension).to_lwe_size(),
            CiphertextModulus::new_native(),
        );
        programmable_bootstrap_f128_lwe_ciphertext(
            &input_ciphertext,
            &mut output_ciphertext,
            &self.accumulator,
            &self.bootstrapping_key,
        );

        FastLwrPrfCiphertext {
            parameters: self.parameters,
            ciphertext: output_ciphertext,
        }
    }
}

impl FastLwrPrfTfheClientKey {
    pub fn parameters(&self) -> FastLwrPrfParameters {
        self.parameters
    }

    /// Decrypts a vector produced by `FastLwrPrfTfheEvaluationKey::evaluate_many`.
    pub fn decrypt_many(&self, ciphertexts: &[FastLwrPrfCiphertext]) -> Vec<u64> {
        ciphertexts
            .iter()
            .map(|ciphertext| self.decrypt(ciphertext))
            .collect()
    }

    /// Decrypts and maps the signed torus output back into Z_p.
    pub fn decrypt(&self, ciphertext: &FastLwrPrfCiphertext) -> u64 {
        assert_eq!(
            self.parameters, ciphertext.parameters,
            "ciphertext parameters do not match the client key"
        );
        let plaintext: Plaintext<u128> =
            decrypt_lwe_ciphertext(&self.output_secret_key, &ciphertext.ciphertext);
        // The LUT output uses TFHE's signed encoding with one padding bit:
        // delta_out = 2^127 / p. The decomposition must therefore preserve
        // log2(2p) most-significant bits, not log2(2N).
        let output_delta = (1_u128 << 127) / (self.parameters.output_modulus as u128);
        let decomposition_base_log =
            DecompositionBaseLog((self.parameters.output_modulus.trailing_zeros() + 1) as usize);
        let decomposer = SignedDecomposer::new(decomposition_base_log, DecompositionLevelCount(1));
        let rounded = decomposer.closest_representable(plaintext.0);
        ((rounded / output_delta) % (self.parameters.output_modulus as u128)) as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::fast_lwr_prf::FastLwrPrf;

    fn small_test_key() -> (FastLwrPrfParameters, FastLwrPrfSecretKey) {
        let parameters = FastLwrPrfParameters {
            lwr_dimension: 8,
            ring_dimension: 64,
            output_modulus: 4,
        };
        let secret_key =
            FastLwrPrfSecretKey::from_bits(parameters, vec![1, 0, 1, 1, 0, 1, 0, 1]).unwrap();
        (parameters, secret_key)
    }

    #[test]
    fn tfhe_single_pbs_matches_cleartext_reference_on_small_parameters() {
        // Tiny parameters are for functional testing only, not security.
        let (_parameters, secret_key) = small_test_key();
        let clear_reference = FastLwrPrf::new(secret_key.clone());
        let (client_key, evaluation_key) = setup_tfhe(&secret_key);
        let input = b"fast-lwr-prf-smoke-test";

        let ciphertext = evaluation_key.evaluate(input);
        assert_eq!(
            client_key.decrypt(&ciphertext),
            clear_reference.evaluate(input)
        );

        // Check many public inputs under the same evaluation key.
        for suffix in 0u8..24 {
            let mut sample = input.to_vec();
            sample.push(suffix);
            let encrypted = evaluation_key.evaluate(&sample);
            assert_eq!(
                client_key.decrypt(&encrypted),
                clear_reference.evaluate(&sample),
                "single-output mismatch for suffix {suffix}"
            );
        }

        // Check the complete multi-output path: H(x, i) -> PBS -> decryption.
        let count = 12;
        let encrypted_vector = evaluation_key.evaluate_many(input, count);
        let decrypted_vector = client_key.decrypt_many(&encrypted_vector);
        let expected_vector = clear_reference.evaluate_many(input, count);
        assert_eq!(decrypted_vector, expected_vector);
        assert_eq!(
            decrypted_vector[0],
            client_key.decrypt(&evaluation_key.evaluate(input)),
            "single-output API must equal vector component 1 (H(x, 1))"
        );
        assert!(decrypted_vector
            .iter()
            .all(|&symbol| symbol < evaluation_key.parameters().output_modulus));

        // A zero-length request is a valid empty vector and performs no PBS.
        assert!(evaluation_key.evaluate_many(input, 0).is_empty());
        assert!(client_key.decrypt_many(&[]).is_empty());
    }

    /// Expensive end-to-end check using the paper's N=2048, p=32, n=445
    /// setting. Kept ignored for the ordinary quick test suite because key
    /// generation is much heavier than the tiny functional test. Run it in
    /// release mode before using the paper-size configuration.
    #[test]
    #[ignore = "paper-size TFHE key generation; run explicitly in release mode"]
    fn paper_default_parameters_match_cleartext_reference() {
        let parameters = FastLwrPrfParameters::paper_default();
        let mut rng = rand::rngs::OsRng;
        let secret_key =
            FastLwrPrfSecretKey::generate(parameters, &mut rng).expect("generate PRF key");
        let clear_reference = FastLwrPrf::new(secret_key.clone());

        let (client_key, evaluation_key) = setup_tfhe(&secret_key);
        assert_eq!(evaluation_key.parameters(), parameters);
        assert_eq!(client_key.parameters(), parameters);

        for input in [
            &b"paper-default-test-a"[..],
            &b"paper-default-test-b"[..],
            &b"identifier-00000000000000000001"[..],
        ] {
            let encrypted = evaluation_key.evaluate(input);
            assert_eq!(
                client_key.decrypt(&encrypted),
                clear_reference.evaluate(input),
                "single-output mismatch for input {:?}",
                input
            );
        }

        let input = b"paper-default-vector-output";
        let encrypted_vector = evaluation_key.evaluate_many(input, 16);
        let decrypted_vector = client_key.decrypt_many(&encrypted_vector);
        assert_eq!(
            decrypted_vector,
            clear_reference.evaluate_many(input, 16),
            "multi-output mismatch under paper-default parameters"
        );
    }
}
