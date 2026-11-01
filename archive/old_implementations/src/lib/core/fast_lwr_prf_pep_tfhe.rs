//! PEP-oriented private-input adapter for the Section 5 LWR PRF.
//!
//! This prototype keeps the identifier/hash vector and PRF output encrypted
//! while performing the linear LWR dot product and one PBS per output symbol.
//! It deliberately follows the traditional PEP trust model in which the
//! transcryptor holds the pseudonymisation factor `s`; it does NOT hide `s`
//! from the transcryptor. The source domain computes H(x, slot) locally and
//! encrypts the vector as a GLWE plaintext polynomial under its own TFHE key.
//! A bootstrapping key maps that source key to the recipient's output key, so
//! evaluation and A->B ciphertext conversion happen in the same PBS path.
//!
//! Experimental candidate: 8-coefficient logical blocks, 8x PBS expansion,
//! but with a source GLWE key sized to the full LWR vector. This removes the
//! trivial 8-bit source-key search-space flaw of the faster B8/E8 experiment.
//! It is still NOT a production security claim: the custom TFHE parameters,
//! modulus-switch failure probability, and lattice security must be evaluated.
//! This file is an experimental adapter, not a production security claim.
//! It evaluates the PRF on an encrypted encoding of H(x,i); it does not
//! convert an already computed F_{s_A}(x) into F_{s_B}(x), and therefore does
//! not implement PEP RS2. The local setup also gives the full PRF key to one
//! evaluator rather than generating distributed factor shares as in n-PEP.
//! The setup helper below creates source/recipient/evaluator material in one
//! process for tests; production needs an appropriate distributed key-setup
//! protocol, serialization, key IDs, parameter review, and authentication.

use core::fmt;
use std::error::Error;

use super::fast_lwr_prf::{hash_to_ring_vector, FastLwrPrfParameters, FastLwrPrfSecretKey};
use tfhe::core_crypto::algorithms::glwe_encryption::encrypt_glwe_ciphertext_assign;
use tfhe::core_crypto::algorithms::glwe_sample_extraction::extract_lwe_sample_from_glwe_ciphertext;
use tfhe::core_crypto::fft_impl::fft128::crypto::bootstrap::Fourier128LweBootstrapKeyOwned;
use tfhe::core_crypto::prelude::*;
use tfhe::core_crypto::algorithms::lwe_programmable_bootstrapping::fft128_pbs::programmable_bootstrap_f128_lwe_ciphertext;


const PBS_BASE_LOG: usize = 23;
const PBS_LEVEL_COUNT: usize = 5;
// Logical plaintext chunk size per ciphertext. IMPORTANT: this does not set
// the source secret-key dimension; the GLWE polynomial/key size remains the
// next power of two of the full LWR dimension (512 for n_LWR=445).
const INPUT_LWE_BLOCK_SIZE: usize = 8;
// Experimental PBS expansion. With 8-dimensional input LWE, this is intended to
// preserve a decision margin while reducing the PBS and key-switching cost.
// These are correctness experiments, not production security parameters.
const PBS_POLY_EXPANSION_FACTOR: usize = 8;
const GLWE_DIMENSION: usize = 1;
const GLWE_SIZE: usize = GLWE_DIMENSION + 1;
const TORUS_GAUSSIAN_STD_DEV: f64 = 2.940_360_153_543_253_3e-16_f64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PepLwrPrfError(pub String);

impl fmt::Display for PepLwrPrfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Error for PepLwrPrfError {}

type Result<T> = std::result::Result<T, PepLwrPrfError>;

fn input_polynomial_size(parameters: FastLwrPrfParameters) -> Result<usize> {
    // Keep the source GLWE/LWE secret dimension large enough to match the full
    // LWR vector, instead of accidentally reducing the binary secret to 8 bits.
    parameters
        .lwr_dimension
        .checked_next_power_of_two()
        .map(|n| n.max(2))
        .ok_or_else(|| PepLwrPrfError("LWR dimension is too large".into()))
}

fn validate_pep_parameters(parameters: FastLwrPrfParameters) -> Result<()> {
    parameters
        .validate()
        .map_err(|e| PepLwrPrfError(e.to_string()))?;
    input_polynomial_size(parameters)?;
    if parameters.output_modulus > 256 {
        return Err(PepLwrPrfError(
            "byte-output adapter currently requires p <= 256".into(),
        ));
    }
    Ok(())
}

/// Number of `Z_p` symbols required for a byte string. For paper parameters
/// p=32, 64 bytes require 103 symbols (515 bits, of which the last 3 are cut).
pub fn output_symbols_for_bytes(
    parameters: FastLwrPrfParameters,
    output_len_bytes: usize,
) -> Result<usize> {
    validate_pep_parameters(parameters)?;
    let bits_per_symbol = parameters.output_modulus.trailing_zeros() as usize;
    let required_bits = output_len_bytes
        .checked_mul(8)
        .ok_or_else(|| PepLwrPrfError("requested output length is too large".into()))?;
    Ok(required_bits
        .checked_add(bits_per_symbol - 1)
        .ok_or_else(|| PepLwrPrfError("requested output length is too large".into()))?
        / bits_per_symbol)
}

/// Source-domain client: owns the source GLWE secret key and encrypts H(x,i).
/// Raw `input` and the clear hash vector are never included in the ciphertext
/// object returned to the evaluator.
pub struct FastLwrPrfPepInputClient {
    parameters: FastLwrPrfParameters,
    input_polynomial_size: PolynomialSize,
    input_glwe_secret_key: GlweSecretKey<Vec<u128>>,
}

/// Recipient client: owns only the output LWE secret key and decrypts symbols.
pub struct FastLwrPrfPepRecipientKey {
    parameters: FastLwrPrfParameters,
    output_lwe_secret_key: LweSecretKey<Vec<u128>>,
}

/// Transcryptor-side material. The LWR pseudonymisation factor is held in clear
/// in this object as in the PEP converter trust model. Input and output values
/// are encrypted; if the key must also be hidden from the transcryptor, this
/// implementation is not that security model.
pub struct FastLwrPrfPepEvaluator {
    parameters: FastLwrPrfParameters,
    input_polynomial_size: PolynomialSize,
    output_polynomial_size: PolynomialSize,
    prf_secret_bits: Vec<u8>,
    bootstrapping_key: Fourier128LweBootstrapKeyOwned,
    accumulator: GlweCiphertext<Vec<u128>>,
}

/// One encrypted vector H(x, slot), split into short GLWE blocks. Each block
/// contains a consecutive segment of the hash vector, padded with zeros when
/// the final segment is shorter than the block size.
pub struct EncryptedFastLwrPrfPepInput {
    parameters: FastLwrPrfParameters,
    output_index: u64,
    ciphertexts: Vec<GlweCiphertext<Vec<u128>>>,
}

impl EncryptedFastLwrPrfPepInput {
    pub fn parameters(&self) -> FastLwrPrfParameters {
        self.parameters
    }

    pub fn output_index(&self) -> u64 {
        self.output_index
    }

    /// Borrow all source-domain GLWE ciphertext blocks. None contains plaintext.
    pub fn glwe_ciphertexts(&self) -> &[GlweCiphertext<Vec<u128>>] {
        &self.ciphertexts
    }

    pub fn into_glwe_ciphertexts(self) -> Vec<GlweCiphertext<Vec<u128>>> {
        self.ciphertexts
    }
}

/// One encrypted PRF symbol under the recipient's output LWE key.
pub struct EncryptedFastLwrPrfPepOutput {
    parameters: FastLwrPrfParameters,
    output_index: u64,
    ciphertext: LweCiphertext<Vec<u128>>,
}

impl EncryptedFastLwrPrfPepOutput {
    pub fn parameters(&self) -> FastLwrPrfParameters {
        self.parameters
    }

    pub fn output_index(&self) -> u64 {
        self.output_index
    }

    pub fn lwe_ciphertext(&self) -> &LweCiphertext<Vec<u128>> {
        &self.ciphertext
    }

    pub fn into_lwe_ciphertext(self) -> LweCiphertext<Vec<u128>> {
        self.ciphertext
    }
}

/// Creates source, recipient and evaluator contexts for local experiments.
/// The source secret and recipient secret are returned in separate objects;
/// only the evaluator object is used to evaluate encrypted inputs.
pub fn setup_pep_lwr_prf(
    parameters: FastLwrPrfParameters,
    prf_secret_key: &FastLwrPrfSecretKey,
) -> Result<(
    FastLwrPrfPepInputClient,
    FastLwrPrfPepRecipientKey,
    FastLwrPrfPepEvaluator,
)> {
    validate_pep_parameters(parameters)?;
    if prf_secret_key.parameters() != parameters {
        return Err(PepLwrPrfError(
            "PRF key parameters do not match setup parameters".into(),
        ));
    }

    let input_n = input_polynomial_size(parameters)?;
    let input_polynomial_size = PolynomialSize(input_n);
    // The LWR modulus N remains unchanged. Plaintext values are split into
    // 8-coefficient chunks, but each GLWE ciphertext uses the full source
    // polynomial size (512 for n_LWR=445), so its binary secret does not have
    // only 8 bits of entropy. The extracted LWE samples are summed before one
    // PBS. The PBS input dimension is the full source dimension, not the chunk
    // size; consequently this candidate may be much slower and may still need
    // different PBS parameters for correctness. This is not a security claim.
    let output_n = parameters
        .ring_dimension
        .checked_mul(PBS_POLY_EXPANSION_FACTOR)
        .ok_or_else(|| PepLwrPrfError("expanded PBS polynomial size overflows usize".into()))?;
    let output_polynomial_size = PolynomialSize(output_n);
    let glwe_dimension = GlweDimension(GLWE_DIMENSION);
    let glwe_size = glwe_dimension.to_glwe_size();
    let ciphertext_modulus = CiphertextModulus::new_native();

    let mut boxed_seeder = new_seeder();
    let seeder = boxed_seeder.as_mut();
    let mut secret_generator =
        SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

    // This is the source-domain encryption key for H(x,slot), independent of
    // the PRF key and independent of the recipient's output decryption key.
    let input_glwe_secret_key = GlweSecretKey::generate_new_binary(
        glwe_dimension,
        input_polynomial_size,
        &mut secret_generator,
    );
    let input_lwe_secret_key = input_glwe_secret_key.clone().into_lwe_secret_key();

    // The recipient's output secret key is the flattening of an independent
    // GLWE key with the paper's output polynomial degree N.
    let output_glwe_secret_key = GlweSecretKey::generate_new_binary(
        glwe_dimension,
        output_polynomial_size,
        &mut secret_generator,
    );
    let output_lwe_secret_key = output_glwe_secret_key.clone().into_lwe_secret_key();

    // The PBS evaluation key maps an LWE sample extracted under the source
    // GLWE key to an output ciphertext under the recipient's GLWE-derived key.
    let base_log = DecompositionBaseLog(PBS_BASE_LOG);
    let level_count = DecompositionLevelCount(PBS_LEVEL_COUNT);
    // TFHE-rs from_dispersion_parameter expects variance (sigma squared).
    let glwe_noise_distribution = Gaussian::from_dispersion_parameter(
        StandardDev(TORUS_GAUSSIAN_STD_DEV),
        0.0,
    );
    let seeded_bootstrapping_key = par_allocate_and_generate_new_seeded_lwe_bootstrap_key(
        &input_lwe_secret_key,
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
        input_lwe_secret_key.lwe_dimension(),
        glwe_size,
        output_polynomial_size,
        base_log,
        level_count,
    );
    convert_standard_lwe_bootstrap_key_to_fourier_128(
        &standard_bootstrapping_key,
        &mut fourier_bootstrapping_key,
    );
    drop(standard_bootstrapping_key);

    let output_delta = (1_u128 << 127) / (parameters.output_modulus as u128);
    let accumulator: GlweCiphertext<Vec<u128>> = generate_programmable_bootstrap_glwe_lut(
        output_polynomial_size,
        glwe_size,
        parameters.ring_dimension,
        ciphertext_modulus,
        output_delta,
        |x: u128| {
            ((parameters.output_modulus as u128) * x
                / (parameters.ring_dimension as u128))
                % (parameters.output_modulus as u128)
        },
    );

    Ok((
        FastLwrPrfPepInputClient {
            parameters,
            input_polynomial_size,
            input_glwe_secret_key,
        },
        FastLwrPrfPepRecipientKey {
            parameters,
            output_lwe_secret_key,
        },
        FastLwrPrfPepEvaluator {
            parameters,
            input_polynomial_size,
            output_polynomial_size,
            prf_secret_bits: prf_secret_key.bits().to_vec(),
            bootstrapping_key: fourier_bootstrapping_key,
            accumulator,
        },
    ))
}

impl FastLwrPrfPepInputClient {
    pub fn parameters(&self) -> FastLwrPrfParameters {
        self.parameters
    }

    pub fn encrypt_input(
        &self,
        input: &[u8],
        output_index: u64,
    ) -> Result<EncryptedFastLwrPrfPepInput> {
        if output_index == 0 {
            return Err(PepLwrPrfError(
                "PRF output indices start at one".into(),
            ));
        }
        let clear_vector = hash_to_ring_vector(self.parameters, input, output_index);
        let delta = (1_u128 << 127) / (self.parameters.ring_dimension as u128);
        let block_size = INPUT_LWE_BLOCK_SIZE.min(self.parameters.lwr_dimension);
        let mut ciphertexts = Vec::with_capacity(
            (clear_vector.len() + block_size - 1) / block_size,
        );

        // Every block gets fresh randomness. All blocks use the same source
        // GLWE key so their extracted LWE samples can be added homomorphically.
        for values in clear_vector.chunks(block_size) {
            let mut ciphertext = GlweCiphertext::new(
                0_u128,
                GlweSize(GLWE_SIZE),
                self.input_polynomial_size,
                CiphertextModulus::new_native(),
            );
            {
                let mut body = ciphertext.get_mut_body();
                let body_coefficients = body.as_mut();
                body_coefficients.fill(0);
                for (destination, value) in body_coefficients
                    .iter_mut()
                    .zip(values.iter().copied())
                {
                    *destination = (value as u128) * delta;
                }
            }

            let mut boxed_seeder = new_seeder();
            let seeder = boxed_seeder.as_mut();
            let mut encryption_generator =
                EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
            let noise_distribution = Gaussian::from_dispersion_parameter(
                StandardDev(TORUS_GAUSSIAN_STD_DEV),
                0.0,
            );
            encrypt_glwe_ciphertext_assign(
                &self.input_glwe_secret_key,
                &mut ciphertext,
                noise_distribution,
                &mut encryption_generator,
            );
            ciphertexts.push(ciphertext);
        }

        Ok(EncryptedFastLwrPrfPepInput {
            parameters: self.parameters,
            output_index,
            ciphertexts,
        })
    }

    pub fn encrypt_inputs(
        &self,
        input: &[u8],
        count: usize,
    ) -> Result<Vec<EncryptedFastLwrPrfPepInput>> {
        (1..=count)
            .map(|index| {
                let index = u64::try_from(index)
                    .map_err(|_| PepLwrPrfError("output index does not fit in u64".into()))?;
                self.encrypt_input(input, index)
            })
            .collect()
    }

    pub fn encrypt_inputs_for_output_bytes(
        &self,
        input: &[u8],
        output_len_bytes: usize,
    ) -> Result<Vec<EncryptedFastLwrPrfPepInput>> {
        self.encrypt_inputs(input, output_symbols_for_bytes(self.parameters, output_len_bytes)?)
    }
}

impl FastLwrPrfPepEvaluator {
    pub fn parameters(&self) -> FastLwrPrfParameters {
        self.parameters
    }

    /// Compute the encrypted dot product by multiplying each GLWE block with
    /// the corresponding PRF-key slice, extracting coefficient zero, then
    /// adding the resulting LWE samples under the same source key. The output
    /// remains one LWE ciphertext of dimension INPUT_LWE_BLOCK_SIZE.
    fn extract_dot_product_lwe(
        &self,
        input: &EncryptedFastLwrPrfPepInput,
    ) -> Result<LweCiphertext<Vec<u128>>> {
        let block_size = INPUT_LWE_BLOCK_SIZE.min(self.parameters.lwr_dimension);
        let expected_blocks = (self.parameters.lwr_dimension + block_size - 1) / block_size;
        if input.parameters != self.parameters
            || input.output_index == 0
            || input.ciphertexts.len() != expected_blocks
            || self.prf_secret_bits.len() != self.parameters.lwr_dimension
            || input.ciphertexts.iter().any(|ct| ct.polynomial_size() != self.input_polynomial_size)
        {
            return Err(PepLwrPrfError(
                "input metadata or ciphertext block dimensions do not match evaluation key".into(),
            ));
        }

        // Sample extraction yields an LWE ciphertext whose dimension equals the
        // full GLWE polynomial size, not the number of meaningful plaintext
        // coefficients in this block.
        let lwe_size = LweDimension(self.input_polynomial_size.0 * GLWE_DIMENSION).to_lwe_size();
        let mut combined = LweCiphertext::new(
            0_u128,
            lwe_size,
            CiphertextModulus::new_native(),
        );

        for (ciphertext, key_chunk) in input
            .ciphertexts
            .iter()
            .zip(self.prf_secret_bits.chunks(block_size))
        {
            let mut product_ciphertext = ciphertext.clone();
            multiply_glwe_ciphertext_by_prf_polynomial(&mut product_ciphertext, key_chunk);

            let mut extracted = LweCiphertext::new(
                0_u128,
                lwe_size,
                CiphertextModulus::new_native(),
            );
            extract_lwe_sample_from_glwe_ciphertext(
                &product_ciphertext,
                &mut extracted,
                MonomialDegree(0),
            );

            // Both samples encrypt under the same flattened source GLWE key.
            // Torus addition combines partial dot products without decryption.
            for (dst, src) in combined.as_mut().iter_mut().zip(extracted.as_ref().iter()) {
                *dst = dst.wrapping_add(*src);
            }
        }
        Ok(combined)
    }

    /// Evaluate one encrypted H(x,slot) vector. All block dot products are
    /// combined before a single PBS, which changes the key to the recipient.
    pub fn evaluate(
        &self,
        input: &EncryptedFastLwrPrfPepInput,
    ) -> Result<EncryptedFastLwrPrfPepOutput> {
        let extracted_input = self.extract_dot_product_lwe(input)?;
        let output_lwe_dimension = self.output_polynomial_size.0 * GLWE_DIMENSION;
        let mut output_ciphertext = LweCiphertext::new(
            0_u128,
            LweDimension(output_lwe_dimension).to_lwe_size(),
            CiphertextModulus::new_native(),
        );
        programmable_bootstrap_f128_lwe_ciphertext(
            &extracted_input,
            &mut output_ciphertext,
            &self.accumulator,
            &self.bootstrapping_key,
        );
        Ok(EncryptedFastLwrPrfPepOutput {
            parameters: self.parameters,
            output_index: input.output_index,
            ciphertext: output_ciphertext,
        })
    }

    pub fn evaluate_many(
        &self,
        inputs: &[EncryptedFastLwrPrfPepInput],
    ) -> Result<Vec<EncryptedFastLwrPrfPepOutput>> {
        for (offset, input) in inputs.iter().enumerate() {
            let expected_index = u64::try_from(offset + 1)
                .map_err(|_| PepLwrPrfError("output index does not fit in u64".into()))?;
            if input.output_index != expected_index {
                return Err(PepLwrPrfError(format!(
                    "encrypted input slots must be ordered and contiguous; expected index {expected_index}"
                )));
            }
        }
        inputs.iter().map(|input| self.evaluate(input)).collect()
    }

    pub fn evaluate_outputs_for_bytes(
        &self,
        inputs: &[EncryptedFastLwrPrfPepInput],
        output_len_bytes: usize,
    ) -> Result<Vec<EncryptedFastLwrPrfPepOutput>> {
        let expected = output_symbols_for_bytes(self.parameters, output_len_bytes)?;
        if inputs.len() != expected {
            return Err(PepLwrPrfError(format!(
                "expected {expected} input slots for {output_len_bytes} bytes, got {}",
                inputs.len()
            )));
        }
        self.evaluate_many(inputs)
    }
}

impl FastLwrPrfPepRecipientKey {
    pub fn parameters(&self) -> FastLwrPrfParameters {
        self.parameters
    }

    pub fn decrypt_output(&self, output: &EncryptedFastLwrPrfPepOutput) -> Result<u8> {
        if output.parameters != self.parameters {
            return Err(PepLwrPrfError(
                "output parameters do not match recipient key".into(),
            ));
        }
        let plaintext: Plaintext<u128> =
            decrypt_lwe_ciphertext(&self.output_lwe_secret_key, &output.ciphertext);
        let output_delta = (1_u128 << 127) / (self.parameters.output_modulus as u128);
        let decomposition_base_log =
            DecompositionBaseLog((self.parameters.output_modulus.trailing_zeros() + 1) as usize);
        let decomposer = SignedDecomposer::new(decomposition_base_log, DecompositionLevelCount(1));
        let rounded = decomposer.closest_representable(plaintext.0);
        let symbol = ((rounded / output_delta)
            % (self.parameters.output_modulus as u128)) as u64;
        if symbol >= self.parameters.output_modulus {
            return Err(PepLwrPrfError("decrypted symbol is outside Z_p".into()));
        }
        Ok(symbol as u8)
    }

    pub fn decrypt_many_outputs(
        &self,
        outputs: &[EncryptedFastLwrPrfPepOutput],
    ) -> Result<Vec<u8>> {
        outputs.iter().map(|output| self.decrypt_output(output)).collect()
    }

    pub fn decrypt_outputs_to_bytes(
        &self,
        outputs: &[EncryptedFastLwrPrfPepOutput],
        output_len_bytes: usize,
    ) -> Result<Vec<u8>> {
        let expected_count = output_symbols_for_bytes(self.parameters, output_len_bytes)?;
        if outputs.len() != expected_count {
            return Err(PepLwrPrfError(format!(
                "expected {expected_count} output slots for {output_len_bytes} bytes, got {}",
                outputs.len()
            )));
        }
        for (offset, output) in outputs.iter().enumerate() {
            let expected_index = u64::try_from(offset + 1)
                .map_err(|_| PepLwrPrfError("output index does not fit in u64".into()))?;
            if output.output_index != expected_index || output.parameters != self.parameters {
                return Err(PepLwrPrfError(format!(
                    "outputs must have matching parameters and contiguous one-based indices; expected slot {expected_index}"
                )));
            }
        }
        let symbols = self.decrypt_many_outputs(outputs)?;
        self.pack_symbols_to_bytes(&symbols, output_len_bytes)
    }

    pub fn pack_symbols_to_bytes(
        &self,
        symbols: &[u8],
        output_len_bytes: usize,
    ) -> Result<Vec<u8>> {
        let bits_per_symbol = self.parameters.output_modulus.trailing_zeros() as usize;
        let required_bits = output_len_bytes
            .checked_mul(8)
            .ok_or_else(|| PepLwrPrfError("requested output length is too large".into()))?;
        if symbols.len().checked_mul(bits_per_symbol).unwrap_or(usize::MAX) < required_bits {
            return Err(PepLwrPrfError(
                "not enough symbols to fill requested output byte string".into(),
            ));
        }
        if symbols
            .iter()
            .any(|&symbol| (symbol as u64) >= self.parameters.output_modulus)
        {
            return Err(PepLwrPrfError("symbol outside Z_p".into()));
        }

        let mut output = vec![0u8; output_len_bytes];
        let mut bit_index = 0usize;
        for &symbol in symbols {
            for bit_pos in (0..bits_per_symbol).rev() {
                if bit_index == required_bits {
                    return Ok(output);
                }
                output[bit_index / 8] |= ((symbol >> bit_pos) & 1) << (7 - (bit_index % 8));
                bit_index += 1;
            }
        }
        Ok(output)
    }
}


/// Computes multiplication by a public signed monomial polynomial S on each
/// GLWE ciphertext component, modulo X^N+1 and the native torus modulus.
/// We set S[0]=s[0] and S[N-i]=-s[i] for i>0. Since the plaintext H(x,slot)
/// occupies coefficients 0..n-1, coefficient 0 of H(x,slot)*S is exactly
/// sum_i H(x,slot)[i]*s[i]. Using coefficient-zero sample extraction keeps
/// the extracted LWE secret aligned with `GlweSecretKey::into_lwe_secret_key`.
fn multiply_glwe_ciphertext_by_prf_polynomial(
    ciphertext: &mut GlweCiphertext<Vec<u128>>,
    secret_bits: &[u8],
) {
    let polynomial_size = ciphertext.polynomial_size().0;
    let source = ciphertext.as_ref().to_vec();
    let mut destination = vec![0_u128; source.len()];
    let source_polynomial_count = source.len() / polynomial_size;

    // For each s[i], multiply by the corresponding coefficient of S(X).
    // The branch depends only on public indices, not on the key bit.
    for (i, &bit) in secret_bits.iter().enumerate() {
        let (secret_degree, sign) = if i == 0 {
            (0usize, 1i8)
        } else {
            (polynomial_size - i, -1i8)
        };
        let signed_bit = (bit as u128).wrapping_mul(if sign < 0 { u128::MAX } else { 1 });
        for component in 0..source_polynomial_count {
            let offset = component * polynomial_size;
            for input_degree in 0..polynomial_size {
                let term = source[offset + input_degree].wrapping_mul(signed_bit);
                let degree = input_degree + secret_degree;
                if degree < polynomial_size {
                    let index = offset + degree;
                    destination[index] = destination[index].wrapping_add(term);
                } else {
                    let index = offset + degree - polynomial_size;
                    destination[index] = destination[index].wrapping_sub(term);
                }
            }
        }
    }
    ciphertext.as_mut().copy_from_slice(&destination);
}

#[cfg(test)]
mod private_phase_diagnostic {
    use super::*;
    use crate::core::fast_lwr_prf::FastLwrPrf;
    use rand::{rngs::StdRng, SeedableRng};

    /// Focused diagnostic for paper-parameter slot 77. It checks whether
    /// coefficient-wise modulus-switch rounding can move the PBS phase across
    /// a nearby LUT boundary after blockwise dot-product aggregation.
    #[test]
    #[ignore = "paper-size TFHE diagnostic; run explicitly in release mode with --ignored"]
    fn inspect_private_pbs_slot_77_modswitch_error() {
        let parameters = FastLwrPrfParameters::paper_default();
        let mut rng = StdRng::seed_from_u64(0x5051_5045_5020_2610);
        let prf_key = FastLwrPrfSecretKey::generate(parameters, &mut rng).unwrap();
        let reference = FastLwrPrf::new(prf_key.clone());
        let identifier = b"pqpep-paper-parameters-private-input-test";
        let slot = 77u64;
        let expected = reference.evaluate_many(identifier, slot as usize)[slot as usize - 1] as u64;
        let (source, recipient, evaluator) = setup_pep_lwr_prf(parameters, &prf_key).unwrap();
        let source_lwe_key = source.input_glwe_secret_key.clone().into_lwe_secret_key();

        let input_delta = (1_u128 << 127) / parameters.ring_dimension as u128;
        let input_modulus = (2 * parameters.ring_dimension) as u128;
        let vector = hash_to_ring_vector(parameters, identifier, slot);
        let expected_phase = vector
            .iter()
            .zip(prf_key.bits())
            .map(|(&a, &key_bit)| (a as u128) * (key_bit as u128))
            .sum::<u128>() % input_modulus;
        let expected_torus_phase = expected_phase * input_delta;
        let boundary_width = parameters.ring_dimension as u64 / parameters.output_modulus;
        let remainder = (expected_phase as u64) % boundary_width;
        let distance_to_boundary = remainder.min(boundary_width - remainder);

        // Exact, mask-free input verifies the accumulator and output decoding.
        let mut exact_input_data = vec![0_u128; source.input_polynomial_size.0 + 1];
        exact_input_data[source.input_polynomial_size.0] = expected_torus_phase;
        let exact_input = LweCiphertext::from_container(
            exact_input_data,
            CiphertextModulus::new_native(),
        );
        let mut exact_output = LweCiphertext::new(
            0_u128,
            LweDimension(evaluator.output_polynomial_size.0 * GLWE_DIMENSION).to_lwe_size(),
            CiphertextModulus::new_native(),
        );
        programmable_bootstrap_f128_lwe_ciphertext(
            &exact_input,
            &mut exact_output,
            &evaluator.accumulator,
            &evaluator.bootstrapping_key,
        );
        let exact_symbol = recipient.decrypt_output(&EncryptedFastLwrPrfPepOutput {
            parameters,
            output_index: slot,
            ciphertext: exact_output,
        }).unwrap() as u64;
        eprintln!(
            "slot={slot} expected_symbol={expected} expected_phase={expected_phase} distance_to_boundary={distance_to_boundary} exact_phase_PBS={exact_symbol} input_lwe_dimension={}",
            source.input_polynomial_size.0,
        );
        assert_eq!(exact_symbol, expected);

        let rotation_modulus = (2 * evaluator.output_polynomial_size.0) as u128;
        let rotation_shift = 128usize - rotation_modulus.trailing_zeros() as usize;
        let rotation_rounding = 1_u128 << (rotation_shift - 1);
        let modulus_switch_to_rotation = |value: u128| -> u128 {
            value.wrapping_add(rotation_rounding) >> rotation_shift
        };
        let phase_decomposer = SignedDecomposer::new(
            DecompositionBaseLog(input_modulus.trailing_zeros() as usize),
            DecompositionLevelCount(1),
        );
        let expansion = (evaluator.output_polynomial_size.0 / parameters.ring_dimension) as u128;
        let expected_pbs_phase = (expected_phase * expansion) % rotation_modulus;
        let mut mismatches = Vec::new();

        for trial in 1..=8 {
            let encrypted = source.encrypt_input(identifier, slot).unwrap();
            let extracted = evaluator.extract_dot_product_lwe(&encrypted).unwrap();
            let actual = recipient.decrypt_output(&evaluator.evaluate(&encrypted).unwrap()).unwrap() as u64;
            let decrypted_phase: Plaintext<u128> = decrypt_lwe_ciphertext(&source_lwe_key, &extracted);
            let rounded_phase = phase_decomposer.closest_representable(decrypted_phase.0);
            let extracted_phase = (rounded_phase / input_delta) % input_modulus;
            let torus_noise = decrypted_phase.0.wrapping_sub(expected_torus_phase) as i128;

            let mut switched_secret_phase = 0_u128;
            for (&mask, &secret_bit) in extracted
                .get_mask().as_ref().iter().zip(source_lwe_key.as_ref().iter())
            {
                switched_secret_phase = (switched_secret_phase
                    + modulus_switch_to_rotation(mask) * secret_bit as u128)
                    % rotation_modulus;
            }
            let switched_body = modulus_switch_to_rotation(*extracted.get_body().data);
            let switched_phase = (switched_body + rotation_modulus - switched_secret_phase) % rotation_modulus;
            let error_mod = (switched_phase + rotation_modulus - expected_pbs_phase) % rotation_modulus;
            let error = if error_mod > rotation_modulus / 2 {
                error_mod as i128 - rotation_modulus as i128
            } else {
                error_mod as i128
            };
            eprintln!(
                "trial={trial} actual={actual} expected={expected} extracted_phase={extracted_phase} phase_noise_units={:.4e} pbs_phase_error={error}",
                (torus_noise as f64) / (input_delta as f64),
            );
            if actual != expected { mismatches.push(trial); }
        }
        eprintln!("mismatch_trials={mismatches:?}");
    }
}

// EXPERIMENT ONLY: append this block to the end of
// src/lib/core/fast_lwr_prf_pep_tfhe.rs (the current KEY512/blockwise source).
//
// This deliberately tests the idea “let the recipient decrypt the unrounded
// dot product and apply LWR rounding locally”. It is NOT a safe PEP design:
// the recipient learns z=<H(x,i),s> mod 2N, which is a higher-resolution
// intermediate than the intended PRF symbol in Z_p. Do not use for real data.

#[cfg(test)]
mod unrounded_recipient_rounding_experiment {
    use super::*;
    use crate::core::fast_lwr_prf::FastLwrPrf;
    use rand::rngs::OsRng;
    use std::time::Instant;
    use tfhe::core_crypto::algorithms::lwe_keyswitch::par_keyswitch_lwe_ciphertext;
    use tfhe::core_crypto::algorithms::lwe_keyswitch_key_generation::allocate_and_generate_new_lwe_keyswitch_key;

    fn extract_encrypted_dot_product(
        input: &EncryptedFastLwrPrfPepInput,
        parameters: FastLwrPrfParameters,
        prf_bits: &[u8],
        input_polynomial_size: PolynomialSize,
    ) -> LweCiphertext<Vec<u128>> {
        let lwe_size = LweDimension(input_polynomial_size.0 * GLWE_DIMENSION).to_lwe_size();
        let mut combined = LweCiphertext::new(
            0_u128,
            lwe_size,
            CiphertextModulus::new_native(),
        );

        let expected_blocks = (parameters.lwr_dimension + INPUT_LWE_BLOCK_SIZE - 1)
            / INPUT_LWE_BLOCK_SIZE;
        assert_eq!(input.ciphertexts.len(), expected_blocks);
        assert_eq!(prf_bits.len(), parameters.lwr_dimension);

        for (ciphertext, key_chunk) in input
            .ciphertexts
            .iter()
            .zip(prf_bits.chunks(INPUT_LWE_BLOCK_SIZE))
        {
            let mut product = ciphertext.clone();
            multiply_glwe_ciphertext_by_prf_polynomial(&mut product, key_chunk);

            let mut extracted = LweCiphertext::new(
                0_u128,
                lwe_size,
                CiphertextModulus::new_native(),
            );
            extract_lwe_sample_from_glwe_ciphertext(
                &product,
                &mut extracted,
                MonomialDegree(0),
            );

            // All extracted samples are under the same source LWE key.
            for (dst, src) in combined.as_mut().iter_mut().zip(extracted.as_ref().iter()) {
                *dst = dst.wrapping_add(*src);
            }
        }
        combined
    }

    fn decode_raw_phase_and_lwr_symbol(
        decrypted_phase: u128,
        parameters: FastLwrPrfParameters,
    ) -> (u64, u64) {
        let n = parameters.ring_dimension as u64;
        let q = (2 * parameters.ring_dimension) as u128;
        let delta = (1_u128 << 127) / parameters.ring_dimension as u128;

        // Decode z in Z_(2N) from the torus phase. This intentionally recovers
        // the unrounded intermediate, not just the PRF output symbol.
        let decomposer = SignedDecomposer::new(
            DecompositionBaseLog(q.trailing_zeros() as usize),
            DecompositionLevelCount(1),
        );
        let rounded_torus = decomposer.closest_representable(decrypted_phase);
        let z = ((rounded_torus / delta) % q) as u64;

        // Same signed floor-rounding map used by the cleartext depth-1 LWR PRF.
        let negative = z >= n;
        let magnitude = z % n;
        let rounded_magnitude = ((parameters.output_modulus as u128)
            * (magnitude as u128)
            / (n as u128)) as u64;
        let symbol = if negative && rounded_magnitude != 0 {
            parameters.output_modulus - rounded_magnitude
        } else {
            rounded_magnitude
        };
        (z, symbol)
    }

    #[test]
    #[ignore = "security-leakage experiment only: recipient intentionally learns the unrounded phase"]
    fn unrounded_recipient_rounding_matches_prf_but_exposes_extra_phase_information() {
        let parameters = FastLwrPrfParameters::paper_default();
        let identifier = b"unrounded-recipient-rounding-leakage-demo";
        let output_count = output_symbols_for_bytes(parameters, 64).unwrap();
        assert_eq!(output_count, 103);

        let mut prf_rng = OsRng;
        let prf_key = FastLwrPrfSecretKey::generate(parameters, &mut prf_rng).unwrap();
        let reference = FastLwrPrf::new(prf_key.clone());
        let expected: Vec<u8> = reference
            .evaluate_many(identifier, output_count)
            .into_iter()
            .map(|symbol| symbol as u8)
            .collect();

        let setup_started = Instant::now();
        let full_source_n = parameters
            .lwr_dimension
            .checked_next_power_of_two()
            .expect("source dimension rounds up to a power of two")
            .max(2);
        let input_polynomial_size = PolynomialSize(full_source_n);
        let mut boxed_seeder = new_seeder();
        let seeder = boxed_seeder.as_mut();
        let mut secret_generator =
            SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

        let source_glwe_secret_key: GlweSecretKey<Vec<u128>> =
            GlweSecretKey::generate_new_binary(
                GlweDimension(GLWE_DIMENSION),
                input_polynomial_size,
                &mut secret_generator,
            );
        let source_lwe_secret_key = source_glwe_secret_key.clone().into_lwe_secret_key();
        let recipient_lwe_secret_key: LweSecretKey<Vec<u128>> =
            LweSecretKey::generate_new_binary(
                LweDimension(full_source_n),
                &mut secret_generator,
            );

        let source = FastLwrPrfPepInputClient {
            parameters,
            input_polynomial_size,
            input_glwe_secret_key: source_glwe_secret_key,
        };

        // This key-switching key changes the raw dot-product ciphertext from
        // the source LWE key to the recipient LWE key. It does not perform PBS.
        // The parameters are experimental only and have not been security-reviewed.
        let mut encryption_generator =
            EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
        let ksk_noise = Gaussian::from_dispersion_parameter(
            StandardDev(TORUS_GAUSSIAN_STD_DEV),
            0.0,
        );
        let ksk = allocate_and_generate_new_lwe_keyswitch_key(
            &source_lwe_secret_key,
            &recipient_lwe_secret_key,
            DecompositionBaseLog(8),
            DecompositionLevelCount(8),
            ksk_noise,
            CiphertextModulus::new_native(),
            &mut encryption_generator,
        );
        eprintln!("[UNROUNDED] setup + key-switch key: {:.3?}", setup_started.elapsed());

        let encrypt_started = Instant::now();
        let encrypted_inputs = source
            .encrypt_inputs_for_output_bytes(identifier, 64)
            .expect("encrypt 103 indexed hash vectors");
        eprintln!("[UNROUNDED] encrypt 103 inputs: {:.3?}", encrypt_started.elapsed());

        let eval_started = Instant::now();
        let mut leaked_phases = Vec::with_capacity(output_count);
        let mut actual = Vec::with_capacity(output_count);
        for input in &encrypted_inputs {
            let dot_product = extract_encrypted_dot_product(
                input,
                parameters,
                prf_key.bits(),
                input_polynomial_size,
            );
            let mut switched = LweCiphertext::new(
                0_u128,
                LweDimension(full_source_n).to_lwe_size(),
                CiphertextModulus::new_native(),
            );
            par_keyswitch_lwe_ciphertext(&ksk, &dot_product, &mut switched);

            let decrypted: Plaintext<u128> =
                decrypt_lwe_ciphertext(&recipient_lwe_secret_key, &switched);
            let (raw_z, symbol) = decode_raw_phase_and_lwr_symbol(decrypted.0, parameters);
            leaked_phases.push(raw_z);
            actual.push(symbol as u8);
        }
        eprintln!("[UNROUNDED] evaluate + key switch + recipient rounding for 103 slots: {:.3?}", eval_started.elapsed());

        let mismatches: Vec<(usize, u8, u8)> = actual
            .iter()
            .zip(expected.iter())
            .enumerate()
            .filter_map(|(i, (&a, &e))| (a != e).then_some((i + 1, a, e)))
            .collect();
        eprintln!("[UNROUNDED] output mismatches (slot, actual, expected): {mismatches:?}");
        assert!(mismatches.is_empty(), "unrounded recipient-side rounding must match the PRF reference");

        let q = 2 * parameters.ring_dimension;
        let bits_revealed_by_raw_phase = q.trailing_zeros();
        let bits_in_prf_symbol = parameters.output_modulus.trailing_zeros();
        eprintln!("[LEAKAGE] recipient sees raw z in Z_(2N), with {bits_revealed_by_raw_phase} encoded bits per slot; intended PRF symbol has {bits_in_prf_symbol} bits.");
        eprintln!("[LEAKAGE] first 16 raw z residues: {:?}", &leaked_phases[..16]);
        eprintln!("[LEAKAGE] This intentionally reveals a higher-resolution intermediate; this is a performance/security experiment, not a deployable PEP mode.");
    }
}
