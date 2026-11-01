//! Correctness-first PEP adapter for the depth-1 LWR PRF using TFHE-rs integer FHE.
//!
//! Input coefficients are encrypted under a SOURCE key. The evaluator knows the
//! PEP/LWR factor in the clear, evaluates the exact integer formula while the
//! input remains encrypted, and keyswitches only the final symbol to the
//! RECIPIENT key. The recipient can decrypt the output, but cannot decrypt the
//! source-key input ciphertexts.
//!
//! This is deliberately a correctness/reference implementation, not the final
//! high-performance implementation. It uses a centralized setup helper to
//! create an A->B KeySwitchingKey. A production n-PEP deployment must replace
//! that helper with an appropriate distributed key-switch/key-generation
//! protocol; this module does not claim that trust problem is solved.

use std::{error::Error, fmt};

use super::fast_lwr_prf::{hash_to_ring_vector, FastLwrPrfParameters, FastLwrPrfSecretKey};
use tfhe::prelude::*;
use tfhe::{
    generate_keys, set_server_key, ClientKey, ConfigBuilder, FheUint16, FheUint32, FheUint8,
    KeySwitchingKey, PublicKey, ServerKey,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PepIntegerTfheError(pub String);

impl fmt::Display for PepIntegerTfheError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Error for PepIntegerTfheError {}

type Result<T> = std::result::Result<T, PepIntegerTfheError>;

fn validate_parameters(parameters: FastLwrPrfParameters) -> Result<()> {
    parameters
        .validate()
        .map_err(|e| PepIntegerTfheError(e.to_string()))?;

    let q = (parameters.ring_dimension as u128) * 2;
    if q > (u16::MAX as u128) + 1 {
        return Err(PepIntegerTfheError(
            "integer-FHE adapter requires 2N <= 65536 for u16 coefficients".into(),
        ));
    }
    if parameters.output_modulus > 256 {
        return Err(PepIntegerTfheError(
            "integer-FHE adapter currently supports p <= 256 (u8 output)".into(),
        ));
    }
    let maximum_sum = (q - 1) * (parameters.lwr_dimension as u128);
    if maximum_sum > u32::MAX as u128 {
        return Err(PepIntegerTfheError(
            "LWR inner product may overflow the u32 accumulator".into(),
        ));
    }
    Ok(())
}

/// Source-side encoder. It has the source public key, but no source secret key.
pub struct FastLwrPrfPepIntegerInputEncryptor {
    parameters: FastLwrPrfParameters,
    source_public_key: PublicKey,
}

/// Recipient/domain B. Only this object has the target ClientKey.
pub struct FastLwrPrfPepIntegerRecipient {
    parameters: FastLwrPrfParameters,
    client_key: ClientKey,
}

/// Transcryptor/evaluator. It has the clear PRF factor, source ServerKey and
/// source-to-recipient keyswitch key. It has neither party's ClientKey.
pub struct FastLwrPrfPepIntegerEvaluator {
    parameters: FastLwrPrfParameters,
    factor_bits: Vec<u8>,
    source_public_key: PublicKey,
    source_server_key: ServerKey,
    output_key_switch: KeySwitchingKey,
}

/// Encrypted H(x, slot) vector under the source key.
pub struct EncryptedFastLwrPrfPepInput {
    parameters: FastLwrPrfParameters,
    output_index: u64,
    encrypted_coefficients: Vec<FheUint16>,
}

impl EncryptedFastLwrPrfPepInput {
    pub fn parameters(&self) -> FastLwrPrfParameters {
        self.parameters
    }

    pub fn output_index(&self) -> u64 {
        self.output_index
    }

    pub fn coefficient_count(&self) -> usize {
        self.encrypted_coefficients.len()
    }
}

/// One PRF symbol encrypted under the recipient key.
pub struct EncryptedFastLwrPrfPepOutput {
    parameters: FastLwrPrfParameters,
    output_index: u64,
    ciphertext: FheUint8,
}

impl EncryptedFastLwrPrfPepOutput {
    pub fn parameters(&self) -> FastLwrPrfParameters {
        self.parameters
    }

    pub fn output_index(&self) -> u64 {
        self.output_index
    }

    pub fn ciphertext(&self) -> &FheUint8 {
        &self.ciphertext
    }
}

/// Creates the source/recipient/evaluator roles for tests and local experiments.
///
/// WARNING: this helper centrally creates both ClientKeys in order to build the
/// TFHE-rs KeySwitchingKey. Do not present it as a distributed n-PEP setup.
pub fn setup_pep_integer_tfhe(
    prf_key: &FastLwrPrfSecretKey,
) -> Result<(
    FastLwrPrfPepIntegerInputEncryptor,
    FastLwrPrfPepIntegerRecipient,
    FastLwrPrfPepIntegerEvaluator,
)> {
    let parameters = prf_key.parameters();
    validate_parameters(parameters)?;

    let (source_client_key, source_server_key) = generate_keys(ConfigBuilder::default().build());
    let (recipient_client_key, recipient_server_key) =
        generate_keys(ConfigBuilder::default().build());

    let output_key_switch = KeySwitchingKey::new(
        (&source_client_key, &source_server_key),
        (&recipient_client_key, &recipient_server_key),
    )
    .map_err(|_| {
        PepIntegerTfheError("source/recipient TFHE parameters are incompatible for key switching".into())
    })?;

    let source_public_key = PublicKey::new(&source_client_key);

    // Drop the source secret key and the target ServerKey from the returned
    // roles. They are only needed by this centralized experimental setup.
    let input_encryptor = FastLwrPrfPepIntegerInputEncryptor {
        parameters,
        source_public_key: source_public_key.clone(),
    };
    let recipient = FastLwrPrfPepIntegerRecipient {
        parameters,
        client_key: recipient_client_key,
    };
    let evaluator = FastLwrPrfPepIntegerEvaluator {
        parameters,
        factor_bits: prf_key.bits().to_vec(),
        source_public_key,
        source_server_key,
        output_key_switch,
    };

    drop(source_client_key);
    drop(recipient_server_key);
    Ok((input_encryptor, recipient, evaluator))
}

impl FastLwrPrfPepIntegerInputEncryptor {
    /// Hashes the identifier locally and encrypts every H(x, slot) coefficient
    /// under the source public key before sending the vector to the evaluator.
    pub fn encrypt_input(
        &self,
        input: &[u8],
        output_index: u64,
    ) -> Result<EncryptedFastLwrPrfPepInput> {
        if output_index == 0 {
            return Err(PepIntegerTfheError(
                "PRF output indices start at one".into(),
            ));
        }

        let clear_vector = hash_to_ring_vector(self.parameters, input, output_index);
        let mut encrypted_coefficients = Vec::with_capacity(clear_vector.len());
        for coefficient in clear_vector {
            let value = u16::try_from(coefficient).map_err(|_| {
                PepIntegerTfheError("H(x, slot) coefficient does not fit in u16".into())
            })?;
            let ct = FheUint16::try_encrypt(value, &self.source_public_key).map_err(|e| {
                PepIntegerTfheError(format!("source input encryption failed: {e}"))
            })?;
            encrypted_coefficients.push(ct);
        }

        Ok(EncryptedFastLwrPrfPepInput {
            parameters: self.parameters,
            output_index,
            encrypted_coefficients,
        })
    }

    pub fn encrypt_inputs(
        &self,
        input: &[u8],
        count: usize,
    ) -> Result<Vec<EncryptedFastLwrPrfPepInput>> {
        let mut encrypted = Vec::with_capacity(count);
        for index in 1..=count {
            let output_index = u64::try_from(index)
                .map_err(|_| PepIntegerTfheError("output index does not fit in u64".into()))?;
            encrypted.push(self.encrypt_input(input, output_index)?);
        }
        Ok(encrypted)
    }
}

impl FastLwrPrfPepIntegerRecipient {
    /// Decrypts only a PRF output, which has already been keyswitched to B.
    pub fn decrypt_output(&self, output: &EncryptedFastLwrPrfPepOutput) -> Result<u8> {
        if output.parameters != self.parameters {
            return Err(PepIntegerTfheError(
                "output parameters do not match recipient parameters".into(),
            ));
        }
        let value: u8 = output.ciphertext.decrypt(&self.client_key);
        if (value as u64) >= self.parameters.output_modulus {
            return Err(PepIntegerTfheError(
                "decrypted output is outside the PRF output modulus".into(),
            ));
        }
        Ok(value)
    }

    pub fn decrypt_many_outputs(
        &self,
        outputs: &[EncryptedFastLwrPrfPepOutput],
    ) -> Result<Vec<u8>> {
        outputs.iter().map(|o| self.decrypt_output(o)).collect()
    }
}

impl FastLwrPrfPepIntegerEvaluator {
    /// Computes one symbol exactly in encrypted integer arithmetic under the
    /// source key, then switches only the final FheUint8 ciphertext to B.
    pub fn evaluate(
        &self,
        input: &EncryptedFastLwrPrfPepInput,
    ) -> Result<EncryptedFastLwrPrfPepOutput> {
        if input.parameters != self.parameters
            || input.output_index == 0
            || input.encrypted_coefficients.len() != self.parameters.lwr_dimension
            || self.factor_bits.len() != self.parameters.lwr_dimension
        {
            return Err(PepIntegerTfheError(
                "input metadata/dimensions do not match evaluator parameters".into(),
            ));
        }

        // Important: all arithmetic up to the last line stays under source key A.
        set_server_key(self.source_server_key.clone());

        let mut sum: FheUint32 = FheUint32::try_encrypt(0_u32, &self.source_public_key)
            .map_err(|e| PepIntegerTfheError(format!("cannot encrypt accumulator zero: {e}")))?;
        for (index, &bit) in self.factor_bits.iter().enumerate() {
            if bit == 1 {
                let term: FheUint32 = input.encrypted_coefficients[index].clone().cast_into();
                sum = &sum + &term;
            }
        }

        // Exact signed-floor map in Eq. (7). N and p are powers of two, so
        // modulo 2N, floor(p*x/N), and negation mod p are masks/shifts.
        let n = self.parameters.ring_dimension as u32;
        let q_mask = n * 2 - 1;
        let p_mask = (self.parameters.output_modulus - 1) as u32;
        let shift = self.parameters.ring_dimension.trailing_zeros()
            - self.parameters.output_modulus.trailing_zeros();

        let phase = &sum & q_mask;
        let is_negative = (&phase & n).eq(n);
        let magnitude = &phase & (n - 1);
        let rounded = &magnitude >> shift;
        let symbol = &rounded & p_mask;
        let negated = ((&symbol ^ p_mask) + 1_u32) & p_mask;
        let signed_symbol = is_negative.if_then_else(&negated, &symbol);
        let source_output: FheUint8 = signed_symbol.cast_into();

        // Change key only after the PRF has been evaluated. The recipient gets
        // no method/key to decrypt the source-key input vector.
        let recipient_output = self.output_key_switch.keyswitch(&source_output);
        Ok(EncryptedFastLwrPrfPepOutput {
            parameters: self.parameters,
            output_index: input.output_index,
            ciphertext: recipient_output,
        })
    }

    pub fn evaluate_many(
        &self,
        inputs: &[EncryptedFastLwrPrfPepInput],
    ) -> Result<Vec<EncryptedFastLwrPrfPepOutput>> {
        inputs.iter().map(|input| self.evaluate(input)).collect()
    }
}
