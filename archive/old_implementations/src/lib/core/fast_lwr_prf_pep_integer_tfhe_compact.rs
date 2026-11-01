//! Experimental compact-input PEP adapter for the depth-1 LWR PRF using TFHE-rs integer FHE.
//!
//! Input coefficients are encrypted under a SOURCE key. The evaluator knows the
//! PEP/LWR factor in the clear, evaluates the exact integer formula while the
//! input remains encrypted, and keyswitches only the final symbol to the
//! RECIPIENT key. The recipient can decrypt the output, but cannot decrypt the
//! source-key input ciphertexts.
//!
//! This is a correctness-first experiment. It uses TFHE-rs CompactCiphertextList
//! to batch-encrypt input coefficients and a balanced sum tree to avoid a purely
//! serial accumulation pattern. It still uses a centralized A->B key setup and
//! does not claim production security or distributed n-PEP key generation.
//! The compact list reduces input-encryption overhead only; it does not remove
//! the cost of integer homomorphic arithmetic nor solve parameter validation.

use std::{error::Error, fmt};

use super::fast_lwr_prf::{hash_to_ring_vector, FastLwrPrfParameters, FastLwrPrfSecretKey};
use tfhe::prelude::*;
use tfhe::{
    generate_keys, set_server_key, ClientKey, CompactCiphertextList, CompactPublicKey,
    ConfigBuilder, FheUint16, FheUint32, FheUint8, KeySwitchingKey, PublicKey, ServerKey,
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

/// Number of Z_p symbols required to pack `output_len_bytes` bytes, using the
/// PRF's fixed-width log2(p)-bit representation (most-significant bit first).
pub fn output_symbols_for_bytes(
    parameters: FastLwrPrfParameters,
    output_len_bytes: usize,
) -> Result<usize> {
    validate_parameters(parameters)?;
    let bits_per_symbol = parameters.output_modulus.trailing_zeros() as usize;
    let required_bits = output_len_bytes
        .checked_mul(8)
        .ok_or_else(|| PepIntegerTfheError("requested output length is too large".into()))?;
    Ok(required_bits
        .checked_add(bits_per_symbol - 1)
        .ok_or_else(|| PepIntegerTfheError("requested output length is too large".into()))?
        / bits_per_symbol)
}

/// Source-side encoder. It has the source public key, but no source secret key.
pub struct FastLwrPrfPepIntegerInputEncryptor {
    parameters: FastLwrPrfParameters,
    source_public_key: PublicKey,
    source_compact_public_key: CompactPublicKey,
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
    compact_coefficients: CompactCiphertextList,
    coefficient_count: usize,
}

impl EncryptedFastLwrPrfPepInput {
    pub fn parameters(&self) -> FastLwrPrfParameters {
        self.parameters
    }

    pub fn output_index(&self) -> u64 {
        self.output_index
    }

    pub fn coefficient_count(&self) -> usize {
        self.coefficient_count
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
pub fn setup_pep_integer_tfhe_compact(
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
    let source_compact_public_key = CompactPublicKey::try_new(&source_client_key).map_err(|e| {
        PepIntegerTfheError(format!("source parameters do not support compact public-key encryption: {e}"))
    })?;

    // Drop the source secret key and the target ServerKey from the returned
    // roles. They are only needed by this centralized experimental setup.
    let input_encryptor = FastLwrPrfPepIntegerInputEncryptor {
        parameters,
        source_public_key: source_public_key.clone(),
        source_compact_public_key,
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
    /// Hashes the identifier locally and compact-encrypts all H(x, slot)
    /// coefficients under source key A before sending them to the evaluator.
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
        let mut builder = CompactCiphertextList::builder(&self.source_compact_public_key);
        for coefficient in clear_vector.iter().copied() {
            let value = u16::try_from(coefficient).map_err(|_| {
                PepIntegerTfheError("H(x, slot) coefficient does not fit in u16".into())
            })?;
            builder.push(value);
        }
        // One compact list encrypts all H(x, slot) coefficients. The evaluator
        // expands it to ordinary FheUint16 ciphertexts before computation.
        let compact_coefficients = builder.build();
        if compact_coefficients.len() != clear_vector.len() {
            return Err(PepIntegerTfheError(format!(
                "compact input contains {} coefficients, expected {}",
                compact_coefficients.len(), clear_vector.len()
            )));
        }

        Ok(EncryptedFastLwrPrfPepInput {
            parameters: self.parameters,
            output_index,
            compact_coefficients,
            coefficient_count: clear_vector.len(),
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

    /// Encrypt all indexed hash vectors needed for a byte-string output.
    pub fn encrypt_inputs_for_output_bytes(
        &self,
        input: &[u8],
        output_len_bytes: usize,
    ) -> Result<Vec<EncryptedFastLwrPrfPepInput>> {
        let count = output_symbols_for_bytes(self.parameters, output_len_bytes)?;
        self.encrypt_inputs(input, count)
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

    /// Decrypt and pack PRF symbols into exactly `output_len_bytes` bytes.
    pub fn decrypt_outputs_to_bytes(
        &self,
        outputs: &[EncryptedFastLwrPrfPepOutput],
        output_len_bytes: usize,
    ) -> Result<Vec<u8>> {
        let expected_count = output_symbols_for_bytes(self.parameters, output_len_bytes)?;
        if outputs.len() != expected_count {
            return Err(PepIntegerTfheError(format!(
                "expected {expected_count} output symbols for {output_len_bytes} bytes, got {}",
                outputs.len()
            )));
        }
        for (offset, output) in outputs.iter().enumerate() {
            let expected_index = u64::try_from(offset + 1)
                .map_err(|_| PepIntegerTfheError("output index does not fit in u64".into()))?;
            if output.output_index != expected_index || output.parameters != self.parameters {
                return Err(PepIntegerTfheError(format!(
                    "outputs must have matching parameters and contiguous one-based indices; expected slot {expected_index}"
                )));
            }
        }
        let symbols = self.decrypt_many_outputs(outputs)?;
        pack_symbols_to_bytes(self.parameters, &symbols, output_len_bytes)
    }
}

/// Pack fixed-width PRF symbols into bytes, most-significant bit first.
/// Any unused trailing bits in the final symbol are discarded.
pub fn pack_symbols_to_bytes(
    parameters: FastLwrPrfParameters,
    symbols: &[u8],
    output_len_bytes: usize,
) -> Result<Vec<u8>> {
    validate_parameters(parameters)?;
    let bits_per_symbol = parameters.output_modulus.trailing_zeros() as usize;
    let required_bits = output_len_bytes
        .checked_mul(8)
        .ok_or_else(|| PepIntegerTfheError("requested output length is too large".into()))?;
    let available_bits = symbols
        .len()
        .checked_mul(bits_per_symbol)
        .unwrap_or(usize::MAX);
    if available_bits < required_bits {
        return Err(PepIntegerTfheError(
            "not enough PRF symbols to fill requested output bytes".into(),
        ));
    }
    if symbols.iter().any(|&symbol| (symbol as u64) >= parameters.output_modulus) {
        return Err(PepIntegerTfheError("symbol outside Z_p".into()));
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

impl FastLwrPrfPepIntegerEvaluator {
    /// Expands the compact input list, computes one symbol with exact integer
    /// arithmetic under source key A, and switches only the final FheUint8 to B.
    pub fn evaluate(
        &self,
        input: &EncryptedFastLwrPrfPepInput,
    ) -> Result<EncryptedFastLwrPrfPepOutput> {
        if input.parameters != self.parameters
            || input.output_index == 0
            || input.coefficient_count != self.parameters.lwr_dimension
            || input.compact_coefficients.len() != self.parameters.lwr_dimension
            || self.factor_bits.len() != self.parameters.lwr_dimension
        {
            return Err(PepIntegerTfheError(
                "input metadata/dimensions do not match evaluator parameters".into(),
            ));
        }

        // Important: all arithmetic up to the final key switch stays under source key A.
        set_server_key(self.source_server_key.clone());
        let expanded = input.compact_coefficients.expand().map_err(|e| {
            PepIntegerTfheError(format!("cannot expand compact input coefficients: {e}"))
        })?;

        // Collect only terms whose public factor bit is 1. A balanced reduction
        // limits the serial dependency chain; default `+` keeps carries canonical.
        let mut terms: Vec<FheUint32> = Vec::with_capacity(self.factor_bits.iter().filter(|&&b| b == 1).count());
        for (index, &bit) in self.factor_bits.iter().enumerate() {
            if bit == 1 {
                let coefficient: FheUint16 = expanded
                    .get::<FheUint16>(index)
                    .map_err(|e| PepIntegerTfheError(format!("cannot read compact coefficient {index}: {e}")))?
                    .ok_or_else(|| PepIntegerTfheError(format!("compact input is missing coefficient {index}")))?;
                let term: FheUint32 = coefficient.cast_into();
                terms.push(term);
            }
        }

        let sum: FheUint32 = if terms.is_empty() {
            FheUint32::try_encrypt(0_u32, &self.source_public_key)
                .map_err(|e| PepIntegerTfheError(format!("cannot encrypt accumulator zero: {e}")))?
        } else {
            while terms.len() > 1 {
                let mut next = Vec::with_capacity((terms.len() + 1) / 2);
                let mut iter = terms.into_iter();
                while let Some(left) = iter.next() {
                    if let Some(right) = iter.next() {
                        next.push(&left + &right);
                    } else {
                        next.push(left);
                    }
                }
                terms = next;
            }
            terms.pop().expect("non-empty sum terms")
        };

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
        for (offset, input) in inputs.iter().enumerate() {
            let expected_index = u64::try_from(offset + 1)
                .map_err(|_| PepIntegerTfheError("output index does not fit in u64".into()))?;
            if input.output_index != expected_index {
                return Err(PepIntegerTfheError(format!(
                    "encrypted input slots must be ordered and contiguous; expected index {expected_index}"
                )));
            }
        }
        inputs.iter().map(|input| self.evaluate(input)).collect()
    }

    /// Evaluate exactly the number of PRF symbols needed to form a byte string.
    pub fn evaluate_outputs_for_bytes(
        &self,
        inputs: &[EncryptedFastLwrPrfPepInput],
        output_len_bytes: usize,
    ) -> Result<Vec<EncryptedFastLwrPrfPepOutput>> {
        let expected_count = output_symbols_for_bytes(self.parameters, output_len_bytes)?;
        if inputs.len() != expected_count {
            return Err(PepIntegerTfheError(format!(
                "expected {expected_count} input slots for {output_len_bytes} bytes, got {}",
                inputs.len()
            )));
        }
        self.evaluate_many(inputs)
    }
}
