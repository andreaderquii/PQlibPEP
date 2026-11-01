//! Private-input adaptation of the Section 5 LWR PRF.
//!
//! IMPORTANT: this preserves the PRF function, but not the paper's depth-1
//! evaluation algorithm. The paper's one-PBS trick requires H(x) to be public.
//! Here the client computes H(x, slot) locally and encrypts every coefficient
//! under the recipient's TFHE public key. The evaluator only receives those
//! ciphertexts and an encrypted PRF key, so it never sees x or H(x).
//!
//! This is a correctness prototype using TFHE-rs high-level integer FHE. It
//! performs one encrypted conditional-select per LWR-key coefficient, followed
//! by encrypted accumulation and rounding. It is expected to be much slower
//! than the paper's public-input, one-PBS path. It is not yet an A->B key-switch
//! or proxy-re-encryption protocol: the input and output in this prototype are
//! encrypted under the same recipient key.

use std::{error::Error, fmt};

use super::fast_lwr_prf::{hash_to_ring_vector, FastLwrPrfParameters, FastLwrPrfSecretKey};
use tfhe::prelude::*;
use tfhe::{
    generate_keys, set_server_key, ClientKey, ConfigBuilder, FheBool, FheUint16, FheUint32,
    FheUint8, PublicKey, ServerKey,
};

/// Error from the private-input TFHE adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateInputPrfError(pub String);

impl fmt::Display for PrivateInputPrfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Error for PrivateInputPrfError {}

type Result<T> = std::result::Result<T, PrivateInputPrfError>;

fn validate_private_input_parameters(parameters: FastLwrPrfParameters) -> Result<()> {
    parameters
        .validate()
        .map_err(|error| PrivateInputPrfError(error.to_string()))?;

    // Coefficients of H(x, i) are in Z_(2N) and are encrypted as u16.
    // The output is returned as u8. The accumulator must fit in u32.
    let q = (parameters.ring_dimension as u128) * 2;
    if q > (u16::MAX as u128) + 1 {
        return Err(PrivateInputPrfError(
            "private-input prototype requires 2N <= 65536 for u16 coefficients".into(),
        ));
    }
    if parameters.output_modulus > 256 {
        return Err(PrivateInputPrfError(
            "private-input prototype currently supports p <= 256 (u8 output)".into(),
        ));
    }
    let maximum_sum = (q - 1) * (parameters.lwr_dimension as u128);
    if maximum_sum > u32::MAX as u128 {
        return Err(PrivateInputPrfError(
            "private-input dot product may overflow the u32 accumulator".into(),
        ));
    }
    Ok(())
}

/// Client/recipient context. Keep `client_key` secret; distribute only
/// `public_key` to the party preparing encrypted PRF inputs and PRF-key shares.
pub struct FastLwrPrfPrivateInputClient {
    parameters: FastLwrPrfParameters,
    client_key: ClientKey,
    public_key: PublicKey,
}

/// Server-side evaluator. It stores the TFHE server key and only encrypted PRF
/// key bits. It does not store a ClientKey or the clear PRF key.
pub struct FastLwrPrfPrivateInputEvaluationKey {
    parameters: FastLwrPrfParameters,
    encrypted_prf_key: Vec<FheBool>,
    server_key: ServerKey,
}

/// Encrypted representation of a PRF input component. The clear identifier
/// and the clear hash vector are not included in this object.
pub struct EncryptedFastLwrPrfInput {
    parameters: FastLwrPrfParameters,
    output_index: u64,
    encrypted_coefficients: Vec<FheUint16>,
}

impl EncryptedFastLwrPrfInput {
    pub fn parameters(&self) -> FastLwrPrfParameters {
        self.parameters
    }

    /// Slot index starts at one, following H(x, i) in the paper.
    pub fn output_index(&self) -> u64 {
        self.output_index
    }

    pub fn coefficient_count(&self) -> usize {
        self.encrypted_coefficients.len()
    }
}

/// One encrypted PRF symbol in Z_p, represented as an FHE u8 ciphertext.
pub struct EncryptedFastLwrPrfOutput {
    parameters: FastLwrPrfParameters,
    output_index: u64,
    ciphertext: FheUint8,
}

impl EncryptedFastLwrPrfOutput {
    pub fn parameters(&self) -> FastLwrPrfParameters {
        self.parameters
    }

    pub fn output_index(&self) -> u64 {
        self.output_index
    }

    /// Borrow the raw high-level TFHE ciphertext for later serialization or
    /// key-switch integration. Serialization is not implemented by this module.
    pub fn ciphertext(&self) -> &FheUint8 {
        &self.ciphertext
    }
}

impl FastLwrPrfPrivateInputClient {
    /// Generates recipient keys. The caller keeps this client's secret key and
    /// gives the returned ServerKey to the evaluator. The PublicKey is used to
    /// encrypt both H(x, i) and the PRF-key bits without revealing either value.
    pub fn generate(parameters: FastLwrPrfParameters) -> Result<(Self, ServerKey)> {
        validate_private_input_parameters(parameters)?;
        let (client_key, server_key) = generate_keys(ConfigBuilder::default().build());
        let public_key = PublicKey::new(&client_key);
        Ok((
            Self {
                parameters,
                client_key,
                public_key,
            },
            server_key,
        ))
    }

    pub fn parameters(&self) -> FastLwrPrfParameters {
        self.parameters
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Runs the public random-oracle encoding locally, then encrypts every
    /// coefficient before anything is sent to the evaluator. The evaluator's
    /// API never accepts the raw identifier.
    pub fn encrypt_input(
        &self,
        input: &[u8],
        output_index: u64,
    ) -> Result<EncryptedFastLwrPrfInput> {
        validate_private_input_parameters(self.parameters)?;
        if output_index == 0 {
            return Err(PrivateInputPrfError(
                "PRF output indices start at one".into(),
            ));
        }

        let clear_vector = hash_to_ring_vector(self.parameters, input, output_index);
        let mut encrypted_coefficients = Vec::with_capacity(clear_vector.len());
        for coefficient in clear_vector {
            let coefficient = u16::try_from(coefficient).map_err(|_| {
                PrivateInputPrfError("H(x, i) coefficient does not fit in u16".into())
            })?;
            let ciphertext =
                FheUint16::try_encrypt(coefficient, &self.public_key).map_err(|error| {
                    PrivateInputPrfError(format!("input encryption failed: {error}"))
                })?;
            encrypted_coefficients.push(ciphertext);
        }

        Ok(EncryptedFastLwrPrfInput {
            parameters: self.parameters,
            output_index,
            encrypted_coefficients,
        })
    }

    /// Encrypts a vector of slots H(x, 1), ..., H(x, count). This constructs
    /// the encrypted input side of a multi-slot PRF evaluation. `count = 0`
    /// returns an empty vector without doing any encryption.
    pub fn encrypt_inputs(
        &self,
        input: &[u8],
        count: usize,
    ) -> Result<Vec<EncryptedFastLwrPrfInput>> {
        let mut encrypted = Vec::with_capacity(count);
        for index in 1..=count {
            let index = u64::try_from(index).map_err(|_| {
                PrivateInputPrfError("output slot index does not fit in u64".into())
            })?;
            encrypted.push(self.encrypt_input(input, index)?);
        }
        Ok(encrypted)
    }

    /// Decrypts a result as the recipient. The evaluator cannot call this
    /// method because it does not possess this ClientKey.
    pub fn decrypt_output(&self, output: &EncryptedFastLwrPrfOutput) -> Result<u8> {
        if output.parameters != self.parameters {
            return Err(PrivateInputPrfError(
                "output parameters do not match recipient parameters".into(),
            ));
        }
        let value: u8 = output.ciphertext.decrypt(&self.client_key);
        if (value as u64) >= self.parameters.output_modulus {
            return Err(PrivateInputPrfError(
                "decrypted symbol is outside Z_p".into(),
            ));
        }
        Ok(value)
    }

    /// Decrypts all output slots in index order.
    pub fn decrypt_many_outputs(&self, outputs: &[EncryptedFastLwrPrfOutput]) -> Result<Vec<u8>> {
        outputs
            .iter()
            .map(|output| self.decrypt_output(output))
            .collect()
    }

    /// Packs decrypted p=2^k PRF symbols into a byte string, most-significant
    /// bit first. Excess final bits are truncated to `output_len_bytes`; too
    /// few symbols are rejected. The recipient is allowed to see this plaintext.
    pub fn pack_symbols_to_bytes(
        &self,
        symbols: &[u8],
        output_len_bytes: usize,
    ) -> Result<Vec<u8>> {
        let bits_per_symbol = self.parameters.output_modulus.trailing_zeros() as usize;
        let required_bits = output_len_bytes
            .checked_mul(8)
            .ok_or_else(|| PrivateInputPrfError("requested output length is too large".into()))?;
        if symbols
            .len()
            .checked_mul(bits_per_symbol)
            .unwrap_or(usize::MAX)
            < required_bits
        {
            return Err(PrivateInputPrfError(
                "not enough PRF symbols to fill the requested byte string".into(),
            ));
        }
        if symbols
            .iter()
            .any(|&symbol| (symbol as u64) >= self.parameters.output_modulus)
        {
            return Err(PrivateInputPrfError("symbol outside Z_p".into()));
        }

        let mut output = vec![0u8; output_len_bytes];
        let mut output_bit_index = 0usize;
        for &symbol in symbols {
            for bit_pos in (0..bits_per_symbol).rev() {
                if output_bit_index == required_bits {
                    return Ok(output);
                }
                let bit = (symbol >> bit_pos) & 1;
                let byte_index = output_bit_index / 8;
                let bit_in_byte = 7 - (output_bit_index % 8);
                output[byte_index] |= bit << bit_in_byte;
                output_bit_index += 1;
            }
        }
        Ok(output)
    }
}

impl FastLwrPrfPrivateInputEvaluationKey {
    /// Encrypts the LWR key bits under the recipient's public key and retains
    /// only ciphertexts plus the public TFHE server key.
    pub fn new(
        prf_secret_key: &FastLwrPrfSecretKey,
        recipient_public_key: &PublicKey,
        server_key: ServerKey,
    ) -> Result<Self> {
        let parameters = prf_secret_key.parameters();
        validate_private_input_parameters(parameters)?;

        let mut encrypted_prf_key = Vec::with_capacity(parameters.lwr_dimension);
        for &bit in prf_secret_key.bits() {
            let ciphertext =
                FheBool::try_encrypt(bit == 1, recipient_public_key).map_err(|error| {
                    PrivateInputPrfError(format!("PRF-key encryption failed: {error}"))
                })?;
            encrypted_prf_key.push(ciphertext);
        }

        Ok(Self {
            parameters,
            encrypted_prf_key,
            server_key,
        })
    }

    pub fn parameters(&self) -> FastLwrPrfParameters {
        self.parameters
    }

    /// Evaluates one PRF slot from an encrypted H(x, i) vector. Every term is
    /// selected homomorphically by an encrypted bit s_j; the server does not
    /// receive the clear input x, the hash vector, or the clear PRF key.
    ///
    /// This is the private-input adaptation, not the paper's one-PBS algorithm:
    /// hiding H(x, i) requires additional encrypted computation.
    pub fn evaluate(&self, input: &EncryptedFastLwrPrfInput) -> Result<EncryptedFastLwrPrfOutput> {
        if input.parameters != self.parameters {
            return Err(PrivateInputPrfError(
                "input parameters do not match evaluation-key parameters".into(),
            ));
        }
        if input.output_index == 0
            || input.encrypted_coefficients.len() != self.parameters.lwr_dimension
            || self.encrypted_prf_key.len() != self.parameters.lwr_dimension
        {
            return Err(PrivateInputPrfError(
                "encrypted input or PRF-key vector has an invalid length/index".into(),
            ));
        }

        set_server_key(self.server_key.clone());

        // a_j and s_j are encrypted under the recipient's TFHE key. Since s_j
        // is encrypted Boolean, cmux(a_j, 0) computes a_j * s_j without ever
        // disclosing the bit. The sum is bounded by lwr_dimension * (2N - 1).
        let first =
            self.encrypted_prf_key[0].scalar_if_then_else(&input.encrypted_coefficients[0], 0_u16);
        let mut sum: FheUint32 = first.cast_into();

        for index in 1..self.parameters.lwr_dimension {
            let selected = self.encrypted_prf_key[index]
                .scalar_if_then_else(&input.encrypted_coefficients[index], 0_u16);
            let term: FheUint32 = selected.cast_into();
            sum = &sum + &term;
        }

        // Q = 2N is a power of two, so reduction modulo Q is a bit mask.
        // The paper's depth-1 PRF returns (-1)^msb(phase) * floor(p*(phase mod N)/N) mod p.
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
        // Two's-complement negation modulo p: -v mod 2^k = ((v XOR (p-1)) + 1) AND (p-1).
        let negated = ((&symbol ^ p_mask) + 1_u32) & p_mask;
        let signed_symbol = is_negative.if_then_else(&negated, &symbol);
        let ciphertext: FheUint8 = signed_symbol.cast_into();

        Ok(EncryptedFastLwrPrfOutput {
            parameters: self.parameters,
            output_index: input.output_index,
            ciphertext,
        })
    }

    /// Evaluates all encrypted input slots in order. This is sequential on
    /// purpose: TFHE's high-level ServerKey is installed in a thread-local context.
    pub fn evaluate_many(
        &self,
        inputs: &[EncryptedFastLwrPrfInput],
    ) -> Result<Vec<EncryptedFastLwrPrfOutput>> {
        inputs.iter().map(|input| self.evaluate(input)).collect()
    }
}
