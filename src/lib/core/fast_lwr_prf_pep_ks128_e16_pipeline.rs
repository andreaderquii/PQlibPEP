//! Experimental pipeline adapter for the Section 5 depth-1 LWR PRF.
//! Adds versioned wire envelopes and context/batch identifiers around the tested KS128/E16 packed path.
//!
//! This prototype keeps the identifier/hash vector and PRF output encrypted
//! while performing the linear LWR dot product and one PBS per output symbol.
//! It deliberately follows the traditional PEP trust model in which the
//! transcryptor holds the pseudonymisation factor `s`; it does NOT hide `s`
//! from the transcryptor. The source domain computes H(x, slot) locally and
//! encrypts the vector as a GLWE plaintext polynomial under its own TFHE key.
//! The evaluation pipeline key-switches the extracted dot-product sample to an
//! intermediate LWE key, then a PBS maps it to the recipient's output key.
//!
//! Experimental packed candidate: the full H(x,i) vector is encrypted in one
//! GLWE ciphertext when the configured input block accommodates the PRF vector.
//! A key switch reduces the extracted LWE sample to the configured intermediate dimension
//! before one PBS with 16x polynomial expansion. This removes the earlier 56
//! ciphertext blocks per slot, but does not reduce the PBS output ciphertext size.
//! This remains experimental: parameter security, failure probability and
//! lattice security must be reviewed before any deployment claim. The expanded
//! PBS polynomial size is derived from the PRF ring dimension and configured expansion;
//! setup may be slow.
//! This file is an experimental adapter, not a production security claim.
//! It evaluates the PRF on an encrypted encoding of H(x,i); it does not
//! convert an already computed F_{s_A}(x) into F_{s_B}(x), and therefore does
//! not implement PEP RS2. The local setup also gives the full PRF key to one
//! evaluator rather than generating distributed factor shares as in n-PEP.
//! The setup helper below creates source/recipient/evaluator material in one
//! process for tests; production needs a documented trusted or distributed provisioning
//! protocol, parameter review, and authenticated transport. The versioned wire envelopes
//! and random context/batch tags in this module are experimental protocol hygiene only;
//! tags are not MACs/signatures and do not prevent a malicious network peer from tampering.

use crate::parameters::tfhe_private_input_prototype as parameter_profile;
use core::fmt;
use rand::{rngs::OsRng, RngCore};
use std::error::Error;

use super::fast_lwr_prf::{hash_to_ring_vector, FastLwrPrfParameters, FastLwrPrfSecretKey};
use tfhe::core_crypto::algorithms::glwe_encryption::encrypt_glwe_ciphertext_assign;
use tfhe::core_crypto::algorithms::glwe_sample_extraction::extract_lwe_sample_from_glwe_ciphertext;
use tfhe::core_crypto::algorithms::lwe_keyswitch::par_keyswitch_lwe_ciphertext;
use tfhe::core_crypto::algorithms::lwe_keyswitch_key_generation::allocate_and_generate_new_lwe_keyswitch_key;
use tfhe::core_crypto::algorithms::lwe_programmable_bootstrapping::fft128_pbs::programmable_bootstrap_f128_lwe_ciphertext;
use tfhe::core_crypto::fft_impl::fft128::crypto::bootstrap::Fourier128LweBootstrapKeyOwned;
use tfhe::core_crypto::prelude::*;

const PBS_BASE_LOG: usize = parameter_profile::PBS_BASE_LOG;
const PBS_LEVEL_COUNT: usize = parameter_profile::PBS_LEVEL_COUNT;
const INPUT_LWE_BLOCK_SIZE: usize = parameter_profile::INPUT_BLOCK_SIZE;
const PBS_POLY_EXPANSION_FACTOR: usize = parameter_profile::PBS_POLYNOMIAL_EXPANSION_FACTOR;
const PBS_INPUT_LWE_DIMENSION: usize = parameter_profile::PBS_INPUT_LWE_DIMENSION;
const KSK_BASE_LOG: usize = parameter_profile::KSK_BASE_LOG;
const KSK_LEVEL_COUNT: usize = parameter_profile::KSK_LEVEL_COUNT;
const GLWE_DIMENSION: usize = parameter_profile::SOURCE_GLWE_DIMENSION;
const GLWE_SIZE: usize = GLWE_DIMENSION + 1;
const INPUT_GLWE_GAUSSIAN_STD_DEV: f64 = parameter_profile::INPUT_GLWE_GAUSSIAN_STD_DEV;
const KSK_GAUSSIAN_STD_DEV: f64 = parameter_profile::KSK_GAUSSIAN_STD_DEV;
const PBS_GAUSSIAN_STD_DEV: f64 = parameter_profile::PBS_GAUSSIAN_STD_DEV;
const WIRE_VERSION: u8 = crate::parameters::pep_wire::VERSION;
const INPUT_WIRE_MAGIC: &[u8; 4] = &crate::parameters::pep_wire::PRF_INPUT_MAGIC;
const OUTPUT_WIRE_MAGIC: &[u8; 4] = &crate::parameters::pep_wire::PRF_OUTPUT_MAGIC;
pub const PEP_CONTEXT_ID_LEN: usize = crate::parameters::pep_wire::CONTEXT_ID_BYTES;
const CONTEXT_ID_LEN: usize = PEP_CONTEXT_ID_LEN;
// Keep the configured torus width synchronized with the concrete ciphertext type.
const _: [(); parameter_profile::TORUS_MODULUS_BITS] = [(); u128::BITS as usize];

fn fresh_id() -> [u8; CONTEXT_ID_LEN] {
    let mut id = [0u8; CONTEXT_ID_LEN];
    let mut rng = OsRng;
    rng.fill_bytes(&mut id);
    id
}

fn write_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}
fn write_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}
fn write_u128(out: &mut Vec<u8>, value: u128) {
    out.extend_from_slice(&value.to_le_bytes());
}
fn write_parameters(out: &mut Vec<u8>, parameters: FastLwrPrfParameters) -> Result<()> {
    write_u64(
        out,
        u64::try_from(parameters.lwr_dimension)
            .map_err(|_| PepLwrPrfError("LWR dimension does not fit the wire format".into()))?,
    );
    write_u64(
        out,
        u64::try_from(parameters.ring_dimension)
            .map_err(|_| PepLwrPrfError("ring dimension does not fit the wire format".into()))?,
    );
    write_u64(out, parameters.output_modulus);
    Ok(())
}

struct WireReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> WireReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }
    fn take(&mut self, length: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or_else(|| PepLwrPrfError("wire length overflow".into()))?;
        if end > self.bytes.len() {
            return Err(PepLwrPrfError("truncated wire message".into()));
        }
        let result = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(result)
    }
    fn read_u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn read_u32(&mut self) -> Result<u32> {
        let raw: [u8; 4] = self
            .take(4)?
            .try_into()
            .map_err(|_| PepLwrPrfError("invalid u32 field".into()))?;
        Ok(u32::from_le_bytes(raw))
    }
    fn read_u64(&mut self) -> Result<u64> {
        let raw: [u8; 8] = self
            .take(8)?
            .try_into()
            .map_err(|_| PepLwrPrfError("invalid u64 field".into()))?;
        Ok(u64::from_le_bytes(raw))
    }
    fn read_u128(&mut self) -> Result<u128> {
        let raw: [u8; 16] = self
            .take(16)?
            .try_into()
            .map_err(|_| PepLwrPrfError("invalid u128 field".into()))?;
        Ok(u128::from_le_bytes(raw))
    }
    fn read_id(&mut self) -> Result<[u8; CONTEXT_ID_LEN]> {
        self.take(CONTEXT_ID_LEN)?
            .try_into()
            .map_err(|_| PepLwrPrfError("invalid context ID".into()))
    }
    fn ensure_finished(&self) -> Result<()> {
        if self.offset != self.bytes.len() {
            return Err(PepLwrPrfError("wire message has trailing bytes".into()));
        }
        Ok(())
    }
}

fn read_parameters(reader: &mut WireReader<'_>) -> Result<FastLwrPrfParameters> {
    let lwr_dimension = usize::try_from(reader.read_u64()?)
        .map_err(|_| PepLwrPrfError("wire LWR dimension does not fit usize".into()))?;
    let ring_dimension = usize::try_from(reader.read_u64()?)
        .map_err(|_| PepLwrPrfError("wire ring dimension does not fit usize".into()))?;
    let parameters = FastLwrPrfParameters {
        lwr_dimension,
        ring_dimension,
        output_modulus: reader.read_u64()?,
    };
    validate_pep_parameters(parameters)?;
    Ok(parameters)
}

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
    if parameters.output_modulus > crate::parameters::fast_lwr_prf::BYTE_ADAPTER_MAX_OUTPUT_MODULUS
    {
        return Err(PepLwrPrfError(format!(
            "byte-output adapter currently requires p <= {}",
            crate::parameters::fast_lwr_prf::BYTE_ADAPTER_MAX_OUTPUT_MODULUS
        )));
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
#[cfg_attr(feature = "pep-role-lab", derive(serde::Serialize, serde::Deserialize))]
pub struct FastLwrPrfPepInputClient {
    parameters: FastLwrPrfParameters,
    input_polynomial_size: PolynomialSize,
    input_glwe_secret_key: GlweSecretKey<Vec<u128>>,
    source_context_id: [u8; CONTEXT_ID_LEN],
}

/// Recipient client: owns only the output LWE secret key and decrypts symbols.
#[cfg_attr(feature = "pep-role-lab", derive(serde::Serialize, serde::Deserialize))]
pub struct FastLwrPrfPepRecipientKey {
    parameters: FastLwrPrfParameters,
    output_lwe_secret_key: LweSecretKey<Vec<u128>>,
    recipient_key_id: [u8; CONTEXT_ID_LEN],
}

/// Transcryptor-side material. The LWR pseudonymisation factor is held in clear
/// in this object as in the PEP converter trust model. Input and output values
/// are encrypted; if the key must also be hidden from the transcryptor, this
/// implementation is not that security model.
#[cfg_attr(feature = "pep-role-lab", derive(serde::Serialize, serde::Deserialize))]
pub struct FastLwrPrfPepEvaluator {
    parameters: FastLwrPrfParameters,
    input_polynomial_size: PolynomialSize,
    output_polynomial_size: PolynomialSize,
    prf_secret_bits: Vec<u8>,
    source_context_id: [u8; CONTEXT_ID_LEN],
    recipient_key_id: [u8; CONTEXT_ID_LEN],
    /// Key-switches extracted samples from the full source LWE key (dimension 512
    /// for paper parameters) to an independent intermediate LWE key (dimension 128).
    input_to_pbs_keyswitch_key: LweKeyswitchKey<Vec<u128>>,
    bootstrapping_key: Fourier128LweBootstrapKeyOwned,
    accumulator: GlweCiphertext<Vec<u128>>,
}

/// One encrypted vector H(x, slot), packed into GLWE block(s). With paper
/// parameters, the 445 coefficients fit in one GLWE plaintext of size 512.
pub struct EncryptedFastLwrPrfPepInput {
    parameters: FastLwrPrfParameters,
    source_context_id: [u8; CONTEXT_ID_LEN],
    batch_id: [u8; CONTEXT_ID_LEN],
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

    /// Non-secret routing tag identifying the source encryption context. This is
    /// not an authentication token and does not protect against wire tampering.
    pub fn source_context_id(&self) -> [u8; CONTEXT_ID_LEN] {
        self.source_context_id
    }

    /// Identifier shared by all indexed slots belonging to one pseudonym request.
    pub fn batch_id(&self) -> [u8; CONTEXT_ID_LEN] {
        self.batch_id
    }

    /// Versioned little-endian envelope for transport between process boundaries.
    /// The receiver must authenticate the message separately in an adversarial network.
    pub fn to_wire_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        out.extend_from_slice(INPUT_WIRE_MAGIC);
        out.push(WIRE_VERSION);
        write_parameters(&mut out, self.parameters)?;
        out.extend_from_slice(&self.source_context_id);
        out.extend_from_slice(&self.batch_id);
        write_u64(&mut out, self.output_index);
        write_u32(
            &mut out,
            u32::try_from(self.ciphertexts.len())
                .map_err(|_| PepLwrPrfError("too many GLWE blocks for wire format".into()))?,
        );
        for ciphertext in &self.ciphertexts {
            let coefficients = ciphertext.as_ref();
            write_u64(
                &mut out,
                u64::try_from(coefficients.len()).map_err(|_| {
                    PepLwrPrfError("GLWE ciphertext too large for wire format".into())
                })?,
            );
            for &coefficient in coefficients {
                write_u128(&mut out, coefficient);
            }
        }
        Ok(out)
    }
}

/// One encrypted PRF symbol under the recipient's output LWE key.
pub struct EncryptedFastLwrPrfPepOutput {
    parameters: FastLwrPrfParameters,
    source_context_id: [u8; CONTEXT_ID_LEN],
    recipient_key_id: [u8; CONTEXT_ID_LEN],
    batch_id: [u8; CONTEXT_ID_LEN],
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

    pub fn recipient_key_id(&self) -> [u8; CONTEXT_ID_LEN] {
        self.recipient_key_id
    }
    pub fn source_context_id(&self) -> [u8; CONTEXT_ID_LEN] {
        self.source_context_id
    }
    pub fn batch_id(&self) -> [u8; CONTEXT_ID_LEN] {
        self.batch_id
    }

    /// Versioned little-endian envelope. Context tags detect accidental context
    /// mix-ups; callers still need authenticated transport to detect modification.
    pub fn to_wire_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        out.extend_from_slice(OUTPUT_WIRE_MAGIC);
        out.push(WIRE_VERSION);
        write_parameters(&mut out, self.parameters)?;
        out.extend_from_slice(&self.source_context_id);
        out.extend_from_slice(&self.recipient_key_id);
        out.extend_from_slice(&self.batch_id);
        write_u64(&mut out, self.output_index);
        let coefficients = self.ciphertext.as_ref();
        write_u64(
            &mut out,
            u64::try_from(coefficients.len())
                .map_err(|_| PepLwrPrfError("LWE ciphertext too large for wire format".into()))?,
        );
        for &coefficient in coefficients {
            write_u128(&mut out, coefficient);
        }
        Ok(out)
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
    // The LWR modulus N remains unchanged. With paper parameters, all 445 hash
    // coefficients fit into one GLWE plaintext polynomial of size 512. The source
    // secret dimension is therefore 512, while the intermediate LWE dimension
    // before PBS is 128. This is an experimental correctness/performance candidate,
    // not a security claim.
    let output_n = parameters
        .ring_dimension
        .checked_mul(PBS_POLY_EXPANSION_FACTOR)
        .ok_or_else(|| PepLwrPrfError("expanded PBS polynomial size overflows usize".into()))?;
    let output_polynomial_size = PolynomialSize(output_n);
    let glwe_dimension = GlweDimension(GLWE_DIMENSION);
    let glwe_size = glwe_dimension.to_glwe_size();
    let ciphertext_modulus = CiphertextModulus::new_native();

    // Routing tags bind envelopes to these locally generated contexts. They are
    // public metadata, not cryptographic authentication and not key material.
    let source_context_id = fresh_id();
    let recipient_key_id = fresh_id();

    let mut boxed_seeder = new_seeder();
    let seeder = boxed_seeder.as_mut();
    let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

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

    // This independent intermediate key shortens the LWE dimension entering PBS.
    // It is not given to the evaluator; evaluation keys below support the switch
    // and PBS, as in standard TFHE key switching/bootstrapping.
    let pbs_input_lwe_secret_key: LweSecretKey<Vec<u128>> = LweSecretKey::generate_new_binary(
        LweDimension(PBS_INPUT_LWE_DIMENSION),
        &mut secret_generator,
    );

    // Key-switch source-extracted samples (dimension 512 for paper parameters)
    // to the intermediate LWE key before PBS. Use a separate seeder so its
    // encryption generator does not borrow the setup seeder needed by the BSK.
    let input_to_pbs_keyswitch_key = {
        let mut ksk_boxed_seeder = new_seeder();
        let ksk_seeder = ksk_boxed_seeder.as_mut();
        let mut ksk_encryption_generator =
            EncryptionRandomGenerator::<DefaultRandomGenerator>::new(ksk_seeder.seed(), ksk_seeder);
        let ksk_noise_distribution =
            Gaussian::from_dispersion_parameter(StandardDev(KSK_GAUSSIAN_STD_DEV), 0.0);
        allocate_and_generate_new_lwe_keyswitch_key(
            &input_lwe_secret_key,
            &pbs_input_lwe_secret_key,
            DecompositionBaseLog(KSK_BASE_LOG),
            DecompositionLevelCount(KSK_LEVEL_COUNT),
            ksk_noise_distribution,
            ciphertext_modulus,
            &mut ksk_encryption_generator,
        )
    };

    // The PBS evaluation key now maps the intermediate LWE key to the recipient
    // key. With dimension 128 and expansion 16, this experiment tests whether reducing the
    // number of modulus-switched mask coefficients improves E16 correctness and lowers BSK cost.
    // Key-switch noise and correctness still require empirical validation.
    let base_log = DecompositionBaseLog(PBS_BASE_LOG);
    let level_count = DecompositionLevelCount(PBS_LEVEL_COUNT);
    // TFHE-rs from_dispersion_parameter expects variance (sigma squared).
    let glwe_noise_distribution =
        Gaussian::from_dispersion_parameter(StandardDev(PBS_GAUSSIAN_STD_DEV), 0.0);
    let seeded_bootstrapping_key = par_allocate_and_generate_new_seeded_lwe_bootstrap_key(
        &pbs_input_lwe_secret_key,
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
        pbs_input_lwe_secret_key.lwe_dimension(),
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
            ((parameters.output_modulus as u128) * x / (parameters.ring_dimension as u128))
                % (parameters.output_modulus as u128)
        },
    );

    Ok((
        FastLwrPrfPepInputClient {
            parameters,
            input_polynomial_size,
            input_glwe_secret_key,
            source_context_id,
        },
        FastLwrPrfPepRecipientKey {
            parameters,
            output_lwe_secret_key,
            recipient_key_id,
        },
        FastLwrPrfPepEvaluator {
            parameters,
            input_polynomial_size,
            output_polynomial_size,
            prf_secret_bits: prf_secret_key.bits().to_vec(),
            source_context_id,
            recipient_key_id,
            input_to_pbs_keyswitch_key,
            bootstrapping_key: fourier_bootstrapping_key,
            accumulator,
        },
    ))
}

impl FastLwrPrfPepInputClient {
    pub fn parameters(&self) -> FastLwrPrfParameters {
        self.parameters
    }

    pub fn source_context_id(&self) -> [u8; CONTEXT_ID_LEN] {
        self.source_context_id
    }

    pub fn encrypt_input(
        &self,
        input: &[u8],
        output_index: u64,
    ) -> Result<EncryptedFastLwrPrfPepInput> {
        self.encrypt_input_with_batch(input, output_index, fresh_id())
    }

    fn encrypt_input_with_batch(
        &self,
        input: &[u8],
        output_index: u64,
        batch_id: [u8; CONTEXT_ID_LEN],
    ) -> Result<EncryptedFastLwrPrfPepInput> {
        if output_index == 0 {
            return Err(PepLwrPrfError("PRF output indices start at one".into()));
        }
        let clear_vector = hash_to_ring_vector(self.parameters, input, output_index);
        let delta = (1_u128 << 127) / (self.parameters.ring_dimension as u128);
        let block_size = INPUT_LWE_BLOCK_SIZE.min(self.parameters.lwr_dimension);
        let mut ciphertexts =
            Vec::with_capacity((clear_vector.len() + block_size - 1) / block_size);

        // With paper parameters, block_size=445 and this loop produces one GLWE
        // ciphertext containing the entire hash vector. Smaller dimensions also
        // use one block. Each ciphertext uses fresh encryption randomness.
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
                for (destination, value) in body_coefficients.iter_mut().zip(values.iter().copied())
                {
                    *destination = (value as u128) * delta;
                }
            }

            let mut boxed_seeder = new_seeder();
            let seeder = boxed_seeder.as_mut();
            let mut encryption_generator =
                EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
            let noise_distribution =
                Gaussian::from_dispersion_parameter(StandardDev(INPUT_GLWE_GAUSSIAN_STD_DEV), 0.0);
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
            source_context_id: self.source_context_id,
            batch_id,
            output_index,
            ciphertexts,
        })
    }

    pub fn encrypt_inputs(
        &self,
        input: &[u8],
        count: usize,
    ) -> Result<Vec<EncryptedFastLwrPrfPepInput>> {
        // All indexed symbols for one pseudonym share one batch ID, allowing the
        // evaluator/recipient to reject accidentally mixed slots from other requests.
        let batch_id = fresh_id();
        (1..=count)
            .map(|index| {
                let index = u64::try_from(index)
                    .map_err(|_| PepLwrPrfError("output index does not fit in u64".into()))?;
                self.encrypt_input_with_batch(input, index, batch_id)
            })
            .collect()
    }

    pub fn encrypt_inputs_for_output_bytes(
        &self,
        input: &[u8],
        output_len_bytes: usize,
    ) -> Result<Vec<EncryptedFastLwrPrfPepInput>> {
        self.encrypt_inputs(
            input,
            output_symbols_for_bytes(self.parameters, output_len_bytes)?,
        )
    }
}

impl FastLwrPrfPepEvaluator {
    /// Public routing identifiers, not authentication credentials.
    pub fn source_context_id(&self) -> [u8; CONTEXT_ID_LEN] {
        self.source_context_id
    }
    pub fn recipient_key_id(&self) -> [u8; CONTEXT_ID_LEN] {
        self.recipient_key_id
    }

    pub fn parameters(&self) -> FastLwrPrfParameters {
        self.parameters
    }

    /// Compute the encrypted dot product by multiplying each packed GLWE block with
    /// its matching PRF-key slice, extracting coefficient zero, then adding the
    /// resulting LWE samples. With paper parameters there is only one block; its
    /// plaintext contains the full 445-dimensional hash vector.
    fn extract_dot_product_lwe(
        &self,
        input: &EncryptedFastLwrPrfPepInput,
    ) -> Result<LweCiphertext<Vec<u128>>> {
        let block_size = INPUT_LWE_BLOCK_SIZE.min(self.parameters.lwr_dimension);
        let expected_blocks = (self.parameters.lwr_dimension + block_size - 1) / block_size;
        if input.parameters != self.parameters
            || input.source_context_id != self.source_context_id
            || input.output_index == 0
            || input.ciphertexts.len() != expected_blocks
            || self.prf_secret_bits.len() != self.parameters.lwr_dimension
            || input
                .ciphertexts
                .iter()
                .any(|ct| ct.polynomial_size() != self.input_polynomial_size)
        {
            return Err(PepLwrPrfError(
                "input metadata or ciphertext block dimensions do not match evaluation key".into(),
            ));
        }

        // Sample extraction yields an LWE ciphertext whose dimension equals the
        // full GLWE polynomial size, not the number of meaningful plaintext
        // coefficients in this block.
        let lwe_size = LweDimension(self.input_polynomial_size.0 * GLWE_DIMENSION).to_lwe_size();
        let mut combined = LweCiphertext::new(0_u128, lwe_size, CiphertextModulus::new_native());

        for (ciphertext, key_chunk) in input
            .ciphertexts
            .iter()
            .zip(self.prf_secret_bits.chunks(block_size))
        {
            let mut product_ciphertext = ciphertext.clone();
            multiply_glwe_ciphertext_by_prf_polynomial(&mut product_ciphertext, key_chunk);

            let mut extracted =
                LweCiphertext::new(0_u128, lwe_size, CiphertextModulus::new_native());
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

    /// Evaluate one encrypted H(x,slot) vector. The extracted dot product is
    /// key-switched to a 128-dimensional intermediate key, then processed by one
    /// PBS to the recipient key.
    pub fn evaluate(
        &self,
        input: &EncryptedFastLwrPrfPepInput,
    ) -> Result<EncryptedFastLwrPrfPepOutput> {
        let extracted_input = self.extract_dot_product_lwe(input)?;
        let mut pbs_input = LweCiphertext::new(
            0_u128,
            LweDimension(PBS_INPUT_LWE_DIMENSION * GLWE_DIMENSION).to_lwe_size(),
            CiphertextModulus::new_native(),
        );
        par_keyswitch_lwe_ciphertext(
            &self.input_to_pbs_keyswitch_key,
            &extracted_input,
            &mut pbs_input,
        );
        let output_lwe_dimension = self.output_polynomial_size.0 * GLWE_DIMENSION;
        let mut output_ciphertext = LweCiphertext::new(
            0_u128,
            LweDimension(output_lwe_dimension).to_lwe_size(),
            CiphertextModulus::new_native(),
        );
        programmable_bootstrap_f128_lwe_ciphertext(
            &pbs_input,
            &mut output_ciphertext,
            &self.accumulator,
            &self.bootstrapping_key,
        );
        Ok(EncryptedFastLwrPrfPepOutput {
            parameters: self.parameters,
            source_context_id: input.source_context_id,
            recipient_key_id: self.recipient_key_id,
            batch_id: input.batch_id,
            output_index: input.output_index,
            ciphertext: output_ciphertext,
        })
    }

    pub fn evaluate_many(
        &self,
        inputs: &[EncryptedFastLwrPrfPepInput],
    ) -> Result<Vec<EncryptedFastLwrPrfPepOutput>> {
        let expected_batch = inputs.first().map(|input| input.batch_id);
        for (offset, input) in inputs.iter().enumerate() {
            if Some(input.batch_id) != expected_batch {
                return Err(PepLwrPrfError(
                    "input slots from different pseudonym batches cannot be mixed".into(),
                ));
            }
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

    /// Parse an input envelope, check parameters/source-context binding, evaluate
    /// the ciphertext and return an output envelope. This is the wire boundary used
    /// by an integration layer. The envelope is not authenticated.
    pub fn evaluate_wire_input(&self, wire: &[u8]) -> Result<Vec<u8>> {
        let input = self.decode_wire_input(wire)?;
        self.evaluate(&input)?.to_wire_bytes()
    }

    fn decode_wire_input(&self, wire: &[u8]) -> Result<EncryptedFastLwrPrfPepInput> {
        let mut reader = WireReader::new(wire);
        if reader.take(4)? != &INPUT_WIRE_MAGIC[..] {
            return Err(PepLwrPrfError("invalid input wire magic".into()));
        }
        if reader.read_u8()? != WIRE_VERSION {
            return Err(PepLwrPrfError("unsupported input wire version".into()));
        }
        let parameters = read_parameters(&mut reader)?;
        if parameters != self.parameters {
            return Err(PepLwrPrfError(
                "wire input parameters do not match evaluator".into(),
            ));
        }
        let source_context_id = reader.read_id()?;
        if source_context_id != self.source_context_id {
            return Err(PepLwrPrfError(
                "wire input belongs to a different source context".into(),
            ));
        }
        let batch_id = reader.read_id()?;
        let output_index = reader.read_u64()?;
        if output_index == 0 {
            return Err(PepLwrPrfError("wire input uses invalid zero slot".into()));
        }
        let block_count = usize::try_from(reader.read_u32()?)
            .map_err(|_| PepLwrPrfError("block count does not fit usize".into()))?;
        let block_size = INPUT_LWE_BLOCK_SIZE.min(self.parameters.lwr_dimension);
        let expected_blocks = (self.parameters.lwr_dimension + block_size - 1) / block_size;
        if block_count != expected_blocks {
            return Err(PepLwrPrfError(
                "wire input has an invalid GLWE block count".into(),
            ));
        }
        let expected_coefficients = GLWE_SIZE * self.input_polynomial_size.0;
        let mut ciphertexts = Vec::with_capacity(expected_blocks);
        for _ in 0..expected_blocks {
            let coefficient_count = usize::try_from(reader.read_u64()?)
                .map_err(|_| PepLwrPrfError("GLWE coefficient count does not fit usize".into()))?;
            if coefficient_count != expected_coefficients {
                return Err(PepLwrPrfError(
                    "wire GLWE has an invalid coefficient count".into(),
                ));
            }
            let mut coefficients = Vec::with_capacity(expected_coefficients);
            for _ in 0..expected_coefficients {
                coefficients.push(reader.read_u128()?);
            }
            let ciphertext = GlweCiphertext::from_container(
                coefficients,
                self.input_polynomial_size,
                CiphertextModulus::new_native(),
            );
            ciphertexts.push(ciphertext);
        }
        reader.ensure_finished()?;
        Ok(EncryptedFastLwrPrfPepInput {
            parameters,
            source_context_id,
            batch_id,
            output_index,
            ciphertexts,
        })
    }
}

impl FastLwrPrfPepRecipientKey {
    pub fn parameters(&self) -> FastLwrPrfParameters {
        self.parameters
    }

    pub fn recipient_key_id(&self) -> [u8; CONTEXT_ID_LEN] {
        self.recipient_key_id
    }

    pub fn decrypt_output(&self, output: &EncryptedFastLwrPrfPepOutput) -> Result<u8> {
        if output.parameters != self.parameters {
            return Err(PepLwrPrfError(
                "output parameters do not match recipient key".into(),
            ));
        }
        if output.recipient_key_id != self.recipient_key_id {
            return Err(PepLwrPrfError(
                "output is bound to a different recipient key context".into(),
            ));
        }
        let plaintext: Plaintext<u128> =
            decrypt_lwe_ciphertext(&self.output_lwe_secret_key, &output.ciphertext);
        let output_delta = (1_u128 << 127) / (self.parameters.output_modulus as u128);
        let decomposition_base_log =
            DecompositionBaseLog((self.parameters.output_modulus.trailing_zeros() + 1) as usize);
        let decomposer = SignedDecomposer::new(decomposition_base_log, DecompositionLevelCount(1));
        let rounded = decomposer.closest_representable(plaintext.0);
        let symbol = ((rounded / output_delta) % (self.parameters.output_modulus as u128)) as u64;
        if symbol >= self.parameters.output_modulus {
            return Err(PepLwrPrfError("decrypted symbol is outside Z_p".into()));
        }
        Ok(symbol as u8)
    }

    pub fn decrypt_many_outputs(
        &self,
        outputs: &[EncryptedFastLwrPrfPepOutput],
    ) -> Result<Vec<u8>> {
        outputs
            .iter()
            .map(|output| self.decrypt_output(output))
            .collect()
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
        let expected_batch = outputs.first().map(|output| output.batch_id);
        let expected_source = outputs.first().map(|output| output.source_context_id);
        for (offset, output) in outputs.iter().enumerate() {
            let expected_index = u64::try_from(offset + 1)
                .map_err(|_| PepLwrPrfError("output index does not fit in u64".into()))?;
            if output.output_index != expected_index || output.parameters != self.parameters {
                return Err(PepLwrPrfError(format!(
                    "outputs must have matching parameters and contiguous one-based indices; expected slot {expected_index}"
                )));
            }
            if Some(output.batch_id) != expected_batch
                || Some(output.source_context_id) != expected_source
            {
                return Err(PepLwrPrfError(
                    "outputs from different pseudonym batches or source contexts cannot be mixed"
                        .into(),
                ));
            }
        }
        let symbols = self.decrypt_many_outputs(outputs)?;
        self.pack_symbols_to_bytes(&symbols, output_len_bytes)
    }

    /// Decode one versioned output envelope and decrypt one PRF symbol.
    pub fn decrypt_wire_output(&self, wire: &[u8]) -> Result<u8> {
        let output = self.decode_wire_output(wire)?;
        self.decrypt_output(&output)
    }

    /// Decode a complete ordered output batch and pack it into a fixed-length byte string.
    pub fn decrypt_wire_outputs_to_bytes(
        &self,
        wires: &[Vec<u8>],
        output_len_bytes: usize,
    ) -> Result<Vec<u8>> {
        let expected = output_symbols_for_bytes(self.parameters, output_len_bytes)?;
        if wires.len() != expected {
            return Err(PepLwrPrfError(format!(
                "expected {expected} serialized outputs, got {}",
                wires.len()
            )));
        }
        let mut outputs = Vec::with_capacity(wires.len());
        for wire in wires {
            outputs.push(self.decode_wire_output(wire)?);
        }
        self.decrypt_outputs_to_bytes(&outputs, output_len_bytes)
    }

    /// Validate the entire output batch against the caller's pending request.
    /// These checks catch substitution/context mistakes; they are not authentication.
    pub fn decrypt_wire_outputs_for_request(
        &self,
        wires: &[Vec<u8>],
        output_len_bytes: usize,
        expected_batch: &[u8; CONTEXT_ID_LEN],
        expected_source: Option<&[u8; CONTEXT_ID_LEN]>,
    ) -> Result<Vec<u8>> {
        let expected = output_symbols_for_bytes(self.parameters, output_len_bytes)?;
        if wires.len() != expected || wires.is_empty() {
            return Err(PepLwrPrfError(
                "unexpected output count for pending request".into(),
            ));
        }
        let mut outputs = Vec::with_capacity(expected);
        for wire in wires {
            let output = self.decode_wire_output(wire)?;
            if &output.batch_id != expected_batch {
                return Err(PepLwrPrfError(
                    "output batch does not match pending request".into(),
                ));
            }
            if let Some(source) = expected_source {
                if &output.source_context_id != source {
                    return Err(PepLwrPrfError(
                        "output source does not match pending request".into(),
                    ));
                }
            }
            outputs.push(output);
        }
        self.decrypt_outputs_to_bytes(&outputs, output_len_bytes)
    }

    fn decode_wire_output(&self, wire: &[u8]) -> Result<EncryptedFastLwrPrfPepOutput> {
        let mut reader = WireReader::new(wire);
        if reader.take(4)? != &OUTPUT_WIRE_MAGIC[..] {
            return Err(PepLwrPrfError("invalid output wire magic".into()));
        }
        if reader.read_u8()? != WIRE_VERSION {
            return Err(PepLwrPrfError("unsupported output wire version".into()));
        }
        let parameters = read_parameters(&mut reader)?;
        if parameters != self.parameters {
            return Err(PepLwrPrfError(
                "wire output parameters do not match recipient".into(),
            ));
        }
        let source_context_id = reader.read_id()?;
        let recipient_key_id = reader.read_id()?;
        if recipient_key_id != self.recipient_key_id {
            return Err(PepLwrPrfError(
                "wire output belongs to a different recipient context".into(),
            ));
        }
        let batch_id = reader.read_id()?;
        let output_index = reader.read_u64()?;
        if output_index == 0 {
            return Err(PepLwrPrfError("wire output uses invalid zero slot".into()));
        }
        let expected_coefficients = self
            .parameters
            .ring_dimension
            .checked_mul(PBS_POLY_EXPANSION_FACTOR)
            .and_then(|n| n.checked_mul(GLWE_DIMENSION))
            .and_then(|n| n.checked_add(1))
            .ok_or_else(|| PepLwrPrfError("output ciphertext size overflow".into()))?;
        let coefficient_count = usize::try_from(reader.read_u64()?)
            .map_err(|_| PepLwrPrfError("LWE coefficient count does not fit usize".into()))?;
        if coefficient_count != expected_coefficients {
            return Err(PepLwrPrfError(
                "wire LWE has an invalid coefficient count".into(),
            ));
        }
        let mut coefficients = Vec::with_capacity(expected_coefficients);
        for _ in 0..expected_coefficients {
            coefficients.push(reader.read_u128()?);
        }
        reader.ensure_finished()?;
        let ciphertext =
            LweCiphertext::from_container(coefficients, CiphertextModulus::new_native());
        Ok(EncryptedFastLwrPrfPepOutput {
            parameters,
            source_context_id,
            recipient_key_id,
            batch_id,
            output_index,
            ciphertext,
        })
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
        if symbols
            .len()
            .checked_mul(bits_per_symbol)
            .unwrap_or(usize::MAX)
            < required_bits
        {
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
