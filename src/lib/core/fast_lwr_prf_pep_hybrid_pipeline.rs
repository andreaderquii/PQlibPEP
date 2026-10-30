//! Low-level hybrid envelope. Prefer `core::pep` for the application contract.
//! Experimental and unauthenticated: this module is not a production protocol.
//!
//! The TFHE branch computes a 32-byte LWR pseudonym from encrypted H(ID, i)
//! vectors and returns its symbol ciphertexts under the recipient's TFHE key.
//! Independently, the RLWE branch rekeys an application payload A -> B and
//! rerandomizes it with a fresh encryption of zero under B.
//!
//! This module binds two independent branches to one transaction and batch at
//! the application/wire boundary:
//! - TFHE evaluates the FastLwrPrf on encrypted hash-vector inputs to produce a pseudonym.
//! - Optionally, the existing Ring-LWR `RlwrPrf` derives a domain-transition factor
//!   for the RLWE payload; the payload is reshuffled, rekeyed A -> B, and rerandomized.
//!
//! TFHE and RLWE ciphertexts are never combined algebraically. The TFHE pseudonym
//! is not used as the RLWE factor. The coefficient-wise lift R_17 -> R_Q is
//! approximate, so correctness must be tested against the RLWE decoding/noise margin.
//! Key setup remains centralized in this prototype. Wire IDs are metadata, NOT
//! authentication or replay protection; this module does not provide RS2.

use core::fmt;
use std::error::Error;

use rand::{rngs::OsRng, RngCore};

use crate::algebra::ring::PolyRq;
use crate::core::fast_lwr_prf_pep_ks128_e16_pipeline::{
    output_symbols_for_bytes, FastLwrPrfPepEvaluator, FastLwrPrfPepInputClient,
    FastLwrPrfPepRecipientKey,
};
use crate::core::reshuffle::reshuffle;
#[cfg(feature = "experimental-linear-reshuffle")]
use crate::core::reshuffle::{derive_domain_transform_factor, derive_invertible_reshuffle_factor};
use crate::core::rlwe::{PublicKey, SecretKey};
use crate::core::rlwe_pke::{decrypt_poly, Ciphertext};
use crate::core::rlwe_pre::{decompose_poly, reencrypt_and_rerandomize, ReEncryptionKey};
#[cfg(feature = "experimental-linear-reshuffle")]
use crate::core::rlwr_prf::RlwrPrf;
use crate::parameters::pep_wire as wire_parameters;

const WIRE_VERSION: u8 = wire_parameters::VERSION;
const REQUEST_MAGIC: &[u8; 4] = &wire_parameters::HYBRID_REQUEST_MAGIC;
const RESPONSE_MAGIC: &[u8; 4] = &wire_parameters::HYBRID_RESPONSE_MAGIC;
const ID_LEN: usize = wire_parameters::CONTEXT_ID_BYTES;
const MAX_FRAME_BYTES: usize = wire_parameters::MAX_FRAME_BYTES;
const MAX_ITEM_BYTES: usize = wire_parameters::MAX_ITEM_BYTES;
const MAX_SYMBOLS: usize = wire_parameters::MAX_PRF_SYMBOLS;

pub type HybridResult<T> = std::result::Result<T, HybridPepPipelineError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HybridPepPipelineError(pub String);

impl fmt::Display for HybridPepPipelineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Error for HybridPepPipelineError {}

fn err(message: impl Into<String>) -> HybridPepPipelineError {
    HybridPepPipelineError(message.into())
}

fn fresh_id() -> [u8; ID_LEN] {
    let mut id = [0u8; ID_LEN];
    let mut rng = OsRng;
    rng.fill_bytes(&mut id);
    id
}

fn write_u8(out: &mut Vec<u8>, value: u8) {
    out.push(value);
}

fn write_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn write_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn write_id(out: &mut Vec<u8>, value: &[u8; ID_LEN]) {
    out.extend_from_slice(value);
}

fn usize_to_u32(value: usize, what: &str) -> HybridResult<u32> {
    u32::try_from(value).map_err(|_| err(format!("{what} exceeds wire-format limit")))
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> HybridResult<Self> {
        if bytes.len() > MAX_FRAME_BYTES {
            return Err(err("wire frame exceeds maximum allowed size"));
        }

        Ok(Self { bytes, offset: 0 })
    }

    fn take(&mut self, length: usize) -> HybridResult<&'a [u8]> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or_else(|| err("wire length overflow"))?;

        if end > self.bytes.len() {
            return Err(err("truncated hybrid wire frame"));
        }

        let slice = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(slice)
    }

    fn read_u8(&mut self) -> HybridResult<u8> {
        Ok(self.take(1)?[0])
    }

    fn read_u32(&mut self) -> HybridResult<u32> {
        let bytes: [u8; 4] = self
            .take(4)?
            .try_into()
            .map_err(|_| err("invalid u32 field"))?;

        Ok(u32::from_le_bytes(bytes))
    }

    fn read_u64(&mut self) -> HybridResult<u64> {
        let bytes: [u8; 8] = self
            .take(8)?
            .try_into()
            .map_err(|_| err("invalid u64 field"))?;

        Ok(u64::from_le_bytes(bytes))
    }

    fn read_id(&mut self) -> HybridResult<[u8; ID_LEN]> {
        self.take(ID_LEN)?
            .try_into()
            .map_err(|_| err("invalid transaction ID"))
    }

    fn read_bounded_blob(&mut self, max_len: usize, what: &str) -> HybridResult<Vec<u8>> {
        let len = usize::try_from(self.read_u32()?)
            .map_err(|_| err(format!("{what} length overflow")))?;

        if len > max_len {
            return Err(err(format!("{what} exceeds maximum allowed length")));
        }

        Ok(self.take(len)?.to_vec())
    }

    fn ensure_finished(&self) -> HybridResult<()> {
        if self.offset != self.bytes.len() {
            return Err(err("trailing bytes after hybrid wire frame"));
        }

        Ok(())
    }
}

/// Serialize an RLWE ciphertext using exactly n coefficients for each
/// polynomial, where n is the configured ring dimension.
fn write_rlwe_ciphertext(out: &mut Vec<u8>, ciphertext: &Ciphertext) -> HybridResult<()> {
    let n = ciphertext.u.degree_bound();
    let q = ciphertext.u.modulus();

    let u = ciphertext.u.to_coeffs_vec();
    let v = ciphertext.v.to_coeffs_vec();

    if n == 0 {
        return Err(err("RLWE ring dimension is zero"));
    }

    if q < 2 {
        return Err(err("RLWE modulus must be at least 2"));
    }

    if ciphertext.v.degree_bound() != n {
        return Err(err("RLWE u and v have different ring dimensions"));
    }

    if ciphertext.v.modulus() != q {
        return Err(err("RLWE u and v use different moduli"));
    }

    // PolyRq may expose n coefficients or n coefficients plus a
    // canonical trailing zero, depending on its representation.
    let valid_len = |len: usize| len == n || len == n + 1;

    if !valid_len(u.len()) {
        return Err(err(format!(
            "RLWE u has an unexpected coefficient count: \
             expected {n} or {}, got {}",
            n + 1,
            u.len()
        )));
    }

    if !valid_len(v.len()) {
        return Err(err(format!(
            "RLWE v has an unexpected coefficient count: \
             expected {n} or {}, got {}",
            n + 1,
            v.len()
        )));
    }

    if u.len() == n + 1 && u[n] != 0 {
        return Err(err("RLWE u has a non-zero trailing coefficient"));
    }

    if v.len() == n + 1 && v[n] != 0 {
        return Err(err("RLWE v has a non-zero trailing coefficient"));
    }

    if u[..n].iter().any(|&c| c >= q) {
        return Err(err("RLWE u contains a coefficient outside the modulus"));
    }

    if v[..n].iter().any(|&c| c >= q) {
        return Err(err("RLWE v contains a coefficient outside the modulus"));
    }

    write_u32(out, usize_to_u32(n, "RLWE ring dimension")?);
    write_u64(out, q);

    write_u32(out, usize_to_u32(n, "RLWE u coefficient count")?);
    for &coefficient in &u[..n] {
        write_u64(out, coefficient);
    }

    write_u32(out, usize_to_u32(n, "RLWE v coefficient count")?);
    for &coefficient in &v[..n] {
        write_u64(out, coefficient);
    }

    Ok(())
}

fn read_rlwe_ciphertext(
    reader: &mut Reader<'_>,
    expected_n: usize,
    expected_q: u64,
) -> HybridResult<Ciphertext> {
    let n = usize::try_from(reader.read_u32()?).map_err(|_| err("RLWE ring dimension overflow"))?;

    let q = reader.read_u64()?;

    if n != expected_n || q != expected_q || n == 0 {
        return Err(err(
            "RLWE ciphertext parameters do not match the configured key",
        ));
    }

    let u_len = usize::try_from(reader.read_u32()?).map_err(|_| err("RLWE u length overflow"))?;

    if u_len != n {
        return Err(err("RLWE u polynomial has an invalid coefficient count"));
    }

    let mut u = Vec::with_capacity(n);

    for _ in 0..n {
        let coefficient = reader.read_u64()?;

        if coefficient >= q {
            return Err(err("RLWE u coefficient is outside the modulus"));
        }

        u.push(coefficient);
    }

    let v_len = usize::try_from(reader.read_u32()?).map_err(|_| err("RLWE v length overflow"))?;

    if v_len != n {
        return Err(err("RLWE v polynomial has an invalid coefficient count"));
    }

    let mut v = Vec::with_capacity(n);

    for _ in 0..n {
        let coefficient = reader.read_u64()?;

        if coefficient >= q {
            return Err(err("RLWE v coefficient is outside the modulus"));
        }

        v.push(coefficient);
    }

    Ok(Ciphertext {
        u: PolyRq::from_coeffs(&u, n, q),
        v: PolyRq::from_coeffs(&v, n, q),
    })
}

/// Source-side wrapper. It hashes the identifier locally, encrypts indexed
/// vectors under the source TFHE key, and binds their wires to an RLWE payload.
pub struct HybridPepSource {
    input_client: FastLwrPrfPepInputClient,
}

/// Prepared application request. The IDs are public correlation metadata only.
pub struct PreparedHybridPepRequest {
    transaction_id: [u8; ID_LEN],
    batch_id: [u8; ID_LEN],
    wire_bytes: Vec<u8>,
}

impl PreparedHybridPepRequest {
    pub fn transaction_id(&self) -> [u8; ID_LEN] {
        self.transaction_id
    }

    pub fn batch_id(&self) -> [u8; ID_LEN] {
        self.batch_id
    }

    pub fn wire_bytes(&self) -> &[u8] {
        &self.wire_bytes
    }

    pub fn into_wire_bytes(self) -> Vec<u8> {
        self.wire_bytes
    }
}

impl HybridPepSource {
    pub fn new(input_client: FastLwrPrfPepInputClient) -> Self {
        Self { input_client }
    }

    /// Prepare a single application request. `payload_ciphertext` must already
    /// be encrypted under the source RLWE public key. The ID is never embedded
    /// in the wire envelope; only encrypted hash-vector inputs are included.
    pub fn prepare_request(
        &self,
        identifier: &[u8],
        payload_ciphertext: &Ciphertext,
        pseudonym_len_bytes: usize,
    ) -> HybridResult<PreparedHybridPepRequest> {
        if pseudonym_len_bytes == 0 {
            return Err(err("pseudonym length must be non-zero"));
        }

        let expected_count =
            output_symbols_for_bytes(self.input_client.parameters(), pseudonym_len_bytes)
                .map_err(|e| err(e.to_string()))?;

        if expected_count == 0 || expected_count > MAX_SYMBOLS {
            return Err(err(
                "pseudonym output symbol count is outside allowed limits",
            ));
        }

        let encrypted_inputs = self
            .input_client
            .encrypt_inputs_for_output_bytes(identifier, pseudonym_len_bytes)
            .map_err(|e| err(e.to_string()))?;

        if encrypted_inputs.len() != expected_count {
            return Err(err(
                "source produced an unexpected number of PRF input slots",
            ));
        }

        let batch_id = encrypted_inputs
            .first()
            .ok_or_else(|| err("no PRF input slots were created"))?
            .batch_id();

        let mut input_wires = Vec::with_capacity(expected_count);

        for (index, input) in encrypted_inputs.iter().enumerate() {
            if input.batch_id() != batch_id || input.output_index() != (index as u64 + 1) {
                return Err(err("source produced mixed or unordered PRF input slots"));
            }

            input_wires.push(input.to_wire_bytes().map_err(|e| err(e.to_string()))?);
        }

        let transaction_id = fresh_id();
        let mut out = Vec::new();

        out.extend_from_slice(REQUEST_MAGIC);
        write_u8(&mut out, WIRE_VERSION);
        write_id(&mut out, &transaction_id);
        write_id(&mut out, &batch_id);
        write_u32(
            &mut out,
            usize_to_u32(pseudonym_len_bytes, "pseudonym length")?,
        );
        write_u32(&mut out, usize_to_u32(input_wires.len(), "PRF slot count")?);

        for wire in input_wires {
            if wire.len() > MAX_ITEM_BYTES {
                return Err(err("encrypted TFHE input envelope exceeds wire item limit"));
            }

            write_u32(
                &mut out,
                usize_to_u32(wire.len(), "TFHE input envelope length")?,
            );
            out.extend_from_slice(&wire);
        }

        write_rlwe_ciphertext(&mut out, payload_ciphertext)?;

        if out.len() > MAX_FRAME_BYTES {
            return Err(err("hybrid request exceeds maximum wire frame size"));
        }

        Ok(PreparedHybridPepRequest {
            transaction_id,
            batch_id,
            wire_bytes: out,
        })
    }
}

/// Transcryptor-side orchestration. It evaluates the TFHE branch and independently
/// rekeys/rerandomizes the RLWE payload; the two ciphertext systems remain separate.
// Validate all switching polynomials before reaching arithmetic assertions.
// PKE encrypt/decrypt use the central scalar modulus, so accepting another
// modulus here would silently mix two incompatible schemes.
fn validate_switch_material(
    pk: &PublicKey,
    rekey: &ReEncryptionKey,
    base_bits: usize,
) -> HybridResult<()> {
    if base_bits == 0 || base_bits > 62 {
        return Err(err("RLWE rekey base bits must be in 1..=62"));
    }
    let n = pk.a.degree_bound();
    let q = pk.a.modulus();
    if n == 0
        || !n.is_power_of_two()
        || pk.b.degree_bound() != n
        || q != crate::algebra::ring::Q
        || pk.b.modulus() != q
    {
        return Err(err(
            "recipient RLWE public key has inconsistent or unsupported parameters",
        ));
    }
    let bits = (u64::BITS - (q - 1).leading_zeros()) as usize;
    let entries = (bits + base_bits - 1) / base_bits;
    if rekey.entries.len() != entries
        || rekey.entries.iter().any(|entry| {
            entry.k0.degree_bound() != n
                || entry.k1.degree_bound() != n
                || entry.k0.modulus() != q
                || entry.k1.modulus() != q
        })
    {
        return Err(err(
            "RLWE switching material has incompatible dimensions, modulus or digit count",
        ));
    }
    Ok(())
}

pub struct HybridPepTranscryptor {
    evaluator: FastLwrPrfPepEvaluator,
    rlwe_rekey: ReEncryptionKey,
    recipient_rlwe_public_key: PublicKey,
    rlwe_rekey_base_bits: usize,
    /// Optional polynomial factor lifted to the RLWE ciphertext modulus.
    /// `None` preserves the original rekey + rerandomize path.
    reshuffle_factor: Option<PolyRq>,
}

impl HybridPepTranscryptor {
    pub fn new(
        evaluator: FastLwrPrfPepEvaluator,
        rlwe_rekey: ReEncryptionKey,
        recipient_rlwe_public_key: PublicKey,
        rlwe_rekey_base_bits: usize,
    ) -> HybridResult<Self> {
        validate_switch_material(
            &recipient_rlwe_public_key,
            &rlwe_rekey,
            rlwe_rekey_base_bits,
        )?;

        Ok(Self {
            evaluator,
            rlwe_rekey,
            recipient_rlwe_public_key,
            rlwe_rekey_base_bits,
            reshuffle_factor: None,
        })
    }

    /// Create a transcryptor for a domain transition A -> B.
    ///
    /// The input RLWE ciphertext must encrypt a domain-encoded plaintext
    /// M*g_A in R_17. This method derives t = g_A^(-1)*g_B mod 17 with the
    /// existing Ring-LWR `RlwrPrf`, then lifts t into R_Q. The encrypted
    /// payload is transformed to M*g_B before rekeying and rerandomization.
    ///
    /// This does not alter the independent TFHE pseudonym branch.
    #[cfg(feature = "experimental-linear-reshuffle")]
    pub fn new_with_domain_transition(
        evaluator: FastLwrPrfPepEvaluator,
        rlwe_rekey: ReEncryptionKey,
        recipient_rlwe_public_key: PublicKey,
        rlwe_rekey_base_bits: usize,
        domain_prf: &RlwrPrf,
        source_domain: &str,
        target_domain: &str,
    ) -> HybridResult<Self> {
        let ring_n = recipient_rlwe_public_key.a.degree_bound();
        let modulus = recipient_rlwe_public_key.a.modulus();

        let factor = derive_domain_transform_factor(
            domain_prf,
            source_domain,
            target_domain,
            ring_n,
            modulus,
        )
        .map_err(|e| err(e))?;

        let mut transcryptor = Self::new(
            evaluator,
            rlwe_rekey,
            recipient_rlwe_public_key,
            rlwe_rekey_base_bits,
        )?;
        transcryptor.reshuffle_factor = Some(factor);
        Ok(transcryptor)
    }

    /// Create a transcryptor for a raw plaintext M -> M*g_target transform.
    /// Unlike `new_with_domain_transition`, the payload must not already be
    /// encoded with a source-domain factor.
    #[cfg(feature = "experimental-linear-reshuffle")]
    pub fn new_with_target_reshuffle(
        evaluator: FastLwrPrfPepEvaluator,
        rlwe_rekey: ReEncryptionKey,
        recipient_rlwe_public_key: PublicKey,
        rlwe_rekey_base_bits: usize,
        domain_prf: &RlwrPrf,
        target_domain: &str,
    ) -> HybridResult<Self> {
        let ring_n = recipient_rlwe_public_key.a.degree_bound();
        let modulus = recipient_rlwe_public_key.a.modulus();

        let factor = derive_invertible_reshuffle_factor(domain_prf, target_domain, ring_n, modulus)
            .map_err(|e| err(e))?
            .factor_mod_q;

        let mut transcryptor = Self::new(
            evaluator,
            rlwe_rekey,
            recipient_rlwe_public_key,
            rlwe_rekey_base_bits,
        )?;
        transcryptor.reshuffle_factor = Some(factor);
        Ok(transcryptor)
    }

    /// Process one complete request envelope.
    pub fn process_request_wire<R: RngCore>(
        &self,
        request_wire: &[u8],
        rng: &mut R,
    ) -> HybridResult<Vec<u8>> {
        self.process_request_wire_with_rekey(
            request_wire,
            &self.rlwe_rekey,
            &self.recipient_rlwe_public_key,
            self.rlwe_rekey_base_bits,
            rng,
        )
    }

    /// Process a request using per-request RLWE switching material while
    /// reusing the already-provisioned TFHE evaluator. The caller is
    /// responsible for associating `rlwe_rekey` with the payload's source key
    /// and `recipient_rlwe_public_key`; the wire context does not authenticate
    /// that association.
    pub fn process_request_wire_with_rekey<R: RngCore>(
        &self,
        request_wire: &[u8],
        rlwe_rekey: &ReEncryptionKey,
        recipient_rlwe_public_key: &PublicKey,
        rlwe_rekey_base_bits: usize,
        rng: &mut R,
    ) -> HybridResult<Vec<u8>> {
        validate_switch_material(recipient_rlwe_public_key, rlwe_rekey, rlwe_rekey_base_bits)?;

        let mut reader = Reader::new(request_wire)?;

        if reader.take(4)? != &REQUEST_MAGIC[..] {
            return Err(err("invalid hybrid request magic"));
        }

        if reader.read_u8()? != WIRE_VERSION {
            return Err(err("unsupported hybrid request version"));
        }

        let transaction_id = reader.read_id()?;
        let batch_id = reader.read_id()?;

        let pseudonym_len_bytes =
            usize::try_from(reader.read_u32()?).map_err(|_| err("pseudonym length overflow"))?;

        if pseudonym_len_bytes == 0 {
            return Err(err("pseudonym length must be non-zero"));
        }

        let expected_count =
            output_symbols_for_bytes(self.evaluator.parameters(), pseudonym_len_bytes)
                .map_err(|e| err(e.to_string()))?;

        if expected_count == 0 || expected_count > MAX_SYMBOLS {
            return Err(err(
                "pseudonym output symbol count is outside allowed limits",
            ));
        }

        let input_count = usize::try_from(reader.read_u32()?)
            .map_err(|_| err("PRF input slot count overflow"))?;

        if input_count != expected_count {
            return Err(err(
                "hybrid request has the wrong number of PRF input slots",
            ));
        }

        let mut input_wires = Vec::with_capacity(input_count);

        for index in 0..input_count {
            let wire = reader.read_bounded_blob(MAX_ITEM_BYTES, "TFHE input envelope")?;

            let (wire_batch, wire_index) = read_input_wire_binding(&wire)?;

            if wire_batch != batch_id || wire_index != index as u64 + 1 {
                return Err(err(
                    "input slots have a mixed batch ID or invalid index order",
                ));
            }

            input_wires.push(wire);
        }

        let ring_n = recipient_rlwe_public_key.a.degree_bound();
        let modulus = recipient_rlwe_public_key.a.modulus();

        let payload_ciphertext = read_rlwe_ciphertext(&mut reader, ring_n, modulus)?;

        reader.ensure_finished()?;

        if decompose_poly(&payload_ciphertext.u, rlwe_rekey_base_bits).len()
            != rlwe_rekey.entries.len()
        {
            return Err(err(
                "RLWE rekey key is incompatible with payload parameters",
            ));
        }

        // Apply the optional RLWR-derived polynomial factor to the RLWE
        // ciphertext. This does not combine it with the TFHE ciphertexts.
        let payload_for_rekey = match self.reshuffle_factor.as_ref() {
            Some(factor) => {
                if factor.degree_bound() != ring_n || factor.modulus() != modulus {
                    return Err(err(
                        "reshuffle factor does not match payload RLWE parameters",
                    ));
                }
                reshuffle(&payload_ciphertext, factor)
            }
            None => payload_ciphertext,
        };

        let mut output_wires = Vec::with_capacity(input_wires.len());

        for input_wire in &input_wires {
            output_wires.push(
                self.evaluator
                    .evaluate_wire_input(input_wire)
                    .map_err(|e| err(e.to_string()))?,
            );
        }

        let rekeyed_payload = reencrypt_and_rerandomize(
            rng,
            &payload_for_rekey,
            rlwe_rekey,
            recipient_rlwe_public_key,
            rlwe_rekey_base_bits,
        );

        encode_response(
            &transaction_id,
            &batch_id,
            pseudonym_len_bytes,
            &output_wires,
            &rekeyed_payload,
        )
    }
}

fn read_input_wire_binding(wire: &[u8]) -> HybridResult<([u8; ID_LEN], u64)> {
    // The active offsets are defined with the wire-format profile in parameters.rs.
    if wire.len() < wire_parameters::PRF_INPUT_MIN_HEADER_BYTES
        || wire.get(..wire_parameters::MAGIC_BYTES) != Some(&wire_parameters::PRF_INPUT_MAGIC[..])
        || wire[wire_parameters::MAGIC_BYTES] != wire_parameters::VERSION
    {
        return Err(err("invalid or truncated PLPI input envelope"));
    }

    let batch_start = wire_parameters::PRF_INPUT_BATCH_ID_OFFSET;
    let batch_end = batch_start + ID_LEN;
    let batch: [u8; ID_LEN] = wire[batch_start..batch_end]
        .try_into()
        .map_err(|_| err("invalid input batch ID"))?;

    let slot_start = wire_parameters::PRF_INPUT_SLOT_INDEX_OFFSET;
    let slot_end = slot_start + wire_parameters::U64_FIELD_BYTES;
    let index_bytes: [u8; 8] = wire[slot_start..slot_end]
        .try_into()
        .map_err(|_| err("invalid input slot index"))?;

    Ok((batch, u64::from_le_bytes(index_bytes)))
}

fn encode_response(
    transaction_id: &[u8; ID_LEN],
    batch_id: &[u8; ID_LEN],
    pseudonym_len_bytes: usize,
    output_wires: &[Vec<u8>],
    payload_ciphertext: &Ciphertext,
) -> HybridResult<Vec<u8>> {
    let mut out = Vec::new();

    out.extend_from_slice(RESPONSE_MAGIC);
    write_u8(&mut out, WIRE_VERSION);
    write_id(&mut out, transaction_id);
    write_id(&mut out, batch_id);
    write_u32(
        &mut out,
        usize_to_u32(pseudonym_len_bytes, "pseudonym length")?,
    );
    write_u32(
        &mut out,
        usize_to_u32(output_wires.len(), "PRF output count")?,
    );

    for wire in output_wires {
        if wire.len() > MAX_ITEM_BYTES {
            return Err(err("TFHE output envelope exceeds wire item limit"));
        }

        write_u32(
            &mut out,
            usize_to_u32(wire.len(), "TFHE output envelope length")?,
        );
        out.extend_from_slice(wire);
    }

    write_rlwe_ciphertext(&mut out, payload_ciphertext)?;

    if out.len() > MAX_FRAME_BYTES {
        return Err(err("hybrid response exceeds maximum wire frame size"));
    }

    Ok(out)
}

/// Recipient-side wrapper holding the destination TFHE and RLWE secret keys.
pub struct HybridPepRecipient {
    tfhe_recipient: FastLwrPrfPepRecipientKey,
    rlwe_secret_key: SecretKey,
    rlwe_ring_dimension: usize,
}

/// Plaintext result returned after validating and decrypting both branches.
#[derive(Debug)]
pub struct HybridPepPlaintextResult {
    pub transaction_id: [u8; ID_LEN],
    pub batch_id: [u8; ID_LEN],
    pub pseudonym: Vec<u8>,
    pub payload_coefficients: Vec<u64>,
}

impl HybridPepRecipient {
    pub fn new(
        tfhe_recipient: FastLwrPrfPepRecipientKey,
        rlwe_secret_key: SecretKey,
        rlwe_ring_dimension: usize,
    ) -> HybridResult<Self> {
        if rlwe_ring_dimension == 0
            || !rlwe_ring_dimension.is_power_of_two()
            || rlwe_secret_key.s.degree_bound() != rlwe_ring_dimension
            || rlwe_secret_key.s.modulus() != crate::algebra::ring::Q
        {
            return Err(err(
                "recipient RLWE secret key has an unexpected ring dimension",
            ));
        }

        Ok(Self {
            tfhe_recipient,
            rlwe_secret_key,
            rlwe_ring_dimension,
        })
    }

    /// Check caller-expected IDs and dimensions, then decrypt both branches.
    /// Transaction and batch IDs are metadata, not cryptographic authentication.
    pub fn open_response_wire(
        &self,
        response_wire: &[u8],
        expected_transaction_id: &[u8; ID_LEN],
        expected_batch_id: &[u8; ID_LEN],
        expected_pseudonym_len_bytes: usize,
    ) -> HybridResult<HybridPepPlaintextResult> {
        self.open_response_wire_checked(
            response_wire,
            expected_transaction_id,
            expected_batch_id,
            expected_pseudonym_len_bytes,
            None,
        )
    }

    /// Strict entry point: bind the source context as well as the outer IDs.
    pub fn open_response_wire_in_context(
        &self,
        response_wire: &[u8],
        expected_transaction_id: &[u8; ID_LEN],
        expected_batch_id: &[u8; ID_LEN],
        expected_pseudonym_len_bytes: usize,
        expected_source_context: &[u8; ID_LEN],
    ) -> HybridResult<HybridPepPlaintextResult> {
        self.open_response_wire_checked(
            response_wire,
            expected_transaction_id,
            expected_batch_id,
            expected_pseudonym_len_bytes,
            Some(expected_source_context),
        )
    }

    fn open_response_wire_checked(
        &self,
        response_wire: &[u8],
        expected_transaction_id: &[u8; ID_LEN],
        expected_batch_id: &[u8; ID_LEN],
        expected_pseudonym_len_bytes: usize,
        expected_source_context: Option<&[u8; ID_LEN]>,
    ) -> HybridResult<HybridPepPlaintextResult> {
        let mut reader = Reader::new(response_wire)?;

        if reader.take(4)? != &RESPONSE_MAGIC[..] {
            return Err(err("invalid hybrid response magic"));
        }

        if reader.read_u8()? != WIRE_VERSION {
            return Err(err("unsupported hybrid response version"));
        }

        let transaction_id = reader.read_id()?;
        let batch_id = reader.read_id()?;

        if &transaction_id != expected_transaction_id || &batch_id != expected_batch_id {
            return Err(err(
                "response transaction or batch ID does not match the pending request",
            ));
        }

        let pseudonym_len_bytes = usize::try_from(reader.read_u32()?)
            .map_err(|_| err("response pseudonym length overflow"))?;

        if pseudonym_len_bytes != expected_pseudonym_len_bytes || pseudonym_len_bytes == 0 {
            return Err(err("response pseudonym length does not match the request"));
        }

        let expected_count =
            output_symbols_for_bytes(self.tfhe_recipient.parameters(), pseudonym_len_bytes)
                .map_err(|e| err(e.to_string()))?;

        if expected_count == 0 || expected_count > MAX_SYMBOLS {
            return Err(err("response symbol count is outside allowed limits"));
        }

        let output_count =
            usize::try_from(reader.read_u32()?).map_err(|_| err("PRF output count overflow"))?;

        if output_count != expected_count {
            return Err(err(
                "hybrid response has the wrong number of PRF output slots",
            ));
        }

        let mut output_wires = Vec::with_capacity(output_count);

        for _ in 0..output_count {
            output_wires.push(reader.read_bounded_blob(MAX_ITEM_BYTES, "TFHE output envelope")?);
        }

        let rlwe_modulus = self.rlwe_secret_key.s.modulus();

        let payload_ciphertext =
            read_rlwe_ciphertext(&mut reader, self.rlwe_ring_dimension, rlwe_modulus)?;

        reader.ensure_finished()?;

        let pseudonym = self
            .tfhe_recipient
            .decrypt_wire_outputs_for_request(
                &output_wires,
                pseudonym_len_bytes,
                expected_batch_id,
                expected_source_context,
            )
            .map_err(|e| err(e.to_string()))?;

        // IMPORTANT FIX:
        // decrypt_poly(...).to_coeffs_vec() can return either n coefficients
        // or n+1 values, where the final value is the canonical trailing zero.
        // Reject any other length and do not expose the optional extra value.
        let decrypted_payload = decrypt_poly(
            &self.rlwe_secret_key,
            &payload_ciphertext,
            self.rlwe_ring_dimension,
        )
        .to_coeffs_vec();

        let n = self.rlwe_ring_dimension;
        let len = decrypted_payload.len();

        if len != n && len != n + 1 {
            return Err(err(format!(
                "decrypted RLWE payload has an invalid coefficient count: \
                 expected {n} or {}, got {len}",
                n + 1,
            )));
        }

        if len == n + 1 && decrypted_payload[n] != 0 {
            return Err(err(
                "decrypted RLWE payload has a non-zero trailing coefficient",
            ));
        }

        // Return exactly n application-level coefficients.
        let payload_coefficients = decrypted_payload[..n].to_vec();

        Ok(HybridPepPlaintextResult {
            transaction_id,
            batch_id,
            pseudonym,
            payload_coefficients,
        })
    }
}
