//! Preferred experimental application API: canonical input -> domain pseudonym.
//!
//! Contract: trusted input producer, trusted provisioning, honest evaluation;
//! The low-level API requires external authenticated transport/replay handling.
//! `pep_roles` and the `pqpep-lab` binary supply these for the three-role lab.
//! No RS2, no proof of H(input), no proxy/recipient collusion resistance, and
//! no production security claim for the custom TFHE/RLWE parameters.
//! Attributes are ONLY rekeyed and rerandomized. The linear reshuffle is not used.
use super::fast_lwr_prf_pep_hybrid_pipeline::{
    HybridPepPipelineError, HybridPepRecipient, HybridPepSource, HybridPepTranscryptor,
    HybridResult,
};
use super::fast_lwr_prf_pep_ks128_e16_pipeline::{
    FastLwrPrfPepEvaluator, FastLwrPrfPepInputClient, FastLwrPrfPepRecipientKey,
};
use super::pep_context::{CanonicalIdentifier, DomainId, PepContext};
use super::rlwe::{PublicKey, SecretKey};
use super::rlwe_pke::Ciphertext;
use super::rlwe_pre::ReEncryptionKey;
use crate::parameters::{application, pep_wire};
use rand::{CryptoRng, RngCore};

const PSEUDONYM_BYTES: usize = application::PID_BYTES;
const HEADER_BYTES: usize = pep_wire::ENVELOPE_HEADER_BYTES;
const MAX_INNER_BYTES: usize = pep_wire::MAX_ENVELOPE_INNER_BYTES;
fn error(s: &str) -> HybridPepPipelineError {
    HybridPepPipelineError(s.into())
}

/// An already encrypted R_17 attribute, under the provisioned source RLWE key.
/// The constructor labels its semantic role; it cannot prove key ownership.
pub struct EncryptedAttribute(Ciphertext);
impl EncryptedAttribute {
    pub fn new(ciphertext: Ciphertext) -> Self {
        Self(ciphertext)
    }
}

pub struct DomainPseudonym {
    domain: DomainId,
    prf_epoch: u64,
    bytes: [u8; PSEUDONYM_BYTES],
}
impl DomainPseudonym {
    pub fn domain(&self) -> &DomainId {
        &self.domain
    }
    pub fn prf_epoch(&self) -> u64 {
        self.prf_epoch
    }
    pub fn as_bytes(&self) -> &[u8; PSEUDONYM_BYTES] {
        &self.bytes
    }
}
pub struct PepPlaintext {
    pub pseudonym: DomainPseudonym,
    pub attribute_coefficients: Vec<u64>,
}

/// Deliver to the recipient through an authenticated control channel.
/// Its control parser requires authenticated source A: bytes supplied by T
/// must not become the authority used to validate T's own response.
#[derive(Clone)]
pub struct PendingPepRequest {
    context: [u8; application::CONTEXT_FINGERPRINT_BYTES],
    transaction: [u8; pep_wire::CONTEXT_ID_BYTES],
    batch: [u8; pep_wire::CONTEXT_ID_BYTES],
}
impl PendingPepRequest {
    /// Fixed-size control message. Transmit it directly from A to B through an
    /// authenticated channel; the transcryptor must never choose these values.
    pub fn to_control_bytes(&self) -> Vec<u8> {
        let mut bytes = b"PQPC\x01".to_vec();
        bytes.extend_from_slice(&self.context);
        bytes.extend_from_slice(&self.transaction);
        bytes.extend_from_slice(&self.batch);
        bytes
    }

    /// Caller MUST authenticate A before calling this parser. This is an
    /// encoding, not a signature or MAC, and must not be accepted from T.
    pub fn from_authenticated_source(bytes: &[u8]) -> HybridResult<Self> {
        let expected = 5 + application::CONTEXT_FINGERPRINT_BYTES + 2 * pep_wire::CONTEXT_ID_BYTES;
        if bytes.len() != expected || &bytes[..5] != b"PQPC\x01" {
            return Err(error("invalid source control message"));
        }
        let context_end = 5 + application::CONTEXT_FINGERPRINT_BYTES;
        let transaction_end = context_end + pep_wire::CONTEXT_ID_BYTES;
        Ok(Self {
            context: bytes[5..context_end].try_into().unwrap(),
            transaction: bytes[context_end..transaction_end].try_into().unwrap(),
            batch: bytes[transaction_end..].try_into().unwrap(),
        })
    }
    pub fn transaction_id(&self) -> [u8; pep_wire::CONTEXT_ID_BYTES] {
        self.transaction
    }
}

pub struct PepRequest {
    bytes: Vec<u8>,
    pending: PendingPepRequest,
}
impl PepRequest {
    pub fn wire_bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn pending(&self) -> PendingPepRequest {
        self.pending.clone()
    }
}

pub struct PepSource {
    context: PepContext,
    inner: HybridPepSource,
}
impl PepSource {
    pub fn new(context: PepContext, client: FastLwrPrfPepInputClient) -> HybridResult<Self> {
        if client.source_context_id() != context.source_context_id() {
            return Err(error("source key does not match PEP context"));
        }
        Ok(Self {
            context,
            inner: HybridPepSource::new(client),
        })
    }
    pub fn prepare_request(
        &self,
        identifier: &CanonicalIdentifier,
        attribute: &EncryptedAttribute,
    ) -> HybridResult<PepRequest> {
        let encoded = self.context.encode_prf_input(identifier);
        let request = self
            .inner
            .prepare_request(&encoded, &attribute.0, PSEUDONYM_BYTES)?;
        let pending = PendingPepRequest {
            context: self.context.fingerprint(),
            transaction: request.transaction_id(),
            batch: request.batch_id(),
        };
        Ok(PepRequest {
            bytes: wrap(
                &pep_wire::PEP_REQUEST_MAGIC,
                &self.context,
                request.wire_bytes(),
            )?,
            pending,
        })
    }
}

pub struct PepTranscryptor {
    context: PepContext,
    inner: HybridPepTranscryptor,
}
impl PepTranscryptor {
    /// Provision the PRF key for this domain/epoch, and an RLWE switching key
    /// and public key for the same source/recipient pair. The caller owns this
    /// association; public context IDs do not prove it cryptographically.
    pub fn new(
        context: PepContext,
        evaluator: FastLwrPrfPepEvaluator,
        rekey: ReEncryptionKey,
        recipient_public_key: PublicKey,
        base_bits: usize,
    ) -> HybridResult<Self> {
        if evaluator.source_context_id() != context.source_context_id()
            || evaluator.recipient_key_id() != context.recipient_key_id()
        {
            return Err(error("evaluation keys do not match PEP context"));
        }
        let inner = HybridPepTranscryptor::new(evaluator, rekey, recipient_public_key, base_bits)?;
        Ok(Self { context, inner })
    }
    pub fn process_request<R: RngCore + CryptoRng>(
        &self,
        wire: &[u8],
        rng: &mut R,
    ) -> HybridResult<Vec<u8>> {
        let request = unwrap(&pep_wire::PEP_REQUEST_MAGIC, &self.context, wire)?;
        let response = self.inner.process_request_wire(request, rng)?;
        wrap(&pep_wire::PEP_RESPONSE_MAGIC, &self.context, &response)
    }

    /// Process one request with request-scoped RLWE rekey material while
    /// retaining this transcryptor's TFHE evaluator. The caller must ensure
    /// that the rekey and recipient public key belong to this request and its
    /// encrypted attribute; context metadata alone cannot verify that binding.
    pub fn process_request_with_rekey<R: RngCore + CryptoRng>(
        &self,
        wire: &[u8],
        rekey: &ReEncryptionKey,
        recipient_public_key: &PublicKey,
        base_bits: usize,
        rng: &mut R,
    ) -> HybridResult<Vec<u8>> {
        let request = unwrap(&pep_wire::PEP_REQUEST_MAGIC, &self.context, wire)?;
        let response = self.inner.process_request_wire_with_rekey(
            request,
            rekey,
            recipient_public_key,
            base_bits,
            rng,
        )?;
        wrap(&pep_wire::PEP_RESPONSE_MAGIC, &self.context, &response)
    }
}

pub struct PepRecipient {
    context: PepContext,
    inner: HybridPepRecipient,
}
impl PepRecipient {
    pub fn new(
        context: PepContext,
        key: FastLwrPrfPepRecipientKey,
        rlwe_key: SecretKey,
        ring_dimension: usize,
    ) -> HybridResult<Self> {
        if key.recipient_key_id() != context.recipient_key_id() {
            return Err(error("recipient key does not match PEP context"));
        }
        Ok(Self {
            context,
            inner: HybridPepRecipient::new(key, rlwe_key, ring_dimension)?,
        })
    }
    pub fn open_response(
        &self,
        wire: &[u8],
        pending: &PendingPepRequest,
    ) -> HybridResult<PepPlaintext> {
        if pending.context != self.context.fingerprint() {
            return Err(error("pending request belongs to another PEP context"));
        }
        let response = unwrap(&pep_wire::PEP_RESPONSE_MAGIC, &self.context, wire)?;
        let result = self.inner.open_response_wire_in_context(
            response,
            &pending.transaction,
            &pending.batch,
            PSEUDONYM_BYTES,
            &self.context.source_context_id(),
        )?;
        let bytes = result
            .pseudonym
            .try_into()
            .map_err(|_| error("invalid pseudonym length"))?;
        Ok(PepPlaintext {
            pseudonym: DomainPseudonym {
                domain: self.context.domain().clone(),
                prf_epoch: self.context.prf_epoch(),
                bytes,
            },
            attribute_coefficients: result.payload_coefficients,
        })
    }
}

fn wrap(
    magic: &[u8; pep_wire::MAGIC_BYTES],
    context: &PepContext,
    inner: &[u8],
) -> HybridResult<Vec<u8>> {
    if inner.len() > MAX_INNER_BYTES {
        return Err(error("PEP envelope too large"));
    }
    let mut out = Vec::with_capacity(HEADER_BYTES + inner.len());
    out.extend_from_slice(magic);
    out.push(pep_wire::VERSION);
    out.extend_from_slice(&context.fingerprint());
    out.extend_from_slice(inner);
    Ok(out)
}
fn unwrap<'a>(
    magic: &[u8; pep_wire::MAGIC_BYTES],
    context: &PepContext,
    wire: &'a [u8],
) -> HybridResult<&'a [u8]> {
    if wire.len() < HEADER_BYTES || wire.len() > HEADER_BYTES + MAX_INNER_BYTES {
        return Err(error("invalid PEP envelope length"));
    }
    if &wire[..pep_wire::MAGIC_BYTES] != magic || wire[pep_wire::MAGIC_BYTES] != pep_wire::VERSION {
        return Err(error("invalid PEP envelope magic or version"));
    }
    let context_start = pep_wire::MAGIC_BYTES + pep_wire::VERSION_FIELD_BYTES;
    if wire[context_start..HEADER_BYTES] != context.fingerprint()[..] {
        return Err(error("PEP envelope belongs to another context"));
    }
    Ok(&wire[HEADER_BYTES..])
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn envelopes_reject_wrong_domain_direction_version_and_truncation() {
        let a = PepContext::new(
            DomainId::new("a").unwrap(),
            1,
            [1; application::CONTEXT_TAG_BYTES],
            [2; application::CONTEXT_TAG_BYTES],
        );
        let b = PepContext::new(
            DomainId::new("b").unwrap(),
            1,
            [1; application::CONTEXT_TAG_BYTES],
            [2; application::CONTEXT_TAG_BYTES],
        );
        let wire = wrap(&pep_wire::PEP_REQUEST_MAGIC, &a, b"payload").unwrap();
        assert_eq!(
            unwrap(&pep_wire::PEP_REQUEST_MAGIC, &a, &wire).unwrap(),
            b"payload"
        );
        assert!(unwrap(&pep_wire::PEP_REQUEST_MAGIC, &b, &wire).is_err());
        assert!(unwrap(&pep_wire::PEP_RESPONSE_MAGIC, &a, &wire).is_err());
        assert!(unwrap(&pep_wire::PEP_REQUEST_MAGIC, &a, &wire[..HEADER_BYTES - 1]).is_err());
        let mut wrong = wire;
        wrong[pep_wire::MAGIC_BYTES] = pep_wire::VERSION.wrapping_add(1);
        assert!(unwrap(&pep_wire::PEP_REQUEST_MAGIC, &a, &wrong).is_err());
    }
}
