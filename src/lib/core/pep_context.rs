//! Application contract: non-reversible, domain-separated PRF pseudonymization.
//! Encoding v1 intentionally differs from legacy zero-padded string_to_id.
//! Domain/epoch belong to the PRF input; encryption session IDs do not.
use crate::parameters::application as app_parameters;
use sha3::{Digest, Sha3_256};

const _: [(); app_parameters::FIELD_LENGTH_PREFIX_BYTES] = [(); (u64::BITS as usize) / 8];

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "pep-role-lab", derive(serde::Serialize, serde::Deserialize))]
pub struct DomainId(String);

impl DomainId {
    pub fn new(value: impl Into<String>) -> Result<Self, String> {
        let value = value.into();
        validate_name(&value, app_parameters::MAX_DOMAIN_ID_BYTES)?;
        Ok(Self(value))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Exact bytes in an explicit namespace. No Unicode normalization or padding.
/// Deliberately does not implement Debug, to avoid accidental identifier logs.
pub struct CanonicalIdentifier {
    namespace: String,
    value: Vec<u8>,
}

impl CanonicalIdentifier {
    pub fn new(namespace: impl Into<String>, value: &[u8]) -> Result<Self, String> {
        let namespace = namespace.into();
        validate_name(&namespace, app_parameters::MAX_NAMESPACE_BYTES)?;
        if value.is_empty() || value.len() > app_parameters::MAX_IDENTIFIER_BYTES {
            return Err(format!(
                "identifier must contain 1..={} bytes",
                app_parameters::MAX_IDENTIFIER_BYTES
            ));
        }
        Ok(Self {
            namespace,
            value: value.to_vec(),
        })
    }
}

/// Trusted provisioning metadata. IDs are routing values, not proofs of key ownership.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "pep-role-lab", derive(serde::Serialize, serde::Deserialize))]
pub struct PepContext {
    domain: DomainId,
    prf_epoch: u64,
    source_context: [u8; app_parameters::CONTEXT_TAG_BYTES],
    recipient_key: [u8; app_parameters::CONTEXT_TAG_BYTES],
}

impl PepContext {
    pub fn new(
        domain: DomainId,
        prf_epoch: u64,
        source_context: [u8; app_parameters::CONTEXT_TAG_BYTES],
        recipient_key: [u8; app_parameters::CONTEXT_TAG_BYTES],
    ) -> Self {
        Self {
            domain,
            prf_epoch,
            source_context,
            recipient_key,
        }
    }
    pub fn domain(&self) -> &DomainId {
        &self.domain
    }
    pub fn prf_epoch(&self) -> u64 {
        self.prf_epoch
    }
    pub fn source_context_id(&self) -> [u8; app_parameters::CONTEXT_TAG_BYTES] {
        self.source_context
    }
    pub fn recipient_key_id(&self) -> [u8; app_parameters::CONTEXT_TAG_BYTES] {
        self.recipient_key
    }

    /// Stable across encryption-key rotation, provided the PRF key is retained.
    /// The evaluator cannot verify this encoding inside a malicious ciphertext.
    pub fn encode_prf_input(&self, identifier: &CanonicalIdentifier) -> Vec<u8> {
        let mut out = app_parameters::CANONICAL_PRF_INPUT_DOMAIN.to_vec();
        field(&mut out, self.domain.0.as_bytes());
        out.extend_from_slice(&self.prf_epoch.to_le_bytes());
        field(&mut out, identifier.namespace.as_bytes());
        field(&mut out, &identifier.value);
        out
    }

    /// Public context fingerprint, including encryption routing metadata.
    pub fn fingerprint(&self) -> [u8; app_parameters::CONTEXT_FINGERPRINT_BYTES] {
        let mut out = app_parameters::CONTEXT_FINGERPRINT_DOMAIN.to_vec();
        field(&mut out, self.domain.0.as_bytes());
        out.extend_from_slice(&self.prf_epoch.to_le_bytes());
        out.extend_from_slice(&self.source_context);
        out.extend_from_slice(&self.recipient_key);
        Sha3_256::digest(&out).into()
    }
}

fn field(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u64).to_le_bytes());
    out.extend_from_slice(value);
}
fn validate_name(value: &str, max: usize) -> Result<(), String> {
    if value.is_empty()
        || value.len() > max
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err("name is empty, too long, padded with whitespace or contains controls".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn context(domain: &str) -> PepContext {
        PepContext::new(
            DomainId::new(domain).unwrap(),
            1,
            [1; app_parameters::CONTEXT_TAG_BYTES],
            [2; app_parameters::CONTEXT_TAG_BYTES],
        )
    }
    #[test]
    fn domain_namespace_length_and_epoch_are_unambiguous() {
        let a = CanonicalIdentifier::new("patients", b"alice").unwrap();
        let b = CanonicalIdentifier::new("patients", b"alice\0").unwrap();
        let c = CanonicalIdentifier::new("staff", b"alice").unwrap();
        let ctx = context("hospital-a");
        assert_ne!(ctx.encode_prf_input(&a), ctx.encode_prf_input(&b));
        assert_ne!(ctx.encode_prf_input(&a), ctx.encode_prf_input(&c));
        assert_ne!(
            ctx.encode_prf_input(&a),
            context("hospital-b").encode_prf_input(&a)
        );
        let mut next = ctx.clone();
        next.prf_epoch += 1;
        assert_ne!(ctx.encode_prf_input(&a), next.encode_prf_input(&a));
        assert!(DomainId::new("hospital-a\0").is_err());
    }
    #[test]
    fn encryption_rotation_preserves_prf_input_but_changes_wire_context() {
        let id = CanonicalIdentifier::new("patients", b"alice").unwrap();
        let a = context("hospital-a");
        let mut b = a.clone();
        b.source_context = [3; app_parameters::CONTEXT_TAG_BYTES];
        b.recipient_key = [4; app_parameters::CONTEXT_TAG_BYTES];
        assert_eq!(a.encode_prf_input(&id), b.encode_prf_input(&id));
        assert_ne!(a.fingerprint(), b.fingerprint());
    }
}
