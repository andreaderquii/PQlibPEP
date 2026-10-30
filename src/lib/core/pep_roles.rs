//! Role ownership for the experimental A -> T -> B pipeline.
//!
//! An OFFLINE TRUSTED DEALER creates the three bundles. It sees all secrets
//! during setup; this is not distributed TFHE key generation. Runtime T owns
//! the clear PRF key and evaluation/rekey material, but no A/B decryption key.
//! Bundles are secret local configuration, never network payloads. Only load
//! authenticated files produced by this exact library/TFHE version.
use super::fast_lwr_prf::{FastLwrPrf, FastLwrPrfParameters, FastLwrPrfSecretKey};
use super::fast_lwr_prf_pep_ks128_e16_pipeline::{
    setup_pep_lwr_prf, FastLwrPrfPepEvaluator, FastLwrPrfPepInputClient, FastLwrPrfPepRecipientKey,
};
use super::pep::{
    EncryptedAttribute, PendingPepRequest, PepPlaintext, PepRecipient, PepSource, PepTranscryptor,
};
use super::pep_context::{CanonicalIdentifier, DomainId, PepContext};
use super::rlwe::{KeyGenResult, PublicKey, SecretKey};
use super::rlwe_pke::encrypt_poly;
use super::rlwe_pre::{generate_rekey, KeySwitchEntry, ReEncryptionKey};
use crate::algebra::ring::{PolyRq, Q};
use crate::parameters::rlwe_prototype;
use bincode::Options;
use rand::{CryptoRng, RngCore};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const MAX_BUNDLE_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const CONTROL_BYTES: usize = 5
    + crate::parameters::application::CONTEXT_FINGERPRINT_BYTES
    + 2 * crate::parameters::pep_wire::CONTEXT_ID_BYTES;
const REPLAY_CAPACITY: usize = 4096;

#[derive(Serialize, Deserialize)]
struct Route {
    context: PepContext,
    n: usize,
    base_bits: usize,
    source_public: PublicMaterial,
    recipient_public: PublicMaterial,
}
#[derive(Serialize, Deserialize)]
struct PublicMaterial {
    a: Vec<u64>,
    b: Vec<u64>,
}
impl PublicMaterial {
    fn from_key(pk: &PublicKey, n: usize) -> Self {
        Self {
            a: pk.a.coefficients()[..n].to_vec(),
            b: pk.b.coefficients()[..n].to_vec(),
        }
    }
    fn key(&self, n: usize) -> Result<PublicKey> {
        Ok(PublicKey {
            a: polynomial(&self.a, n)?,
            b: polynomial(&self.b, n)?,
        })
    }
}
fn polynomial(coefficients: &[u64], n: usize) -> Result<PolyRq> {
    if coefficients.len() != n || coefficients.iter().any(|&x| x >= Q) {
        return Err("invalid canonical RLWE polynomial in role bundle".into());
    }
    Ok(PolyRq::from_coeffs(coefficients, n, Q))
}
impl Route {
    fn validate(&self) -> Result<()> {
        if self.n == 0
            || !self.n.is_power_of_two()
            || self.n > 16384
            || self.base_bits == 0
            || self.base_bits > 62
        {
            return Err("unsupported RLWE route dimensions/decomposition".into());
        }
        DomainId::new(self.context.domain().as_str())?;
        self.source_public.key(self.n)?;
        self.recipient_public.key(self.n)?;
        Ok(())
    }
    fn fingerprint(&self) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(b"PQPEP-role-route-v1");
        h.update(self.context.fingerprint());
        h.update((self.n as u64).to_le_bytes());
        h.update(Q.to_le_bytes());
        h.update((self.base_bits as u64).to_le_bytes());
        for coefficients in [
            &self.source_public.a,
            &self.source_public.b,
            &self.recipient_public.a,
            &self.recipient_public.b,
        ] {
            for value in coefficients {
                h.update(value.to_le_bytes());
            }
        }
        h.finalize().into()
    }
}

/// Only A's TFHE/RLWE keys and public routing configuration. No PRF or B secret.
#[derive(Serialize, Deserialize)]
pub struct SourceBundle {
    route: Route,
    tfhe: FastLwrPrfPepInputClient,
    rlwe_secret: Vec<u64>,
}
impl RecipientBundle {
    pub fn context(&self) -> &PepContext {
        &self.route.context
    }
    pub fn ring_dimension(&self) -> usize {
        self.route.n
    }
}
/// T has the clear PRF key inside `tfhe`, encrypted switching material and
/// public RLWE keys. There is deliberately no decryption-key field.
#[derive(Serialize, Deserialize)]
pub struct TranscryptorBundle {
    route: Route,
    tfhe: FastLwrPrfPepEvaluator,
    rekey: Vec<(Vec<u64>, Vec<u64>)>,
}
/// Only B's TFHE/RLWE decryption keys and public routing configuration.
#[derive(Serialize, Deserialize)]
pub struct RecipientBundle {
    route: Route,
    tfhe: FastLwrPrfPepRecipientKey,
    rlwe_secret: Vec<u64>,
}

/// Fresh-PRF experimental setup: a new call changes PIDs. Prefer
/// OfflinePrfKey::provision when retaining the same domain/epoch.
/// Trusted offline provisioning, retained explicitly as an assumption. Never run
/// this constructor in a runtime transcryptor service. A new route needs new
/// TFHE evaluation material; no claim of decentralized key provisioning is made.
pub fn trusted_dealer_setup<R: RngCore + CryptoRng>(
    parameters: FastLwrPrfParameters,
    n: usize,
    domain: DomainId,
    epoch: u64,
    rng: &mut R,
) -> Result<(SourceBundle, TranscryptorBundle, RecipientBundle)> {
    let key = FastLwrPrfSecretKey::generate(parameters, rng)?;
    trusted_dealer_setup_with_key(&key, n, domain, epoch, rng)
}

fn trusted_dealer_setup_with_key<R: RngCore + CryptoRng>(
    key: &FastLwrPrfSecretKey,
    n: usize,
    domain: DomainId,
    epoch: u64,
    rng: &mut R,
) -> Result<(SourceBundle, TranscryptorBundle, RecipientBundle)> {
    if n == 0 || !n.is_power_of_two() || n > 16384 {
        return Err("invalid RLWE dimension".into());
    }
    let parameters = key.parameters();
    let (client, recipient, evaluator) = setup_pep_lwr_prf(parameters, key)?;
    let a = KeyGenResult::keygen(rng, n);
    let b = KeyGenResult::keygen(rng, n);
    let base_bits = rlwe_prototype::PRE_GADGET_BASE_BITS;
    // Source-side operation: only A's secret and B's public key are needed.
    let rekey = generate_rekey(rng, &a.sk, &b.pk, base_bits);
    let context = PepContext::new(
        domain,
        epoch,
        client.source_context_id(),
        recipient.recipient_key_id(),
    );
    let make_route = || Route {
        context: context.clone(),
        n,
        base_bits,
        source_public: PublicMaterial::from_key(&a.pk, n),
        recipient_public: PublicMaterial::from_key(&b.pk, n),
    };
    Ok((
        SourceBundle {
            route: make_route(),
            tfhe: client,
            rlwe_secret: a.sk.s.coefficients()[..n].to_vec(),
        },
        TranscryptorBundle {
            route: make_route(),
            tfhe: evaluator,
            rekey: rekey
                .entries
                .iter()
                .map(|entry| {
                    (
                        entry.k0.coefficients()[..n].to_vec(),
                        entry.k1.coefficients()[..n].to_vec(),
                    )
                })
                .collect(),
        },
        RecipientBundle {
            route: make_route(),
            tfhe: recipient,
            rlwe_secret: b.sk.s.coefficients()[..n].to_vec(),
        },
    ))
}

/// Persistent domain/epoch PRF secret for the trusted offline provisioner.
/// Reuse it across source routes and encryption-key rotations to retain PID
/// consistency. Never distribute this file to A or B.
#[derive(Serialize, Deserialize)]
pub struct OfflinePrfKey {
    parameters: FastLwrPrfParameters,
    bits: Vec<u8>,
    domain: DomainId,
    epoch: u64,
}
impl OfflinePrfKey {
    pub fn generate<R: RngCore + CryptoRng>(
        parameters: FastLwrPrfParameters,
        domain: DomainId,
        epoch: u64,
        rng: &mut R,
    ) -> Result<Self> {
        let key = FastLwrPrfSecretKey::generate(parameters, rng)?;
        Ok(Self {
            parameters,
            bits: key.bits().to_vec(),
            domain,
            epoch,
        })
    }
    pub fn parameters(&self) -> FastLwrPrfParameters {
        self.parameters
    }
    /// Offline correctness oracle for synthetic laboratory inputs only.
    /// Evaluates the clear PRF, without TFHE encryption/evaluation/decryption.
    /// This does not distribute the PRF key to the recipient.
    pub fn reference_pseudonym(
        &self,
        context: &PepContext,
        identifier: &CanonicalIdentifier,
    ) -> Result<Vec<u8>> {
        if context.domain() != &self.domain || context.prf_epoch() != self.epoch {
            return Err("reference PRF domain/epoch differs from recipient context".into());
        }
        self.parameters.validate()?;
        let bits = self.parameters.output_modulus.trailing_zeros() as usize;
        if bits == 0 || !self.parameters.output_modulus.is_power_of_two() {
            return Err("reference requires a power-of-two PRF output modulus".into());
        }
        let required = crate::parameters::application::PID_BYTES * 8;
        let count = required.div_ceil(bits);
        let key = FastLwrPrfSecretKey::from_bits(self.parameters, self.bits.clone())?;
        let symbols = FastLwrPrf::new(key).evaluate_many(&context.encode_prf_input(identifier), count);
        // Independent MSB-first packing, truncated to the application PID length.
        let mut output = vec![0u8; crate::parameters::application::PID_BYTES];
        for bit in 0..required {
            let value = (symbols[bit / bits] >> (bits - 1 - bit % bits)) & 1;
            output[bit / 8] |= (value as u8) << (7 - bit % 8);
        }
        Ok(output)
    }
    pub fn provision<R: RngCore + CryptoRng>(
        &self,
        n: usize,
        rng: &mut R,
    ) -> Result<(SourceBundle, TranscryptorBundle, RecipientBundle)> {
        let key = FastLwrPrfSecretKey::from_bits(self.parameters, self.bits.clone())?;
        DomainId::new(self.domain.as_str())?;
        trusted_dealer_setup_with_key(&key, n, self.domain.clone(), self.epoch, rng)
    }
}

fn write_bundle<T: Serialize>(path: &Path, role: u8, value: &T) -> Result<()> {
    // Never silently replace keys of an existing route.
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = BufWriter::with_capacity(1024 * 1024, options.open(path)?);
    file.write_all(b"PQROLE\x01")?;
    file.write_all(&[role])?;
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(MAX_BUNDLE_BYTES)
        .serialize_into(&mut file, value)?;
    file.flush()?;
    file.get_ref().sync_all()?;
    Ok(())
}
fn read_bundle<T: DeserializeOwned>(path: &Path, role: u8) -> Result<T> {
    let file = File::open(path)?;
    if file.metadata()?.len() > MAX_BUNDLE_BYTES {
        return Err("role bundle exceeds size limit".into());
    }
    let mut file = BufReader::with_capacity(1024 * 1024, file);
    let mut header = [0u8; 8];
    file.read_exact(&mut header)?;
    if &header[..7] != b"PQROLE\x01" || header[7] != role {
        return Err("wrong bundle role/version".into());
    }
    let value = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(MAX_BUNDLE_BYTES)
        .deserialize_from(&mut file)?;
    let mut trailing = [0u8; 1];
    if file.read(&mut trailing)? != 0 {
        return Err("trailing role-bundle data".into());
    }
    Ok(value)
}
macro_rules! bundle_io {
    ($name:ident, $tag:expr) => {
        impl $name {
            pub fn write_new(&self, path: impl AsRef<Path>) -> Result<()> {
                write_bundle(path.as_ref(), $tag, self)
            }
            /// Trusted local file only. The binary format is pinned to this
            /// application and TFHE version; it is not an untrusted wire parser.
            pub fn read_trusted(path: impl AsRef<Path>) -> Result<Self> {
                read_bundle(path.as_ref(), $tag)
            }
        }
    };
}
bundle_io!(OfflinePrfKey, b'K');
bundle_io!(SourceBundle, b'A');
bundle_io!(TranscryptorBundle, b'T');
bundle_io!(RecipientBundle, b'B');

pub struct SourceRole {
    source: PepSource,
    public_key: PublicKey,
    _source_secret: SecretKey,
    n: usize,
    binding: [u8; 32],
}
pub struct TranscryptorRole {
    transcryptor: PepTranscryptor,
    binding: [u8; 32],
    seen: HashSet<[u8; 32]>,
}
pub struct RecipientRole {
    recipient: PepRecipient,
    binding: [u8; 32],
    seen: HashSet<[u8; crate::parameters::pep_wire::CONTEXT_ID_BYTES]>,
}
impl SourceRole {
    pub fn from_bundle(bundle: SourceBundle) -> Result<Self> {
        bundle.route.validate()?;
        let source_secret = SecretKey {
            s: polynomial(&bundle.rlwe_secret, bundle.route.n)?,
        };
        let binding = bundle.route.fingerprint();
        let public_key = bundle.route.source_public.key(bundle.route.n)?;
        let source = PepSource::new(bundle.route.context, bundle.tfhe)?;
        Ok(Self {
            source,
            public_key,
            _source_secret: source_secret,
            n: bundle.route.n,
            binding,
        })
    }
    pub fn ring_dimension(&self) -> usize {
        self.n
    }
    pub fn prepare<R: RngCore + CryptoRng>(
        &self,
        identifier: &CanonicalIdentifier,
        attribute: &[u64],
        rng: &mut R,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        if attribute.len() != self.n
            || attribute
                .iter()
                .any(|&x| x >= rlwe_prototype::PLAINTEXT_MODULUS)
        {
            return Err("attribute must contain exactly N canonical plaintext coefficients".into());
        }
        let plain = PolyRq::from_coeffs(attribute, self.n, Q);
        let encrypted =
            EncryptedAttribute::new(encrypt_poly(rng, &self.public_key, &plain, self.n));
        let request = self.source.prepare_request(identifier, &encrypted)?;
        let mut wire = self.binding.to_vec();
        wire.extend_from_slice(request.wire_bytes());
        let mut control = self.binding.to_vec();
        control.extend_from_slice(&request.pending().to_control_bytes());
        Ok((wire, control))
    }
}
impl TranscryptorRole {
    pub fn from_bundle(bundle: TranscryptorBundle) -> Result<Self> {
        bundle.route.validate()?;
        let binding = bundle.route.fingerprint();
        let rekey = ReEncryptionKey {
            entries: bundle
                .rekey
                .iter()
                .map(|(a, b)| {
                    Ok(KeySwitchEntry {
                        k0: polynomial(a, bundle.route.n)?,
                        k1: polynomial(b, bundle.route.n)?,
                    })
                })
                .collect::<Result<Vec<_>>>()?,
        };
        let pk = bundle.route.recipient_public.key(bundle.route.n)?;
        let transcryptor = PepTranscryptor::new(
            bundle.route.context,
            bundle.tfhe,
            rekey,
            pk,
            bundle.route.base_bits,
        )?;
        Ok(Self {
            transcryptor,
            binding,
            seen: HashSet::new(),
        })
    }
    /// Call only after transport authentication/authorization of source A.
    /// Fail closed when replay memory fills; persistent crash-safe replay
    /// storage and retry recovery remain outside this lab implementation.
    pub fn process_from_authenticated_source<R: RngCore + CryptoRng>(
        &mut self,
        wire: &[u8],
        rng: &mut R,
    ) -> Result<Vec<u8>> {
        if wire.len() < 32 || wire[..32] != self.binding {
            return Err("request route mismatch".into());
        }
        let digest: [u8; 32] = Sha3_256::digest(wire).into();
        if self.seen.contains(&digest) || self.seen.len() >= REPLAY_CAPACITY {
            return Err("duplicate request or replay capacity exhausted".into());
        }
        let response = self.transcryptor.process_request(&wire[32..], rng)?;
        self.seen.insert(digest);
        Ok(response)
    }
}
impl RecipientRole {
    pub fn from_bundle(bundle: RecipientBundle) -> Result<Self> {
        bundle.route.validate()?;
        let binding = bundle.route.fingerprint();
        let sk = SecretKey {
            s: polynomial(&bundle.rlwe_secret, bundle.route.n)?,
        };
        let recipient = PepRecipient::new(bundle.route.context, bundle.tfhe, sk, bundle.route.n)?;
        Ok(Self {
            recipient,
            binding,
            seen: HashSet::new(),
        })
    }
    /// Control comes from authenticated A, never from the transcryptor. The
    /// encrypted response may be relayed by A; only B opens its plaintext.
    pub fn open_from_authenticated_source(
        &mut self,
        control: &[u8],
        response: &[u8],
    ) -> Result<PepPlaintext> {
        if control.len() != 32 + CONTROL_BYTES || control[..32] != self.binding {
            return Err("control route/length mismatch".into());
        }
        let pending = PendingPepRequest::from_authenticated_source(&control[32..])?;
        let id = pending.transaction_id();
        if self.seen.contains(&id) || self.seen.len() >= REPLAY_CAPACITY {
            return Err("response replay or replay capacity exhausted".into());
        }
        let plaintext = self.recipient.open_response(response, &pending)?;
        self.seen.insert(id);
        Ok(plaintext)
    }
}
