//! Three runtime processes over mutually authenticated TLS. Run `provision`
//! offline first; it is a TRUSTED DEALER, not a runtime fourth service.
use pq_libpep::core::fast_lwr_prf::FastLwrPrfParameters;
use pq_libpep::core::pep_context::{CanonicalIdentifier, DomainId};
use pq_libpep::core::pep_roles::*;
use pq_libpep::parameters::rlwe_prototype;
use rand::rngs::OsRng;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, StreamOwned,
};
use std::fs::{self, File, OpenOptions};
use serde::{Serialize, Deserialize};
use bincode::Options;
use std::io::{BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const MAX_FRAME: usize = 256 * 1024 * 1024;

// Trusted offline test vector, never a production identifier lookup table.
// No PRF secret or original identifier is included. Runtime B only sees its fixture.
#[derive(Serialize, Deserialize)]
struct LabReference {
    magic: [u8; 8],
    context: [u8; 32],
    pid: Vec<u8>,
    attribute: Vec<u64>,
}
fn lab_identifier() -> Result<CanonicalIdentifier> {
    let id = std::env::var("PQPEP_LAB_ID").unwrap_or_else(|_| "patient-demo-001".into());
    Ok(CanonicalIdentifier::new("hospital-patient-id", id.as_bytes())?)
}
fn lab_attribute(n: usize) -> Vec<u64> {
    (0..n).map(|i| i as u64 % rlwe_prototype::PLAINTEXT_MODULUS).collect()
}
impl LabReference {
    fn write_new(&self, path: &Path) -> Result<()> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        { use std::os::unix::fs::OpenOptionsExt; options.mode(0o600); }
        let mut file = options.open(path)?;
        bincode::serialize_into(&mut file, self)?;
        file.sync_all()?;
        Ok(())
    }
    fn read(path: &Path) -> Result<Self> {
        let bytes = fs::read(path)?;
        if bytes.len() > 1024 * 1024 { return Err("lab reference is too large".into()); }
        let value: Self = bincode::DefaultOptions::new().with_fixint_encoding()
            .with_limit(1024 * 1024).reject_trailing_bytes().deserialize(&bytes)?;
        if &value.magic != b"PQLABEQ1" || value.pid.len() != pq_libpep::parameters::application::PID_BYTES {
            return Err("invalid lab reference version/PID length".into());
        }
        Ok(value)
    }
    fn verify(&self, context: &[u8; 32], pid: &[u8], attribute: &[u64]) -> Result<()> {
        if context != &self.context { return Err("lab reference context mismatch".into()); }
        if pid != self.pid { return Err("PID equality FAILED against offline clear-PRF reference".into()); }
        if attribute.len() != self.attribute.len() {
            return Err("attribute equality FAILED: coefficient count differs".into());
        }
        if let Some(index) = attribute.iter().zip(&self.attribute).position(|(a, b)| a != b) {
            return Err(format!("attribute equality FAILED at coefficient {index}").into());
        }
        Ok(())
    }
}
fn write_lab_reference(root: &Path, key: &OfflinePrfKey, bundle: &RecipientBundle) -> Result<()> {
    let fixture = LabReference {
        magic: *b"PQLABEQ1",
        context: bundle.context().fingerprint(),
        pid: key.reference_pseudonym(bundle.context(), &lab_identifier()?)?,
        attribute: lab_attribute(bundle.ring_dimension()),
    };
    fixture.write_new(&root.join("b/lab-reference.bin"))?;
    println!("[REFERENCE] Offline clear-PRF PID and {} synthetic coefficients saved for B; no keys changed", fixture.attribute.len());
    println!("[REFERENCE] Synthetic lab data only; no PRF key/identifier included; equality is functional correctness, not a security proof");
    Ok(())
}

// UTC Unix time permits correlating A/T/B logs without exposing identifiers or keys.
// These diagnostic wall times are not a repeated statistical benchmark.
fn trace(role: &str, message: impl std::fmt::Display) {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    println!("[{}.{:03}] [{role}] {message}", now.as_secs(), now.subsec_millis());
    let _ = std::io::stdout().flush();
}

fn certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let value = rustls_pemfile::certs(&mut BufReader::new(File::open(path)?))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if value.is_empty() {
        return Err("empty certificate file".into());
    }
    Ok(value)
}
fn key(dir: &Path) -> Result<PrivateKeyDer<'static>> {
    rustls_pemfile::private_key(&mut BufReader::new(File::open(dir.join("key.pem"))?))?
        .ok_or_else(|| "no private TLS key found".into())
}
fn roots(dir: &Path) -> Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    for certificate in certs(&dir.join("ca.pem"))? {
        roots.add(certificate)?;
    }
    Ok(roots)
}
fn socket(socket: TcpStream) -> Result<TcpStream> {
    socket.set_read_timeout(Some(Duration::from_secs(1800)))?;
    socket.set_write_timeout(Some(Duration::from_secs(1800)))?;
    socket.set_nodelay(true)?;
    Ok(socket)
}
fn read_frame(reader: &mut impl Read) -> Result<Vec<u8>> {
    let mut header = [0u8; 8];
    reader.read_exact(&mut header)?;
    let length = usize::try_from(u64::from_be_bytes(header))?;
    if length == 0 || length > MAX_FRAME {
        return Err("invalid network frame length".into());
    }
    let mut data = vec![0u8; length];
    reader.read_exact(&mut data)?;
    Ok(data)
}
fn write_frame(writer: &mut impl Write, data: &[u8]) -> Result<()> {
    if data.is_empty() || data.len() > MAX_FRAME {
        return Err("invalid output frame length".into());
    }
    writer.write_all(&(data.len() as u64).to_be_bytes())?;
    writer.write_all(data)?;
    writer.flush()?;
    Ok(())
}
fn send(dir: &Path, address: &str, server_name: &str, data: &[u8]) -> Result<Vec<u8>> {
    let exchange_start = Instant::now();
    trace("A", format!("Connecting to {server_name} at {address}"));
    let config = ClientConfig::builder()
        .with_root_certificates(roots(dir)?)
        .with_client_auth_cert(certs(&dir.join("cert.pem"))?, key(dir)?)?;
    let conn = ClientConnection::new(
        Arc::new(config),
        ServerName::try_from(server_name.to_owned())?,
    )?;
    let tcp = socket(TcpStream::connect(address)?)?;
    trace("A", format!("TCP connected: {} -> {}", tcp.local_addr()?, tcp.peer_addr()?));
    let mut stream = StreamOwned::new(conn, tcp);
    while stream.conn.is_handshaking() {
        stream.conn.complete_io(&mut stream.sock)?;
    }
    trace("A", format!("TLS handshake completed with {server_name}: server CA/name verified, A client certificate presented, protocol={:?}", stream.conn.protocol_version()));
    trace("A", format!("Sending {} application bytes to {server_name} (TLS/framing overhead excluded)", data.len()));
    write_frame(&mut stream, data)?;
    trace("A", format!("Waiting for {server_name} response"));
    let reply = read_frame(&mut stream)?;
    if reply[0] != 0 {
        return Err("remote role rejected the request; inspect its own log".into());
    }
    trace("A", format!("Received {} application bytes from {server_name}; exchange wall time={:.3}s (connect/TLS/transfer/remote processing)", reply.len() - 1, exchange_start.elapsed().as_secs_f64()));
    stream.conn.send_close_notify();
    let _ = stream.flush();
    Ok(reply[1..].to_vec())
}
fn serve(
    role: &str,
    dir: &Path,
    address: &str,
    mut handler: impl FnMut(&[u8]) -> Result<Vec<u8>>,
) -> Result<()> {
    let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots(dir)?)).build()?;
    let config = Arc::new(
        ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(certs(&dir.join("cert.pem"))?, key(dir)?)?,
    );
    // CA authentication alone is insufficient: authorize A's exact leaf certificate.
    let source_certificate = certs(&dir.join("authorized-source.pem"))?.remove(0);
    let listener = TcpListener::bind(address)?;
    trace(role, format!("[READY] mTLS listener {}; only provisioned source A is authorized", listener.local_addr()?));
    for incoming in listener.incoming() {
        let result = (|| -> Result<()> {
            let tcp = socket(incoming?)?;
            trace(role, format!("TCP accepted: peer={} -> local={}", tcp.peer_addr()?, tcp.local_addr()?));
            let conn = ServerConnection::new(config.clone())?;
            let mut stream = StreamOwned::new(conn, tcp);
            while stream.conn.is_handshaking() {
                stream.conn.complete_io(&mut stream.sock)?;
            }
            if stream.conn.peer_certificates().and_then(|c| c.first()) != Some(&source_certificate) {
                return Err("authenticated peer is not authorized source A".into());
            }
            trace(role, format!("mTLS authenticated and authorized A: client CA verified and leaf certificate matched; protocol={:?}", stream.conn.protocol_version()));
            let request = read_frame(&mut stream)?;
            trace(role, format!("Received {} application bytes from A", request.len()));
            match handler(&request) {
                Ok(response) => {
                    trace(role, format!("Sending {} application bytes back to A", response.len()));
                    let mut reply = vec![0u8];
                    reply.extend(response);
                    write_frame(&mut stream, &reply)?;
                }
                Err(error) => {
                    eprintln!("[{role}] [REJECT] {error}");
                    write_frame(&mut stream, b"\x01request rejected")?;
                }
            }
            stream.conn.send_close_notify();
            let _ = stream.flush();
            trace(role, "Connection to A completed");
            Ok(())
        })();
        if let Err(error) = result {
            eprintln!("[{role}] [CONNECTION REJECTED] {error}");
        }
    }
    Ok(())
}
fn require<'a>(arguments: &'a [String], index: usize) -> Result<&'a str> {
    arguments
        .get(index)
        .map(String::as_str)
        .ok_or_else(|| "missing command argument".into())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("[ERROR] {error}");
        std::process::exit(1);
    }
}
fn run() -> Result<()> {
    let arguments: Vec<String> = std::env::args().collect();
    match require(&arguments, 1)? {
        "provision" => {
            let output = PathBuf::from(require(&arguments, 2)?);
            let profile = arguments.get(3).map(String::as_str).unwrap_or("paper");
            let (parameters, n) = match profile {
                "paper" => (FastLwrPrfParameters::paper_default(), rlwe_prototype::RING_DIMENSION),
                "toy" => (FastLwrPrfParameters { lwr_dimension: 8, ring_dimension: 64, output_modulus: 32 }, 64),
                _ => return Err("profile must be paper or toy".into()),
            };
            println!("[SETUP] OFFLINE TRUSTED DEALER; profile={profile}; sees all secrets during setup");
            println!("[SECURITY] Runtime roles will be separate; parameter/deployment security remains unestablished");
            for role in ["a", "b", "transcryptor"] { fs::create_dir_all(output.join(role))?; }
            // Check before expensive setup; write_new also prevents overwriting.
            if ["a", "b", "transcryptor"].iter().any(|role| output.join(role).join("role.bin").exists()) {
                return Err("existing role.bin: use a new provisioning directory".into());
            }
            let epoch_key = if let Some(path) = arguments.get(4) {
                let existing = OfflinePrfKey::read_trusted(path)?;
                if existing.parameters() != parameters { return Err("profile differs from retained PRF key".into()); }
                existing
            } else {
                let generated = OfflinePrfKey::generate(parameters, DomainId::new("research-b")?, 1, &mut OsRng)?;
                generated.write_new(output.join("offline-prf-epoch.bin"))?;
                generated
            };
            let (a, t, b) = epoch_key.provision(n, &mut OsRng)?;
            a.write_new(output.join("a/role.bin"))?;
            t.write_new(output.join("transcryptor/role.bin"))?;
            b.write_new(output.join("b/role.bin"))?;
            write_lab_reference(&output, &epoch_key, &b)?;
            println!("[DONE] Three role-specific bundles saved; provision TLS files separately");
        }
        "reference" => {
            let root = Path::new(require(&arguments, 2)?);
            let key = OfflinePrfKey::read_trusted(root.join("offline-prf-epoch.bin"))?;
            let bundle = RecipientBundle::read_trusted(root.join("b/role.bin"))?;
            write_lab_reference(root, &key, &bundle)?;
        }
        "source" => {
            trace("A", format!("Starting source process; namespace-local process ID={} (may be 1 inside a container)", std::process::id()));
            let dir = Path::new(require(&arguments, 2)?);
            let load_start = Instant::now();
            let a = SourceRole::from_bundle(SourceBundle::read_trusted(dir.join("role.bin"))?)?;
            trace("A", format!("Own bundle loaded in {:.3}s; source TFHE/RLWE keys, no recipient decryption key or PRF key", load_start.elapsed().as_secs_f64()));
            let identifier = lab_identifier()?;
            let attribute = lab_attribute(a.ring_dimension());
            trace("A", format!("Preparing a {}-byte PID request and {} synthetic attribute coefficients; identifier is not logged", pq_libpep::parameters::application::PID_BYTES, attribute.len()));
            let transaction_start = Instant::now();
            let prepare_start = Instant::now();
            let (request, control) = a.prepare(&identifier, &attribute, &mut OsRng)?;
            trace("A", format!("Preparation completed in {:.3}s: encrypted PRF inputs + RLWE Enc_A(attribute)", prepare_start.elapsed().as_secs_f64()));
            trace("A", format!("Sending encrypted request: {} bytes; separate A->B control: {} bytes", request.len(), control.len()));
            let response = send(dir, require(&arguments, 3)?, "transcryptor", &request)?;
            trace("A", "T returned an encrypted response; A relays it without decrypting B's PID or attributes");
            let mut delivery = (control.len() as u32).to_be_bytes().to_vec();
            delivery.extend(control); delivery.extend(response);
            trace("A", format!("Delivering A's own pending control plus encrypted response to B: {} bytes", delivery.len()));
            let acknowledgment = send(dir, require(&arguments, 4)?, "recipient", &delivery)?;
            if acknowledgment != b"verified" { return Err("invalid recipient acknowledgment".into()); }
            trace("A", "[PASS] B acknowledged EXACT PID and ALL attribute equality against the offline reference. Plaintext/PID remain at B.");
            trace("A", format!("Request-to-acknowledgment wall time={:.3}s; includes preparation, both TLS exchanges and remote processing; excludes role-bundle loading/offline setup", transaction_start.elapsed().as_secs_f64()));
        }
        "transcryptor" => {
            trace("T", format!("Starting transcryptor process; namespace-local process ID={} (may be 1 inside a container)", std::process::id()));
            let dir = Path::new(require(&arguments, 2)?);
            let load_start = Instant::now();
            trace("T", "Loading own bundle and TFHE evaluation keys; large bundles may take time");
            let mut t = TranscryptorRole::from_bundle(TranscryptorBundle::read_trusted(dir.join("role.bin"))?)?;
            trace("T", format!("Bundle loaded in {:.3}s", load_start.elapsed().as_secs_f64()));
            trace("T", "Owns clear PRF key, TFHE evaluation material, RLWE rekey and public keys; no explicit A/B plaintext decryption-key fields");
            serve("T", dir, require(&arguments, 3)?, |wire| {
                trace("T", "Starting pipeline: route/replay checks, encrypted-input PRF evaluation, RLWE A->B rekeying and fresh Enc_B(0) rerandomization");
                trace("T", "PRF input/output and attribute payload remain encrypted in this process");
                let start = Instant::now();
                let response = t.process_from_authenticated_source(wire, &mut OsRng)?;
                trace("T", format!("Processed encrypted request in {:.3}s; response={} bytes; this timer excludes TLS/network transfer", start.elapsed().as_secs_f64(), response.len()));
                Ok(response)
            })?;
        }
        "recipient" => {
            trace("B", format!("Starting recipient process; namespace-local process ID={} (may be 1 inside a container)", std::process::id()));
            let dir = Path::new(require(&arguments, 2)?);
            let load_start = Instant::now();
            let bundle = RecipientBundle::read_trusted(dir.join("role.bin"))?;
            let expected_context = bundle.context().fingerprint();
            let expected_n = bundle.ring_dimension();
            let reference = LabReference::read(&dir.join("lab-reference.bin"))?;
            if reference.context != expected_context || reference.attribute.len() != expected_n {
                return Err("offline lab reference does not match recipient bundle".into());
            }
            trace("B", "Offline synthetic reference loaded; exact PID/attribute equality is mandatory before acknowledgment");
            let mut b = RecipientRole::from_bundle(bundle)?;
            trace("B", format!("Own bundle loaded in {:.3}s; recipient TFHE/RLWE decryption keys, no source secret or PRF key", load_start.elapsed().as_secs_f64()));
            serve("B", dir, require(&arguments, 3)?, |wire| {
                if wire.len() < 4 { return Err("truncated A->B delivery".into()); }
                let length = u32::from_be_bytes(wire[..4].try_into()?) as usize;
                if length > 1024 || wire.len() <= 4 + length { return Err("invalid A->B control length".into()); }
                trace("B", format!("Delivery from authenticated A: control={} bytes, encrypted response={} bytes", length, wire.len() - 4 - length));
                trace("B", "Checking A's pending context/transaction/batch and replay state, then decrypting the PID and RLWE attribute");
                let open_start = Instant::now();
                let opened = b.open_from_authenticated_source(&wire[4..4+length], &wire[4+length..])?;
                let open_seconds = open_start.elapsed().as_secs_f64();
                let verify_start = Instant::now();
                reference.verify(&expected_context, opened.pseudonym.as_bytes(), &opened.attribute_coefficients)?;
                trace("B", format!("[PASS] PID equality: all {} bytes match the offline CLEAR-PRF reference", reference.pid.len()));
                trace("B", format!("[PASS] Attribute equality: ALL {}/{} coefficients match the original synthetic payload after RLWE rekeying + rerandomization", reference.attribute.len(), reference.attribute.len()));
                trace("B", format!("Reference comparison completed in {:.6}s (separate from response opening)", verify_start.elapsed().as_secs_f64()));
                let pid = opened.pseudonym.as_bytes().iter().map(|x| format!("{x:02x}")).collect::<String>();
                trace("B", format!("Opened response: PID={pid}; attributes={} coefficients; domain={}; epoch={}", opened.attribute_coefficients.len(), opened.pseudonym.domain().as_str(), opened.pseudonym.prf_epoch()));
                trace("B", format!("Response opening completed in {:.3}s; this timer excludes TLS/network transfer", open_seconds));
                trace("B", "Returning only the 'verified' acknowledgment after BOTH exact comparisons passed; no plaintext/PID is included");
                Ok(b"verified".to_vec())
            })?;
        }
        _ => return Err("usage: pqpep-lab provision DIR [paper|toy] [RETAINED_PRF_KEY] | reference MATERIAL_DIR | source DIR T:PORT B:PORT | transcryptor DIR BIND:PORT | recipient DIR BIND:PORT".into()),
    }
    Ok(())
}

#[cfg(test)]
mod equality_tests {
    use super::*;
    #[test]
    fn exact_reference_rejects_corruption_lengths_and_wrong_context() {
        let reference = LabReference { magic: *b"PQLABEQ1", context: [3; 32], pid: vec![5; 32], attribute: lab_attribute(64) };
        reference.verify(&[3;32], &[5;32], &lab_attribute(64)).unwrap();
        let mut wrong_pid = vec![5;32]; wrong_pid[31] ^= 1;
        assert!(reference.verify(&[3;32], &wrong_pid, &lab_attribute(64)).is_err());
        let mut wrong_attribute = lab_attribute(64); wrong_attribute[63] ^= 1;
        assert!(reference.verify(&[3;32], &[5;32], &wrong_attribute).is_err());
        assert!(reference.verify(&[3;32], &[5;32], &lab_attribute(63)).is_err());
        assert!(reference.verify(&[4;32], &[5;32], &lab_attribute(64)).is_err());
    }
}
