use pq_libpep::algebra::ring::{PolyRq, Q};
use pq_libpep::core::fast_lwr_prf::{FastLwrPrf, FastLwrPrfParameters, FastLwrPrfSecretKey};
use pq_libpep::core::fast_lwr_prf_pep_ks128_e16_pipeline::setup_pep_lwr_prf;
use pq_libpep::core::pep::*;
use pq_libpep::core::pep_context::*;
use pq_libpep::core::rlwe::{KeyGenResult, SecretKey};
use pq_libpep::core::rlwe_pke::{decrypt_poly, encrypt_poly, Ciphertext};
use pq_libpep::core::rlwe_pre::{generate_rekey, reencrypt, reencrypt_and_rerandomize};
use pq_libpep::parameters::{application, fast_lwr_prf, rlwe_prototype, tfhe_private_input_prototype};
use rand::rngs::OsRng;
use std::time::{Duration, Instant};

// Benchmark configuration is read from the central active profiles.
const RLWE_N: usize = rlwe_prototype::RING_DIMENSION;
const BASE_BITS: usize = rlwe_prototype::PRE_GADGET_BASE_BITS;
const PLAINTEXT_MODULUS: u64 = rlwe_prototype::PLAINTEXT_MODULUS;
const OUTPUT_BYTES: usize = application::PID_BYTES;

fn timed<T>(label: &str, operation: impl FnOnce() -> T) -> T {
    println!("[START] {label}");
    let start = Instant::now();
    let result = operation();
    println!("[TIME] {label}: {:.6} s", start.elapsed().as_secs_f64());
    result
}

fn benchmark_repetitions() -> usize {
    std::env::var("PQPEP_BENCH_REPETITIONS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(10)
        .clamp(2, 20)
}

fn warmup<T>(label: &str, operation: impl FnOnce() -> T, validate: impl FnOnce(&T)) {
    println!("[WARMUP] {label}: one untimed run (excluded from statistics)");
    let result = operation();
    validate(&result);
    drop(result);
}

fn repeated<T>(
    label: &str,
    repetitions: usize,
    mut operation: impl FnMut() -> T,
    mut validate: impl FnMut(&T),
) -> T {
    let mut samples = Vec::with_capacity(repetitions);
    let mut last_result = None;
    for run in 1..=repetitions {
        let start = Instant::now();
        let result = operation();
        samples.push(start.elapsed());
        validate(&result);
        println!("[SAMPLE] {label} run {run}/{repetitions}: {:.6} s", samples.last().unwrap().as_secs_f64());
        last_result = Some(result);
    }

    report_samples(label, &samples);
    last_result.expect("benchmark needs at least one repetition")
}

fn report_samples(label: &str, samples: &[Duration]) {
    assert!(!samples.is_empty(), "cannot summarize an empty benchmark");
    let mut sorted: Vec<f64> = samples.iter().map(Duration::as_secs_f64).collect();
    sorted.sort_by(f64::total_cmp);
    let mean = sorted.iter().sum::<f64>() / sorted.len() as f64;
    let median = if sorted.len() % 2 == 0 {
        (sorted[sorted.len() / 2 - 1] + sorted[sorted.len() / 2]) / 2.0
    } else {
        sorted[sorted.len() / 2]
    };
    let variance = sorted
        .iter()
        .map(|sample| (sample - mean).powi(2))
        .sum::<f64>()
        / (sorted.len() - 1) as f64;
    println!(
        "[STATS] {label}: n={}, mean={mean:.6}s, median={median:.6}s, min={:.6}s, max={:.6}s, sd={:.6}s",
        sorted.len(),
        sorted[0],
        sorted[sorted.len() - 1],
        variance.sqrt()
    );
}

// Outside timed regions. Process-wide resident memory, not live Rust allocations.
fn memory(label: &str) {
    #[cfg(target_os = "linux")]
    {
        match std::fs::read_to_string("/proc/self/status") {
            Ok(status) => {
                let rss = status
                    .lines()
                    .find(|s| s.starts_with("VmRSS:"))
                    .unwrap_or("VmRSS: unavailable");
                let peak = status
                    .lines()
                    .find(|s| s.starts_with("VmHWM:"))
                    .unwrap_or("VmHWM: unavailable");
                println!("[MEMORY] {label}: {rss}; {peak} (process cumulative peak)");
            }
            Err(e) => println!("[MEMORY] unavailable: {e}"),
        }
    }
    #[cfg(target_os = "windows")]
    {
        let command = format!("$p = Get-Process -Id {}; Write-Output ($p.WorkingSet64.ToString() + ' ' + $p.PeakWorkingSet64.ToString())", std::process::id());
        match std::process::Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", &command])
            .output()
        {
            Ok(out) if out.status.success() => println!(
                "[MEMORY] {label}: RSS / cumulative peak bytes = {}",
                String::from_utf8_lossy(&out.stdout).trim()
            ),
            _ => println!("[MEMORY] {label}: unavailable (PowerShell/Get-Process)"),
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    println!("[MEMORY] {label}: unavailable on this platform");
}

fn ciphertext_bytes(ct: &Ciphertext) -> usize {
    // Coefficient storage only: excludes Vec/struct/allocator/NTT caches.
    (ct.u.coefficients().len() + ct.v.coefficients().len()) * std::mem::size_of::<u64>()
}

fn validate_ciphertext(sk: &SecretKey, ct: &Ciphertext, plain: &[u64]) -> i64 {
    let delta = Q / PLAINTEXT_MODULUS;
    let phase = ct.v.sub(&ct.u.mul_ntt(&sk.s));
    let mut max_error = 0_i64;
    for (i, &m) in plain.iter().enumerate() {
        let actual = phase.coefficients().get(i).copied().unwrap_or(0);
        let target = ((m as u128 * delta as u128) % Q as u128) as u64;
        let residue = (actual + Q - target) % Q;
        let centered = if residue > Q / 2 {
            residue as i64 - Q as i64
        } else {
            residue as i64
        };
        max_error = max_error.max(centered.abs());
    }
    // Conservative sufficient margin; accounts for the plaintext encoding gap.
    let limit = delta / 2 - PLAINTEXT_MODULUS;
    assert!(
        (max_error as u64) < limit,
        "noise margin exhausted"
    );
    let decoded = decrypt_poly(sk, ct, RLWE_N);
    assert_eq!(
        &decoded.coefficients()[..RLWE_N],
        plain,
        "plaintext mismatch"
    );
    max_error
}

fn check_noise(label: &str, sk: &SecretKey, ct: &Ciphertext, plain: &[u64]) {
    let max_error = validate_ciphertext(sk, ct, plain);
    let delta = Q / PLAINTEXT_MODULUS;
    let limit = delta / 2 - PLAINTEXT_MODULUS;
    println!("[NOISE] {label}: max |phase-Delta*m| = {max_error}; conservative limit = {limit}; remaining = {}", limit as i64 - max_error);
}

pub fn run(benchmark: bool) {
    let total = Instant::now();
    let repetitions = if benchmark {
        benchmark_repetitions()
    } else {
        1
    };
    println!("\n=== PQlibPEP: PAPER PRF / EXPERIMENTAL ENCRYPTION ===");
    println!(
        "Mode: {}",
        if benchmark {
            "repeated diagnostic benchmark; functional correctness only"
        } else {
            "full preferred-API round trip"
        }
    );
    if benchmark {
        println!("BENCHMARK: {repetitions} measured samples per operation; configure with PQPEP_BENCH_REPETITIONS (2..=20); one untimed warm-up for TFHE PRF evaluation and full PEP transaction. TFHE key setup is measured as a cold-start operation.");
        let logical_threads = std::thread::available_parallelism()
            .map(|count| count.get())
            .unwrap_or(1);
        println!(
            "[ENV] os={}, arch={}, logical_threads={}, build=release (required for comparable timings)",
            std::env::consts::OS,
            std::env::consts::ARCH,
            logical_threads
        );
    }
    println!("SECURITY: only the PRF parameters have a paper-reported estimate.\nKS128 means LWE dimension 128, NOT 128-bit security. RLWE parameters are unvalidated.\nNo collusion-resistance, malicious-input, authentication or failure-probability proof.");
    let parameters = FastLwrPrfParameters::paper_default();
    assert_eq!(
        (
            parameters.lwr_dimension,
            parameters.ring_dimension,
            parameters.output_modulus
        ),
        (
            fast_lwr_prf::LWR_DIMENSION,
            fast_lwr_prf::RING_DIMENSION,
            fast_lwr_prf::OUTPUT_MODULUS
        )
    );
    let tfhe_output_polynomial_size = parameters.ring_dimension
        * tfhe_private_input_prototype::PBS_POLYNOMIAL_EXPANSION_FACTOR;
    println!("[PARAM] PRF: {} secret n={}, N={}, q_LWR={}, p={}; {} symbols -> {} bytes",
        fast_lwr_prf::KEY_DISTRIBUTION,
        parameters.lwr_dimension,
        parameters.ring_dimension,
        fast_lwr_prf::LWR_MODULUS,
        parameters.output_modulus,
        application::PID_SYMBOLS_5_BIT,
        OUTPUT_BYTES);
    println!("[PARAM] TFHE: source GLWE k={},N={} -> KS LWE n={} -> PBS GLWE k={},N={}",
        tfhe_private_input_prototype::SOURCE_GLWE_DIMENSION,
        tfhe_private_input_prototype::INPUT_BLOCK_SIZE,
        tfhe_private_input_prototype::PBS_INPUT_LWE_DIMENSION,
        tfhe_private_input_prototype::SOURCE_GLWE_DIMENSION,
        tfhe_output_polynomial_size);
    println!(
        "[PARAM] TFHE: native 2^{} torus; input/KSK/PBS sigma={:.16e}/{:.16e}/{:.16e}; KS={}x{}; PBS={}x{}",
        tfhe_private_input_prototype::TORUS_MODULUS_BITS,
        tfhe_private_input_prototype::INPUT_GLWE_GAUSSIAN_STD_DEV,
        tfhe_private_input_prototype::KSK_GAUSSIAN_STD_DEV,
        tfhe_private_input_prototype::PBS_GAUSSIAN_STD_DEV,
        tfhe_private_input_prototype::KSK_BASE_LOG,
        tfhe_private_input_prototype::KSK_LEVEL_COUNT,
        tfhe_private_input_prototype::PBS_BASE_LOG,
        tfhe_private_input_prototype::PBS_LEVEL_COUNT,
    );
    let base = 1u64 << BASE_BITS;
    let rekey_entries = (u64::BITS as usize - Q.leading_zeros() as usize + BASE_BITS - 1) / BASE_BITS;
    println!("[PARAM] RLWE: N={RLWE_N}, q={Q}, t={PLAINTEXT_MODULUS}, CBD eta={}, PRE base={base}, {rekey_entries} rekey entries",
        rlwe_prototype::SMALL_NOISE_ETA);
    println!("[PARAM] RLWE profile is the current project prototype; it is not inherited from the PRF paper.");
    let bound = (2 + rekey_entries * (base as usize - 1)) * (8 * RLWE_N + 2);
    println!(
        "[NOISE BOUND] One RLWE hop + RR: conservative CBD2 bound {bound}; Delta/2={}",
        (Q / PLAINTEXT_MODULUS) / 2
    );
    assert!((bound as u64) < (Q / PLAINTEXT_MODULUS) / 2 - PLAINTEXT_MODULUS);
    let mut rng = OsRng;
    memory("before setup");
    let key = timed("PRF binary secret generation (OsRng)", || {
        FastLwrPrfSecretKey::generate(parameters, &mut rng).unwrap()
    });
    let reference = FastLwrPrf::new(key.clone());
    let setup_label = "TFHE setup: source + intermediate + destination keys, KSK, Fourier BSK and LUT";
    let (client, output_key, evaluator) = if benchmark {
        repeated(
            setup_label,
            repetitions,
            || setup_pep_lwr_prf(parameters, &key).unwrap(),
            |(client, output_key, _)| {
                assert_eq!(client.parameters(), parameters);
                assert_eq!(output_key.parameters(), parameters);
            },
        )
    } else {
        timed(setup_label, || setup_pep_lwr_prf(parameters, &key).unwrap())
    };
    memory("after TFHE setup");
    let context = PepContext::new(
        DomainId::new("research-a").unwrap(),
        1,
        client.source_context_id(),
        output_key.recipient_key_id(),
    );
    let identifier = CanonicalIdentifier::new("hospital-patient-id", b"patient-001").unwrap();
    let encoded = context.encode_prf_input(&identifier);
    println!("[INPUT] Synthetic ID, namespace hospital-patient-id; domain research-a, PRF epoch=1; canonical encoding {} bytes", encoded.len());
    let symbols = timed("clear reference PRF (correctness oracle only)", || {
        reference.evaluate_many(&encoded, application::PID_SYMBOLS_5_BIT)
    });
    let symbol_count = application::PID_SYMBOLS_5_BIT;
    let mut expected = [0u8; OUTPUT_BYTES];
    let bits_per_symbol = parameters.output_modulus.trailing_zeros() as usize;
    for bit in 0..OUTPUT_BYTES * 8 {
        expected[bit / 8] |= (((symbols[bit / bits_per_symbol]
            >> (bits_per_symbol - 1 - bit % bits_per_symbol)) & 1) as u8)
            << (7 - bit % 8);
    }
    let source_keys = if benchmark {
        repeated(
            "RLWE source key generation",
            repetitions,
            || KeyGenResult::keygen(&mut rng, RLWE_N),
            |_| {},
        )
    } else {
        timed("RLWE source key generation", || KeyGenResult::keygen(&mut rng, RLWE_N))
    };
    let destination = if benchmark {
        repeated(
            "RLWE destination key generation",
            repetitions,
            || KeyGenResult::keygen(&mut rng, RLWE_N),
            |_| {},
        )
    } else {
        timed("RLWE destination key generation", || KeyGenResult::keygen(&mut rng, RLWE_N))
    };
    let plain: Vec<u64> = (0..RLWE_N)
        .map(|i| i as u64 % PLAINTEXT_MODULUS)
        .collect();
    let polynomial = PolyRq::from_coeffs(&plain, RLWE_N, Q);
    let ct = if benchmark {
        repeated(
            "RLWE encryption: u=a*r+e1; v=b*r+e2+Delta*m",
            repetitions,
            || encrypt_poly(&mut rng, &source_keys.pk, &polynomial, RLWE_N),
            |ct| {
                validate_ciphertext(&source_keys.sk, ct, &plain);
            },
        )
    } else {
        timed("RLWE encryption: u=a*r+e1; v=b*r+e2+Delta*m", || {
            encrypt_poly(&mut rng, &source_keys.pk, &polynomial, RLWE_N)
        })
    };
    println!("[SIZE] Attribute: {RLWE_N} Z_{PLAINTEXT_MODULUS} coefficients; {} bytes in Vec<u64>; ciphertext coefficient storage {} bytes (not wire size)", RLWE_N * std::mem::size_of::<u64>(), ciphertext_bytes(&ct));
    check_noise("encryption under source", &source_keys.sk, &ct, &plain);
    let rekey_label =
        "RLWE rekey generation: encrypt gadget multiples of source secret under destination";
    let rekey = if benchmark {
        repeated(
            rekey_label,
            repetitions,
            || generate_rekey(&mut rng, &source_keys.sk, &destination.pk, BASE_BITS),
            |rekey| assert_eq!(rekey.entries.len(), rekey_entries),
        )
    } else {
        timed(rekey_label, || {
            generate_rekey(&mut rng, &source_keys.sk, &destination.pk, BASE_BITS)
        })
    };
    let rekey_storage: usize = rekey
        .entries
        .iter()
        .map(|e| (e.k0.coefficients().len() + e.k1.coefficients().len()) * 8)
        .sum();
    println!("[SIZE] Rekey: {} entries; {rekey_storage} coefficient bytes; excludes allocator/struct overhead", rekey.entries.len());
    if benchmark {
        println!("\n=== ISOLATED PRIMITIVES (extra work, separate from API transaction) ===");
        let input_label = format!(
            "PRF input preparation: SHAKE hash vectors + GLWE encryption, {symbol_count} slots"
        );
        let inputs = repeated(
            &input_label,
            repetitions,
            || {
                client
                    .encrypt_inputs_for_output_bytes(&encoded, OUTPUT_BYTES)
                    .unwrap()
            },
            |inputs| assert_eq!(inputs.len(), symbol_count),
        );
        let input_bytes: usize = inputs
            .iter()
            .map(|x| x.to_wire_bytes().unwrap().len())
            .sum();
        println!("[SIZE] PRF input envelopes summed: {input_bytes} bytes");
        let evaluation_label = format!(
            "TFHE PRF only: {symbol_count} encrypted scalar products + KS + PBS"
        );
        warmup(
            "TFHE PRF evaluation",
            || {
                evaluator
                    .evaluate_outputs_for_bytes(&inputs, OUTPUT_BYTES)
                    .unwrap()
            },
            |outputs| {
                let decoded = output_key.decrypt_many_outputs(outputs).unwrap();
                assert_eq!(
                    decoded.into_iter().map(u64::from).collect::<Vec<_>>(),
                    symbols
                );
            },
        );
        let outputs = repeated(
            &evaluation_label,
            repetitions,
            || {
                evaluator
                    .evaluate_outputs_for_bytes(&inputs, OUTPUT_BYTES)
                    .unwrap()
            },
            |outputs| {
                let decoded = output_key.decrypt_many_outputs(outputs).unwrap();
                assert_eq!(
                    decoded.into_iter().map(u64::from).collect::<Vec<_>>(),
                    symbols
                );
            },
        );
        let output_bytes: usize = outputs
            .iter()
            .map(|x| x.to_wire_bytes().unwrap().len())
            .sum();
        println!("[SIZE] PRF output envelopes summed: {output_bytes} bytes");
        let decrypt_label = format!(
            "PRF symbol decryption (all {symbol_count} symbols, including discarded tail bits)"
        );
        let all_symbols = timed(
            &decrypt_label,
            || output_key.decrypt_many_outputs(&outputs).unwrap(),
        );
        assert_eq!(
            all_symbols
                .iter()
                .map(|&x| u64::from(x))
                .collect::<Vec<_>>(),
            symbols
        );
        let packed = timed("PRF output decryption + byte packing", || {
            output_key
                .decrypt_outputs_to_bytes(&outputs, OUTPUT_BYTES)
                .unwrap()
        });
        assert_eq!(packed, expected);
        memory("after isolated TFHE evaluation");
        let switched = repeated(
            "RLWE rekeying only: gadget decomposition + entry products",
            repetitions,
            || reencrypt(&ct, &rekey, BASE_BITS),
            |switched| {
                validate_ciphertext(&destination.sk, switched, &plain);
            },
        );
        check_noise(
            "rekeying to destination",
            &destination.sk,
            &switched,
            &plain,
        );
        let zero = PolyRq::from_coeffs(&vec![0; RLWE_N], RLWE_N, Q);
        let refreshed = repeated(
            "RLWE rerandomization only: fresh Enc_destination(0) + ciphertext addition",
            repetitions,
            || switched.add(&encrypt_poly(&mut rng, &destination.pk, &zero, RLWE_N)),
            |refreshed| {
                validate_ciphertext(&destination.sk, refreshed, &plain);
            },
        );
        check_noise("rerandomization", &destination.sk, &refreshed, &plain);
        println!("[PASS] Separate RK and RR preserve every attribute coefficient.");

        println!("\n=== RLWE/PRE CHAIN: A -> B -> C -> D (3 HOPS) ===");
        let key_c = repeated(
            "RLWE key generation for hop C",
            repetitions,
            || KeyGenResult::keygen(&mut rng, RLWE_N),
            |_| {},
        );
        let key_d = repeated(
            "RLWE key generation for hop D",
            repetitions,
            || KeyGenResult::keygen(&mut rng, RLWE_N),
            |_| {},
        );
        let rekey_bc = repeated(
            "RLWE rekey generation B -> C",
            repetitions,
            || generate_rekey(&mut rng, &destination.sk, &key_c.pk, BASE_BITS),
            |rk| assert_eq!(rk.entries.len(), rekey_entries),
        );
        let rekey_cd = repeated(
            "RLWE rekey generation C -> D",
            repetitions,
            || generate_rekey(&mut rng, &key_c.sk, &key_d.pk, BASE_BITS),
            |rk| assert_eq!(rk.entries.len(), rekey_entries),
        );

        let ct_b = reencrypt_and_rerandomize(
            &mut rng,
            &ct,
            &rekey,
            &destination.pk,
            BASE_BITS,
        );
        validate_ciphertext(&destination.sk, &ct_b, &plain);
        let ct_c = reencrypt_and_rerandomize(
            &mut rng,
            &ct_b,
            &rekey_bc,
            &key_c.pk,
            BASE_BITS,
        );
        validate_ciphertext(&key_c.sk, &ct_c, &plain);

        repeated(
            "RLWE one-hop A -> B (rekey + rerandomize)",
            repetitions,
            || reencrypt_and_rerandomize(&mut rng, &ct, &rekey, &destination.pk, BASE_BITS),
            |out| {
                validate_ciphertext(&destination.sk, out, &plain);
            },
        );
        repeated(
            "RLWE one-hop B -> C (rekey + rerandomize)",
            repetitions,
            || reencrypt_and_rerandomize(&mut rng, &ct_b, &rekey_bc, &key_c.pk, BASE_BITS),
            |out| {
                validate_ciphertext(&key_c.sk, out, &plain);
            },
        );
        repeated(
            "RLWE one-hop C -> D (rekey + rerandomize)",
            repetitions,
            || reencrypt_and_rerandomize(&mut rng, &ct_c, &rekey_cd, &key_d.pk, BASE_BITS),
            |out| {
                validate_ciphertext(&key_d.sk, out, &plain);
            },
        );

        let (hop1, hop2, hop3) = repeated(
            "RLWE complete 3-hop A -> B -> C -> D (rekey + rerandomize each hop)",
            repetitions,
            || {
                let hop1 = reencrypt_and_rerandomize(
                    &mut rng,
                    &ct,
                    &rekey,
                    &destination.pk,
                    BASE_BITS,
                );
                let hop2 = reencrypt_and_rerandomize(
                    &mut rng,
                    &hop1,
                    &rekey_bc,
                    &key_c.pk,
                    BASE_BITS,
                );
                let hop3 = reencrypt_and_rerandomize(
                    &mut rng,
                    &hop2,
                    &rekey_cd,
                    &key_d.pk,
                    BASE_BITS,
                );
                (hop1, hop2, hop3)
            },
            |(hop1, hop2, hop3)| {
                validate_ciphertext(&destination.sk, hop1, &plain);
                validate_ciphertext(&key_c.sk, hop2, &plain);
                validate_ciphertext(&key_d.sk, hop3, &plain);
            },
        );
        for (index, (sk, hop)) in [
            (&destination.sk, &hop1),
            (&key_c.sk, &hop2),
            (&key_d.sk, &hop3),
        ]
        .into_iter()
        .enumerate()
        {
            let max_error = validate_ciphertext(sk, hop, &plain);
            println!("[HOP {}] decrypts correctly; max phase error={max_error}", index + 1);
        }
        println!("[PASS] Three sequential RLWE rekey+rerandomize hops preserve the payload under D's key.");
        println!("LIMIT: this is a functional/noise experiment. It does not establish multi-hop PRE security or collusion resistance.");
    }
    println!("\n=== PREFERRED PEP API END-TO-END ===");
    let source = PepSource::new(context.clone(), client).unwrap();
    let converter =
        PepTranscryptor::new(context.clone(), evaluator, rekey, destination.pk, BASE_BITS).unwrap();
    let recipient = PepRecipient::new(context.clone(), output_key, destination.sk, RLWE_N).unwrap();
    let attribute = EncryptedAttribute::new(ct);
    let request_label =
        "API request preparation: canonical input, encrypted hash vectors, attribute and envelopes";
    let transcryptor_label =
        "API transcryptor: parsing + TFHE PRF + RLWE RK/RR + response serialization";
    let response_open_label =
        "API response opening: envelope/context checks, TFHE decryption/packing, RLWE decryption";
    let (request, response, opened, pending) = if benchmark {
        let mut request_samples = Vec::with_capacity(repetitions);
        let mut transcryptor_samples = Vec::with_capacity(repetitions);
        let mut open_samples = Vec::with_capacity(repetitions);
        let mut total_samples = Vec::with_capacity(repetitions);
        let mut final_result = None;
        warmup(
            "complete PEP API transaction",
            || {
                let request = source.prepare_request(&identifier, &attribute).unwrap();
                let pending = request.pending();
                let response = converter
                    .process_request(request.wire_bytes(), &mut rng)
                    .unwrap();
                let opened = recipient.open_response(&response, &pending).unwrap();
                (opened, pending)
            },
            |(opened, _)| {
                assert_eq!(opened.pseudonym.as_bytes(), &expected);
                assert_eq!(opened.attribute_coefficients, plain);
            },
        );
        for run in 1..=repetitions {
            let total_start = Instant::now();
            let stage_start = Instant::now();
            let request = source.prepare_request(&identifier, &attribute).unwrap();
            request_samples.push(stage_start.elapsed());
            let pending = request.pending();

            let stage_start = Instant::now();
            let response = converter
                .process_request(request.wire_bytes(), &mut rng)
                .unwrap();
            transcryptor_samples.push(stage_start.elapsed());

            let stage_start = Instant::now();
            let opened = recipient.open_response(&response, &pending).unwrap();
            open_samples.push(stage_start.elapsed());
            total_samples.push(total_start.elapsed());

            assert_eq!(opened.pseudonym.as_bytes(), &expected);
            assert_eq!(opened.pseudonym.domain(), context.domain());
            assert_eq!(opened.pseudonym.prf_epoch(), context.prf_epoch());
            assert_eq!(opened.attribute_coefficients, plain);
            println!("[SAMPLE] API transaction run {run}/{repetitions}: {:.6}s", total_samples.last().unwrap().as_secs_f64());
            final_result = Some((request, response, opened, pending));
        }
        report_samples(request_label, &request_samples);
        report_samples(transcryptor_label, &transcryptor_samples);
        report_samples(response_open_label, &open_samples);
        report_samples("API complete request-to-open latency (setup excluded)", &total_samples);
        final_result.expect("transaction benchmark needs at least one repetition")
    } else {
        let request = timed(request_label, || {
            source.prepare_request(&identifier, &attribute).unwrap()
        });
        let pending = request.pending();
        let response = timed(transcryptor_label, || {
            converter
                .process_request(request.wire_bytes(), &mut rng)
                .unwrap()
        });
        let opened = timed(response_open_label, || {
            recipient.open_response(&response, &pending).unwrap()
        });
        (request, response, opened, pending)
    };
    println!(
        "[SIZE] Complete PEP request: {} wire bytes",
        request.wire_bytes().len()
    );
    println!(
        "[SIZE] Complete PEP response: {} wire bytes",
        response.len()
    );
    memory("after API evaluation");
    assert_eq!(opened.pseudonym.as_bytes(), &expected);
    assert_eq!(opened.pseudonym.domain(), context.domain());
    assert_eq!(opened.pseudonym.prf_epoch(), context.prf_epoch());
    assert_eq!(opened.attribute_coefficients, plain);
    println!("[PASS] {OUTPUT_BYTES}-byte PID equals reference; domain/epoch match; all attributes unchanged.");
    let other = source.prepare_request(&identifier, &attribute).unwrap();
    assert!(recipient
        .open_response(&response, &other.pending())
        .is_err());
    let mut wrong = request.wire_bytes().to_vec();
    wrong[5] ^= 1;
    assert!(converter.process_request(&wrong, &mut rng).is_err());
    let mut wrong = response;
    wrong[5] ^= 1;
    assert!(recipient.open_response(&wrong, &pending).is_err());
    println!("[PASS] Foreign pending batch and mutated request/response contexts rejected (consistency checks, not authentication).");
    memory("finished");
    println!(
        "[TOTAL] {:.6} s (includes setup, reference, diagnostics and checks; not just latency)",
        total.elapsed().as_secs_f64()
    );
    println!("RESULT: functional checks passed; security level NOT established.\n");
}
