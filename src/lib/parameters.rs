//! Central register of parameter profiles used or evaluated by PQlibPEP.
//!
//! Each profile is named by scheme and status. Values under `prototype` are
//! the values the current code actually uses; `research_candidate` contains
//! literature-backed targets that still need implementation and validation.
//! Do not treat a parameter from one profile as applicable to another scheme.

/// Application-format choices; these are not cryptographic security levels.
pub mod application {
    /// Stable pseudonym length at the PEP API boundary.
    pub const PID_BYTES: usize = 32;
    /// Symbols needed to encode 256 bits using 5-bit symbols (`p = 32`).
    pub const PID_SYMBOLS_5_BIT: usize = 52;
    /// Existing encrypted payload alphabet.
    pub const PAYLOAD_MODULUS: u64 = 17;
    pub const CONTEXT_TAG_BYTES: usize = 16;
    /// Maximum UTF-8 byte length of a domain name.
    pub const MAX_DOMAIN_ID_BYTES: usize = 255;
    /// Maximum UTF-8 byte length of an identifier namespace.
    pub const MAX_NAMESPACE_BYTES: usize = 128;
    /// Maximum raw identifier length in bytes.
    pub const MAX_IDENTIFIER_BYTES: usize = 4096;
    /// Context fingerprint length produced by SHA3-256.
    pub const CONTEXT_FINGERPRINT_BYTES: usize = 32;
    /// Length prefix size for fields in the canonical PRF-input encoding.
    pub const FIELD_LENGTH_PREFIX_BYTES: usize = 8;
    /// Hash used to derive the public context fingerprint.
    pub const CONTEXT_HASH_ALGORITHM: &str = "SHA3-256";
    pub const CANONICAL_PRF_INPUT_DOMAIN: &[u8] = b"PQlibPEP/canonical-prf-input/v1";
    pub const CONTEXT_FINGERPRINT_DOMAIN: &[u8] = b"PQlibPEP/context/v1";
}

/// Wire-format constants for the active PEP transaction and its envelopes.
/// These values are protocol-format choices, not cryptographic security levels.
pub mod pep_wire {
    pub const VERSION: u8 = 1;
    pub const MAGIC_BYTES: usize = 4;
    pub const VERSION_FIELD_BYTES: usize = 1;
    pub const U32_FIELD_BYTES: usize = 4;
    pub const U64_FIELD_BYTES: usize = 8;
    pub const CONTEXT_ID_BYTES: usize = super::application::CONTEXT_TAG_BYTES;
    pub const CONTEXT_FINGERPRINT_BYTES: usize = super::application::CONTEXT_FINGERPRINT_BYTES;
    pub const ENVELOPE_HEADER_BYTES: usize =
        MAGIC_BYTES + VERSION_FIELD_BYTES + CONTEXT_FINGERPRINT_BYTES;
    pub const MAX_ENVELOPE_INNER_BYTES: usize = 128 * 1024 * 1024;
    pub const MAX_FRAME_BYTES: usize = MAX_ENVELOPE_INNER_BYTES;
    pub const MAX_ITEM_BYTES: usize = 4 * 1024 * 1024;
    pub const MAX_PRF_SYMBOLS: usize = 4096;

    pub const PEP_REQUEST_MAGIC: [u8; 4] = *b"PPRQ";
    pub const PEP_RESPONSE_MAGIC: [u8; 4] = *b"PPRS";
    pub const HYBRID_REQUEST_MAGIC: [u8; 4] = *b"HPRQ";
    pub const HYBRID_RESPONSE_MAGIC: [u8; 4] = *b"HPRS";
    pub const PRF_INPUT_MAGIC: [u8; 4] = *b"PLPI";
    pub const PRF_OUTPUT_MAGIC: [u8; 4] = *b"PLPO";

    /// Fixed header offsets used by the hybrid adapter to bind PRF inputs.
    pub const PRF_PARAMETER_FIELD_COUNT: usize = 3;
    pub const PRF_INPUT_PARAMETER_BYTES: usize = PRF_PARAMETER_FIELD_COUNT * U64_FIELD_BYTES;
    pub const PRF_INPUT_BATCH_ID_OFFSET: usize =
        MAGIC_BYTES + VERSION_FIELD_BYTES + PRF_INPUT_PARAMETER_BYTES + CONTEXT_ID_BYTES;
    pub const PRF_INPUT_SLOT_INDEX_OFFSET: usize = PRF_INPUT_BATCH_ID_OFFSET + CONTEXT_ID_BYTES;
    pub const PRF_INPUT_BLOCK_COUNT_OFFSET: usize = PRF_INPUT_SLOT_INDEX_OFFSET + U64_FIELD_BYTES;
    pub const PRF_INPUT_MIN_HEADER_BYTES: usize =
        PRF_INPUT_BLOCK_COUNT_OFFSET + U32_FIELD_BYTES;
}

/// Section 5 depth-one LWR PRF profile from the 2024 paper.
/// Paper-reported estimator result applies to this PRF construction only.
/// Source: https://eprint.iacr.org/2024/665
pub mod fast_lwr_prf {
    pub const LWR_DIMENSION: usize = 445;
    pub const RING_DIMENSION: usize = 2048;
    pub const OUTPUT_MODULUS: u64 = 32;
    /// Maximum p accepted by the byte-oriented adapter.
    pub const BYTE_ADAPTER_MAX_OUTPUT_MODULUS: u64 = 256;
    pub const LWR_MODULUS: u64 = 4096; // q = 2N
    pub const KEY_DISTRIBUTION: &str = "uniform binary";
    pub const HASH_ALGORITHM: &str = "SHAKE256";
    pub const HASH_DOMAIN: &[u8] = b"PQlibPEP/FastLWRPRF/H/v2";
}

/// Current custom private-input TFHE adapter values. These are experimental,
/// not an externally validated TFHE parameter preset. No failure exponent is
/// claimed for this custom configuration.
pub mod tfhe_private_input_prototype {
    pub const SOURCE_GLWE_DIMENSION: usize = 1;
    pub const INPUT_BLOCK_SIZE: usize = 512;
    pub const PBS_INPUT_LWE_DIMENSION: usize = 128;
    pub const PBS_POLYNOMIAL_EXPANSION_FACTOR: usize = 16;
    /// Native torus modulus used by the `u128` ciphertext representation.
    pub const TORUS_MODULUS_BITS: usize = 128;
    pub const SECRET_DISTRIBUTION: &str = "uniform binary";
    pub const INPUT_GLWE_GAUSSIAN_STD_DEV: f64 = 2.940_360_153_543_253_3e-16_f64;
    pub const PBS_BASE_LOG: usize = 23;
    pub const PBS_LEVEL_COUNT: usize = 5;
    pub const KSK_BASE_LOG: usize = 8;
    pub const KSK_LEVEL_COUNT: usize = 8;
    pub const KSK_GAUSSIAN_STD_DEV: f64 = 2.940_360_153_543_253_3e-16_f64;
    pub const PBS_GAUSSIAN_STD_DEV: f64 = 2.940_360_153_543_253_3e-16_f64;
}

/// Versioned TFHE-rs preset candidate for a five-bit output alphabet.
/// It is not wired into the custom adapter above yet.
/// Preset definitions: https://docs.rs/tfhe/1.6.2/tfhe/shortint/parameters/v1_6/index.html
pub mod tfhe_research_candidate {
    pub const TFHE_RS_VERSION: &str = "1.6.2";
    pub const PRESET: &str = "V1_6_PARAM_MESSAGE_3_CARRY_3_KS_PBS_TUNIFORM_2M128";
    pub const OUTPUT_PLAINTEXT_BITS: usize = 6;
    pub const TARGET_FAILURE_EXPONENT: u32 = 128;
}

/// Existing scalar RLWE PKE/PRE prototype profile.
pub mod rlwe_prototype {
    pub const CIPHERTEXT_MODULUS: u64 = 998_244_353;
    pub const PLAINTEXT_MODULUS: u64 = super::application::PAYLOAD_MODULUS;
    /// N used by the paper-parameter end-to-end benchmark profile.
    /// Generic RLWE functions still accept a caller-selected dimension.
    pub const RING_DIMENSION: usize = 256;
    pub const DEFAULT_RING_DIMENSION: usize = RING_DIMENSION;
    pub const SMALL_NOISE_ETA: usize = 2;
    pub const PRE_GADGET_BASE_BITS: usize = 4;
    pub const SECRET_DISTRIBUTION: &str = "centered-binomial eta=2";
    pub const ERROR_DISTRIBUTION: &str = "centered-binomial eta=2";
    pub const ENCRYPTION_RANDOMNESS_DISTRIBUTION: &str = "centered-binomial eta=2";
}

/// RLWE/PRE research candidate derived from the 2024 HE security-guideline
/// model (N=2048, ternary secret, discrete Gaussian error sigma=3.19).
/// The prime is chosen to satisfy q = 1 mod 4096 and q = 1 mod 17. It still
/// requires an exact estimator run and PRE noise/collusion analysis.
/// Source: https://eprint.iacr.org/2024/463
pub mod rlwe_pre_research_candidate {
    pub const RING_DIMENSION: usize = 2048;
    pub const CIPHERTEXT_MODULUS: u64 = 1_125_899_905_884_161;
    pub const PLAINTEXT_MODULUS: u64 = 17;
    pub const ERROR_STANDARD_DEVIATION: f64 = 3.19;
    pub const PRE_GADGET_BASE_BITS: usize = 4;
}

/// Current RNS RLWE arithmetic prototype values.
pub mod rns_prototype {
    pub const PLAINTEXT_MODULUS: u64 = super::application::PAYLOAD_MODULUS;
    pub const RING_DIMENSION: usize = 256;
    /// Current RNS sampler selects coefficients from [-2, 2].
    pub const SMALL_COEFFICIENT_SUPPORT: i64 = 2;
    pub const MODULI: [u64; 9] = [
        8_416_769, 8_434_177, 8_573_441, 8_599_553, 8_782_337, 8_825_857,
        8_834_561, 8_860_673, 8_904_193,
    ];
}

/// Current leveled RNS RLWE HE prototype values used by `RlweHe`.
pub mod rns_rlwe_he_prototype {
    pub const PLAINTEXT_MODULUS: u64 = super::application::PAYLOAD_MODULUS;
    pub const MODULI: [u64; 12] = [
        8_416_769, 8_434_177, 8_573_441, 8_599_553, 8_782_337, 8_825_857,
        8_834_561, 8_860_673, 8_904_193, 9_113_089, 9_139_201, 9_165_313,
    ];
    pub const RELINEARIZATION_BASE_BITS: usize = 8;
}

/// Source-backed BGV/RNS benchmark target from the 2024 HE guidelines.
/// The P and dnum values are tied to the cited key-switching setup and are
/// not direct settings for the current custom RNS evaluator.
/// Source: https://cic.iacr.org/p/1/4/26/pdf
pub mod bgv_research_candidate {
    pub const RING_DIMENSION: usize = 16_384;
    pub const PLAINTEXT_MODULUS: u64 = 65_537;
    pub const ERROR_STANDARD_DEVIATION: f64 = 3.19;
    pub const MULTIPLICATIVE_LEVELS: usize = 8;
    pub const CIPHERTEXT_MODULUS_BITS: usize = 337;
    pub const AUXILIARY_MODULUS_BITS: usize = 60;
    pub const HYBRID_KEY_SWITCH_DIGITS: usize = 10;
}

/// Current leveled BGV prototype chain. These values target functionality,
/// not a documented security level.
pub mod bgv_prototype {
    pub const PLAINTEXT_MODULUS: u64 = 17;
    pub const FINAL_MODULUS: u64 = 3_500_000_002;
    pub const DROP_FACTORS: [u64; 4] = [256, 256, 137, 528];
}

/// Recursive BPR12 Ring-LWR implementation parameters (legacy baseline).
pub mod bpr12_prototype {
    pub const RING_DIMENSION: usize = 256;
    pub const RADIX: u64 = 17;
    pub const CRT_PACKED_RING_DIMENSION: usize = 256;
    pub const CRT_PACKED_SLOTS: usize = 8;
    pub const INPUT_BITS: usize = 256;
    pub const DEPTH: usize = 8;
    pub const MODULUS_COUNT: usize = DEPTH + 1;
}

/// Linear reshuffle prototype uses this plaintext field; this does not provide
/// unlinkability regardless of the selected numeric parameters.
pub mod reshuffle_prototype {
    pub const PLAINTEXT_MODULUS: u64 = super::application::PAYLOAD_MODULUS;
}
