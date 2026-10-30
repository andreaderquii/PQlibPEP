# Old implementations

Archivio delle implementazioni sperimentali precedenti di PQlibPEP.
I file qui contenuti non sono moduli compilati da Cargo.
I percorsi originali sono preservati sotto src/lib/core, tests ed examples.

Backup del mod.rs corrente: src/lib/core/mod.rs.before-cleanup-20261026-193312.txt

## File spostati in questa operazione
- `src\lib\core\fast_lwr_prf_tfhe.rs`
- `src\lib\core\fast_lwr_prf_private_tfhe.rs`
- `src\lib\core\fast_lwr_prf_pep_tfhe.rs`
- `src\lib\core\fast_lwr_prf_pep_integer_tfhe.rs`
- `src\lib\core\fast_lwr_prf_pep_integer_tfhe_compact.rs`
- `src\lib\core\fast_lwr_prf_pep_tfhe_ks256_exp16.rs`
- `src\lib\core\fast_lwr_prf_pep_tfhe_ks256_exp8_packed.rs`
- `src\lib\core\fast_lwr_prf_pep_tfhe_ks128_exp8_packed.rs`
- `src\lib\core\fast_lwr_prf_pep_tfhe_ks128_exp16_packed.rs`
- `tests\fast_lwr_prf_paper_public_input_benchmark.rs`
- `tests\fast_lwr_prf_paper_public_input_stress_test.rs`
- `tests\fast_lwr_prf_pep_integer_tfhe_compact_test.rs`
- `tests\fast_lwr_prf_pep_integer_tfhe_test.rs`
- `tests\fast_lwr_prf_pep_ks128_e16_packed_validation.rs`
- `tests\fast_lwr_prf_pep_tfhe_diagnostic_test.rs`
- `tests\fast_lwr_prf_pep_tfhe_key512_single_slot_test.rs`
- `tests\fast_lwr_prf_pep_tfhe_ks128_exp16_packed_test.rs`
- `tests\fast_lwr_prf_pep_tfhe_ks128_exp8_packed_test.rs`
- `tests\fast_lwr_prf_pep_tfhe_ks256_exp8_packed_test.rs`
- `tests\fast_lwr_prf_pep_tfhe_stress_test.rs`
- `tests\fast_lwr_prf_pep_tfhe_test.rs`
- `tests\fast_lwr_prf_private_tfhe_test.rs`
- `tests\fast_lwr_prf_pep_hybrid_e2e.rs`
- `examples\fast_lwr_prf_bench.rs`

## Moduli attivi conservati

- fast_lwr_prf.rs
- fast_lwr_prf_pep_ks128_e16_pipeline.rs
- fast_lwr_prf_pep_hybrid_pipeline.rs
- rlwr_prf.rs
- reshuffle.rs
- rlwe.rs, rlwe_pke.rs, rlwe_pre.rs

Per ripristinare un vecchio modulo, riportare il file sotto src/lib/core
e reintrodurre la relativa dichiarazione pub mod nel mod.rs.
