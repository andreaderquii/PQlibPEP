//! Paper-PRF functional experiment, NOT a 128-bit-secure pipeline preset.
#![cfg(feature = "fast-prf-tfhe-private-input")]
#[path = "support/pep_paper.rs"]
mod experiment;

#[test]
#[ignore = "expensive: paper PRF + experimental KS128/E16 and RLWE"]
fn paper_api_round_trip() {
    experiment::run(false);
}

#[test]
#[ignore = "expensive repeated benchmark: TFHE setup/evaluation, PEP transactions and up to three RLWE hops"]
fn paper_operations_benchmark() {
    experiment::run(true);
}
