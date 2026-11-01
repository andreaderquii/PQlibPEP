# PQlibPEP

Experimental post-quantum polymorphic encryption and pseudonymisation prototype.
The current transaction combines two independent branches: a TFHE-evaluated
private-input LWR PRF for the PID, and RLWE rekeying/rerandomisation for attributes.
It demonstrates functional correctness; its custom parameters, known RLWE rekey
collusion weakness and clear PRF key at the evaluator prevent deployment-security claims.

## Project layout

| Path | Purpose |
| --- | --- |
| `src/` | Active library and three-role lab executable |
| `tests/` | Active integration tests and benchmark targets |
| `examples/` | One runnable local hybrid transaction demonstration |
| `scripts/` | PowerShell launchers; independent of the caller's working directory |
| `scripts/common/` | Shared project-root and results-directory resolution |
| `benchmarks/results/` | Recorded benchmark evidence and project copies of new logs |
| `docs/` | Usage and reorganisation notes |
| `archive/old_implementations/` | Historical experiments, outside Cargo's module/test discovery |
| `lab/` | Existing Docker configuration and locally generated material; omitted from the supplied ZIP |

Keep `Cargo.toml` and `Cargo.lock` at the project root. Do not hide or delete the
research archive to clean up the root: it is deliberately collected under `archive/`.

## Run from PowerShell

From the project root:

```powershell
# Logging only: no cryptographic benchmark, no result-log overwrite.
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\run_prf_scaling_benchmark.ps1 -SelfTest

# Local operation/API benchmark.
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\run_pep_benchmark.ps1

# PRF scaling: choose the full sweep OR dedicated repeat(s).
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\run_prf_scaling_benchmark.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\run_prf_scaling_16_benchmark.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\run_prf_scaling_32_benchmark.ps1

# Independent local RLWE hop/noise benchmark.
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\run_rlwe_hop_noise_benchmark.ps1

# Existing Docker lab, with existing keys and provisioning material.
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\run_network_verified.ps1
```

Run benchmarks separately, on mains power and without competing workloads.
The launchers also work when invoked by absolute path from another directory.
They locate `Cargo.toml` relative to `scripts/`, not relative to your current directory.
The benchmark commands are local Rust tests; the network launcher runs the Docker lab.
The scaling launchers retain authoritative live/raw logs under
`%LOCALAPPDATA%\PQlibPEP\benchmarks` (TEMP fallback), and copy their final log into
`benchmarks/results/`. `-SelfTest` leaves real benchmark logs untouched.

`lab/` was excluded by the sender: preserve it in your existing checkout. A fresh
extraction cannot run the Docker experiment until its lab configuration and
required provisioning material have been restored. The migration installer does
not alter `lab/`, `.git/` or `target/` (except updating textual script references in lab guides).

## Example

```powershell
cargo run --locked --release --features fast-prf-tfhe-private-input --example hybrid_pep_transaction_demo
```

This is a local toy-parameter demonstration with exact PID/payload checks and
centrally generated keys, not a benchmark or a network/deployment test. Cargo
only builds it when requested (or when checking all targets with its required feature).
See [reorganisation notes](docs/REORGANIZATION_IT.md) and
[recorded benchmark evidence](benchmarks/results/README.md).

Validation details: [reorganisation checks](docs/REORGANIZATION_VALIDATION.md).
