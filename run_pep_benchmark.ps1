$ErrorActionPreference = 'Continue'

$env:PQPEP_BENCH_REPETITIONS = '10'
$logPath = Join-Path $PSScriptRoot ("pep_benchmark_{0}.log" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))

Write-Host "Running PQlibPEP benchmark with 10 measured repetitions."
Write-Host "Full output will be written to: $logPath"

& cargo test --locked --release --features fast-prf-tfhe-private-input --test pep_api_paper_test paper_operations_benchmark -- --exact --ignored --nocapture --test-threads=1 *> $logPath
$cargoExitCode = $LASTEXITCODE

Write-Host "Benchmark command finished with exit code $cargoExitCode."
Write-Host "Log file: $logPath"

exit $cargoExitCode
