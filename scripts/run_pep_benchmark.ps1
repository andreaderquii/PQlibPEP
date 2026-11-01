$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common/ProjectPaths.ps1')
$projectPaths = Get-PqPepProjectPaths -ScriptsDirectory $PSScriptRoot
$projectRoot = $projectPaths.Root
$resultsDirectory = $projectPaths.Results


$env:PQPEP_BENCH_REPETITIONS = '10'
$logPath = Join-Path $resultsDirectory ("pep_benchmark_{0}.log" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))

Write-Host "Running PQlibPEP benchmark with 10 measured repetitions."
Write-Host "Full output will be written to: $logPath"

$cargo = Get-PqPepCargoPath
Push-Location -LiteralPath $projectRoot
try {
    & $cargo test --locked --release --features fast-prf-tfhe-private-input --test pep_api_paper_test paper_operations_benchmark -- --exact --ignored --nocapture --test-threads=1 *> $logPath
    $cargoExitCode = $LASTEXITCODE

} finally {
    Pop-Location
}

Write-Host "Benchmark command finished with exit code $cargoExitCode."
Write-Host "Log file: $logPath"

exit $cargoExitCode
