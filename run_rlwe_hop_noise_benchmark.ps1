$ErrorActionPreference = 'Stop'
$logPath = Join-Path $PSScriptRoot 'rlwe_hop_noise_output.txt'
$tempPrefix = Join-Path $env:TEMP ("pqpep_rlwe_hops_{0}" -f [guid]::NewGuid().ToString('N'))
$stdoutPath = "$tempPrefix.stdout"
$stderrPath = "$tempPrefix.stderr"

$cargo = (Get-Command cargo.exe -ErrorAction Stop).Source
$arguments = @(
    'test', '--locked', '--release', '--test', 'rlwe_hop_noise_benchmark',
    'rlwe_hop_noise_sweep', '--', '--exact', '--ignored', '--nocapture',
    '--test-threads=1'
)

Write-Host 'Running the RLWE PRE hop/noise sweep (10 chains, up to 10 hops each).'
Write-Host 'Output is captured in the local TEMP directory during the run.'
Write-Host "Final log: $logPath"

$process = Start-Process -FilePath $cargo -ArgumentList $arguments -WorkingDirectory $PSScriptRoot -NoNewWindow -PassThru -Wait -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath

@('=== CARGO STDOUT ===') | Set-Content -Path $logPath -Encoding UTF8
if (Test-Path $stdoutPath) {
    Get-Content -Path $stdoutPath | Add-Content -Path $logPath -Encoding UTF8
}
@('=== CARGO STDERR ===') | Add-Content -Path $logPath -Encoding UTF8
if (Test-Path $stderrPath) {
    Get-Content -Path $stderrPath | Add-Content -Path $logPath -Encoding UTF8
}
Remove-Item -Path $stdoutPath, $stderrPath -Force -ErrorAction SilentlyContinue

Write-Host "Cargo exit code: $($process.ExitCode)"
Write-Host "Full output saved to: $logPath"
exit $process.ExitCode
