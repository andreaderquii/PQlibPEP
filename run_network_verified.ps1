[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
function Invoke-DockerChecked([string[]]$DockerArguments) {
    & docker @DockerArguments
    if ($LASTEXITCODE -ne 0) { throw ('Docker failed: docker ' + ($DockerArguments -join ' ')) }
}
$binarySource = Join-Path $PSScriptRoot 'src\bin\pqpep_lab.rs'
$rolesSource = Join-Path $PSScriptRoot 'src\lib\core\pep_roles.rs'
if (-not (Test-Path $binarySource) -or -not (Select-String -LiteralPath $binarySource -SimpleMatch '"reference" => ' -Quiet)) {
    throw 'Replace src\bin\pqpep_lab.rs with the file from THIS patch first; reference is missing.'
}
if (-not (Test-Path $rolesSource) -or -not (Select-String -LiteralPath $rolesSource -SimpleMatch 'pub fn reference_pseudonym' -Quiet)) {
    throw 'Replace src\lib\core\pep_roles.rs with the file from THIS patch first.'
}
foreach ($path in @('lab\material\offline-prf-epoch.bin', 'lab\material\a\role.bin', 'lab\material\b\role.bin', 'lab\material\transcryptor\role.bin')) {
    if (-not (Test-Path -LiteralPath $path)) { throw ('Missing existing material: ' + $path + '. This script does not regenerate keys.') }
}
$compose = @('compose', '-f', 'lab/compose.yaml')
Invoke-DockerChecked ($compose + @('down'))
Invoke-DockerChecked ($compose + @('--profile', 'setup', 'build', 'setup'))
$env:PQPEP_PROFILE = 'paper'
$env:PQPEP_LAB_ID = 'patient-demo-001'
if (-not (Test-Path -LiteralPath 'lab\material\b\lab-reference.bin')) {
    Invoke-DockerChecked ($compose + @('--profile', 'setup', 'run', '--rm', '-e', 'PQPEP_LAB_ID=patient-demo-001', '--entrypoint', 'pqpep-lab', 'setup', 'reference', '/material'))
} else {
    Write-Host '[REFERENCE] Keeping the existing lab-reference.bin. B will check its context and exact results.'
}
Invoke-DockerChecked ($compose + @('up', '-d', '--no-build', 'transcryptor', 'recipient'))
$deadline = (Get-Date).AddMinutes(10)
foreach ($service in @('transcryptor', 'recipient')) {
    Write-Host ('[WAIT] Waiting for ' + $service + ' [READY]...')
    while ($true) {
        $logs = & docker @compose logs --no-color $service 2>&1
        if ($LASTEXITCODE -ne 0) { throw ('Cannot read logs for ' + $service) }
        $text = $logs -join "`n"
        if ($text -match '\[READY\]') { break }
        if ($text -match '\[ERROR\]') { throw $text }
        if ((Get-Date) -gt $deadline) { throw ('Readiness timeout: ' + $service + '. Inspect docker compose logs.') }
        Start-Sleep -Seconds 2
    }
}
Invoke-DockerChecked ($compose + @('--profile', 'send', 'run', '--rm', 'source'))
Invoke-DockerChecked ($compose + @('logs', '--timestamps', 'transcryptor', 'recipient'))
Write-Host '[DONE] Verified network transaction completed. Existing keys preserved.'
