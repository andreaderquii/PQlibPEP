[CmdletBinding()]
param([switch]$SelfTest)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common/ProjectPaths.ps1')
$projectPaths = Get-PqPepProjectPaths -ScriptsDirectory $PSScriptRoot
$projectRoot = $projectPaths.Root
$resultsDirectory = $projectPaths.Results

# The authoritative log lives outside OneDrive and is never deleted.
$basePath = if ($env:LOCALAPPDATA) { $env:LOCALAPPDATA } else { $env:TEMP }
$runDirectory = Join-Path $basePath ('PQlibPEP\benchmarks\prf-scaling-32-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $runDirectory -Force | Out-Null
$logPath = Join-Path $runDirectory 'pep_prf_scaling_32_output.txt'
$stdoutPath = Join-Path $runDirectory 'stdout.txt'
$stderrPath = Join-Path $runDirectory 'stderr.txt'
$projectLog = Join-Path $resultsDirectory 'pep_prf_scaling_32_output.txt'
$utf8 = New-Object System.Text.UTF8Encoding($false)
$writer = New-Object System.IO.StreamWriter($logPath, $false, $utf8)
$writer.AutoFlush = $true
$process = $null
$readers = @()
$exitCode = 1

function Write-RunLine([string]$Line) {
    Write-Host $Line
    $writer.WriteLine($Line)
}
function Drain-Output {
    foreach ($entry in $readers) {
        $chunk = $entry.Reader.ReadToEnd()
        if ($chunk.Length -gt 0) {
            Write-Host -NoNewline $chunk
            $writer.Write($chunk)
        }
    }
}

try {
    Write-RunLine ('[START] ' + (Get-Date -Format o))
    Write-RunLine ('[LOG] Persistent live log: ' + $logPath)
    Write-RunLine ('[RAW] stdout/stderr retained in: ' + $runDirectory)
    if ($SelfTest) {
        Write-RunLine '[SELFTEST] Logging check only; no cryptographic benchmark.'
        $childPath = Join-Path $runDirectory 'logging-test.ps1'
        [System.IO.File]::WriteAllText($childPath, "[Console]::Out.WriteLine('SELFTEST_STDOUT'); Start-Sleep -Milliseconds 200; [Console]::Error.WriteLine('SELFTEST_STDERR'); exit 0", $utf8)
        $executable = (Get-Process -Id $PID).Path
        $arguments = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"' + $childPath + '"'))
    } else {
        $executable = Get-PqPepCargoPath
        $arguments = @('test', '--locked', '--release', '--features', 'fast-prf-tfhe-private-input', '--test', 'pep_prf_scaling_32_benchmark', 'prf_output_length_scaling_32', '--', '--exact', '--ignored', '--nocapture', '--test-threads=1')
        Write-RunLine '[BENCHMARK] Paper profile: 32 bytes ONLY; 10 measured samples and one warm-up.'
        Write-RunLine '[BENCHMARK] One setup and fixed input shared across runs. Run without other benchmarks.'
    }
    Write-RunLine ('[COMMAND] ' + $executable + ' ' + ($arguments -join ' '))
    $process = Start-Process -FilePath $executable -ArgumentList $arguments -WorkingDirectory $projectRoot -NoNewWindow -PassThru -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath
    $null = $process.Handle
    foreach ($path in @($stdoutPath, $stderrPath)) {
        $stream = [System.IO.File]::Open($path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        $readers += @{ Reader = (New-Object System.IO.StreamReader($stream, $utf8, $true)) }
    }
    $heartbeat = [System.Diagnostics.Stopwatch]::StartNew()
    while (-not $process.HasExited) {
        Drain-Output
        if ($heartbeat.Elapsed.TotalSeconds -ge 30) {
            Write-Host ('[RUNNING] ' + (Get-Date -Format T) + ' - live log: ' + $logPath)
            $heartbeat.Restart()
        }
        Start-Sleep -Milliseconds 500
        $process.Refresh()
    }
    $process.WaitForExit()
    Drain-Output
    if ($null -eq $process.ExitCode) { throw 'Could not obtain child process exit code; inspect retained raw logs.' }
    $exitCode = [int]$process.ExitCode
    Write-RunLine ('[EXIT] Child process exit code: ' + $exitCode)
    if ($exitCode -eq 0) {
        # Windows requires the reader to allow the existing writer handle.
        # ReadAllText's default sharing conflicts with the live StreamWriter.
        $writer.Flush()
        $checkStream = [System.IO.File]::Open($logPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        $checkReader = $null
        try {
            $checkReader = New-Object System.IO.StreamReader($checkStream, $utf8, $true)
            $contents = $checkReader.ReadToEnd()
        } finally {
            if ($null -ne $checkReader) { $checkReader.Dispose() } else { $checkStream.Dispose() }
        }
        if ($SelfTest) {
            if ($contents -notmatch 'SELFTEST_STDOUT' -or $contents -notmatch 'SELFTEST_STDERR') { throw 'Logging self-test failed: stdout or stderr missing.' }
            Write-RunLine '[PASS] Both stdout and stderr were saved to the live log.'
        } else {
            $samples = ([regex]::Matches($contents, '\[SAMPLE\] PRF eval ')).Count
            $statistics = ([regex]::Matches($contents, '\[STATS\] PRF evaluation, ')).Count
            if ($samples -ne 10 -or $statistics -ne 1 -or $contents -notmatch 'test result: ok\. 1 passed') {
                throw "Incomplete benchmark output: samples=$samples/10; summaries=$statistics/1. Raw logs retained."
            }
            Write-RunLine '[PASS] Complete results: 10 measured samples, 1 summary, Rust test passed.'
        }
    }
} catch {
    $exitCode = 1
    Write-RunLine ('[ERROR] ' + $_.Exception.Message)
} finally {
    if ($null -ne $process -and -not $process.HasExited) {
        Write-RunLine '[INTERRUPTED] The cargo process may still be active; inspect it before starting another run.'
    }
    foreach ($entry in $readers) { $entry.Reader.Dispose() }
    $writer.Dispose()
    # Self-test must not overwrite an actual benchmark log in the project.
    if (-not $SelfTest) {
        try {
            Copy-Item -LiteralPath $logPath -Destination $projectLog -Force -ErrorAction Stop
            if ((Get-Item -LiteralPath $projectLog).Length -ne (Get-Item -LiteralPath $logPath).Length) { throw 'Copied log length differs.' }
            Write-Host ('[COPY] Project log: ' + $projectLog)
        } catch {
            Write-Warning ('Project copy failed. Use the retained authoritative log: ' + $logPath + ' - ' + $_.Exception.Message)
        }
    }
    Write-Host ('[SAVED] Authoritative log: ' + $logPath)
    Write-Host ('[SAVED] Raw output retained: ' + $runDirectory)
}
exit $exitCode
