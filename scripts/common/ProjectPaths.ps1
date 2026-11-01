# Shared path resolution for scripts stored directly under scripts/.
function Get-PqPepProjectPaths {
    param([Parameter(Mandatory = $true)][string]$ScriptsDirectory)
    $root = (Resolve-Path -LiteralPath (Join-Path $ScriptsDirectory '..') -ErrorAction Stop).Path
    if (-not (Test-Path -LiteralPath (Join-Path $root 'Cargo.toml') -PathType Leaf)) {
        throw 'Cannot find Cargo.toml in the parent of scripts/. Keep the project directory structure intact.'
    }
    $results = Join-Path $root 'benchmarks/results'
    New-Item -ItemType Directory -Path $results -Force -ErrorAction Stop | Out-Null
    [pscustomobject]@{ Root = $root; Results = $results }
}

function Get-PqPepCargoPath {
    $command = Get-Command cargo.exe -ErrorAction SilentlyContinue
    if ($null -eq $command) { $command = Get-Command cargo -ErrorAction Stop }
    $command.Source
}
