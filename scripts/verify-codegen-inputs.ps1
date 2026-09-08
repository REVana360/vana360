[CmdletBinding()]
param(
    [string]$Root = (Join-Path $PSScriptRoot '..\game'),
    [switch]$ContractOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$discGuide = Get-Content -LiteralPath (Join-Path $repo 'docs\supported-disc.md') -Raw
$rowPattern = '(?m)^\| `(?<path>[^`]+)` \| (?<size>[0-9,]+) \| `(?<sha>[0-9a-f]{64})` \|\r?$'
$checks = @([regex]::Matches($discGuide, $rowPattern) | ForEach-Object {
    [pscustomobject]@{
        Path = $_.Groups['path'].Value
        Size = [int64]$_.Groups['size'].Value.Replace(',', '')
        Sha256 = $_.Groups['sha'].Value
    }
})

$manifest = Get-Content -LiteralPath (Join-Path $repo 'revana_manifest.toml') -Raw
$manifestPaths = @([regex]::Matches(
    $manifest,
    '(?m)^\s*file_path\s*=\s*"game/([^"]+)"\s*$'
) | ForEach-Object { $_.Groups[1].Value } | Sort-Object)
$checkPaths = @($checks.Path | Sort-Object)
if (($manifestPaths -join "`n") -cne ($checkPaths -join "`n")) {
    throw 'Codegen input verifier paths do not match revana_manifest.toml.'
}

if ($ContractOnly) {
    Write-Output "codegen-inputs: contract passed files=$($checks.Count)"
    return
}

$rootItem = Get-Item -LiteralPath $Root -Force
if (-not $rootItem.PSIsContainer) {
    throw 'Codegen input root is not a directory'
}
if ($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) {
    throw 'Codegen input root is a reparse point'
}

$rootPath = $rootItem.FullName.TrimEnd('\')
$rootPrefix = $rootPath + '\'
$verifiedBytes = [int64]0
foreach ($check in $checks) {
    $candidate = [IO.Path]::GetFullPath(
        (Join-Path $rootPath $check.Path.Replace('/', '\'))
    )
    if (-not $candidate.StartsWith(
        $rootPrefix,
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw "Codegen input escapes the root: $($check.Path)"
    }

    $ancestor = Split-Path -Parent $candidate
    while ($ancestor -and $ancestor.StartsWith(
        $rootPath,
        [StringComparison]::OrdinalIgnoreCase
    )) {
        if (Test-Path -LiteralPath $ancestor) {
            $ancestorItem = Get-Item -LiteralPath $ancestor -Force
            if ($ancestorItem.Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw 'Codegen input crosses a reparse point'
            }
        }
        if ($ancestor.Equals($rootPath, [StringComparison]::OrdinalIgnoreCase)) {
            break
        }
        $ancestor = Split-Path -Parent $ancestor
    }

    if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
        throw "Codegen input is missing: $($check.Path)"
    }
    $item = Get-Item -LiteralPath $candidate -Force
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw "Codegen input is a reparse point: $($check.Path)"
    }
    if ($item.Length -ne $check.Size) {
        throw "Codegen input has the wrong size: $($check.Path)"
    }
    $hash = (Get-FileHash -LiteralPath $candidate -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($hash -cne $check.Sha256) {
        throw "Codegen input has the wrong SHA-256: $($check.Path)"
    }
    $verifiedBytes += $item.Length
}

Write-Output "codegen-inputs: verified files=$($checks.Count) bytes=$verifiedBytes"
