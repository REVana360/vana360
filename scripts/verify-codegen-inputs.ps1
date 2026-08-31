[CmdletBinding()]
param(
    [string]$Root = (Join-Path $PSScriptRoot '..\game'),
    [switch]$ContractOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$checks = @(
    [pscustomobject]@{
        Path = 'PlayOnline/GameExecContent0001.xex'
        Size = 233472L
        Sha256 = '8eb1d6870a9884b479c2b53b5a0d8fea74b8006ddaf3de7b1e44b97fbc353e83'
    }
    [pscustomobject]@{
        Path = 'PlayOnline/PolCoreContent.xex'
        Size = 925696L
        Sha256 = 'f5e831f9cb20cbfa4be17d50d8c8b62a15614d1c636b09780a18610ce125cf5c'
    }
    [pscustomobject]@{
        Path = '0001/FFXi.dll'
        Size = 3121152L
        Sha256 = '406a3c9e2fc1d543e1f76484026fdbff35aa163c749190a74f024fc23c343434'
    }
    [pscustomobject]@{
        Path = '0001/FFXiMain.dll'
        Size = 7876608L
        Sha256 = 'ea25366fed9ce07baaed60934e41411b59ae681163e3d2fd6788dc874ef5c47d'
    }
    [pscustomobject]@{
        Path = '0001/patch.xex'
        Size = 135168L
        Sha256 = '23b498a696faf06faa336faa49d938b6f55fcd281861ee3ded8705a405b1e480'
    }
)

$manifest = Get-Content -LiteralPath (Join-Path $repo 'revana_manifest.toml') -Raw
$manifestPaths = @([regex]::Matches(
    $manifest,
    '(?m)^\s*file_path\s*=\s*"game/([^"]+)"\s*$'
) | ForEach-Object { $_.Groups[1].Value } | Sort-Object)
$checkPaths = @($checks.Path | Sort-Object)
if (($manifestPaths -join "`n") -cne ($checkPaths -join "`n")) {
    throw 'Codegen input verifier paths do not match revana_manifest.toml.'
}

$discGuide = Get-Content -LiteralPath (Join-Path $repo 'docs\supported-disc.md') -Raw
$rowPattern = '(?m)^\| `(?<path>[^`]+)` \| (?<size>[0-9,]+) \| `(?<sha>[0-9a-f]{64})` \|\r?$'
$discRows = @{}
foreach ($match in [regex]::Matches($discGuide, $rowPattern)) {
    $discRows[$match.Groups['path'].Value] = [pscustomobject]@{
        Size = [int64]$match.Groups['size'].Value.Replace(',', '')
        Sha256 = $match.Groups['sha'].Value
    }
}
foreach ($check in $checks) {
    if (-not $discRows.ContainsKey($check.Path)) {
        throw "Supported-disc guide is missing codegen input: $($check.Path)"
    }
    $row = $discRows[$check.Path]
    if ($row.Size -ne $check.Size -or $row.Sha256 -cne $check.Sha256) {
        throw "Supported-disc identity differs for $($check.Path)"
    }
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
