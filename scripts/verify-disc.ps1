[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$expectedSize = 7838695424L
$expectedHash = '5fd1258ee10fae4bf27d685868dde79ef753da01722350f86c8291fe5235934f'

$resolved = Resolve-Path -LiteralPath $Path -ErrorAction Stop
$item = Get-Item -LiteralPath $resolved.Path
if ($item.PSIsContainer) {
    throw "Disc path is not a file: $Path"
}
if ($item.Length -ne $expectedSize) {
    throw "Disc size mismatch: expected $expectedSize, got $($item.Length)"
}

$actualHash = (Get-FileHash -LiteralPath $resolved.Path -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualHash -cne $expectedHash) {
    throw "Disc SHA-256 mismatch: expected $expectedHash, got $actualHash"
}

Write-Output "verify-disc: passed size=$expectedSize sha256=$expectedHash"
