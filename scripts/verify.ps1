Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$failures = [System.Collections.Generic.List[string]]::new()

function Add-Failure([string]$Message) {
    [void]$failures.Add($Message)
}

function Relative-Path([string]$Path) {
    return $Path.Substring($repo.Length + 1).Replace('\', '/')
}

$listed = @(git -C $repo ls-files --cached --others --exclude-standard)
if ($LASTEXITCODE -ne 0 -or $listed.Count -eq 0) {
    throw 'git ls-files returned no repository files'
}
$paths = @($listed | ForEach-Object { Join-Path $repo $_ } |
    Where-Object { Test-Path -LiteralPath $_ -PathType Leaf })
$machinePatterns = @(
    '[A-Z]:' + '\\' + 'Users' + '\\',
    '/' + 'home' + '/[^/]+/',
    '/' + 'Users' + '/[^/]+/'
)

$forbiddenPaths = @($listed | Where-Object {
    ($_ -match '(?i)(^|/)(game|private|logs|out|scratch)/') -or
    ($_ -match '(?i)\.(iso|xex|xexp|dll|dat|bin|gpr|gzf)$') -or
    ($_ -match '(?i)(codegen\.stamp|codegen\.partition\.json|_recomp\.\d+\.cpp)$')
})
if ($forbiddenPaths.Count -gt 0) {
    Add-Failure "forbidden tracked or candidate path: $($forbiddenPaths -join ', ')"
}

$textPaths = @($paths | Where-Object { $_ -notmatch '(?i)\.(ico|png|jpg|jpeg|gif)$' })
foreach ($file in $textPaths) {
    $relative = Relative-Path $file
    try {
        $bytes = [IO.File]::ReadAllBytes($file)
        $badByte = $bytes | Where-Object { $_ -gt 127 } | Select-Object -First 1
        if ($null -ne $badByte) {
            throw "non-ASCII byte 0x$('{0:X2}' -f $badByte)"
        }
        $text = [Text.Encoding]::ASCII.GetString($bytes)
        if ($text -match ('(?i)' + ($machinePatterns -join '|'))) {
            Add-Failure "private machine path: $relative"
        }
        $lineNumber = 0
        foreach ($line in ($text -split "`n")) {
            $lineNumber++
            if ($line.TrimEnd("`r", ' ', "`t").Length -ne $line.TrimEnd("`r").Length) {
                Add-Failure "trailing whitespace: ${relative}:$lineNumber"
                break
            }
        }
    } catch {
        Add-Failure "text hygiene failed: ${relative}: $($_.Exception.Message)"
    }
}

foreach ($file in @($paths | Where-Object { $_ -match '(?i)\.json$' })) {
    try {
        $null = Get-Content -LiteralPath $file -Raw -Encoding UTF8 | ConvertFrom-Json
    } catch {
        Add-Failure "JSON parse failed: $(Relative-Path $file): $($_.Exception.Message)"
    }
}

try {
    $sdkLock = Get-Content -LiteralPath (Join-Path $repo 'rexglue-sdk.lock.json') -Raw |
        ConvertFrom-Json
    if ($sdkLock.repository -cne 'https://github.com/REVana360/vana360-sdk' -or
        $sdkLock.branch -cne 'main' -or
        $sdkLock.commit -cnotmatch '^[0-9a-f]{40}$') {
        Add-Failure 'rexglue-sdk.lock.json does not identify the maintained SDK fork'
    }
} catch {
    Add-Failure "SDK lock validation failed: $($_.Exception.Message)"
}

try {
    $serverLock = Get-Content -LiteralPath (Join-Path $repo 'vana360-lsb.lock.json') -Raw |
        ConvertFrom-Json
    if ($serverLock.repository -cne 'https://github.com/REVana360/vana360-lsb' -or
        $serverLock.branch -cne 'main' -or
        $serverLock.commit -cnotmatch '^[0-9a-f]{40}$') {
        Add-Failure 'vana360-lsb.lock.json does not identify the maintained server fork'
    }
} catch {
    Add-Failure "Server lock validation failed: $($_.Exception.Message)"
}

$requiredClangFormatMajor = 22
$clangFormat = Get-Command clang-format -ErrorAction SilentlyContinue
$clangFormatStatus = 'failed'
if (-not $clangFormat) {
    Add-Failure "clang-format $requiredClangFormatMajor.x is required but was not found on PATH"
} else {
    try {
        $versionOutput = @(& $clangFormat.Source --version 2>&1)
        if ($LASTEXITCODE -ne 0) {
            Add-Failure "clang-format version check failed: $($versionOutput -join ' ')"
        } else {
            $versionText = $versionOutput -join "`n"
            $versionMatch = [regex]::Match(
                $versionText,
                'clang-format version (?<version>\d+\.\d+\.\d+)')
            if (-not $versionMatch.Success) {
                Add-Failure "clang-format version check returned an unrecognized version: $versionText"
            } elseif (-not $versionMatch.Groups['version'].Value.StartsWith("$requiredClangFormatMajor.")) {
                Add-Failure "clang-format $requiredClangFormatMajor.x is required; found $($versionMatch.Groups['version'].Value)"
            } else {
                $clangFormatStatus = 'clean'
                foreach ($file in @($paths | Where-Object { $_ -match '(?i)\.(cpp|h)$' })) {
                    $formatOutput = @(& $clangFormat.Source --dry-run --Werror $file 2>&1)
                    if ($LASTEXITCODE -ne 0) {
                        $clangFormatStatus = 'failed'
                        Add-Failure "clang-format failed: $(Relative-Path $file): $($formatOutput -join ' ')"
                    }
                }
            }
        }
    } catch {
        Add-Failure "clang-format version check failed: $($_.Exception.Message)"
    }
}

$python = Get-Command python -ErrorAction SilentlyContinue
$pythonTestStatus = 'skipped'
if (-not $python) {
    Add-Failure 'python is required for TOML, manifest, and unit-test checks'
} else {
    $tomlCode = 'import pathlib,sys,tomllib; [tomllib.loads(pathlib.Path(p).read_text(encoding="ascii")) for p in sys.argv[1:]]'
    $tomlFiles = @($paths | Where-Object { $_ -match '(?i)\.toml$' })
    $tomlOutput = @(& $python.Source -c $tomlCode @tomlFiles 2>&1)
    if ($LASTEXITCODE -ne 0) {
        Add-Failure "TOML parse failed: $($tomlOutput -join ' ')"
    }

    $manifestOutput = @(& $python.Source (Join-Path $PSScriptRoot 'verify-module-graph.py') $repo 2>&1)
    if ($LASTEXITCODE -ne 0) {
        Add-Failure "manifest graph failed: $($manifestOutput -join ' ')"
    }

    $pythonFiles = @($paths | Where-Object { $_ -match '(?i)\.py$' })
    $astCode = 'import ast,pathlib,sys; [ast.parse(pathlib.Path(p).read_text(encoding="ascii"), filename=p) for p in sys.argv[1:]]'
    $astOutput = @(& $python.Source -c $astCode @pythonFiles 2>&1)
    if ($LASTEXITCODE -ne 0) {
        Add-Failure "Python AST parse failed: $($astOutput -join ' ')"
    }

    $testRoot = Join-Path $PSScriptRoot 'tests'
    $testOutput = @(& $python.Source -B -m unittest discover -s $testRoot -p 'test_*.py' 2>&1)
    if ($LASTEXITCODE -ne 0) {
        Add-Failure "Python tests failed: $($testOutput -join ' ')"
    } else {
        $pythonTestStatus = 'passed'
    }

    $commitMessage = (git -C $repo log -1 --format=%B | Out-String).TrimEnd()
    if ($LASTEXITCODE -ne 0) {
        Add-Failure 'git log failed while checking the commit subject'
    } else {
        $subjectErrors = [System.Collections.Generic.List[string]]::new()
        $subjectLines = @($commitMessage -split '\r?\n')
        $subject = $subjectLines[0]
        $subjectPattern = '^(?:title|runtime|login|build|deps|resources|tools|docs|ci|test|chore|refactor): \S'
        if ([string]::IsNullOrWhiteSpace($subject)) {
            [void]$subjectErrors.Add('empty message')
        } else {
            if ($subjectLines.Count -ne 1) {
                [void]$subjectErrors.Add('message must be one line')
            }
            if ($subject -match '[^\x00-\x7F]') {
                [void]$subjectErrors.Add('contains non-ASCII text')
            }
            if ($subject.Length -gt 50) {
                [void]$subjectErrors.Add("exceeds 50 chars ($($subject.Length))")
            }
            if ($subject -notmatch $subjectPattern) {
                [void]$subjectErrors.Add('missing or invalid type')
            }
            if ($subject.Contains('(') -or $subject.Contains(')')) {
                [void]$subjectErrors.Add('contains parentheses')
            }
        }
        if ($subjectErrors.Count -gt 0) {
            Add-Failure "commit subject failed: $($subjectErrors -join ', ')"
        }
    }
}

$parser = [System.Management.Automation.Language.Parser]
foreach ($file in @($paths | Where-Object { $_ -match '(?i)\.ps1$' })) {
    $tokens = $null
    $errors = $null
    $null = $parser::ParseFile($file, [ref]$tokens, [ref]$errors)
    if ($errors.Count -gt 0) {
        Add-Failure "PowerShell parse failed: $(Relative-Path $file): $($errors[0].Message)"
    }
}

foreach ($file in @($paths | Where-Object { $_ -match '(?i)\.md$' })) {
    $markdown = Get-Content -LiteralPath $file -Raw -Encoding UTF8
    foreach ($match in [regex]::Matches($markdown, '\]\(([^)]*)\)')) {
        $target = $match.Groups[1].Value.Trim()
        if (-not $target -or $target -match '(?i)^(https?|mailto):' -or $target.StartsWith('#')) {
            continue
        }
        $target = ($target -split '\s+', 2)[0].Trim('<', '>')
        $target = ($target -split '#', 2)[0]
        if (-not $target) {
            continue
        }
        $candidate = Join-Path (Split-Path -Parent $file) $target
        if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
            Add-Failure "Markdown link missing: $(Relative-Path $file) -> $target"
        }
    }
}

try {
    $codegenInputOutput = @(& (Join-Path $PSScriptRoot 'verify-codegen-inputs.ps1') `
        -ContractOnly 2>&1)
    if ($LASTEXITCODE -ne 0) {
        Add-Failure "codegen input contract failed: $($codegenInputOutput -join ' ')"
    }
} catch {
    Add-Failure "codegen input contract failed: $($_.Exception.Message)"
}

foreach ($cached in @($false, $true)) {
    if ($cached) {
        $diffOutput = @(& git -C $repo diff --cached --check 2>&1)
    } else {
        $diffOutput = @(& git -C $repo diff --check 2>&1)
    }
    if ($LASTEXITCODE -ne 0) {
        $label = if ($cached) { 'cached git diff' } else { 'git diff' }
        Add-Failure "$label check failed: $($diffOutput -join ' ')"
    }
}

if ($failures.Count -gt 0) {
    foreach ($failure in $failures) {
        Write-Error $failure
    }
    exit 1
}

Write-Output "verify: passed files=$($listed.Count) private-paths=1 retail-generated=1 ASCII=1 JSON=1 TOML=1 Python=1 Python-tests=$pythonTestStatus PowerShell=1 Markdown=1 manifest-graph=1 codegen-inputs=1 sdk-lock=1 server-lock=1 clang-format=$clangFormatStatus git-whitespace=1"
