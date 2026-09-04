# Build and package Vana360

## Prerequisites

Vana360 supports Windows 10 or 11 x64. Install:

- CMake 3.25 or newer
- Ninja
- Python 3.11 or newer
- LLVM/Clang

The Windows presets resolve `clang++` from `PATH`.

The sibling `vana360-sdk` checkout must match [`rexglue-sdk.lock.json`](../rexglue-sdk.lock.json).
Keep legally owned retail inputs on your machine and untracked.

The supported external server source profile is the maintained fork and exact revision
in [`vana360-lsb.lock.json`](../vana360-lsb.lock.json).
The title build does not consume or vendor that server checkout.

## Native tests

The login and protocol tests do not require retail inputs:

```powershell
cmake --preset win-amd64-debug
cmake --build --preset win-amd64-debug
ctest --preset win-amd64-debug
```

## Title generation and build

Verify the supported ISO before extracting content:

```powershell
.\scripts\verify-disc.ps1 -Path <path-to-iso>
```

Restore the extracted runtime beneath ignored `game/`.
[`revana_manifest.toml`](../revana_manifest.toml) declares the five inputs.
Generation reads only those inputs and writes ignored output beneath `generated/`.

```powershell
& ..\vana360-sdk\out\install\win-amd64\bin\rexglue.exe codegen .\revana_manifest.toml
cmake --preset win-amd64-title-release
cmake --build --preset win-amd64-title-release --parallel
ctest --test-dir .\build\win-amd64-title-release --output-on-failure
```

## Package

After the Release build passes, create the deterministic Windows x64 archive:

```powershell
python .\scripts\package.py
```

The archive is written beneath ignored `out/`. Its explicit allowlist contains
only the following package contents:

- the host executable and compiled guest modules
- required ReXGlue runtime libraries
- licenses and the packaged player guide
- `build-info.json`
- an empty `game/` directory

`build-info.json` is copied without recomputing Git state. It records the exact
public title and SDK revisions together with the title worktree's clean or dirty
state. Title configuration separately requires a clean SDK checkout matching
the lock. The record also includes the SDK API, toolchain, backend, and
supported input profile. Retail inputs, DAT files, generated source, logs, and
credentials are never staged.
CI verifies the private runtime inputs separately. Their revision is not written
to the archive.

## Repository check

Run the same public repository check used by GitHub Actions:

```powershell
.\scripts\verify.ps1
```

Repository checks use the root `.clang-format`; CI installs `clang-format` 22.1.8.
This check does not require retail inputs. Full title generation and builds use
the pinned SDK and runtime inputs extracted from your legally owned disc.
