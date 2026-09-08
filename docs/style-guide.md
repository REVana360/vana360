# Style guide

This guide covers authored title code, build files, repository tools,
configuration, and documentation. It complements the
[contribution contract](../CONTRIBUTING.md). Style does not establish runtime
behavior, packet semantics, guest addresses, identifiers, or static data.

## General

- Prefer existing local patterns once they exist.
- Keep changes scoped to the subsystem being maintained.
- Prefer a direct implementation before introducing a shared abstraction.
- Edit the inputs to generated code. Do not reformat generated guest code,
  installed SDK files, third-party code, or private runtime inputs.
- Treat guest addresses, register lists, field offsets, IDs, lookup tables, and
  tuning values as behavior rather than style.

The [comment and public prose policy](ai_agents/comments-and-prose.md) owns
comments and authored documentation. The
[evidence policy](ai_agents/evidence-and-claims.md) owns behavioral claims and
provenance.

## C++

### Language and structure

- Use C++23.
- Prefer standard library types and algorithms when they clarify ownership or
  intent.
- Use `const` where it improves correctness or documents intent.
- Avoid exceptions for normal control flow. Do not allow exceptions to escape
  a guest or external ABI boundary.
- Prefer explicit types when `auto` would hide ownership, width, signedness, or
  an iterator/value distinction.
- Keep login code in `src/login`, runtime integration in `src/runtime`, and the
  application host in `src` until a more specific module is justified.

### Formatting

Use [`.clang-format`](../.clang-format) with clang-format 22 for mechanical
formatting. Keep this guide and the configuration consistent when changing a
style choice. `Standard: Latest` in the formatter does not change the C++23
language level selected by [CMakeLists.txt](../CMakeLists.txt).

- Use Allman braces, four spaces, and no tabs.
- Brace control-flow bodies and put one statement on each line.
- Use `Type* pointer`, `const Type* pointer`, and `Type& reference`.
- Keep include sorting and declaration spacing under formatter control.
- Prefer early returns when they make error handling flatter and clearer.
- There is no fixed column limit. Break long declarations and calls at
  meaningful boundaries.

```cpp
if (!IsReady())
{
    return false;
}
```

### Names and headers

- Use `lower_snake_case` filenames.
- Use `UpperCamelCase` for types and namespaced functions.
- Use `lower_snake_case` for variables and parameters, a trailing underscore
  for private class data members, and `kUpperCamelCase` for constants and
  scoped enum values.
- Put reusable internal C++ in the `revana` namespace and its feature
  namespaces.
- Preserve `Revana` global entry-point names and other names required by guest,
  generated, SDK, serialized, or platform interfaces. This includes global
  application types required by the SDK.
- Use `#pragma once`, include a header's direct dependencies, and keep public
  headers small.

### Casts, ownership, and errors

- Use `static_cast` for safe, intentional value conversions and `dynamic_cast`
  for checked downcasts of polymorphic C++ objects.
- Avoid C-style casts. Preserve boundary-specific guest address and platform
  function-pointer conversions.
- Prefer explicit ownership and standard library value types in host code.
- Use fixed-width integer types where width or signedness is part of a protocol,
  ABI, or guest layout.
- Validate foreign inputs before reading or copying them. Preserve documented
  error ordering, output clearing, fallback behavior, and registration order.

### Tests

- Add CTest coverage for behavior that can regress.
- Keep tests narrow and fast when they do not require retail inputs.
- Prefer tests at protocol and subsystem boundaries over copies of the
  implementation.

## Build files, tools, and data

The root [`.editorconfig`](../.editorconfig) defines text-file indentation,
line endings, final newlines, and trailing-whitespace handling.

- Name title-owned CMake targets and built executables in `lower_snake_case`.
  Preserve generated module target names. Keep changes target-scoped rather
  than adding global flags for one feature.
- Python uses four spaces, `snake_case` functions and variables, and
  `UPPER_SNAKE_CASE` constants. Keep imports explicit.
- PowerShell uses four spaces, established Verb-Noun helper names, strict error
  handling, and literal-path operations where paths may contain user input.
- JSON and YAML use two spaces. Preserve JSON and TOML keys, schemas, source
  locators, encodings, and meaningful record order.
- All tracked text must remain ASCII, as enforced by the repository check.

## Verification

From the repository root, run:

```powershell
.\scripts\verify.ps1
```

The check validates tracked-file hygiene, configuration syntax, Python tests,
PowerShell parsing, Markdown links, manifests, dependency locks, and
clang-format 22. Follow [Build and package Vana360](building.md) for native
CTest and title-build commands when a change affects those boundaries. Always
run `git diff --check` and inspect the complete diff before committing.
