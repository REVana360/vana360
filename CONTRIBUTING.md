# Contributing

Vana360 accepts focused changes that improve the ReXGlue title build,
runtime correctness, internal login path, documentation, or supporting analysis tools.
Do not submit:

- copyrighted game files or extracted assets
- generated guest code or build output
- credentials, logs, or private evidence

## Before a change

- Read [`docs/ai_agents/README.md`](docs/ai_agents/README.md)
  for the contribution and evidence policies.
- Follow the repository [style guide](docs/style-guide.md) for authored code,
  build files, tools, configuration, and documentation.
- Base runtime work on the exact dependency commits:
  - SDK: [`rexglue-sdk.lock.json`](rexglue-sdk.lock.json)
  - external server: [`vana360-lsb.lock.json`](vana360-lsb.lock.json)
- Keep sibling SDK and server checkouts read-only
  unless the change is explicitly scoped to their repository.

## Commit subjects

- Use `type: imperative summary`.
- Keep the subject to one ASCII line of 50 characters or fewer,
  including the type.
- Use exactly one space after the colon.
- Do not use a body, parentheses, or trailers.
- Preserve another contributor's credit with Git author metadata
  rather than a commit-message trailer.

Choose one type from this fixed list:

- `title` selected-client structure and title-owned behavior.
- `runtime` compatibility hooks and runtime integration.
- `login` internal login services and protocol handling.
- `build` CMake, code generation, packaging, and build drivers.
- `deps` dependency locks and external component revisions.
- `resources` resource declarations and distributable project data.
- `tools` repository and analysis tooling.
- `docs` documentation and contributor guidance.
- `ci` hosted checks and automation.
- `test` test fixtures and harnesses.
- `chore` repository housekeeping with no single code area.
- `refactor` behavior-preserving changes spanning areas.

Prefer the owning area over the kind of change. `landmark`, `feat`, and `fix`
are not types in this repository.

## Before submitting

Follow [Build and package Vana360](docs/building.md).
It contains the repository check, native-test, and title-build instructions.

## Change boundaries

- Preserve the title's original control flow unless a documented compatibility contract
  requires a hook.
- Keep diagnostics disabled by default and preserve original behavior
  when they are enabled.
- Put each settled public fact in one public guide and link to it elsewhere.
  Keep machine paths, experiments, and private evidence out of tracked files.
- Do not edit generated files directly.
