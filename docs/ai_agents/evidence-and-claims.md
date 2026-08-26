# Evidence and claims

This repository records behavior recovered from an owner-supplied title image and the ReXGlue runtime.
The title image, extracted assets, generated guest code, traces, and private analysis files are never committed.

## What counts as evidence

Static guest code evidence records:

- a durable address or symbol
- the tool or generated artifact used
- the observation
- any unresolved ambiguity

Runtime evidence records the build, command, observable result, and boundary
tested.

The tool is an instrument, not the authority.
Decompiled types, inferred names, and generated control flow remain interpretations
until supported by the guest instructions, data, or an independent runtime observation.
A green build proves compilation, not title behavior.

Repository code, tests, manifests, and validation results establish repository
contracts. Agent output, summaries, and uncited notes are leads, not evidence.

## Claim boundary

Make the narrowest claim supported by the cited observation.
Keep static evidence separate from runtime evidence.
Do not use a successful code generation step as a runtime claim.
A forced transition does not prove the title's natural path.

Preserve placeholder names when the evidence does not establish a stable identity.
Record conflicts instead of merging candidates into one assertion.
Hand-placed coordinates, tuning constants, and conspicuously round values
are deliberate until evidence proves otherwise.

## Public documentation

Tracked public documentation contains settled conclusions and reproducible methods.
It excludes retail inputs, generated guest code, machine paths, branch status,
temporary work notes, session logs, private title material, and private analysis data.
Each public claim must carry enough context to be reviewed without access to those materials.

Structured data contains evidence and current conclusions, not prompts,
assignments, review status, or implementation plans. Use stable identifiers
derived from the artifact or subject. Do not use internal labels such as
`lane1`, `followup`, or milestone status codes.

Tests assert semantic contracts and observable results. They do not encode
planning status or review conclusions.

Preserve source, reference, permission, and provenance citations verbatim,
including dates embedded in external citations.

## Numbers in prose

Keep a number when it carries the claim: an address, offset, size, hash, version pin,
tuning constant, exact tool result, or coverage result.
Remove incidental counts whose omission does not change the sentence's meaning.
