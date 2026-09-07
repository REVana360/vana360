# Comments and prose

Deletion is the default for comments in host code and driver scripts.
Keep a comment only when it records a current invariant,
a guest or host ABI contract, a client quirk, a safety constraint,
a source citation, or the source of a manually placed value.

Keep source attributions and packet, DAT, wiki, and other source locators
verbatim. They provide provenance.

Prefer a surviving comment of one to three lines at the use site. Clarity,
correctness, source quotations, licensing, and provenance may require more
context. Move a longer contract to a declaration or technical guide and leave
a short pointer.
Remove temporary work-log details.
Keep dates or identifiers when they provide provenance.

Treat generated comments as generated output.
Preserve them, or update their owning generator and regenerate.
Do not edit generated PPC, switch-table,
ReXGlue output, or progress files during a prose pass.

Runtime strings, command help, manifest fields, workflow data, and self-test labels
are behavior or data. Do not rewrite them as if they were comments.

## Authored public prose

Public prose includes every tracked Markdown file, regardless of its directory.
Use a plain, direct register.

- Wrap prose at natural phrase boundaries.
- Use bullets for collections of links or items.
- Avoid over-hyphenation. Keep hyphens in established technical terms.
  Prefer ordinary noun phrases to invented compound modifiers or long chains.
- Use semicolons sparingly. Prefer a period, comma, or short list
  unless a semicolon makes two closely related clauses materially clearer.
- Remove parenthetical asides. Make important context a short sentence.
  Delete the rest.
- Use short declarative sentences with one idea each.
  Give a rule one line of practical justification.
- Avoid slang. Name the actual hazard or dependency.
- Do not publish prompts, assignments, work-session plans,
  handoff notes, or self-review metadata.
- Use words such as lane, gate, phase, wave, and handoff only for literal
  technical concepts, not internal workflow labels.

Internal working notes are not public documentation.
