# Phase 4 protocol schema bootstrap

This directory anchors a **standalone, self-contained** validation of the Phase 4
wire-protocol schema. It covers the committed meta (`protocol-schema-meta.v1.json`), the
strict JSON bootstrap parser, and a byte-exact fixture corpus. It is validated on its own
by a dedicated parent validator that launches a bounded child process; nothing here reaches
into the module loader, CI, workflows, evidence, or policy.

## Components

| File | Role |
| --- | --- |
| `certification/schema/protocol-schema-meta.v1.json` | The committed meta grammar (the authority). |
| `certification/lib/Pspkt.Certification.SchemaBootstrap.cs` | Strict JSON reader plus meta / schema-against-meta validator. Compiled by the child only. |
| `certification/lib/Pspkt.Certification.SchemaFixtureContract.ps1` | Shared corpus contract (constants, path grammar, shape / set / hash / length checks). |
| `certification/lib/Pspkt.Certification.BoundedProcess.cs` | Bounded process launcher: Job object, gate event, watchdog, argv quoting, bounded drains. |
| `certification/validators/Test-PspktPhase4Schema.ps1` | The gate-first child harness: helper load, watchdog, contract validation, sealed result. |
| `certification/validators/Invoke-PspktPhase4SchemaValidators.ps1` | The outer validator, contained Worker, and generator bootstrap. |
| `certification/vectors/New-PspktPhase4SchemaVectors.ps1` | The dedicated fixture generator. |
| `certification/vectors/phase4-schema/` | The 68-file fixture corpus (67 fixture inputs + the manifest). |

## Limits

Strict JSON reader (`StrictJsonReader`):

- File bytes: `1048576`. A fixture may be exactly `1048577` bytes to exercise the over-limit case, so the fixture size cap is `1048577` inclusive.
- Depth: `32`. Properties per object: `4096`. Array items: `8192`. String bytes: `262144`. Allocation budget: `2097152`.

Contract file caps: meta `1048576`, manifest `65536`, fixture `1048577` (inclusive). File length is checked before any read.

## Grammar

- Primitives, productions, semantic-string encodings, and grammars are closed sets fixed by the meta.
- `FieldDeclarationList` and `TypeDeclarationList` `maxCount` are structurally pinned to `4096`; `EnumMemberDeclarationList` `maxCount` is pinned to `8192` (`StrictJsonReader.MaxArrayItems`). A mismatch is `invalid-cardinality`.
- Field declarations may omit `profile`/`status` for `Any`/`Required`, or use `InteractiveSeat` / `NonInteractiveElevated` with `Required` / `Forbidden`. Conditional declarations resolve each profile independently; invalid conditions return `invalid-field-condition`.
- `U+FFFD` is forbidden after a valid raw UTF-8 sequence or after `\uFFFD` escape decoding, reported as `replacement-character-forbidden`. Malformed UTF-8 and unpaired surrogates keep their own reasons.
- Meta authority: after every structural check succeeds, the SHA-256 of the raw meta bytes must equal the compiled digest (`BootstrapMetaGrammar.CommittedMetaSha256`), otherwise `meta-authority-mismatch`. Structural reasons always take precedence over the authority check. Both the `bootstrap-meta` stage and the `schema-against-meta` stage share this check.

## Corpus (68 / 16 / 36)

- `68` cases across three stages: `json`, `bootstrap-meta`, `schema-against-meta`.
- Exactly `16` accepted and `52` rejected.
- Exactly `36` closed reason codes; the manifest's unique `expectedReason` set equals them.
- `68` directory files = `67` fixture inputs + the fixture manifest. Exactly one case (the committed meta) points outside the directory.
- The manifest records `byteLength` (int64) and lowercase `sha256` for every case, including the meta.

## Commands

Regenerate and self-test the corpus (writes each file atomically; never deletes stale files, extras fail):

```
pwsh       -File certification/vectors/New-PspktPhase4SchemaVectors.ps1 -SelfTest
powershell -File certification/vectors/New-PspktPhase4SchemaVectors.ps1 -SelfTest
```

Validate the slice directly under the installed Store/MSIX PowerShell 7 host and Windows
PowerShell 5.1 (each must exit `0`):

```
pwsh       -File certification/validators/Invoke-PspktPhase4SchemaValidators.ps1
powershell -File certification/validators/Invoke-PspktPhase4SchemaValidators.ps1
```

The outer validator binds the selected Git index bytes, materializes a private 78-path
snapshot, compiles `BoundedProcess.cs` with the pinned .NET Framework compiler, and loads
the helper from verified bytes. It launches a Job-contained Worker that runs the process,
event, drain, manifest, and schema-child checks. The child compiles the parser, evaluates
all 68 cases, and writes a nonce-bound sealed result. The outer also runs the generator in
contained mode and independently verifies its 68-file digest and hard-link replacement
evidence.

Helper-owned PowerShell processes inherit the caller console. They do not use
`CREATE_NO_WINDOW`; this supports the Store/MSIX `pwsh.exe` used with PowerShell Gallery
module installations without requiring a separate pspkt installer.

## Byte policy

- The meta and manifest are canonical JSON: sorted object keys, integer-only numbers, and no byte-order mark.
- Fixtures are byte-exact test inputs, not uniformly canonical JSON. Rejected fixtures intentionally contain malformed UTF-8, comments, duplicate keys, trailing data, a byte-order mark, NUL, or other forbidden forms.
- The meta, manifest, and every fixture are byte-exact. `.gitattributes` marks them `-text` (no normalization); the parent verifies each worktree file against its selected index object.
- Source and documentation in this slice use LF (`text eol=lf`) with filter, ident, and working-tree-encoding disabled.

## Maintenance sequence

1. **Meta.** Edit `protocol-schema-meta.v1.json`, keeping it canonical JSON.
2. **Pin.** Compute the SHA-256 of the meta bytes and update `BootstrapMetaGrammar.CommittedMetaSha256` in `Pspkt.Certification.SchemaBootstrap.cs`.
3. **Generate.** Run `New-PspktPhase4SchemaVectors.ps1`; it rebuilds every fixture and the manifest and prints the meta digest to pin.
4. **Compiled digest.** Confirm the pinned digest is correct: the committed meta is accepted and every authority tamper is rejected with `meta-authority-mismatch`.
5. **Dual hosts.** Run the parent validator under `pwsh` and `powershell`; both must pass.

## Scope

This bootstrap is intentionally self-contained. It has **no** CI, **no** module-loader
reconciliation, and **no** workflow, evidence, or policy integration. A future broader
certification foundation should delegate to (or remove the duplicated code in) this slice
rather than fork it. The coordinated parser and meta edits in this slice are intended and
mutually consistent.

The user-selected PowerShell host, the already loaded outer validator, and the same-user
outer process are trusted bootstrap authorities. Validation binds all post-bootstrap child
code and data to the selected index snapshot and rechecks the index/worktree state through
cleanup. It does not attest bytes executed before the validator's first statement and does
not resist a malicious outer process or coordinated same-user replacement and restoration.
