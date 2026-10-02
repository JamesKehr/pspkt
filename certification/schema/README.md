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

## Protocol declaration inputs and outputs

The protocol authority uses three maintained inputs. Generation reads these committed
snapshots, not the external design documents. Source artifact identities and SHA-256
values, filtered catalog digests, removal ordinals/categories, union mappings, output
digests, and the five nested attribute policies are pinned by
`certification/lib/Pspkt.Certification.ProtocolSchemaContract.ps1`.

| Input | SHA-256 |
| --- | --- |
| `catalog/protocol-base.catalog.v1.json` | `955b1a3042a6bf18eea4339d1a1896199a19ae3ba312ed08ac4bc1304c7bdc82` |
| `catalog/overlay.catalog.v1.json` | `0d28afe037201403c5b05db3600268aea5599ac1221ae657a65287fe588daa79` |
| `protocol-inventory.v1.json` | `d67cb37777eaa5fee07404894b0d1f4a20bf11d4a4c95085bc60e350805f265f` |

The inventory preserves the complete lifecycle source bytes as Base64 and copies its exact six
ordered lifecycle lists. Its parsed lifecycle projection excludes the source's floating-point
summary counters; totals are independently derived from the lists as integers. The original
source digest remains `8718dd1de27850663988c52bdd41a5ca5617c584b9a84f59e6d5a1cdfaa0d496`.
Semantic union labels are provenance, not emitted identifiers. Each emitted branch
identifier is both its enum member and its Named declaration; the OperationRecord
value-18 identifier is `AbortedCompilationDefinitivelyFailedWithLaunchAuthority`.

Only the generator writes the following four canonical UTF-8, no-BOM outputs. They have
sorted object keys, integer numbers, stable array order, and no trailing newline.

| Output | SHA-256 |
| --- | --- |
| `protocol-schema.v1.json` | `6d76911009b64e52417b3ca519d3b3166cfdf675a4d4deede5ab0dce449c9db4` |
| `generated-base-id-map.v1.json` | `66884fb48fcd5ebc3949957c57906614ce3d0d3a6644c6808b1d1796afb45c91` |
| `protocol-message-association.v1.json` | `031bf566279871cd79db696ff436aa6d9383f1bb26a62467c3364880a012c5af` |
| `mandatory-tail-schedule.v1.json` | `9852528ea500edc054a0380afa03f20993ed9aaae876e54025178106b4e50312` |

`protocolSchemaDigest` is the SHA-256 of `protocol-schema.v1.json` only. The association,
map, and schedule are separate pinned projections, not extra schema root properties.

## Protocol counts and exclusions

The base and overlay contain 308 and 434 operations. Exact-reference reverse closure
removes 12 base and 79 overlay operations before the single V2 evaluation, preserving
296 base operations followed by 355 overlay operations. It omits exactly
`MintAttestedV1`, `S4UMintSlotV1`, `ServiceControlEventNodeProofV1`, `IsolationAdmission`,
and `IsolationExit`, plus BrokerControl messages `MintAttested`, `IsolationAdmission`,
`IsolationExit`, and `MintRevoked`. Forward dependencies and the `MintRevokedV1`
declaration remain retained. No IDs are reassigned after V2.

The outputs contain 107 types (90 generated and 17 literal), 53 concrete union branches,
and 681 map rows: 37 type, 507 field, 31 kind, 53 enum-member, and 53 union-branch rows.
The 31 association rows represent 26 channel-qualified message identities; repeated
directions share their kind and payload. WorkerApp and BrokerControl share the identical
`Keepalive` type but use separate `BootstrapHostHello` and `BrokerBootstrapHostHello`
payload declarations. Literal generated-parent extensions use exactly 46 parents and
56 field sets.

The WorkerApp schedule has 842 rows over 421 states in six variants, ordered by variant,
state, then HostToWorker/WorkerToHost. Empty rows are explicit. Ordinary messages,
including Keepalive, never enter the mandatory tail. Certificate maxima are 1,431 and
1,529 bytes; BootstrapWorkerContext maxima are 1,958 and 2,078 bytes for InteractiveSeat
and NonInteractiveElevated respectively. Checked sizing includes TLV headers and list
count/element framing, with depth at most four, 5,535 records, and 29,360,128 wrapper bytes.

BrokerControl/LocalIpc tails, runtime code, services, evidence/signing-ledger schemas,
aggregate matrices, CI/workflows, databases, locks, workers, and recovery remain excluded.
Issue #40 remains deferred. The existing Foundation engine/policy, public V1/V2 API,
bootstrap/meta, 68-case corpus, and normal 1A path set are unchanged.

## Protocol commands

Run from the repository root, using fresh processes:

```powershell
pwsh -NoProfile -File .\certification\vectors\New-PspktPhase4ProtocolSchemaVectors.ps1
pwsh -NoProfile -File .\certification\validators\Invoke-PspktPhase4ProtocolSchemaAuthorityValidators.ps1
powershell -NoProfile -File .\certification\vectors\New-PspktPhase4ProtocolSchemaVectors.ps1
powershell -NoProfile -File .\certification\validators\Invoke-PspktPhase4ProtocolSchemaAuthorityValidators.ps1
```

Generation accepts `-OutputRoot <directory>` for isolated output. Validation accepts the
same parameter to check those four files against the committed inputs and pins. It checks
frozen source and attribute hashes before compilation and input hashes before generation.
Path parameters must resolve to stable absolute FileSystem paths. Device namespaces,
drive-relative paths, final-component DOS device aliases, and normalization-sensitive
names are rejected before child launch.
The child compiles on-disk `SchemaBootstrap.dll`, `FoundationEngine.dll`,
`ProtocolAuthority.dll`, and `ProtocolVerify.dll`; the verifier references SchemaBootstrap
only, never the engine or authority. Verifier references must carry a public-key token or
match the loaded bootstrap assembly identity exactly.

With Pester 5.3.3 through 5.x available in the selected host:

```powershell
Invoke-Pester -Path .\tests\phase4-protocol\pspkt.Phase4ProtocolSchemaAuthority.Tests.ps1
Invoke-Pester -Path .\tests\phase4-protocol\pspkt.ProtocolCatalogEngineV2.Tests.ps1
```

The authority suite also runs both suites together in one fresh Pester process. Its child
excludes the `ProtocolCombined` tag and sets a recursion guard. Compilation probes remain
in fresh child processes, not the main Pester process.

Run the normal 1A validator only from the later reviewed/staged index or a clean scratch
commit, not against an unstaged README change. Long Foundation validation remains a
separate compatible-Git environment check.
