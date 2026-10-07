# Dormant overlay activation package

This self-contained certification slice produces a complete alternative protocol
package. Its presence does not activate it. All six files remain dormant until
selected together as one digest-bound package in 1C. There are no runtime, module,
workflow, or aggregate-runner references to this slice.

The frozen evidence-ledger remains bound to
`certification/schema/protocol-schema.v1.json`, SHA-256
`6d76911009b64e52417b3ca519d3b3166cfdf675a4d4deede5ab0dce449c9db4`,
and continues to defer `ServiceControlEventNodeProofV1`. The same-named schema in
this directory does not replace that binding. Any 1C evidence activation requires
a separate evidence projection/kind contract. This package does not change frozen
protocol or evidence bytes.

## Entry points

Run from the repository root in Windows PowerShell 5.1 or PowerShell 7:

```powershell
.\certification\overlay\validators\Invoke-PspktPhase4OverlayActivationAuthorityValidators.ps1 -Mode Compile
.\certification\overlay\validators\Invoke-PspktPhase4OverlayActivationAuthorityValidators.ps1 -Mode Validate
.\certification\overlay\vectors\New-PspktPhase4OverlayActivationVectors.ps1 -OutputRoot $outputRoot
.\certification\overlay\validators\Invoke-PspktPhase4OverlayActivationAuthorityValidators.ps1 -Mode Validate -OutputRoot $outputRoot
```

`Generate` requires an explicit filesystem output root. Each mode uses a fresh
child process and assembly directory. Pins are checked before compilation.
Validation never writes pinned files. Generation builds and independently checks
the entire output dictionary before creating the output directory, then replaces
each file atomically. Atomicity is per file, not a six-file transaction.

`OverlayBoundedProcess` creates the child suspended and contained at creation
time in an unnamed Windows Job Object. The launch disables Store/MSIX desktop-app
process-tree breakaway, restricts inherited handles to redirected standard
streams, and kills the contained tree if the parent exits. Root exit, descendant
quiescence, stream completion, output size, and cleanup are bounded separately.
PowerShell-managed output is UTF-8 without BOM; uncaptured native output must be
ASCII or valid UTF-8. Creation-time job attributes require Windows 10 version
1703 or later. When Core PowerShell resolves to the Store execution alias,
Windows PowerShell cross-edition tests use a relay that owns the Core worker
job and aborts it if the contained Desktop bridge exits. MSI and ZIP installs
launch directly.

`OverlayActivationContract` is the root of the acyclic pin graph. It pins frozen
inputs, maintained inventory, source files, this README, local attributes,
entry points, and generated outputs. It does not pin itself or the test file.
All pin and output keys are complete repository-relative paths.

## Outputs

All paths below are relative to `certification/overlay/schema/`.

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| `protocol-schema.v1.json` | 72554 | `11cbae40d33c7f8da0c92a4579a003e51df7c7552b5eb9c7e65adada82f88797` |
| `generated-base-id-map.v1.json` | 123173 | `3b812c056bf63afafd540b9c61f72341a689766318c3606dcd8feba4e2a37ca3` |
| `protocol-message-association.v1.json` | 7880 | `f17afa4eab197340d288fe3aea8154d80a696aa98559ef498844c7036b2e73ed` |
| `mandatory-tail-schedule.v1.json` | 492641 | `d25c2997a24048e14c97dfc94c0ab05c8ffc8138d0cbc2d330c8f759760296a2` |
| `overlay-matrices.v1.json` | 35953 | `e10fccf716e4d935d83adb140a716e1eef9575c57277e250cc40647de07a5f13` |
| `overlay-maxima.v1.json` | 1632 | `4d92ec08e2676e7d59d4cf522b3ede33a7e668e2c1fcd4b87ad41e3b8bb7d86c` |

The total is 733833 bytes. JSON uses ordinally sorted keys, invariant unsigned
integer values, UTF-8 without BOM or final newline, and lowercase `\u00xx` control
escapes. Array order is contractual, not sorted by assigned identifier.

## Activation rules

The authority removes base operations 187-198 and inserts the two Isolation
declarations before the original overlay operation 144. `IsolationAdmission`
uses literal type ID 4872; `IsolationExit` uses 4873. Existing declaration IDs
remain unchanged. IDs 4875 and 4876 remain unassigned; 4881 remains illegal.
The assignment map preserves raw activated catalog ordinals.

Only the two noninteractive lifecycle variants gain `TokenMintAuthorizedSent`,
at index 31 after `TokenMintAuthorized`. Mandatory messages associated with
`None` remain applicable through the last matching state. Broker and Local
channels have only noninteractive schedule cells. `S4UMintSlotV1` is a standalone
numeric wire-state with no message binding or invented U8/U16 enum domains.

The maintained inventory records source identities, engine parameters, exact
rehome shapes, derived lifecycle lists, association and matrix tables, sizes,
counts, and the closed twelve-case mutation table. Inventory validation and
the compiled verifier independently enforce stable-ID and rehome constants.
The verifier does not reference or invoke the authority or catalog engine.
Payload sizes use independent BigInteger calculations with UInt32 bounds.

## Tests

Import one explicit Pester manifest with version at least 5.3.3 and below 6,
then run `tests\phase4-overlay\pspkt.Phase4OverlayActivationAuthority.Tests.ps1`
with the `Precheck` tag. The suite contains exactly sixteen tests. One test
contains the twelve mutation cases; the atomic-replacement test separately
injects deterministic replacement failures.

The `OverlayCombined` test performs fresh discovery and sequential combined runs
under both hosts. Combined runs select exactly four containers and require 102
tests, 99 passes, and only the three static recursion skips. The child sets
`PSPKT_PROTOCOL_COMBINED_CHILD`, `PSPKT_EVIDENCE_LEDGER_COMBINED_CHILD`, and
`PSPKT_OVERLAY_COMBINED_CHILD` to `1`. Eight rejection probes demonstrate that
discovery failures, setup failures, skips, and exclusions cannot produce an
accepted combined result.
