# Evidence runtime conformance capsule

The public validation entrypoint accepts only the complete pipeline described
below. Targeted development tests are not a successful validation result.
Local validation does not substitute for the required published workflow's
four-call aggregate and verified raw-failure probe outcomes.

This capsule is separate from the product module. It is compatible with Windows
PowerShell 5.1, PowerShell 7, and C# 5. It validates canonical evidence structure
and content digests. It does not authenticate evidence, resolve references,
verify signatures, enroll keys, run services, mint tokens, launch candidates,
or claim F-7/F-8/F-9 lifecycle certification.

## Public surface

Exactly two sealed classes are exported from the separately built runtime:

- `Pspkt.Certification.EvidenceRuntime.EvidenceArtifactEnvelopeCodec`
- `Pspkt.Certification.EvidenceRuntime.DecodedEvidenceArtifactEnvelope`

`CreateFromCommittedAuthorities(byte[], byte[], byte[], byte[])` accepts meta,
protocol inventory, evidence schema, and evidence inventory bytes in that order.
`Decode(byte[])` returns a decoded envelope.
`Encode(UInt16, Guid, Byte, byte[])` validates the payload before encoding.
`GetDeclaredSignatureCoveredBytes(byte[])` fully decodes first and returns only
the declared evidence signature preimage. Other kinds raise NotSupportedException.

The envelope exposes getter-only Kind, ArtifactId, Profile, CanonicalPayload,
PayloadDigest, and UncheckedSemantics. Byte and string arrays are defensive
copies. There are no public constructors or descriptor types.

The sole advanced-script/function entrypoint is
`Invoke-PspktPhase4EvidenceRuntimeValidators`. All three parameters are required,
nonempty strings, named-only, without aliases or pipeline binding:

| Parameter | Type |
|---|---|
| RepositoryRoot | System.String |
| WorkRoot | System.String |
| PesterManifestPath | System.String |

There is no operation selector or partial-validation bypass. Every successful
invocation must run the entire pipeline exactly once in a fresh host.
Missing required arguments are tested through metadata, never by prompting.

The independent maintenance script `New-PspktPhase4EvidenceRuntimeVectors.ps1`
takes only RepositoryRoot and OutputRoot. It requires an empty destination,
uses the four frozen authority documents, and never loads the runtime or reads
the protected hand-authored goldens. Validation never runs the generator.

## Authority stages

All four length/hash pins are checked before decoding or gating. Inventories
are ordinary retained JSON, not canonicalized JSON or schema documents.

| Input | Stage | Meta |
|---|---|---|
| meta | bootstrap-meta | null |
| evidenceSchema | schema-against-meta | meta |
| evidenceInventory | json | null |
| protocolInventory | json | null |

Frozen Bootstrap is compiled separately and only its public Evaluate gates are
used. Runtime code has its own private admitted-JSON projection reader. No
Bootstrap implementation is included in the runtime assembly.

Only evidence rules and used primitiveValueMaxima are projected. Ledger profile,
record, Merkle, signing-ledger execution, protocol payload budgets, dormant
authority, product, overlay and live trusted-control inputs are excluded.

## Binary and signature contract

Profiles are 1=InteractiveSeat and 2=NonInteractiveElevated. Kinds are the
22 EvidenceArtifactKind values, not schema declaration IDs.
TLV headers are U16BE tag and U32BE value length. BoundedBytes also has an inner
U32BE length. Fields are exact, ordered, required or forbidden by profile.
Nested profile fields must equal the envelope profile.

Payload cap is 262143 bytes; envelope cap is 262228 bytes. Kind/profile bounds
are computed with BigInteger from evidence fields. Length checks precede
length-directed field allocation. GUID bytes use RFC/network order, SID bytes
retain Windows order, and integer/LUID values retain big-endian order.
AsciiIdentifier is 1-128 non-NUL seven-bit bytes, not a path or declaration name.
RSA public blobs/signatures have only structural 512/384-byte width checks.

Hk is SHA-256 of ASCII(exact evidence domain), NUL, and all payload TLVs.
It includes the signature TLV and excludes outer metadata.
For kinds 16, 17 and 20 only, Sk is ASCII(domain), NUL, and payload fields 1-9.
The whole field-10 signature TLV, including its header, is excluded.
The declared signature algorithm is RSASSA-PKCS1-v1_5/SHA-256 with a 3072-bit
modulus and exponent from the trusted key binding. No key/exponent lookup or
RSA/signature authentication is performed. Copied protocol signatures have no
invented evidence coverage.

Inner payloadDigest fields are producer subjects, never the envelope
payloadDigest. terminalRecordDigest and successorRecordDigest refer to ledger
recordDigest. burnReceiptDigest and authorizationDigest refer to the specified
evidence envelope payloadDigest. No reference is looked up, repaired or verified.

ArtifactId is unbound. Profile is unauthenticated; on profile-independent kinds
its value is also unbound. Changing such outer metadata does not change Hk.

## Unchecked token vocabulary

| Code | Token |
|---|---|
| A | evidence-authenticity-unchecked |
| B | artifact-id-unbound |
| C | profile-authentication-unchecked |
| D | profile-value-unbound |
| E | signature-authentication-unchecked |
| F | signature-key-binding-unchecked |
| G | subject-digest-unchecked |
| H | copied-protocol-digests-unchecked |
| I | cross-envelope-references-unchecked |
| J | freshness-unchecked |
| K | ledger-record-references-unchecked |
| L | schema-bindings-unchecked |
| M | producer-digests-unchecked |

## Ordered kind token lists

| Kind | Codes |
|---|---|
| 0 | ABCEFHJ |
| 1 | ABCHJ |
| 2 | ABCDEFHJ |
| 3 | ABCHJ |
| 4 | ABCHJ |
| 5 | ABCHJ |
| 6 | ABCDHJ |
| 7 | ABCDHJ |
| 8 | ABCDHJ |
| 9 | ABCDHJ |
| 10 | ABCDHJ |
| 11 | ABCDHJ |
| 12 | ABCDHJ |
| 13 | ABCHJ |
| 14 | ABCHJ |
| 15 | ABCEFHJ |
| 16 | ABCDEFGJL |
| 17 | ABCDEFGJL |
| 18 | ABCDJKM |
| 19 | ABCDJM |
| 20 | ABCDEFIJM |
| 21 | ABCDIJKM |

## Non-envelope digest categories

| Kind | Bindings in field order |
|---|---|
| 16 | protocolSchemaDigest:L,evidenceSchemaDigest:L,payloadDigest:G,observerKeyId:F |
| 17 | protocolSchemaDigest:L,evidenceSchemaDigest:L,payloadDigest:G,observerKeyId:F |
| 18 | canonicalSemanticDigest:M,terminalRecordDigest:K,burnReasonDigest:M,observerProofDigest:M |
| 19 | canonicalSemanticDigest:M,successorRunIntentDigest:M,deferralReasonDigest:M |
| 20 | burnReceiptDigest:I,burnedSemanticDigest:M,successorRunIntentDigest:M,authorityKeyId:F |
| 21 | authorizationDigest:I,successorRecordDigest:K,observerProofDigest:M |

## Retained test container

Tests intentionally live in this capsule rather than generic `tests` discovery.
They require exact retained bytes, isolated assembly identities, nine caller
Data values, disabled registry plugins and a fixed 32-case population.
Generic discovery can include excluded authority or conflicting AppDomain types.

Pester 5.3.3 is required. The exact configuration has one caller-bound ScriptBlock
container, no Run.Path, PassThru=true, Exit=false, Throw=false, Precheck tag,
no exclusions or FullName filters, TestDrive=true, TestRegistry=false,
TestResult=false and CodeCoverage=false. Retained original test text is enclosed
in `{` LF and LF `}` without rewriting or reopening it. Both byte identities
are admitted. The literal block is bound in the plain caller's scope before
New-PesterContainer; no module or private resolver manipulation is used.

Data keys are BootstrapAssembly, RuntimeAssembly, AuthorityBytesById,
FixtureBytesById, ManifestRecordsByRole, CompileCensus, MutantBuilds,
ArtifactRoot and CallerScopeMarker. BeforeAll and It must see those exact
objects and a null SessionState.Module. There is no TestRegistry drive or
visible/global TestRegistry variable. HKCU\Software\Pester is never inspected,
created, changed or cleaned.

The caller-scope provenance marker uses a stable domain prefix followed by the
invocation's 32 hexadecimal run-ID digits:

| Provenance marker | Prefix |
| --- | --- |
| CallerScopeMarker | pspkt-evidence-validation: |

Exactly these 32 case IDs run once, with fixture loops inside each case:

| Case | Intent |
|---|---|
| manifest-shape | Rejects undeclared or malformed manifest and result contracts |
| forbidden-inputs | Excludes unadmitted dependencies from every input route |
| authority-gates | Admits only exact authority bytes through their four declared gates |
| public-surface | Exposes exactly two runtime types and three named validation parameters |
| rejection-boundaries | Rejects stale identities and repeated or unsupported invocations before work |
| hand-golden | Matches the independently authored burn receipt bytes and fields |
| tlv-order-and-presence | Rejects malformed field ordering and presence |
| length-boundaries | Rejects inconsistent and excessive lengths before allocation |
| evidence-maxima | Enforces only the exact evidence payload and envelope bounds |
| primitive-representations | Preserves canonical primitive byte representations |
| profile-fields | Resolves conditional fields and nested profiles exactly |
| kind-coverage | Processes all twenty two kinds under both evidence profiles |
| domain-separation | Rejects incorrect digest domains separators and substitutions |
| signature-coverage | Returns exactly the three declared evidence signature preimages |
| signature-mutation | Distinguishes signature bytes from preceding signature covered fields |
| copied-signature-exclusion | Never invents coverage or authentication for copied signatures |
| digest-category-coverage | Classifies every non envelope digest without conflating references |
| unchecked-claims | Preserves unchecked claims without resolving or authenticating them |
| outer-metadata | Keeps outer artifact and profile metadata explicitly unauthenticated |
| encoder-validation | Rejects malformed payloads before encoding an envelope |
| token-document-parity | Matches all documented tokens and categories with defensive copies |
| immutable-state | Preserves immutable state through rejection and interleaved calls |
| compiler-load-contract | Binds retained C sharp five sources and admitted dependency identities |
| caller-bound-tests | Runs retained tests in caller scope with all nine data identities |
| independent-generator | Keeps generated vectors and protected goldens independent of production |
| initialized-mutants | Kills three distinct initialized mutants with independent oracles |
| complete-census | Rejects incomplete per call and aggregate evidence counts |
| corpus-and-export-integrity | Rejects incomplete corpus discovery configuration or export evidence |
| workflow-invocations | Requires exact isolated workflow invocations and fail closed receipts |
| registry-and-cleanup | Requires registry absence and complete owned resource cleanup |
| source-and-stale-audit | Separates admitted sources from outputs and rejects obsolete surfaces |
| failure-propagation | Rejects every failed malformed missing duplicated or incomplete result |

## Required acceptance

| Measurement | Required |
|---|---|
| CompilationCount | 5 |
| LoadCount | 5 |
| InitializedMutantKillCount | 3 |
| ContainerCount | 1 |
| TotalCount | 32 |
| SelectedCount | 32 |
| ExecutedCount | 32 |
| PassedCount | 32 |
| FailedCount | 0 |
| SkippedCount | 0 |
| NotRunCount | 0 |
| FailedBlocksCount | 0 |
| FailedContainersCount | 0 |

Build/load roles are exactly Bootstrap, Runtime, M1, M2, M3. Runtime and mutants
each use the seven retained source strings. Desktop uses CodeDom C#5 and
LoadFrom; Core uses selected Roslyn C#5 syntax trees and the default load
context's LoadFromAssemblyPath. Assemblies are invoked through retained
Assembly objects. Reference keys are selected simple names and public key
tokens, with recorded culture/version, not mutable cross-release version guesses.

The three distinct initialized mutants reverse the U32 writer, omit Hk's NUL,
and include the signature TLV in Sk. Actual independent oracle failures are
required; a compilation, load or factory failure is not a mutant kill.

Only a single closed ValidationSucceeded result may succeed. Missing, multiple,
malformed, failed, count-mismatched or cleanup-incomplete results must terminate
the wrapper and workflow step. A valid ValidationFailed diagnostic may be emitted
once only with a terminating error. Success is emitted only after cleanup.
Status values, test identities and source membership use ordinal comparisons.
Test identities are checked individually with exact cardinality, not as a joined
string. Receipt JSON rejects duplicate property names before materialization;
raw workflow outcomes must be strings rather than Boolean or numeric substitutes.

Required success fields:
`SchemaId,SchemaVersion,Outcome,RunId,BaseCommit,HostEdition,HostVersion,PesterVersion,RepositoryRoot,WorkRoot,RunRoot,SourceManifestSha256,CompilationCount,LoadCount,InitializedMutantKillCount,CompilationRecords,LoadRecords,MutantResults,Pester,Gates,Cleanup`.

The dedicated workflow requires literal powershell and pwsh jobs, each with
fresh-host checkout and actual no-.git exported-source invocations. A third
aggregate job requires four successful bound calls, totals 20 builds, 20 loads,
12 initialized kills and 128 passed tests, plus ten verified raw-failure
result-boundary probes. Returned diagnostics alone never make a step green.

Each step forwards a copy of the admission census from the same compilation,
load and mutant records used to construct the returned result. This is a
consistency comparison, not an independently captured measurement. The aggregate
independently reconstructs fixed counts, test identities,
source hashes, and run-derived assembly identities/paths from the reviewed
contract. A returned object cannot supply its own expected counts.

The success `Gates` flags are completion assertions assigned only after the
validation and cleanup sequence completes, not separately measured booleans.
Acceptance still requires every flag to be true alongside the exact observed
counts, Pester outcome, role identities, source pins and mutant results. Failed
checks or cleanup throw before success is constructed. Cleanup flags similarly
report the completed cleanup obligations; they are not an independent observer.

After parameter binding, script entry atomically claims the one-shot host marker
before any preflight or source admission. A failed preflight consumes that host;
retry in a fresh process. Binding errors occur before the script body and do not
claim the marker. The `rejection-boundaries` regression executes an actual failed
preflight and rejected retry in one in-process runspace using a unique test marker,
without resetting the live
validation marker or adding a compilation/load.

Failure diagnostics traverse at most 64 exception nodes and emit an ordinally
sorted list of at most 16 inner messages, 32 failed Pester ExpandedPath values,
and one truncation indication. Each line is at most 256 printable ASCII
characters. Exact static messages from retained admitted implementation source
and exact pinned test paths are emitted. A closed category is preserved only
when the failure actually emits that prefix, even before the full message
allowlist exists. No setup/validate category is inferred from the operation stage.
Registration of those names does not establish an emitting or reachable failure
path. Unmatched uncategorized workflow literals use the generic redacted
diagnostic, including unprefixed literals presented from otherwise unreachable
pinned-input paths. If the formatter itself is unavailable, the separate neutral
workflow-step-failed fallback remains in effect.

| Diagnostic case | Behavior |
| --- | --- |
| Emitted closed category | Preserve the category; redact unsafe variable text. |
| Unmatched uncategorized literal | Generic redacted diagnostic; no category inferred. |
| Registered but un-emitted category | No runtime emission or reachability claim. |

These rows are mechanically checked against the validator's diagnostic contract.
Unsafe variable text becomes `Category: Variable details redacted.`; unknown
categories receive the generic redacted diagnostic.
The only variable suffixes retained are an exact relative path in the fixed
74-path source manifest (1 through 128 permitted ASCII path characters) in the
source-pin or source-length message templates, or an exact M1, M2 or M3 role in the mutant-survived
template. Traversal, aliases, extra text, control characters, unknown paths/roles
and oversized messages are not passed through. Arbitrary toolchain, OS or caller
text is suppressed rather than echoed.
Dynamic Pester count diagnostics use the closed count-name set. The validator
throws a sanitized aggregate and both it and workflow catches print the bounded
list to stderr, never a success object. Unknown failures remain red.

Pinned file lengths are checked against the opened stream before allocating the
source byte buffer or reading source bytes. A mismatch emits
`source-length: Retained byte length differs for <fixed manifest path>.`
The same path template and ordinal membership rules protect both source-length
and source-pin diagnostics; absolute or arbitrary paths are never substituted.
Preloaded pinned bytes are length-checked before hashing or cloning.

## Workflow supply and retry contract

All three checkout steps pin `actions/checkout` v7.0.1 to immutable commit
`3d3c42e5aac5ba805825da76410c181273ba90b1`, not a floating tag.
The [official stable release](https://github.com/actions/checkout/releases/tag/v7.0.1)
and its tag resolve to this commit. The
[immutable action.yml](https://github.com/actions/checkout/blob/3d3c42e5aac5ba805825da76410c181273ba90b1/action.yml)
declares `runs.using: node24`; the
[package manifest](https://github.com/actions/checkout/blob/3d3c42e5aac5ba805825da76410c181273ba90b1/package.json)
declares version `7.0.1` and Node.js `>=24`.

| Checkout provenance | Value |
| --- | --- |
| CheckoutRepository | actions/checkout |
| CheckoutReleaseTag | v7.0.1 |
| CheckoutVersion | 7.0.1 |
| CheckoutCommitSha | 3d3c42e5aac5ba805825da76410c181273ba90b1 |
| CheckoutRuntime | node24 |
| CheckoutMinimumRunnerVersion | 2.327.1 |
| CheckoutReleaseId | 356804776 |
| CheckoutPublishedUtc | 2026-07-20T15:10:05Z |
| CheckoutActionManifestBlob | 5b0524f730db83f9513c18ab31a6c086c7239076 |
| CheckoutActionManifestBytes | 5144 |
| CheckoutActionManifestSha256 | d59219cb79590abdb877deaa14e3b65a00c05318bf5a6f3b989b9162b5d08c35 |

The [published Node24 minimum](https://github.com/actions/checkout/blob/3d3c42e5aac5ba805825da76410c181273ba90b1/README.md)
is Actions Runner 2.327.1; the verified runner 2.338.0 satisfies it.
These Windows-hosted jobs use default self-checkout, no container action and
`persist-credentials: false`. No explicit repository/ref or unsafe pull-request
override is added. Static tests pin all three uses and these source-verified
provenance rows without fetching remote authority during conformance validation.
The local shell-step rehearsal does not execute the hosted checkout action.

CI always downloads Pester,
checks its package bytes before extraction, and never substitutes an installed
module based only on version. Network, length or digest failure fails closed.
Setup failures emit one closed `pester-setup` subreason: source-load,
source-admission, temporary-storage, tls, download, package-length, package-hash,
compression-load, archive-extract, manifest or publish. The subreason identifies
the operation being attempted, not an inferred exception cause. Unknown stage
values produce only unknown-stage. Messages are fixed printable ASCII, bounded
to 256 characters, and never contain exception text, URLs, paths or secrets.
If the contract cannot be loaded, source-load is the fixed fallback.

| Package | Bytes | SHA-256 |
| --- | --- | --- |
| Pester 5.3.3 | 271297 | bf450611b92dee8de7dd5e69809d5b37f86bff9f8f3b6eb3129d2fbdd889b579 |

The package was verified against the Gallery's published SHA-512 value
`EfhT3U70y4s/HnNhSfSXNdfE+tAib8Rdq+O83iscGwbWIDXaPzq4czZ8yOzUbe2OhVzTI3Nk8bHwRnkopoXDjA==`.
The host/edition table and probe-reason table each have one retained implementation
source; test expectations remain independent.

Probe confirmation and aggregate jobs use `!cancelled()`: ordinary failures still
run the fail-closed checks, while cancellation does not trigger meaningless
aggregation. **Rerun the whole workflow**, not only failed jobs. Every receipt is
bound to `GITHUB_RUN_ATTEMPT`; mixing retained successful-job receipts from an
earlier attempt with rerun jobs is deliberately rejected. The
`workflow-invocations` tests cover rejection of mixed/stale attempts and acceptance
of a complete new-attempt receipt set.
Synthetic receipt paths deliberately use a drive absent from the current
PowerShell session. Fixture construction and aggregate path checks use
provider-independent `System.IO.Path.Combine`; they never require that drive to
exist. This prevents a development-machine drive from masking a hosted-runner
test failure. Discovery, selection, execution and passing counts remain exactly
32 per successful call.
The aggregate initializes its contract diagnostic formatter and allowlist before
checking dependency-job outcomes. A failed dependency reports the fixed
workflow-dependency reason for that host. If diagnostic initialization itself is
unavailable, the fallback only states that the workflow step failed; it does not
invent a formatter or dependency cause.

## Custody and cleanup

Exact retained byte lengths/hashes are authority. Pinned root/ancestor/capsule
byte-policy files are inputs, not effective machine/global/info attributes.
Normalization drift fails pins. No Git process or repository metadata is needed.
The exact source set excludes overlay and deferred/live authority material.
Source-manifest identity is SHA-256 over UTF-8 rows in SourceExportPaths order:
role, NUL, path, NUL, invariant-decimal byte length, NUL, lowercase SHA-256, LF.
The reviewed contract root is retained and represented without a circular
self-pin; every subordinate file has a literal length/hash pin.

The local operator/toolchain/filesystem and authenticated local principals are
trusted. There is no hostile-local-principal or ancestor-ACL isolation claim.
The DLL close-to-load interval is therefore not treated as a hostile-writer
boundary. No additional DLL read lock is introduced. Image length/hash/identity
are admitted before load, loaded identities/paths/references are checked, and
declared residual images are rehashed at the end. That final rehash detects
persistent changes, not a hostile transient replacement followed by restoration.
After load, Bootstrap exports must be exactly `Pspkt.Certification.SchemaBootstrap`
and `Pspkt.Certification.SchemaCheckResult`, separately from the runtime's two
public types.
An absolute fixed-volume WorkRoot has a fresh unpredictable child, no reparse
points or preexisting entries, exclusive CreateNew outputs and exact containment.
The normalized absolute **WorkRoot maximum length is 100 characters** (using
`System.String.Length`). A trailing
directory separator is removed before measuring, except for the volume root.
This preserves the existing Desktop-safe run/image budget; 100 is accepted by
the length gate and 101 is rejected. All other existence, overlap and custody
requirements still apply.

| Operator limit | Characters |
| --- | --- |
| WorkRootMaximumLength | 100 |

The validator mechanically checks this row against its retained contract constant.
WorkRoot must not equal, contain or lie under the repository/original checkout.
Directory overlap uses boundary-aware, case-insensitive equality or ancestry.

Operator roots remain under the approved Q: session root. CI uses an absolute
RUNNER_TEMP root outside GITHUB_WORKSPACE and exported sources. TEMP/TMP and
physical TestDrive stay beneath the owned run child and are restored/cleaned.
Owned streams and compiler byproducts are closed and inventoried. Potentially
mapped images are explicitly retained until host exit, not falsely unloaded.
Unexpected residue or failed restoration prevents a successful result.

No credentials, private keys, secrets, token handles or live authority are
persisted. These checks do not complete any deferred trusted-control obligation.
