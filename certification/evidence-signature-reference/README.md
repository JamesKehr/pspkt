# Evidence signature and reference certification

This standalone, source-only capsule checks declared evidence signatures and two
typed cross-envelope references. It does not import the pspkt module, open a
capture, use a live key registry, or require elevation. Windows PowerShell 5.1
and supported Windows PowerShell 7 hosts compile the retained C# sources in
fresh processes.

## Conditional facts, not evidence authenticity

A successful assessment says that all admitted inputs passed the exact
structural, signature, caller-key eligibility, schema-byte and reference checks
described here. It is not enrollment, machine identity, producer truth,
freshness, replay protection, ledger-state validation, lifecycle certification,
or an authenticity verdict for the entire evidence set.

The caller supplies an independently pinned synthetic or operational key
snapshot, a ledger identity, a host-inventory policy digest, and an explicit
UInt64 evaluation time. The capsule cannot establish the provenance or
correctness of those caller choices. Its committed fixture keys are synthetic,
non-enrolled public keys and must not be used as operational trust roots.

The new contract script is a reviewed, deliberately unpinned local source root.
Its own retained hash contributes to invocation/export consistency, not to an
independent claim of its authenticity. Its subordinate pins and all frozen
inputs must match exactly.

## Public C# API

Namespace: `Pspkt.Certification.EvidenceSignatureReference`.

All five public types are sealed. Constructors are nonpublic; properties are
getter-only; every public array getter returns a copy.

- `EvidenceSetChecker.CreateFromCommittedAuthorities(byte[], byte[], byte[],
  byte[], byte[], byte[], byte[], byte[], byte[])` takes, in order, the protocol
  meta, protocol inventory, evidence schema, evidence inventory, protocol
  schema, trusted-control authority, trust-roots schema, capsule snapshot
  descriptor, and capsule signature/reference policy.
- `EvidenceSetChecker.AdmitKeyBindings(byte[] canonicalKeyBindingBytes,
  byte[] expectedKeyBindingSha256, ulong evaluationTime,
  Guid expectedLedgerIdentity, byte[] expectedHostInventoryPolicyDigest)`
  returns a context-bound `EvidenceKeyBindingSnapshot`.
- `EvidenceSetChecker.CheckSet(byte[][] envelopeBytes,
  EvidenceKeyBindingSnapshot keyBindings)` returns one
  `EvidenceSetAssessment`, or throws a closed failure without returning partial
  artifacts or edges.

`EvidenceKeyBindingSnapshot` exposes `SnapshotSha256`, `EvaluationTime`,
`LedgerIdentity`, `HostInventoryPolicyDigest`, and `KeyCount`.

`EvidenceSetAssessment` exposes `KeyBindings`, `PolicySha256`, `Artifacts`,
`References`, and `UncheckedSemantics`.

`EvidenceArtifactVerification` exposes `InputIndex`, `Kind`, `ArtifactId`,
`Profile`, `PayloadDigest`, `VerifiedKeyId`, `VerifiedClaims`, and
`UncheckedSemantics`. `VerifiedKeyId` is empty for unsigned/copied-signature
kinds, never a failed-signature result.

`EvidenceReferenceResolution` exposes `SourceInputIndex`, `SourceKind`,
`SourceFieldId`, `ReferenceDigest`, `TargetInputIndex`, `TargetKind`,
`SourceFieldCoveredByVerifiedSignature`, and `MatchedAssertions`.

Artifact order is input order. Edge order is source kind, source input index,
then source field. Set residuals are a deduplicated union in the vocabulary
order below. Snapshots cannot be transferred to another checker, even one
created with identical authority bytes.

## Capsule-local key snapshot policy

The snapshot is not a `PspktTrustRootsSchemaV1` instance. Root properties are,
in exact order:

`schemaId`, `schemaVersion`, `ledgerIdentity`, `keys`,
`maximumSkewHundredNanoseconds`.

The identity is `PspktEvidenceKeyBindingSnapshotV1`, version 1. Each key has, in
order:

`keyId`, `publicBlob`, `algorithm`, `role`, `notBefore`, `notAfter`,
`hostInventoryPolicyDigest`.

Requirements:

- Maximum snapshot size is 1,048,576 bytes and maximum key count is 128.
- Every row is validated and retained, including unused, expired and future
  rows. Duplicate recomputed key IDs are rejected.
- `keyId` is 64 lowercase hex characters: raw SHA-256 of all 512 public-envelope
  bytes, not the modulus alone or its textual encoding.
- `publicBlob` is 1,024 lowercase hex characters.
- The algorithm is exactly `RSA3072PKCS1SHA256`.
- Roles are exactly `HostEvidence` and `RecoveryAuthority`.
- Interval endpoints and caller time are UInt64; admission requires
  `notBefore < notAfter`. Selection requires
  `notBefore <= evaluationTime < notAfter`.
- Every row's policy digest equals the single expected caller digest.
- The lowercase, nonnil D-format ledger GUID must have RFC variant 2, version
  1 through 8, and equal the expected caller ledger.
- `maximumSkewHundredNanoseconds` is parsed and must equal zero.

Canonical JSON is ASCII with no inter-token whitespace, escapes, BOM, CR,
trailing newline, comments, nulls, duplicate/unknown/reordered properties,
fractions, exponents, signs or leading zeros. Integers use their shortest
unsigned decimal encoding. Root values have depth 1; child values add one.
Snapshot parsing is bounded at depth 8, 4,096 nodes, 1,024-byte string values and
64-byte property names. The separately pinned snapshot descriptor uses depth
9. Wire receipts use an independent bounded PowerShell parser, not a normalized
JSON projection.

## Exact signature and schema checks

Only kinds 16, 17 and 20 declare evidence signatures. The raw signed 32-byte key
ID selects exactly one admitted row. Kinds 16/17 require `HostEvidence`; kind
20 requires `RecoveryAuthority`. No other row is tried. Signed observed,
authorized, burned, accepted or deadline timestamps never replace caller time.

The canonical public envelope is 512 bytes. Its six UInt32 little-endian header
values are `(0x31415352,3072,4,384,0,0)`. Bytes 24..27 are `00 01 00 01`;
bytes 28..411 are a 384-byte big-endian modulus with its high bit set; bytes
412..511 are zero. These are format rules, not a proof of prime factors.

Production creates no RSA provider, imports no key, and stores no live crypto
object. It verifies with unsigned OS2IP/I2OSP, `BigInteger.ModPow`, exponent
65537, and the mandatory `s < n` guard. It compares all 384 recovered bytes
against:

`00 01 || FF*330 || 00 || 3031300d060960864801650304020105000420 || SHA256(Sk)`.

For payload kind `k`, the domain is ASCII
`pspkt/evidence/v1/<exact-payload-type>`, followed by one NUL:

- `Hk` hashes that domain plus every canonical payload TLV, including the
  signature TLV.
- `Sk` is that domain plus complete fields 1 through 9. It excludes the entire
  field-10 signature TLV, including its header.

Both following equalities are explicit capsule-local policy for kinds 16/17:

| Field | Raw retained preimage | Bytes | SHA-256 |
|---|---|---:|---|
| 5 | protocol-schema.v1.json | 66838 | `6d76911009b64e52417b3ca519d3b3166cfdf675a4d4deede5ab0dce449c9db4` |
| 6 | evidence-schema.v1.json | 22001 | `49b07b1a401e686ce1bb05fbffb6923f6ef12a9d74deae5a06c840e2abf1fda6` |

There is no schema-domain separation, reserialization, newline normalization,
or meta-schema substitution. Kind 20 fields 5/6 are successor intent fields,
not schema bindings.

The arithmetic verifier is not a FIPS-certified module or a private-key
constant-time implementation. On unsupported Desktop FIPS configurations, an
owned SHA256 construction can fail closed with `runtime:crypto-unavailable`.
An unobservable frozen-operation failure is normalized to `runtime:unexpected`,
not guessed from OS text or attributed to an authority/structure rejection.
No parity is claimed for unsupported configurations.

## Graph cardinality and joins

Targets are indexed by `(kind,Hk)`, not outer ID, inner subject digest, semantic
digest or ledger record digest. Equal typed content is rejected even if outer
ArtifactId/Profile differ.

| Source | Target | Source coverage | Required equalities |
|---|---|---|---|
| 20 field 1 | 18 Hk | true | 20.2 == 18.1; 20.3 == 18.2 |
| 21 field 1 | 20 Hk | false | 21.2 == 20.4 |

An edge is required only when its source exists. Many distinct referrers,
orphan targets and repeated logical identities are allowed. A kind 20 orphan
as a kind 21 target still resolves its own kind 18 edge. There is no reverse
edge, replay, uniqueness, history or timing rule. Joins use only the
digest-resolved target and never search for a different field-matching target.

Kind 18 never becomes signed. Kind 21 remains unsigned and does not inherit the
target's signature or key binding. Its reference discharge is only I.

All envelopes decode before typed duplicates, key selection, signatures,
schema bindings, edge resolution and finally joins. All edges resolve before
any join. Public facts are constructed only after the complete set succeeds
and owned disposal has finished.

Maximum set size is 256 envelopes, 262,228 bytes per envelope and 16,777,216
aggregate bytes. Null/empty slots and limits are checked with an Int64 sum
before any buffer copies. Concurrent mutation of caller buffers during a call
is not a supported synchronization contract.

## Claim vocabulary and exact residual transitions

| Code | Residual |
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
| N | caller-pinned-key-provenance-unchecked |
| O | key-enrollment-unchecked |
| P | caller-time-eligibility-basis-unchecked |
| Q | reference-uniqueness-unchecked |
| R | reference-timing-unchecked |
| S | ledger-state-unchecked |
| T | lifecycle-certification-unchecked |

| Kind | Payload type | Before | Discharged | Added | Residual |
|---:|---|---|---|---|---|
| 0 | WorkerSessionKeyCertificateV1 | ABCEFHJ | | ST | ABCEFHJST |
| 1 | BrokerSessionKeyCertificateBodyV1 | ABCHJ | | ST | ABCHJST |
| 2 | BrokerSessionKeyCertificateEnvelopeV1 | ABCDEFHJ | | ST | ABCDEFHJST |
| 3 | WorkerProcessIsolationAdmissionReceiptV1 | ABCHJ | | ST | ABCHJST |
| 4 | WorkerProcessIsolationReceiptV1 | ABCHJ | | ST | ABCHJST |
| 5 | ServiceLaunchProofV1 | ABCHJ | | ST | ABCHJST |
| 6 | ServiceEnrollmentInstallProofV1 | ABCDHJ | | ST | ABCDHJST |
| 7 | WorkerProcessDaclAccessPolicyProofV1 | ABCDHJ | | ST | ABCDHJST |
| 8 | LiveCandidateAccessProbeV1 | ABCDHJ | | ST | ABCDHJST |
| 9 | LocalTranscriptChunkV1 | ABCDHJ | | ST | ABCDHJST |
| 10 | LocalTranscriptRootV1 | ABCDHJ | | ST | ABCDHJST |
| 11 | LocalTranscriptProofV1 | ABCDHJ | | ST | ABCDHJST |
| 12 | LocalTranscriptRootAcceptedV1 | ABCDHJ | | ST | ABCDHJST |
| 13 | BrokerServiceLaunchProofV1 | ABCHJ | | ST | ABCHJST |
| 14 | CreatorPermitInstallationBodyV1 | ABCHJ | | ST | ABCHJST |
| 15 | CreatorPermitInstallationV1 | ABCEFHJ | | ST | ABCEFHJST |
| 16 | LocalEvidenceReceiptV1 | ABCDEFGJL | EFL | NOPST | ABCDGJNOPST |
| 17 | LocalEvidenceProofV1 | ABCDEFGJL | EFL | NOPST | ABCDGJNOPST |
| 18 | OperationBurnReceiptV1 | ABCDJKM | | QRST | ABCDJKMQRST |
| 19 | OperationBurnDeferralReceiptV1 | ABCDJM | | ST | ABCDJMST |
| 20 | OperationRehabilitationAuthorizationV1 | ABCDEFIJM | EFI | NOPQRST | ABCDJMNOPQRST |
| 21 | OperationRehabilitationReceiptV1 | ABCDIJKM | I | QRST | ABCDJKMQRST |

Discharging E means only the exact declared signature under the selected,
role/time-eligible caller-pinned key passed. A always remains; N/O/P accompany
every E/F discharge. Copied-signature kinds 0/2/15 retain E/F/H. The mixed
kind 0 + kind 16 union is exactly `ABCDEFGHJNOPST`, not intersection `ABCJST`.

Verified claims are:

- 16/17: `signature-verified`, `signature-key-binding-checked`,
  `protocol-schema-bytes-bound`, `evidence-schema-bytes-bound`.
- 20: `signature-verified`, `signature-key-binding-checked`,
  `cross-envelope-reference-resolved`, `linked-assertions-equal`.
- 21: `cross-envelope-reference-resolved`, `linked-assertions-equal`.
- Every other kind: empty.

## Validation, custody and workflow

Run each invocation in a fresh process with an explicit absolute work root
outside the source checkout, no longer than 100 characters.

Start this setup in the repository root. The example manifest location
`..\tools\Pester\Pester.psd1` represents a sibling tools directory; replace it
with the location of your installed or extracted Pester 5.3.3 manifest.
`Resolve-Path` produces explicit absolute repository and manifest paths. The
work root below is an absolute sibling directory. If either derived work path
exceeds 100 characters, set `$workRoot` to a shorter absolute directory outside
the checkout.

```powershell
$repositoryRoot = (Resolve-Path -LiteralPath '.').ProviderPath
$workRoot = [IO.Path]::GetFullPath($repositoryRoot + '-validation')
$pesterManifestPath = (Resolve-Path -LiteralPath '..\tools\Pester\Pester.psd1').ProviderPath
$validatorPath = Join-Path $repositoryRoot 'certification\evidence-signature-reference\validators\Invoke-PspktPhase4EvidenceSignatureReferenceValidators.ps1'

pwsh -NoProfile -File $validatorPath -RepositoryRoot $repositoryRoot `
    -WorkRoot (Join-Path $workRoot 'core') -PesterManifestPath $pesterManifestPath
powershell -NoProfile -File $validatorPath -RepositoryRoot $repositoryRoot `
    -WorkRoot (Join-Path $workRoot 'desktop') -PesterManifestPath $pesterManifestPath
```

The explicit local Pester manifest/module must be exactly version 5.3.3 and have
the admitted origin. This is trusted-local-operator admission, not package
authentication. Hosted setup additionally checks the downloaded package's
271,297-byte length and SHA-256
`bf450611b92dee8de7dd5e69809d5b37f86bff9f8f3b6eb3129d2fbdd889b579`.

There are no partial/selector/skip parameters. Failed preflight consumes the
one-shot host marker. A complete call compiles and loads exactly eight C# 5
images: frozen Bootstrap, frozen seven-source Structural, seventeen-source
Checker and five independently initialized semantic mutants. It executes one
retained caller-bound Pester container with all 48 cases. Successful counts are
8 compilations, 8 loads, 5 initialized mutant kills and 48 passed cases with no
failures, skips, not-run cases or failed blocks/containers.

The closed source/export inventory has 122 paths: 74 frozen structural inputs,
7 additional documentary authorities and 41 repository additions (39 capsule-local files plus two .github files).
Compilation and testing use retained bytes, not reopened repository files. The structural
one-shot validator is never invoked in-process. Desktop uses the exact signed
CodeDom reference list and LoadFrom; Core uses the exact retained Roslyn
reference family and Default load context. Every emitted nonframework
reference is the current call's Bootstrap/Structural identity.

Each top-level runtime type has its own same-named source file. The internal
cross-file support types `EvidenceJsonValue`, `EvidenceKeyBinding` and
`EvidenceResolvedReference` live in `lib\EvidenceJsonValue.cs`,
`lib\EvidenceKeyBinding.cs` and `lib\EvidenceResolvedReference.cs`, respectively.
The readers and resolver retain their original files, and the private nested
StagedFacts stages remain nested. Checker and each mutant compile the same 17
ordered sources; Bootstrap and Structural still compile 1 and 7 sources.

Only eight loaded images, `source-records.v1.json` and
`validation-records.v1.json` are retained in an invocation directory. Loaded
assemblies cannot be unloaded here and Windows can lock their files. Cleanup
does not claim those assemblies were disposed. Staging/TestDrive and undeclared
residue must be gone, registry-drive/variable checks must be clean, and
environment/locations restored before a success result is published. The
owning harness may delete its inspected invocation directory after process exit.

The workflow runs complete checkout and actual no-.git export calls on both
hosts: 32 compilations, 32 loads, 20 initialized kills and 192 passed cases in
four containers. Ten synthetic boundary fault steps must really exit red;
confirmation consumes GitHub's actual string outcomes. These fault probes and
receipt sizing specimens are not additional conformance calls or independent
observers of the underlying machine.

The aggregate independently reconstructs source-set and transformation hashes.
Image, load and framework hashes in receipts are host-produced consistency
records: physical compiler/reference/image custody is checked in each host
call, not independently re-observed from the compact receipt. Checkout/export
framework identities must agree within each host job; image hashes need not
agree across calls or compilers.

Call receipts are capped at 16,384 UTF-8 bytes; individual probe receipts at
1,024; confirmed five-probe groups at 4,096. The reproducible sizing fixtures
are 9,543 and 8,976 bytes, not runtime success evidence. Aggregate transport stages
four call receipts and two probe groups in six separate steps with one payload
environment value per step. Every artifact is bound to the current
`GITHUB_RUN_ID`, `GITHUB_RUN_ATTEMPT`, `GITHUB_SHA` and exact host/source slot.
Rerun the entire workflow, never only failed jobs. Missing or stale outputs
fail closed. Local validation does not establish that a hosted workflow ran.

Failures expose only the closed runtime or validator reason code. Argument
failures are ArgumentException; content/resource/runtime failures are
InvalidDataException without InnerException. A cleanup failure cannot override
an already selected precise primary failure, and incomplete cleanup cannot
publish success.

## Public fixture maintenance

`vectors\New-PspktPhase4EvidenceSignatureReferenceVectors.ps1` is
**NONDETERMINISTIC, TEST-ONLY, NOT AN ENROLLMENT TOOL**. Run it only in a fresh
supported Windows PowerShell 7 process with named `-RepositoryRoot` and
`-OutputRoot`, the latter an empty owned directory. Ordinary validation and CI
never regenerate fixtures.

The generator creates three fresh ephemeral in-memory RSA 3072 CNG keys and
uses the private exponent only for fixture construction. It exports only
canonical public envelopes, five synthetic non-enrolled snapshots, 37 public
evidence envelopes and the fixed 42-row verdict manifest: six generated files.
No private key bytes are intentionally logged, returned or written. Private
parameter arrays are cleared and providers disposed; managed BigInteger memory
erasure is not promised.

Generated output and validation scan every raw file, every decoded bundle item
and snapshot public blob for PEM armor, RSA2, anchored RSA2/RSA3 private
headers, textual private magics and structured DP/DQ/InverseQ fields. Bare
RSA3 is not a marker because `RSA3072PKCS1SHA256` is legitimate. This is
defense in depth, not detection of every covert encoding.

The independent PowerShell oracle uses multiply/add OS2IP and DivRem I2OSP,
not the production conversion implementation. Protected hand-authored
preimages, exact token/claim expectations and encoding recipes are never
generator inputs or outputs. A deliberate corpus change requires review of
the new public bytes, independent goldens and pins; automatic pin advancement
during validation is forbidden.
