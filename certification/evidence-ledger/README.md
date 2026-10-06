# Evidence and signing-ledger schema authority

This slice defines schema authority, not runtime decoding, signing, verification,
or Merkle proof execution. The protocol schema, inventory, and meta remain frozen.
The contract is the root of the source pin graph and is not self-pinned.

The maintained input is `schema/evidence-ledger-inventory.v1.json`.
The three generated outputs are `schema/evidence-schema.v1.json`,
`schema/signing-ledger-schema.v1.json`, and `schema/signing-ledger-maxima.v1.json`.

## Commands

```powershell
.\certification\evidence-ledger\validators\Invoke-PspktPhase4EvidenceLedgerAuthorityValidators.ps1
.\certification\evidence-ledger\vectors\New-PspktPhase4EvidenceLedgerVectors.ps1 -OutputRoot $destination
```

## Schema inventory

The evidence schema has 24 declarations: the 16 forward roots below, then the eight evidence append declarations. The ledger schema has 60 declarations: 45 copied declarations, then 15 ledger append declarations. Copied declarations retain protocol source order and field IDs; type IDs are reassigned sequentially within each schema.

Deferred and absent: `ServiceControlEventNodeProofV1`. Reverse dependents `BootstrapWorkerContext`, `BootstrapBrokerContext`, and `LocalHelloB` are excluded. There is no purpose union or duplicated record count. Local receipt/proof declarations remain evidence-only.

Evidence root order: `WorkerSessionKeyCertificateV1`, `BrokerSessionKeyCertificateBodyV1`, `BrokerSessionKeyCertificateEnvelopeV1`, `WorkerProcessIsolationAdmissionReceiptV1`, `WorkerProcessIsolationReceiptV1`, `ServiceLaunchProofV1`, `ServiceEnrollmentInstallProofV1`, `WorkerProcessDaclAccessPolicyProofV1`, `LiveCandidateAccessProbeV1`, `LocalTranscriptChunkV1`, `LocalTranscriptRootV1`, `LocalTranscriptProofV1`, `LocalTranscriptRootAcceptedV1`, `BrokerServiceLaunchProofV1`, `CreatorPermitInstallationBodyV1`, `CreatorPermitInstallationV1`.

Evidence append order: `LocalEvidenceReceiptV1`, `LocalEvidenceProofV1`, `OperationBurnReceiptV1`, `OperationBurnDeferralReceiptV1`, `OperationRehabilitationAuthorizationV1`, `OperationRehabilitationReceiptV1`, `EvidenceArtifactKind`, `EvidenceArtifactEnvelopeV1`.

Ledger append order: `OperationBurnReceiptV1`, `OperationBurnDeferralReceiptV1`, `OperationRehabilitationAuthorizationV1`, `OperationRehabilitationReceiptV1`, `OperationSigningLedgerKind`, `AuthorizationSigningLedgerRecordEnvelopeV1`, `OperationSigningLedgerRecordEnvelopeV1`, `AuthorizationSigningLedgerRecordList`, `OperationSigningLedgerRecordList`, `SigningLedgerSegmentHeaderV1`, `AuthorizationSigningLedgerSegmentV1`, `OperationSigningLedgerSegmentV1`, `Sha256SiblingList`, `AuthorizationSigningLedgerInclusionProofV1`, `OperationSigningLedgerInclusionProofV1`.

### Evidence kind mapping

| Value | Payload type |
| ---: | --- |
| 0 | `WorkerSessionKeyCertificateV1` |
| 1 | `BrokerSessionKeyCertificateBodyV1` |
| 2 | `BrokerSessionKeyCertificateEnvelopeV1` |
| 3 | `WorkerProcessIsolationAdmissionReceiptV1` |
| 4 | `WorkerProcessIsolationReceiptV1` |
| 5 | `ServiceLaunchProofV1` |
| 6 | `ServiceEnrollmentInstallProofV1` |
| 7 | `WorkerProcessDaclAccessPolicyProofV1` |
| 8 | `LiveCandidateAccessProbeV1` |
| 9 | `LocalTranscriptChunkV1` |
| 10 | `LocalTranscriptRootV1` |
| 11 | `LocalTranscriptProofV1` |
| 12 | `LocalTranscriptRootAcceptedV1` |
| 13 | `BrokerServiceLaunchProofV1` |
| 14 | `CreatorPermitInstallationBodyV1` |
| 15 | `CreatorPermitInstallationV1` |
| 16 | `LocalEvidenceReceiptV1` |
| 17 | `LocalEvidenceProofV1` |
| 18 | `OperationBurnReceiptV1` |
| 19 | `OperationBurnDeferralReceiptV1` |
| 20 | `OperationRehabilitationAuthorizationV1` |
| 21 | `OperationRehabilitationReceiptV1` |

### Authorization kind mapping

| Value | Payload type |
| ---: | --- |
| 0 | `AuthorizationLedgerPreparedV1` |
| 1 | `AuthorizationLedgerSentV1` |
| 2 | `AuthorizationLedgerStoredV1` |
| 3 | `AuthorizationLedgerCreatingV1` |
| 4 | `AuthorizationLedgerCreatedV1` |
| 5 | `AuthorizationLedgerCompletedV1` |
| 6 | `AuthorizationLedgerCreateDefinitivelyFailedV1` |
| 7 | `AuthorizationLedgerAbortedCreateDefinitivelyFailedV1` |
| 8 | `AuthorizationLedgerRevokedBeforeCreateV1` |
| 9 | `AuthorizationLedgerAbortedProvenNotCreatedV1` |
| 10 | `AuthorizationLedgerAbortedCreatedNeverResumedV1` |
| 11 | `AuthorizationLedgerAbortedAttachmentHandshakeV1` |
| 12 | `AuthorizationLedgerAbortedResourcePreparationFailedV1` |
| 13 | `AuthorizationLedgerAbortedCompilationDefinitivelyFailedV1` |
| 14 | `AuthorizationLedgerOutcomeUnknownV1` |
| 15 | `AuthorizationLedgerBurnedUnknownV1` |

### Operation kind mapping

| Value | Payload type |
| ---: | --- |
| 0 | `OperationUnseenV1` |
| 1 | `OperationActiveV1` |
| 2 | `OperationActiveWithLaunchAuthorityV1` |
| 3 | `OperationCompletedV1` |
| 4 | `OperationCompletedWithLaunchAuthorityV1` |
| 5 | `OperationBurnedUnknownV1` |
| 6 | `OperationBurnedUnknownWithLaunchAuthorityV1` |
| 7 | `OperationAbortedProvenNotCreatedV1` |
| 8 | `OperationAbortedProvenNotCreatedWithLaunchAuthorityV1` |
| 9 | `OperationAbortedCreateDefinitivelyFailedV1` |
| 10 | `OperationAbortedCreateDefinitivelyFailedWithLaunchAuthorityV1` |
| 11 | `OperationAbortedCreatedNeverResumedV1` |
| 12 | `OperationAbortedCreatedNeverResumedWithLaunchAuthorityV1` |
| 13 | `OperationAbortedAttachmentHandshakeV1` |
| 14 | `OperationAbortedAttachmentHandshakeWithLaunchAuthorityV1` |
| 15 | `OperationAbortedResourcePreparationFailedV1` |
| 16 | `OperationAbortedResourcePreparationFailedWithLaunchAuthorityV1` |
| 17 | `OperationAbortedCompilationDefinitivelyFailedV1` |
| 18 | `AbortedCompilationDefinitivelyFailedWithLaunchAuthority` |
| 19 | `OperationBurnResolvedV1` |
| 20 | `OperationBurnResolvedWithLaunchAuthorityV1` |
| 21 | `OperationSuccessorAuthorizedPendingCapacityV1` |
| 22 | `OperationSuccessorAuthorizedPendingCapacityWithLaunchAuthorityV1` |
| 23 | `OperationBurnResolutionDeferredV1` |
| 24 | `OperationBurnResolutionDeferredWithLaunchAuthorityV1` |
| 25 | `OperationBurnReceiptV1` |
| 26 | `OperationBurnDeferralReceiptV1` |
| 27 | `OperationRehabilitationAuthorizationV1` |
| 28 | `OperationRehabilitationReceiptV1` |

## Bounds and byte maxima

Maximum segment records: 4096. Maximum inclusion siblings: 12. Evidence payload maximum: 262143; Authorization payload maximum: 649; Operation payload maximum: 636.

| Ledger | Record envelope | Segment | Inclusion proof |
| --- | ---: | ---: | ---: |
| Authorization | 757 | 3117740 | 1038 |
| Operation | 744 | 3064492 | 1038 |

The frozen protocol inventory is intentionally noncanonical and is checked by exact hash, strict JSON, identity, and shape, without canonical-byte comparison. The maintained evidence-ledger inventory and all three outputs require canonical UTF-8 bytes without BOM, whitespace, or a final newline. Only the two new schemas are checked against the frozen schema meta. Validation never writes repository inputs or outputs. Generation replaces each file atomically using a flushed sibling temporary file; this is not a cross-file transaction.

## Deferred binary consumer contract

- Canonical TLV bytes for digest/signature coverage are pinned independently of JSON: fields are ordered by ascending fieldId with conditional effective rows resolved for the selected profile; each field is UInt16 big-endian fieldId || UInt32 big-endian payload length || payload bytes.
- U8 is one byte; EnumU16/U16 are big-endian 2 bytes; U32 is big-endian 4 bytes; U64/FILETIME/QPC are big-endian 8 bytes; GUID uses RFC 4122/network byte order; SHA-256 and fixed opaque/RSA values are their exact bytes; SemanticString is UInt32 big-endian UTF-8 byte length plus exactly that many strict UTF-8 bytes; BoundedBytes is UInt32 big-endian innerLength plus exactly innerLength bytes, and its enclosing field payload length must equal 4 + innerLength; List is UInt32 big-endian count followed by UInt32 big-endian element length plus element bytes; Set uses the same framing with unique elements sorted by unsigned lexicographic element payload bytes, with the shorter payload first when one is a prefix.
- Named is concatenated effective field TLVs.
- Every ASCII domain is followed by one NUL byte before covered bytes.
- Pinned consumer-contract text requires strict payload decoding to reject unknown, duplicate, missing Required, present Forbidden, or out-of-order field IDs; missing/extra list or set elements; duplicate/out-of-order Set elements; primitive/bound violations; inconsistent inner lengths; and trailing bytes.
- It requires canonical re-encoding to be byte-identical before digest/signature comparison.
- Authority and Verify validate this exact contract text and its inventory shape; they do not execute the binary decoder.
- Consumer profile byte mapping is exact: Any=0, InteractiveSeat=1, NonInteractiveElevated=2.
- These are newly defined wire-envelope values and are not the ordinal values of the schema-meta FieldProfile enum.
- EvidenceArtifactEnvelopeV1.profile, AuthorizationLedgerCommonV1.profile, and OperationRecordCommonV1.profile must be 1 or 2; 0 is not concrete.
- Evidence consumers use the envelope profile to select EffectiveFields.
- Copied Authorization and Operation kinds 0..24 use their nested common profile.
- Appended Operation kinds 25..28 have no common/profile and no conditional fields; consumers encode every declared field and do not read a profile.
- I16, I32, and I64 are signed two's-complement values in big-endian 2-, 4-, and 8-byte form.
- OpaqueUtf16 is UInt32 big-endian code-unit count followed by exactly that many UTF-16LE code units; count must not exceed maxCodeUnits and enclosing field length must equal `4 + 2 * count`.
- AsciiIdentifier is 1..128 canonical 7-bit ASCII bytes with no NUL; field TLV length supplies its length.
- BinarySid is canonical Windows self-relative SID bytes with revision exactly 1, subAuthorityCount 0..15, and total length exactly `8 + 4 * subAuthorityCount` (8..68 bytes).
- The six-byte identifier authority and little-endian UInt32 subauthorities retain canonical Windows SID byte order; field TLV length supplies the same exact length.
- Utf8Short is 0..256 strict UTF-8 bytes without BOM, NUL, malformed sequences, or U+FFFD; field TLV length supplies its length.
- LUID is its unsigned 64-bit value in big-endian byte order.
- FixedAscii8 is exactly eight 7-bit ASCII bytes.
- Opaque16 and Opaque32 are exactly 16 and 32 bytes.
- Rsa3072PublicBlob is exactly 512 bytes and Rsa3072Signature exactly 384 bytes.
- Every signature whose covered bytes are newly defined by this slice uses RSASSA-PKCS1-v1_5 with SHA-256 as specified by RFC 8017.
- This set is exactly LocalEvidenceReceiptV1.signature, LocalEvidenceProofV1.signature, OperationRehabilitationAuthorizationV1.authoritySignature, AuthorizationSigningLedgerSegmentV1.signature, OperationSigningLedgerSegmentV1.signature, AuthorizationSigningLedgerInclusionProofV1.signature, and OperationSigningLedgerInclusionProofV1.signature.
- The signature operation hashes the exact domain-separated covered bytes once with SHA-256, applies EMSA-PKCS1-v1_5 encoding for SHA-256, and uses an RSA key whose modulus is exactly 3072 bits; RSA-PSS, raw RSA, alternate hashes, and prehashed-input substitution are forbidden.
- A Rsa3072Signature is the unsigned RSA signature representative encoded as exactly 384 octets by RFC 8017 I2OSP in most-significant-octet-first order; verification rejects any other length, a representative greater than or equal to the modulus, malformed EMSA-PKCS1-v1_5 encoding, or a key-binding mismatch.
- Key binding is exact: LocalEvidenceReceiptV1 and LocalEvidenceProofV1 use observerKeyId; OperationRehabilitationAuthorizationV1 uses authorityKeyId; each segment uses header.signerKeyId; each inclusion proof uses its signerKeyId after proving equality with the matched segment header.
- The public exponent comes from the corresponding trusted key binding.
- Copied protocol signature fields retain only their frozen protocol-defined shape and semantics: this slice assigns them no new algorithm, coverage, or key-binding rule.
- Authority and Verify pin the exact seven-signature set, algorithm, representation, key mapping, and copied-signature exclusion in inventory and README and reject mutation or omission; this slice still does not execute signing or verification.
- Inventory pins one exact, unique ASCII digest/signature domain for every EvidenceArtifactKind member using the case-sensitive formula `pspkt/evidence/v1/<ExactTypeName>`.
- The 22 exact type names come from the pinned kind mapping, so every projected root and every new declaration has a domain.
- LocalEvidenceReceiptV1 and LocalEvidenceProofV1 remain structurally identical but cryptographically non-interchangeable because their exact type names and domains differ.
- LocalEvidenceReceiptV1.signature and LocalEvidenceProofV1.signature each cover ASCII(domain) || NUL || canonical TLV bytes of every preceding field, excluding signature itself.
- OperationRehabilitationAuthorizationV1.authoritySignature uses the same rule with its exact evidence domain and excludes authoritySignature itself.
- Inventory pins two per-kind domains for each record kind: `pspkt/signing-ledger/v1/authorization-record/<ExactTypeName>/payload` and `/record` for 16 Authorization kinds, and `pspkt/signing-ledger/v1/operation-record/<ExactTypeName>/payload` and `/record` for 29 Operation kinds.
- It also pins:
- `payloadDigest` covers ASCII(per-kind `/payload` domain) || NUL || canonical payload TLV bytes.
- `recordDigest` covers ASCII(per-kind `/record` domain) || NUL || canonical envelope TLV bytes for kind, recordSequence, payload, and payloadDigest, excluding recordDigest.
- Merkle leaves are recordDigest, binding kind and sequence.
- `segmentDigest` covers ASCII(segment domain) || NUL || canonical TLV bytes of header, records, and merkleRoot; it excludes segmentDigest and signature.
- The signature covers ASCII(segment domain) || NUL || segmentDigest and uses header.signerKeyId.
- Runtime instance validation and cryptographic execution are explicitly outside this schema-authority slice.
- Authority and Verify pin the following requirements as exact inventory/README text and schema fields; they do not ship a binary decoder, Merkle prover, or signature verifier:
- EvidenceArtifactEnvelope kind maps to the exact payload type, envelope.profile is 1 or 2 and selects that payload's EffectiveFields, and payloadDigest equals SHA-256(ASCII(evidence-kind domain) || NUL || byte-identical canonical payload TLV under envelope.profile).
- Every nested field named `profile` at any depth must be 1 or 2 and equal envelope.profile.
- This includes WorkerSessionKeyCertificateV1, CreatorPermitInstallationV1.body, BrokerSessionKeyCertificateBodyV1, ServiceLaunchProofV1, and BrokerServiceLaunchProofV1.
- Conditional evidence types without an internal profile, including both isolation receipts, use envelope.profile as their sole selector.
- Signing record kind maps to the exact payload type.
- For kinds 0..24, payload.common.profile must be exactly 1 or 2 and selects EffectiveFields; every other value including 0 is rejected.
- Kinds 25..28 have no profile and encode all fields.
- Envelope.recordSequence equals payload.common.recordSequence where present, payloadDigest equals SHA-256(ASCII(per-kind `/payload` domain) || NUL || canonical payload TLV bytes), and recordDigest equals SHA-256(ASCII(per-kind `/record` domain) || NUL || canonical envelope TLVs excluding recordDigest).
- For every segment record index i, records[i].recordSequence equals header.firstRecordSequence + i.
- This applies to copied common records and all four appended operation payload types.
- Merkle leaves are the ordered 32-byte recordDigest values.
- For one record, merkleRoot equals that leaf and no parent hash is performed.
- For a level with at least two nodes, parent = SHA-256(ASCII(`pspkt/signing-ledger/merkle-node/v1`) || NUL || left 32 bytes || right 32 bytes).
- When such a level has an odd final node and at least three nodes, pair that final node with itself.
- Continue until one root remains.
- An empty segment root is SHA-256(ASCII(`pspkt/signing-ledger/merkle-empty/v1`) || NUL).
- segmentDigest equals SHA-256(ASCII(segment-purpose domain) || NUL || canonical TLV bytes of header, records, and merkleRoot), excluding segmentDigest and signature.
- signature verifies ASCII(segment-purpose domain) || NUL || segmentDigest with header.signerKeyId.
- Inclusion proof requires proof.segmentId == segment.header.segmentId, proof.merkleRoot == segment.merkleRoot, proof.segmentDigest == segment.segmentDigest, and proof.signerKeyId == segment.header.signerKeyId.
- `leafIndex < records.Count`; proof.recordSequence equals records[leafIndex].recordSequence; proof.recordDigest equals records[leafIndex].recordDigest.
- Sibling hashes are ordered leaf-to-root.
- Sibling count is ceil(log2(recordCount)), with zero siblings for one record and at most 12.
- For sibling level i, directionBits bit i equals `(leafIndex >> i) & 1`; bit 0 means current-is-left and uses current as left plus sibling as right, while bit 1 means current-is-right and uses sibling as left plus current as right.
- At every proof step compute SHA-256(ASCII(`pspkt/signing-ledger/merkle-node/v1`) || NUL || left || right).
- For an odd duplicated final node, sibling equals current.
- Unused bits above sibling count are zero.
- Proof reduction must equal the proof and segment merkleRoot.
- Proof signature verifies ASCII(proof-purpose domain) || NUL || canonical proof TLV bytes excluding signature with the matched signer key.
- The first segment priorSegmentDigest is 32 zero bytes.
- Every later segment priorSegmentDigest equals the preceding segmentDigest for the same purpose ledger.
- header.protocolSchemaDigest is SHA-256 of committed canonical protocol-schema.v1.json bytes.
- header.evidenceSchemaDigest is SHA-256 of canonical evidence-schema.v1.json bytes.
- priorRecordDigest fields refer to the immediately preceding recordDigest in the same purpose ledger, or 32 zero bytes for the first record.
- terminalRecordDigest and successorRecordDigest refer to the exact target ledger recordDigest.
- burnReceiptDigest refers to the EvidenceArtifactEnvelope payloadDigest for OperationBurnReceiptV1.
- Only OperationRehabilitationReceiptV1.authorizationDigest refers to the EvidenceArtifactEnvelope payloadDigest for OperationRehabilitationAuthorizationV1; existing AuthorizationLedgerCommonV1.authorizationDigest retains its protocol-defined meaning.
- LocalEvidenceReceiptV1.payloadDigest and LocalEvidenceProofV1.payloadDigest remain schema fields whose domain-specific subject bytes are defined by their future producer; their enclosing EvidenceArtifactEnvelope payloadDigest always covers the complete canonical local evidence payload.
- Primitive widths come from the committed protocol inventory for used protocol primitives.
- Independently defined frozen-meta primitives are I16=2, I32=4, I64=8, and OpaqueUtf16=`4 + 2 * maxCodeUnits`.
- BoundedBytes size is 4 + maxBytes.
- Named size is sum of 6-byte field TLV plus field payload.
- EnumU16 is 2.
- SemanticString sizing is 4 + maxBytes and all synthetic fixtures obey the frozen meta's selected encoding, grammar, minBytes, maxBytes, and maxUtf16CodeUnits.
- `AsciiEnvironmentName` requires encoding AsciiEnvironmentName, grammar None, minBytes=1, maxBytes=32767, maxUtf16CodeUnits=32767, and value bytes 1..127 excluding `=`.
- No SemanticString declaration is emitted by the committed 1BC schemas.
- List/Set payload is 4 + maxCount * (4 + element maximum).
- Every Named field containing a list, including records and siblingHashes, adds its own 6-byte TLV outside that list payload.
- Every field payload, maxBytes bound, record envelope, segment, proof, and emitted maximum must fit UInt32 because the encoding uses U32 lengths.
- BigInteger intermediates detect overflow before checked UInt32 conversion.

No runtime services, signing, binary decoder, Merkle prover, CI, database, aggregate matrix, or overlay changes are included. The C# implementations share only the frozen SchemaBootstrap assembly and independently reconstruct projections and exact BigInteger sizes. Reference math in tests does not constitute shipped binary-consumer behavior.

## Pinned bytes

The contract pins this README; neither document contains the contract hash.

| Path | Bytes | SHA-256 |
| --- | ---: | --- |
| `certification/lib/Pspkt.Certification.SchemaBootstrap.cs` | 90801 | `c5b9e5b9fa3fdc4c747d6f7af63185669d86372607773ad91767488ac5b1de74` |
| `certification/schema/protocol-schema-meta.v1.json` | 4533 | `ca08bcb5164acb4522729dc98b2a1bd5ee348a79a14cef95dd852ae1958dcc85` |
| `certification/schema/protocol-schema.v1.json` | 66838 | `6d76911009b64e52417b3ca519d3b3166cfdf675a4d4deede5ab0dce449c9db4` |
| `certification/schema/protocol-inventory.v1.json` | 46479 | `d67cb37777eaa5fee07404894b0d1f4a20bf11d4a4c95085bc60e350805f265f` |
| `certification/evidence-ledger/.gitattributes` | 127 | `02569930d8b1b2dd19e1b7397aebcaa9d7a9db74ed4aebd36f86a717262e7d4b` |
| `certification/evidence-ledger/lib/.gitattributes` | 179 | `ff91d6cdb38028607d0a608d016728e3a95fe85975900d8eeb38ba3f3941e6e5` |
| `certification/evidence-ledger/schema/.gitattributes` | 123 | `ebf2b8bd099a5096aecb683468622d45e74ee7948e20d3750f12442a48f97d91` |
| `certification/evidence-ledger/validators/.gitattributes` | 123 | `ae2525a655e5c7526f534866cfb49e9f83de04e9e80b42d7ecd2b1cb865fef32` |
| `certification/evidence-ledger/vectors/.gitattributes` | 123 | `ae2525a655e5c7526f534866cfb49e9f83de04e9e80b42d7ecd2b1cb865fef32` |
| `tests/phase4-evidence-ledger/.gitattributes` | 123 | `ae2525a655e5c7526f534866cfb49e9f83de04e9e80b42d7ecd2b1cb865fef32` |
| `certification/evidence-ledger/lib/Pspkt.Certification.EvidenceLedgerAuthority.cs` | 29795 | `6c69ee0ac5880310ee5c4b5bc0d53c8e78f123004c849b7a46fd35dd9b03500c` |
| `certification/evidence-ledger/lib/Pspkt.Certification.EvidenceLedgerVerify.cs` | 37623 | `aea9f3d62bb671e8dcd090a9076384fba8d59502cac3ec3c60a2c50acac40771` |
| `certification/evidence-ledger/validators/Invoke-PspktPhase4EvidenceLedgerAuthorityValidators.ps1` | 10610 | `b5912c08307879f3ce1c4ba80169f1d0c9e4e99dd25614775121155bcc291794` |
| `certification/evidence-ledger/vectors/New-PspktPhase4EvidenceLedgerVectors.ps1` | 278 | `6de339879e058597c5cb2a9f099a6aa4725180169be26ec687d55928f155a772` |
| `certification/evidence-ledger/schema/evidence-ledger-inventory.v1.json` | 47347 | `07b39559f1b581dd78623314d3ec44b04a37e278a3e4c90cf2ff9037f46e3dc9` |
| `certification/evidence-ledger/schema/evidence-schema.v1.json` | 22001 | `49b07b1a401e686ce1bb05fbffb6923f6ef12a9d74deae5a06c840e2abf1fda6` |
| `certification/evidence-ledger/schema/signing-ledger-schema.v1.json` | 31271 | `f1599ee3549e5e93783bed9c9db6f2324e41523d780decc9eda54907cd02ec85` |
| `certification/evidence-ledger/schema/signing-ledger-maxima.v1.json` | 394 | `c0e23855864de532ad5e931f75d5125f5467d44c13abc74400cfde77b49432f4` |
