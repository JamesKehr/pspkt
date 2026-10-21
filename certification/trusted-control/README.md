# Phase 4 trusted-control structural authority

This slice emits ten structural schemas. It emits no registry instance, TCAST
instance, aggregate digest, enrollment record, activation selector, runtime
service, or overlay activation.

## Maintained authority

| Input | Authority |
|---|---|
| `trusted-control-authority.v1.json` | Exact output paths, declaration and property order, types, bounds, rules, roles, mutation IDs, and deferrals |
| `trusted-control-json-schema-meta.v1.json` | Closed JSON schema vocabulary and canonical property order |
| `protocol-schema-meta.v1.json` | Frozen meta for the three TLV schema documents |
| `protocol-schema.v1.json` | Frozen merged protocol schema pinned for digest and declaration compatibility |
| `mandatory-tail-schedule.v1.json` | Frozen lifecycle schedule source |
| `protocol-inventory.v1.json` | Hash-pinned pretty JSON source for primitive widths and recursive entrypoint sizing |

The validator script at its repository-canonical path is the deliberately
unpinned local trust root for this dependency slice. Its embedded SHA-256 pins
the exact contract bytes, and the verified contract script is executed from
those bytes rather than reopened. The contract pins every subordinate
authority byte, including the frozen protocol schema. No claim is made that the
validator root pins itself.

Compiled Bootstrap, Verify, and Authority assemblies must pass complete
MethodDef and strict metadata-stream/table validation before use. The public
Authority wrapper has one method and one direct call to the exact public
projection entry point. The projection has an exact closed method and call
surface, including method metadata, IL operands, local types, and per-host
call-target inventories. Shared Bootstrap and Verify reject unapproved
cryptographic types, dynamic capabilities, and authority or Evaluate escapes,
including dormant methods and constructed-generic dispatch. Metadata streams
must be nonempty, disjoint half-open byte ranges; a zero-size stream is rejected
even where its offset would not intersect another range.

Instance interface calls use CLR assignability and actual interface maps when
both interfaces are closed. If either interface is open, every implementation
with the same generic definition and method slot is included, even when its
type arguments could never satisfy the requested substitution. Open class
overrides are likewise included by generic base definition and virtual slot;
closed classes retain CLR assignability. This intentional over-inclusion
fails closed rather than allowing a forbidden call to escape the graph check.
Only checked class and struct types act as interface implementers, and an
unresolved interface map or null target rejects validation.

Declared types in checked Bootstrap, Verify, and Authority assemblies may
inherit only from types in that same assembly or the actual core-runtime
`System.Object`, `System.ValueType`, and `System.Enum` types. Other external
class bases reject before graph traversal; arrays, delegates, and framework
types used only as method operands are not subject to this declaration rule.
Checked covariant-override markers and class-target MethodImpl metadata
reject. Interface MethodImpl rows, including generic explicit implementations,
are admitted only after owner-context resolution and an exact interface-map
slot match. Static
abstract or virtual interface methods reject as shapes, IL operands, or
dispatch roots.

`TrustedControlAuthority` generates all ten outputs from the two maintained
trusted-control inputs. `TrustedControlVerify` independently rederives and
checks those outputs and has no assembly reference to Authority.
The maintained-input set contains exactly six paths: the two trusted-control
inputs and the four frozen protocol inputs listed above. The protocol inventory
is a sizing dependency, not a provenance row. Unlike the compact canonical
inputs, it is pretty JSON accepted by a strict whitespace-tolerant parser after
its exact bytes pass the reviewed hash pin.

Canonical generation parses canonical UTF-8 maintained inputs, validates the
closed JSON meta and semantic-rule closure, then serializes properties in their
declared order with no BOM, whitespace, CR, or trailing data. Generate and
Validate are separate fresh child executions. Each child receives a minimal
environment, drains stdout and stderr concurrently, has a 120-second timeout,
and deletes its private compilation directory in `finally`.
Each pinned file is read once during pin admission from an opened read-only
handle, and those exact bytes are hashed. Pinned C# sources are compiled from
the retained bytes. For this sizing slice, the retained protocol-inventory
bytes are also frozen-JSON-gated and passed to every sizing API. Routing for
the other maintained inputs remains unchanged. FILE_ID_INFO is captured before
and after the pin read, then compared again in the worker. Child PowerShell is
bound by path,
disk hash, volume serial, 128-bit file ID, and a hash of the executable sections
of the running mapped image before admission. It is assigned to a kill-on-close
Job Object and terminated as a process tree on timeout. The parent drains stdout
and stderr concurrently, closes the job before its timeout wait, and deletes
the private compilation directory in `finally`. Timeout is configurable and
defaults to 120 seconds. `TimeoutProbe` and `-TimeoutProbePidFile` are
test-harness hooks for proving descendant termination.

## Output contracts

| Schema | Format | Key contract |
|---|---|---|
| TCAST | TLV | Five ordered fields; artifact paths are unique; digest domain `pspkt-trusted-control-artifact-set-v1` |
| PowerShell entrypoints | TLV | HostTool, GuestCandidate, and HostRunspace declarations; 640,422-byte reviewed root, 2 MiB aggregate policy ceiling, 256 total source sites, 128 total user arguments |
| Supported build entry | TLV | Field IDs 1 through 41; Unicode upcase joins by `supportedBuildKey` |
| Timing | Closed JSON | Deadline uses `LT`; CapacityFit uses `LE`; VT is raise-only; RPN sides contain at most 32 tokens |
| Supported builds | Closed JSON | At most 128 entries; interpreter and checkpoint lists at most 64 |
| Resource | Closed JSON | Thirteen ordered resource fields |
| Unicode | Closed JSON | NFC and CS0 fixed tables plus build-keyed Windows upcase tables |
| Trust roots | Closed JSON | 512-byte RSA public envelope; trust epochs; HostEvidence and RecoveryAuthority roles |
| Counters | Closed JSON | Mutation is fixed `Increment` with delta `+1` |
| Metrics | Closed JSON | Metric IDs and counter IDs are disjoint |

Digest formula for each of the three TLV roots:

`digest = SHA256(ASCII(domain) || NUL || rawFrozenProtocolMetaDigest || rawCorrespondingSchemaDigest || canonicalTLVBytes)`

Canonical digest input is a nonempty sequence of strictly increasing U16BE tags,
each followed by a U32BE length and exactly that many value bytes. Opaque,
truncated, duplicate, out-of-order, and trailing bytes are rejected before
digest comparison.

The frozen protocol-meta digest is
`ca08bcb5164acb4522729dc98b2a1bd5ee348a79a14cef95dd852ae1958dcc85`.
Current digest goldens validate framing and pinned digest inputs; canonical TLV
root-value encode/decode goldens remain part of the deferred instance authority.

Binary conversion rules:

| Value | Encoding |
|---|---|
| RSA public envelope | Six U32LE BCRYPT fields (`RSA1`, 3072, 4, 384, 0, 0), exponent `00 01 00 01`, 384-byte big-endian modulus with top bit set, then 100 zero bytes |
| RSA key ID | Lowercase SHA-256 hex of all 512 canonical envelope bytes |
| LUID | Unsigned 64-bit big-endian bytes |
| GUID | Lowercase nonnil D text, RFC 4122 network byte order, variant bits `10`, versions 1 through 8 |
| FixedAscii8 | Eight bytes from `0x20..0x7E`, 16 lowercase hexadecimal characters, right-NUL padded; controls and `0x7F` forbidden |

`W` is the checked ordered sum of:
`consoleFenceRetirementDeadline`,
`consoleMainReaderJoinDeadline`,
`terminalRestoreEpisodeDeadline`,
`consoleAuxiliaryQuiescenceDeadline`,
`consoleTopologyRevalidationDeadline`,
`finalFrameOutputDeadline`,
`consoleTopologyRevalidationDeadline`,
`consoleControlCallbackDrainDeadline`.

TCAST membership requires exactly one `TrustedControlAuthority`, allows zero
through 510 `TrustedWorkflowRevision` entries, defers zero or one
`EnrolledHostRoot`, and caps total membership at 512. The authority row points
to `certification/trusted-control/schema/trusted-control-authority.v1.json`.
Workflow paths are tracked selected-revision artifacts under `certification/`
and satisfy `TCAST-PATH-001`: printable 7-bit ASCII slash paths with no empty,
dot, traversal, device, ADS, backslash, trailing-dot/space, or case-collision
aliases. Enrolled paths use the closed logical grammar
`enrolled-host-root/<64 lowercase hex>`.
Synthetic membership vectors embed closed `trackedPaths` and `pendingPaths`
fixtures. Their expected results are therefore invariant before and after the
trusted-control slice is committed, including on shallow CI checkouts.
Embedded lists are ordinal-sorted, unique, disjoint, and restricted to strict
`certification/` paths or the enrolled-host logical grammar.
Enrolled-host paths are permitted only in `pendingPaths`; placing one in
`trackedPaths` is invalid. A present enrolled path returns
`membership-path-pending`; an absent enrolled path returns
`membership-path-pending-missing`.

Dependency 1C performs no live selected-revision membership validation and has
no Git or HEAD requirement. The selected-revision TCAST membership check remains
a hard deferred prerequisite for real instance emission. The schema-only check
persists no membership census and grants no activation authority.

Entrypoint schema projection reduces each source-site list to one row and each
host-tool argument list to two rows while retaining 64 rows in each of the three
entrypoint lists. The authority stores the reviewed derived values separately
from policy ceilings: SourceSite 824 bytes, HostInterpreterIdentity 2,266 bytes,
PowerShellArgument 2,058 bytes, HostTool 7,690 bytes, GuestCandidate 1,248
bytes, HostRunspace 1,056 bytes, root 640,422 bytes, 192 source sites, 128 user
arguments, and maximum recursive depth 6. Policy ceilings remain 1 MiB for the
root, 2 MiB for aggregate bytes, 256 source sites, and 128 user arguments. No
aggregate byte maximum is derived from the schema. Each
`HostInterpreterIdentityV1` carries the image digest, volume serial, and opaque
128-bit file ID.

Lifecycle keys are derived as `lifecycleVariant|state` from the pinned merged
`certification/schema/mandatory-tail-schedule.v1.json`; duplicate directional
rows collapse to the first key occurrence. Interpreter paths use explicit
ASCII ordinal-ignore-case comparison after absolute Windows path validation.
DerivedW is represented as CapacityFit with `LE`; VT is a raise-only state rule
and has no relation field.

## Hard deferrals

The AST/Roslyn/YAML source census is a hard prerequisite deferred to launcher
migration. The removed regex scan was not authoritative. External process and
PowerShell migration blockers must be zero before any instance can exist.
Therefore current outputs can never activate.

Launcher migration must also establish a reviewed authority for `pktmon` and
prove the pinned pktmon prerequisite before entrypoint census output is allowed.

Concrete registry values, TCAST instances and digests, enrollment and activation
selection, overlay activation, runtime services, Roslyn execution, and Linux
integration remain outside this slice. The overlay remains dormant.
