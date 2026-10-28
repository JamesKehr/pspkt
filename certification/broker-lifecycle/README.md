# Broker lifecycle structural conformance

This self-contained certification capsule implements bounded BrokerControl and LocalIpc wire parsing and an in-process Broker/Worker lifecycle model. Its trust ceiling is always `StructuralInProcessOnly`.

It does not import the product module, register type accelerators, require elevation, install a service, create a broker/worker process, open a native pipe, mint a token or launch a candidate. Its memory transport is concrete bounded byte storage, not a configurable mock.

## What is and is not established

The admitted base contains 22 directional associations, 18 payload roots, 20 transitive Named types and 14 primitives. All nine WorkerApp rows and omitted Broker kinds 4368, 4370, 4371 and 4374 reject. The selected base provides no active BrokerControl or LocalIpc mandatory-tail schedule; applicable snapshots report `UnavailableForSelectedBaseSnapshot`, not an empty or satisfied tail.

Frames are Header24 + canonical payload + 384 opaque signature bytes. Complete frame length is payload length +408 and cannot exceed 1048576 bytes. Context profile and every carried profile must equal2; otherwise-valid values0/1/3/255 reject as `frame:profile`.

TLV field IDs and lengths are unsigned big-endian values, fields are exact and ascending, and nested objects retain their own field scopes. GUID bytes are RFC4122 network order. ASCII identifiers use 1..128 bytes in `[A-Za-z0-9._:-]`. SID layout, opaque public-blob bounds, bounded-byte prefixes and nested384-byte signatures follow the protocol ABI, not another evidence format.

Frame signatures and nested signatures are not verified. Exact signature preimages, wrapped records and binding/transcript hashes are computed without asserting authentication, enrollment, source Complete, durable acceptance, real peer identity, service trust, process exit or certification. All13 unchecked-semantic tokens remain present.

The original recovered documents are not repository inputs. Public authority files contain only the exact narrow extraction, public source names/hashes/clause mappings and the actual detached design-review activation. Committed provenance classifies the recovered R6 and credential-free delta as IdentityOnlyUnverified; applying a pending-review posture to the normative-table document was a conservative capsule policy extension. Ready design activation is not runtime service trust.

## Public C# surface

All four public types are sealed, have nonpublic constructors and return defensive copies for arrays.

| Type | Surface |
|---|---|
| `BrokerLifecycleProtocol` | Nine-input `CreateFromCommittedAuthorities`; Decode/Encode; signature preimage, record, finished digest, Broker/Local binding and three transcript helpers; `UncheckedSemantics` |
| `DecodedControlFrame` | Twelve readonly properties describing the structural frame and required signer context |
| `CheckpointServiceLifecycle` | CreateInMemory, Start, FeedPeerBytes, QueueFrame, ReadPeerBytes, ObservePeerEof, Pump, RequestStop, GetSnapshot, Dispose |
| `BrokerLifecycleSnapshot` | Thirty-five readonly properties: role/generation/scoped phases, separate progress/tail fields, ownership/first-cause/cleanup fields, twenty named directional metrics and unchecked semantics |

The exact signatures and property names are pinned in `vectors\hand-authored\contract-expectations.v1.json`. There is no StopDeadline property, native transport factory, restart API, mutable clock, authority-digest override or public fault hook.

The assembly namespace is `Pspkt.Certification.BrokerLifecycle`. Each validation call loads invocation-specific images. Resolve types from the exact retained Assembly object, not ambient type names: Runtime and the six mutant images deliberately share full type names.

## Lifecycle and byte ownership

Broker owns BrokerControl and LocalIpc memory pairs; Worker owns only LocalIpc. A generation and exact owner reference are published before setup can open storage or register work. Diagnostic generation numbers are not capabilities.

Owner methods are serialized/nonreentrant. RequestStop may be concurrent and publishes one immutable winner without closing or cleaning inline. A later request cannot replace its deadline. Caller time is monotonic in one opaque run-local unit; no UTC conversion, tick frequency or keepalive timing enrollment is inferred.

The deadline-winner assertions hold a genuine completion with write deadline 500. A winning stop at 100 remains quiescing at 99 and expires at 100 despite a losing request for 200; reversing the winner proves 199/200 instead. These observations use the existing public snapshot, not a private deadline getter, and the held lease prevents early cleanup.

Pump exposes distinct setup, admission-close/draining, local seal and full-close transitions. Quiescing starts before cleanup predicates are complete. Only a fault-free quiescent controller becomes `ControllerStoppedUnverified`. Any fault remains `ControllerFaultedUnverified` after `CleanupComplete=true`.

The complete Broker bootstrap is 4353 B->H0, 4354 H->B0, 4355 B->H0, 4356 B->H0. All three Broker-to-host zeros are legal; application traffic in either direction waits for all four observations. Local application traffic waits for both LocalHelloW and LocalHelloB. Application sequences begin1 independently per direction, with exact increments and no replay/gap/wrap.

The transport supports real fragmented/coalesced input, known short writes, backpressure, explicit EOF, absolute deadlines and abort wake/retirement. Empty ReadPeerBytes is not EOF. EOF before terminal prerequisites faults; local sealed/quiescent EOF does not prove process exit. There is no intentional half-close.

Known complete sent BrokerFailure/LocalFailure terminalizes the send direction and faults with `lifecycle:local-failure-emitted` if no earlier cause exists. Received BrokerFailure or LocalFailure terminalizes its receive direction and uses `lifecycle:peer-failure-observed`. Queueing, partial copying or an ambiguous write is not a successful failure emission.

Every started ordinary write that fails, becomes indeterminate or expires terminalizes its exact send direction. Its operation reason remains `transport:indeterminate-write` or `transport:deadline`. There is no retry or resend, even for a known-zero failed attempt. A later genuine completion cannot revive a retired operation.

At global admission closure, pre-admitted unstarted queued frames retire with `lifecycle:state`, release reservations exactly once and produce no bytes, observation or sequence advance. Only already-started episodes may drain.

New-traffic precedence is:

1. Invalid/null/out-of-range/unresolved arguments keep argument reasons.
2. A resolved terminal direction rejects `lifecycle:traffic-after-terminal`.
3. A resolved nonterminal direction after global closure rejects `lifecycle:state`.
4. Only then may profile/payload/order/cardinality/quota checks produce effects.

These rejections never replace sticky PrimaryReasonCode or reopen cleanup/admission. Operation retirement reason and controller primary cause are distinct. An opened BrokerControl stop cannot claim a clean source success because the selected base omits IsolationExit.

## Bounds

| Resource | Bound |
|---|---:|
| Controllers issued per facade |64 |
| Queued complete frames/direction |8 |
| Queued bytes/direction |2097152 |
| Feed chunk and peer read |65536 |
| Complete frame / partial assembly |1048576 |
| Dispatch leases/controller |64 |
| Scheduler work / Pump step budget |256 |
| Controller-owned byte ceiling |67108864 |
| Local records/full/wrapper bytes per direction |256 /1048576 /1051904 |
| Broker total records/wrapper bytes per direction |4096 /16777216 |
| Broker ordinary records/wrapper bytes per direction |3840 /15728640 |
| Broker / Local keepalive count per direction |256 /64 |
| Failure count per direction, including pending reservations |1 |

The Local relation is W=F+13R. All three bounds and consistency are checked independently; their mathematical dependence is not an excuse to omit a guard or invent a reachable W-only mutant. Some numeric limits exceed what the selected handled grammar can reach. Tests label those as component boundaries, not fictitious valid conversations.

## Closed deterministic test mechanism

LifecycleTestDriver and TransportOutcomeScript are internal, absent from normal construction/API and reachable by admitted tests only through exact signatures. The immutable five-kind vocabulary controls known short increments, fixed failed/indeterminate attempts, genuine completion holding and actual foreign-reference delivery.

The mechanism cannot supply delegates, callbacks, reasons, success flags, owners, clocks or replacement completions. It cannot reset phases/latches, clear the one-shot marker or invoke another validator. Source bytes and supporting completion code remain identical in Runtime/M1-M6; transformations occur only at the six reviewed production sites.

The invocation allowlist is sixteen internal methods and four getters, including the read-only PrimaryWriteRetirementReason. Nine supporting methods and eighteen supporting getters are metadata-pinned but not test-invocable. Fully trusted hostile reflection remains outside this structural conformance ceiling.

| Scenario | Required behavior |
|---|---|
| SC01 | Known short writes of 1 and 7 bytes, then the natural remaining 528 bytes; empty-script control |
| SC02 | Ordinary indeterminate attempt after zero or 3 copied bytes; terminal send direction and no retry |
| SC03 | Ordinary failed attempt after zero or 3 copied bytes; known-zero metadata grants no retry |
| SC04 | Hold a genuine full completion, then publish exactly once through its own controller |
| SC05 | Retire an ordinary or failure-frame held write as indeterminate/faulted, then reject late delivery without frame credit |
| SC06 | Expire a held write at its original effective deadline, then retire its late delivery lease |
| SC07 | Forward an unchanged genuine foreign envelope with equal numeric generation/operation values but different owner references |
| SC08 | Observe peer LocalFailure before an already-started outgoing LocalFailure completes; preserve the first cause and direction-specific rejection |
| SC09 | Closed construction/binding/delivery/disposal misuse, exact reflection boundaries and zero unretired driver ownership |

Protected expected preimages use distinct literal identifiers, nonces, digests, PIDs and time values for different semantic fields. Protocol-fixed profiles, origins, roles and sequences retain their required values. Expected field order is hand-authored, not obtained from the Runtime encoder or maintenance generator.

## Fresh checkout and validation

Use the reviewed LF checkout mechanism. Do not repair or normalize bytes after admission and do not edit frozen ancestor attributes:

```text
git -c core.autocrlf=false -c core.eol=lf clone --no-checkout https://github.com/JamesKehr/pspkt.git <fresh-root>
git -C <fresh-root> -c core.autocrlf=false -c core.eol=lf checkout --detach <reviewed-revision>
```

The validator has exactly three mandatory named-only parameters:

```text
powershell -NoLogo -NoProfile -File .\certification\broker-lifecycle\validators\Invoke-PspktPhase4BrokerLifecycleValidators.ps1 -RepositoryRoot <repo-root> -WorkRoot <fresh-owned-short-root> -PesterManifestPath <verified-pester-manifest>
pwsh -NoLogo -NoProfile -File .\certification\broker-lifecycle\validators\Invoke-PspktPhase4BrokerLifecycleValidators.ps1 -RepositoryRoot <repo-root> -WorkRoot <different-fresh-owned-short-root> -PesterManifestPath <verified-pester-manifest>
```

Each command needs a fresh host. Failed preflight consumes the AppDomain marker. There is no reset, skip-tests, selector, compile-only or repair mode. WorkRoot must be a fresh fixed-volume absolute path of at most100 characters, outside the source/export tree, with no detected reparse ancestors.

Pester5.3.3 is explicit, never selected merely by installed version. Its package is271297 bytes with SHA-256 `bf450611b92dee8de7dd5e69809d5b37f86bff9f8f3b6eb3129d2fbdd889b579`. Tool restoration belongs to orchestration, not the standalone validator.

A complete call retains exactly67 source paths, compiles/loads Bootstrap plus Runtime/M1-M6 under C#5, uses one retained plain-caller Pester container with ten Data identities, executes all32 fixed cases and requires six initialized semantic kills. SourceCount is1 for Bootstrap and31 for every Runtime-derived image. Failed compilation, setup or positive control is not a kill.

After success, only the eight declared image files and source-records.v1.json / validation-records.v1.json remain in the owned invocation directory. Compiler/TestDrive staging is removed; environment and PowerShell/.NET directories are restored. Loaded assemblies remain declared until host exit.

The separate failed-preflight probe uses its own fresh host and the same three parameters. It invokes the actual validator first with overlapping source/work roots, then with a valid external WorkRoot, proving work-root rejection followed by invocation-repeat with zero compilation/load/success output. Its successful proof deliberately exits1; it is not a second validation mode.

## Workflow and receipt boundary

`ci-broker-lifecycle.yml` has independent Desktop/Core jobs and an aggregate. There are four complete calls: checkout and actual67-path no-.git export on each host. Five actual result-boundary red steps per host are distinct from the additional failed-preflight red step per host.

The aggregate requires32 compilations,32 loads,24 initialized kills and128 passed cases, plus ten confirmed boundary reds and two confirmed preflight reds. It consumes eight separately staged, bounded transport values and binds the current run, attempt, revision and unique slot. It consumes GitHub's actual raw outcome string, not a probe's self-asserted failure.

Local parser/configuration fixtures and local success do not prove hosted execution. Neither local nor hosted success establishes native pipe authority, SCM status, process containment, S4U, candidate launch, product integration, durable evidence truth or F-7/F-8/F-9 certification.

Architecture selection considers only the variant-distinguishing probes actually executed. It does not waive any production acceptance obligation. Independent design approval, the bound Ready activation and separate implementation authorization gate editing; all 32 cases, both-host checkout/export calls and actual hosted four-call/ten-boundary-red/two-preflight-red evidence additionally gate completion/publication. A local workflow-context simulation remains parser/binding evidence, never GitHub-hosted execution.
