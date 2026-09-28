Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-PspktFoundationContract {
    [CmdletBinding()]
    param()

    $inputPaths = @(
        'certification/.gitattributes'
        'tests/.gitattributes'
        'certification/schema/catalog/foundation.catalog.v1.json'
        'certification/lib/Pspkt.Certification.FoundationCatalogEngine.cs'
        'certification/lib/Pspkt.Certification.FoundationPolicy.cs'
        'certification/lib/Pspkt.Certification.FoundationVerify.cs'
        'certification/lib/Pspkt.Certification.FoundationContract.ps1'
        'certification/vectors/New-PspktPhase4SchemaAuthorityFoundationVectors.ps1'
        'certification/validators/Invoke-PspktPhase4SchemaAuthorityFoundationValidators.ps1'
        'certification/validators/Test-PspktPhase4SchemaAuthorityFoundation.ps1'
        'tests/pspkt.Phase4SchemaAuthorityFoundation.Tests.ps1'
    )
    $fixtureNames = @(
        'json-bom.json'
        'json-comment.json'
        'json-duplicate-key.json'
        'json-trailing-comma.json'
        'order-ok.json'
        'order-reorder.json'
        'extra-key.json'
        'missing-property.json'
        'duplicate-type-name.json'
        'duplicate-field.json'
        'duplicate-kind.json'
        'emit-ok.json'
        'primitive-unknown.json'
        'primitive-forbidden.json'
        'enum-members-ok.json'
        'enum-duplicate-name.json'
        'enum-duplicate-value.json'
        'enum-value-overflow.json'
        'list-set-ok.json'
        'semantic-string-ok.json'
        'field-overflow-40.json'
        'field-undefined-parent.json'
        'field40-extend-ok.json'
        'extend-invalid-parent.json'
        'extend-lt40.json'
        'extend-missing-literal.json'
        'extend-id-overflow.json'
        'extend-dup-name.json'
        'extend-dup-id.json'
        'op-union-ok.json'
        'op-union-empty.json'
        'op-union-duplicate-branch.json'
        'op-delete-ok.json'
        'op-delete-unknown.json'
        'op-delete-double.json'
        'op-delete-then-use.json'
        'op-reserve-ok.json'
        'op-reserve-missing.json'
        'op-reserve-out-of-range.json'
        'op-reserve-illegal-encoded.json'
        'message-two-direction-ok.json'
        'message-cross-channel-ok.json'
        'message-undefined-payload.json'
        'message-conflict.json'
        'invalid-channel.json'
        'invalid-direction.json'
        'invalid-production.json'
        'op-unknown.json'
        'op-replace-forbidden.json'
        'base-literal-id.json'
        'foundation-name-bad.json'
        'field-defined-parent-ok.json'
    )
    $fixtureRoot = 'certification/vectors/phase4-schema-authority-foundation'
    $outputPaths = @(
        'certification/schema/foundation-schema.v1.json'
        'certification/schema/foundation-id-map.v1.json'
        "$fixtureRoot/fixture-manifest.v1.json"
    )
    $outputPaths += @($fixtureNames | ForEach-Object { "$fixtureRoot/$_" })
    $reasonCodes = @(
        'ok'
        'extra-key'
        'missing-property'
        'op-unknown'
        'op-replace-forbidden'
        'foundation-name'
        'base-literal-id'
        'unknown-primitive'
        'primitive-forbidden'
        'invalid-production'
        'invalid-direction'
        'invalid-channel'
        'field-undefined-parent'
        'extend-invalid-parent'
        'undefined-payload-root'
        'delete-unknown'
        'delete-double'
        'delete-then-use'
        'reserve-missing-literal'
        'reserve-id-out-of-range'
        'reserve-illegal-encoded'
        'enum-duplicate-name'
        'enum-duplicate-value'
        'enum-value-overflow'
        'union-empty'
        'union-duplicate-branch'
        'extend-lt40'
        'extend-missing-literal'
        'extend-id-overflow'
        'extend-dup-name'
        'extend-dup-id'
        'message-metadata-conflict'
        'duplicate-kind'
        'duplicate-identifier'
        'field-overflow-40'
        'reserved-kind-range'
        'reserved-type-range'
        'generated-id-overflow'
        'type-cycle'
        'id-map-drift'
        'map-tamper'
        'init-precondition'
        'init-recovery-required'
        'init-already'
        'bom-forbidden'
        'comment-forbidden'
        'duplicate-key'
        'trailing-comma'
    )
    $expectedReasons = [ordered]@{
        'json-bom.json' = 'bom-forbidden'
        'json-comment.json' = 'comment-forbidden'
        'json-duplicate-key.json' = 'duplicate-key'
        'json-trailing-comma.json' = 'trailing-comma'
        'order-ok.json' = 'ok'
        'order-reorder.json' = 'id-map-drift'
        'extra-key.json' = 'extra-key'
        'missing-property.json' = 'missing-property'
        'duplicate-type-name.json' = 'duplicate-identifier'
        'duplicate-field.json' = 'duplicate-identifier'
        'duplicate-kind.json' = 'duplicate-kind'
        'emit-ok.json' = 'ok'
        'primitive-unknown.json' = 'unknown-primitive'
        'primitive-forbidden.json' = 'primitive-forbidden'
        'enum-members-ok.json' = 'ok'
        'enum-duplicate-name.json' = 'enum-duplicate-name'
        'enum-duplicate-value.json' = 'enum-duplicate-value'
        'enum-value-overflow.json' = 'enum-value-overflow'
        'list-set-ok.json' = 'ok'
        'semantic-string-ok.json' = 'ok'
        'field-overflow-40.json' = 'field-overflow-40'
        'field-undefined-parent.json' = 'field-undefined-parent'
        'field40-extend-ok.json' = 'ok'
        'extend-invalid-parent.json' = 'extend-invalid-parent'
        'extend-lt40.json' = 'extend-lt40'
        'extend-missing-literal.json' = 'extend-missing-literal'
        'extend-id-overflow.json' = 'extend-id-overflow'
        'extend-dup-name.json' = 'extend-dup-name'
        'extend-dup-id.json' = 'extend-dup-id'
        'op-union-ok.json' = 'ok'
        'op-union-empty.json' = 'union-empty'
        'op-union-duplicate-branch.json' = 'union-duplicate-branch'
        'op-delete-ok.json' = 'ok'
        'op-delete-unknown.json' = 'delete-unknown'
        'op-delete-double.json' = 'delete-double'
        'op-delete-then-use.json' = 'delete-then-use'
        'op-reserve-ok.json' = 'ok'
        'op-reserve-missing.json' = 'reserve-missing-literal'
        'op-reserve-out-of-range.json' = 'reserve-id-out-of-range'
        'op-reserve-illegal-encoded.json' = 'reserve-illegal-encoded'
        'message-two-direction-ok.json' = 'ok'
        'message-cross-channel-ok.json' = 'ok'
        'message-undefined-payload.json' = 'undefined-payload-root'
        'message-conflict.json' = 'message-metadata-conflict'
        'invalid-channel.json' = 'invalid-channel'
        'invalid-direction.json' = 'invalid-direction'
        'invalid-production.json' = 'invalid-production'
        'op-unknown.json' = 'op-unknown'
        'op-replace-forbidden.json' = 'op-replace-forbidden'
        'base-literal-id.json' = 'base-literal-id'
        'foundation-name-bad.json' = 'foundation-name'
        'field-defined-parent-ok.json' = 'ok'
    }
    [pscustomobject]@{
        BaselineOid = '2056af494d9a545e58842fee10c2e611ba353c65'
        Branch = 'bb-phase4-schema-authority-1ba'
        InputPathSet = $inputPaths
        OutputPathSet = $outputPaths
        Allowlist = @($inputPaths + $outputPaths)
        FixtureNames = $fixtureNames
        ExpectedReasons = $expectedReasons
        ApplicableReasonCodes = $reasonCodes
        FixtureRoot = $fixtureRoot
        CatalogRelativePath = 'certification/schema/catalog/foundation.catalog.v1.json'
        SchemaRelativePath = 'certification/schema/foundation-schema.v1.json'
        MapRelativePath = 'certification/schema/foundation-id-map.v1.json'
        ManifestRelativePath = "$fixtureRoot/fixture-manifest.v1.json"
        CatalogSchemaId = 'PspktFoundationCatalogV1'
        EmitSchemaId = 'PspktFoundationSchemaV1'
        MapSchemaId = 'PspktFoundationIdMapV1'
        ManifestSchemaId = 'PspktFoundationFixtureManifestV1'
        ExecutionPrestateSchemaId = 'PspktFoundationExecutionPrestateV3'
        RecoveryJournalSchemaId = 'PspktFoundationRecoveryJournalV1'
        InitReceiptSchemaId = 'PspktFoundationInitReceiptV1'
        ReplayReceiptSchemaId = 'PspktFoundationReplayReceiptV2'
        CompletionReceiptSchemaId = 'PspktFoundationCompletionReceiptV1'
        CandidateInputFileMaximumBytes = 1048576
        CandidateInputAggregateMaximumBytes = 8388608
        PrestateMaximumBytes = 67108864
        AuthorityReceiptFileMaximumBytes = 1048576
        AuthorityReceiptAggregateMaximumBytes = 3145728
        GeneratedOutputFileMaximumBytes = 1048576
        GeneratedOutputAggregateMaximumBytes = 16777216
        GitScalarMaximumBytes = 1048576
        GitNulPathMaximumBytes = 16777216
        GitLogicalProjectionMaximumBytes = 16777216
        GitLogicalProjectionAggregateMaximumBytes = 33554432
        RecoveryJournalSegmentMaximumBytes = 16384
        RecoveryJournalMaximumBytes = 33554432
        RecoveryJournalMaximumSegments = 1536
        RecoveryJournalEvidenceReserveBytes = 8388608
        PesterMinimumVersion = '5.3.3'
        OneAChildContractTimeoutSeconds = 180
        OneAEmpiricalRuntimeSeconds = 385
        OneASupervisorTimeoutMilliseconds = 600000
        BoundedProcessLength = 564872
        BoundedProcessSha256 = '6aa8cfe7ef705b1ee27c88ae18f9f5f9fafedc1eec1caee598795ef893eccffb'
        BoundedProcessOid = '8a0cdf88652444f07abd3259a6c078181761f0ab'
        CanonicalJsonLength = 8689
        CanonicalJsonSha256 = '414975df1d4b5d04d9b72a95fcaad7e8fc922b17ee0e969da856c463fc3718c3'
        SchemaBootstrapLength = 76371
        SchemaBootstrapSha256 = 'a86608847c7fdfeee4da43c50545a77a5c4b51d2e12ea77fa61f2ae4a4617f66'
        MetaLength = 4146
        MetaSha256 = '9b13be426d37e3da01870ff32ec5c4e5db63e9699566a1978007e1f8c07fcd2c'
    }
}

function Get-PspktFoundationSha256 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$Bytes
    )

    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $hash = $sha.ComputeHash($Bytes)
        return ([BitConverter]::ToString($hash)).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $sha.Dispose()
    }
}

function Read-PspktFoundationBytes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$LiteralPath,
        [int64]$MaximumLength = 1048576
    )

    $item = Get-Item -LiteralPath $LiteralPath -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $item.PSIsContainer) {
        throw "Expected ordinary file: $LiteralPath"
    }
    if ($item.Length -gt $MaximumLength) {
        throw "File exceeds cap: $LiteralPath"
    }
    return [IO.File]::ReadAllBytes($item.FullName)
}

function Resolve-PspktFoundationPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Root,
        [Parameter(Mandatory = $true)]
        [string]$RelativePath
    )

    if ([IO.Path]::IsPathRooted($RelativePath) -or $RelativePath.Contains('\') -or $RelativePath.Contains('..')) {
        throw "Invalid repository-relative path: $RelativePath"
    }
    $rootPath = [IO.Path]::GetFullPath($Root).TrimEnd('\') + '\'
    $fullPath = [IO.Path]::GetFullPath((Join-Path $Root $RelativePath.Replace('/', '\')))
    if (-not $fullPath.StartsWith($rootPath, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Path escapes root: $RelativePath"
    }
    return $fullPath
}

function Assert-PspktFoundationContract {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Contract
    )

    if ($Contract.InputPathSet.Count -ne 11 -or $Contract.OutputPathSet.Count -ne 55 -or $Contract.Allowlist.Count -ne 66) {
        throw 'Foundation path-set count mismatch.'
    }
    if (($Contract.Allowlist | Sort-Object -Unique).Count -ne 66) {
        throw 'Foundation allowlist contains duplicates.'
    }
    if (@($Contract.InputPathSet | Where-Object { $Contract.OutputPathSet -contains $_ }).Count -ne 0) {
        throw 'Foundation path sets intersect.'
    }
    if ($Contract.FixtureNames.Count -ne 52 -or $Contract.ExpectedReasons.Count -ne 52) {
        throw 'Foundation fixture count mismatch.'
    }
}
