#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$SourceRoot,
    [Parameter(Mandatory = $true)]
    [string]$OutputRoot,
    [Parameter(Mandatory = $true)]
    [string]$CanonicalJsonPath,
    [Parameter(Mandatory = $true)]
    [string]$SchemaBootstrapAssemblyPath,
    [Parameter(Mandatory = $true)]
    [string]$EngineAssemblyPath,
    [Parameter(Mandatory = $true)]
    [string]$VerifyAssemblyPath,
    [Parameter(Mandatory = $true)]
    [string]$MetaPath,
    [Parameter(Mandatory = $true)]
    [string]$ResultPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. $CanonicalJsonPath
. (Join-Path $SourceRoot 'certification\lib\Pspkt.Certification.FoundationContract.ps1')

$contract = Get-PspktFoundationContract
Assert-PspktFoundationContract -Contract $contract
Add-Type -Path $SchemaBootstrapAssemblyPath
Add-Type -Path $EngineAssemblyPath
Add-Type -Path $VerifyAssemblyPath

function New-FoundationCatalog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Entries
    )

    return [ordered]@{
        schemaVersion = 1
        schemaId = $contract.CatalogSchemaId
        space = 'foundation'
        entries = $Entries
    }
}

function New-FoundationNamedEntries {
    [CmdletBinding()]
    param(
        [string]$TypeName = 'FoundationPayload',
        [string]$FieldName = 'FoundationValue',
        [string]$FieldType = 'U8'
    )

    return @(
        [ordered]@{ op = 'type'; name = $TypeName; production = 'Named' }
        [ordered]@{ op = 'field'; name = $FieldName; parent = $TypeName; type = $FieldType }
    )
}

function Copy-FoundationValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Value
    )

    return ((ConvertTo-PspktCanonicalJson -Value $Value) | ConvertFrom-Json)
}

function Add-FoundationFixture {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        [byte[]]$Bytes
    )

    $relativePath = "$($contract.FixtureRoot)/$Name"
    $fullPath = Resolve-PspktFoundationPath -Root $OutputRoot -RelativePath $relativePath
    $parent = Split-Path -Parent $fullPath
    [IO.Directory]::CreateDirectory($parent) | Out-Null
    if ([IO.File]::Exists($fullPath)) {
        throw "Fixture destination already exists: $relativePath"
    }
    [IO.File]::WriteAllBytes($fullPath, $Bytes)
    $script:fixtureBytes[$Name] = $Bytes
}

function Add-FoundationDocumentFixture {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        $Value
    )

    Add-FoundationFixture -Name $Name -Bytes (Get-PspktCanonicalJsonBytes -Value $Value)
}

function New-FoundationMessageCatalog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Messages,
        [object[]]$AdditionalEntries = @()
    )

    $entries = @(New-FoundationNamedEntries)
    $entries += $AdditionalEntries
    $entries += $Messages
    return New-FoundationCatalog -Entries $entries
}

$script:fixtureBytes = @{}
$validEmpty = Get-PspktCanonicalJsonBytes -Value (New-FoundationCatalog -Entries @())
Add-FoundationFixture -Name 'json-bom.json' -Bytes ([byte[]](@(0xEF, 0xBB, 0xBF) + $validEmpty))
Add-FoundationFixture -Name 'json-comment.json' -Bytes ([Text.Encoding]::UTF8.GetBytes('{"schemaVersion":1,//x' + "`n" + '"schemaId":"PspktFoundationCatalogV1","space":"foundation","entries":[]}'))
Add-FoundationFixture -Name 'json-duplicate-key.json' -Bytes ([Text.Encoding]::UTF8.GetBytes('{"entries":[],"schemaId":"PspktFoundationCatalogV1","schemaId":"PspktFoundationCatalogV1","schemaVersion":1,"space":"foundation"}'))
Add-FoundationFixture -Name 'json-trailing-comma.json' -Bytes ([Text.Encoding]::UTF8.GetBytes('{"entries":[],"schemaId":"PspktFoundationCatalogV1","schemaVersion":1,"space":"foundation",}'))

$orderEntries = @(
    [ordered]@{ op = 'type'; name = 'FoundationFirst'; production = 'Named' }
    [ordered]@{ op = 'field'; name = 'FoundationFirstValue'; parent = 'FoundationFirst'; type = 'U8' }
    [ordered]@{ op = 'type'; name = 'FoundationSecond'; production = 'Named' }
    [ordered]@{ op = 'field'; name = 'FoundationSecondValue'; parent = 'FoundationSecond'; type = 'U8' }
)
Add-FoundationDocumentFixture -Name 'order-ok.json' -Value (New-FoundationCatalog -Entries $orderEntries)
Add-FoundationDocumentFixture -Name 'order-reorder.json' -Value (New-FoundationCatalog -Entries @($orderEntries[2], $orderEntries[3], $orderEntries[0], $orderEntries[1]))
Add-FoundationDocumentFixture -Name 'extra-key.json' -Value (New-FoundationCatalog -Entries @([ordered]@{ op = 'type'; name = 'FoundationExtra'; production = 'Named'; unexpected = 1 }))
Add-FoundationDocumentFixture -Name 'missing-property.json' -Value (New-FoundationCatalog -Entries @([ordered]@{ op = 'type'; production = 'Named' }))
Add-FoundationDocumentFixture -Name 'duplicate-type-name.json' -Value (New-FoundationCatalog -Entries @(
    [ordered]@{ op = 'type'; name = 'FoundationDuplicate'; production = 'Named' }
    [ordered]@{ op = 'type'; name = 'FoundationDuplicate'; production = 'Named' }
))
Add-FoundationDocumentFixture -Name 'duplicate-field.json' -Value (New-FoundationCatalog -Entries @(
    [ordered]@{ op = 'type'; name = 'FoundationDuplicateFieldParent'; production = 'Named' }
    [ordered]@{ op = 'field'; name = 'FoundationDuplicateField'; parent = 'FoundationDuplicateFieldParent'; type = 'U8' }
    [ordered]@{ op = 'field'; name = 'FoundationDuplicateField'; parent = 'FoundationDuplicateFieldParent'; type = 'U16' }
))
Add-FoundationDocumentFixture -Name 'duplicate-kind.json' -Value (New-FoundationMessageCatalog -Messages @(
    [ordered]@{ op = 'message'; name = 'FoundationDuplicateMessage'; channel = 'FoundationAlpha'; direction = 'HostToWorker'; payloadRoot = 'FoundationPayload' }
    [ordered]@{ op = 'message'; name = 'FoundationDuplicateMessage'; channel = 'FoundationAlpha'; direction = 'HostToWorker'; payloadRoot = 'FoundationPayload' }
))
$mainCatalogPath = Resolve-PspktFoundationPath -Root $SourceRoot -RelativePath $contract.CatalogRelativePath
Add-FoundationFixture -Name 'emit-ok.json' -Bytes (Read-PspktFoundationBytes -LiteralPath $mainCatalogPath)
Add-FoundationDocumentFixture -Name 'primitive-unknown.json' -Value (New-FoundationCatalog -Entries @([ordered]@{ op = 'primitive'; name = 'NotAPrimitive' }))
Add-FoundationDocumentFixture -Name 'primitive-forbidden.json' -Value (New-FoundationCatalog -Entries @([ordered]@{ op = 'primitive'; name = 'I16' }))
Add-FoundationDocumentFixture -Name 'enum-members-ok.json' -Value (New-FoundationCatalog -Entries @([ordered]@{
    op = 'enum'
    name = 'FoundationEnum'
    members = @([ordered]@{ name = 'FoundationEnumZero' }, [ordered]@{ name = 'FoundationEnumTwo'; value = 2 })
}))
Add-FoundationDocumentFixture -Name 'enum-duplicate-name.json' -Value (New-FoundationCatalog -Entries @([ordered]@{
    op = 'enum'
    name = 'FoundationEnumDuplicateName'
    members = @([ordered]@{ name = 'FoundationMember'; value = 0 }, [ordered]@{ name = 'FoundationMember'; value = 1 })
}))
Add-FoundationDocumentFixture -Name 'enum-duplicate-value.json' -Value (New-FoundationCatalog -Entries @([ordered]@{
    op = 'enum'
    name = 'FoundationEnumDuplicateValue'
    members = @([ordered]@{ name = 'FoundationMemberA'; value = 1 }, [ordered]@{ name = 'FoundationMemberB'; value = 1 })
}))
Add-FoundationDocumentFixture -Name 'enum-value-overflow.json' -Value (New-FoundationCatalog -Entries @([ordered]@{
    op = 'enum'
    name = 'FoundationEnumOverflow'
    members = @([ordered]@{ name = 'FoundationMemberOverflow'; value = 65536 })
}))
Add-FoundationDocumentFixture -Name 'list-set-ok.json' -Value (New-FoundationCatalog -Entries @(
    [ordered]@{ op = 'enum'; name = 'FoundationCollectionElement'; members = @([ordered]@{ name = 'FoundationCollectionValue'; value = 0 }) }
    [ordered]@{ op = 'type'; name = 'FoundationList'; production = 'List'; elementType = 'FoundationCollectionElement'; minCount = 0; maxCount = 2 }
    [ordered]@{ op = 'type'; name = 'FoundationSet'; production = 'Set'; elementType = 'FoundationCollectionElement'; minCount = 0; maxCount = 2 }
))
Add-FoundationDocumentFixture -Name 'semantic-string-ok.json' -Value (New-FoundationCatalog -Entries @([ordered]@{
    op = 'type'
    name = 'FoundationText'
    production = 'SemanticString'
    encoding = 'Utf8'
    grammar = 'None'
    minBytes = 1
    maxBytes = 32
    maxUtf16CodeUnits = 32
}))
$overflowEntries = @([ordered]@{ op = 'type'; name = 'FoundationOverflowParent'; production = 'Named' })
for ($fieldIndex = 1; $fieldIndex -le 40; $fieldIndex++) {
    $overflowEntries += [ordered]@{
        op = 'field'
        name = "FoundationField$fieldIndex"
        parent = 'FoundationOverflowParent'
        type = 'U8'
    }
}
Add-FoundationDocumentFixture -Name 'field-overflow-40.json' -Value (New-FoundationCatalog -Entries $overflowEntries)
Add-FoundationDocumentFixture -Name 'field-undefined-parent.json' -Value (New-FoundationCatalog -Entries @([ordered]@{
    op = 'field'
    name = 'FoundationOrphan'
    parent = 'FoundationMissingParent'
    type = 'U8'
}))
Add-FoundationDocumentFixture -Name 'field40-extend-ok.json' -Value (New-FoundationCatalog -Entries @(
    [ordered]@{ op = 'type'; name = 'FoundationExtendParent'; production = 'Named' }
    [ordered]@{ op = 'field'; name = 'FoundationBaseField'; parent = 'FoundationExtendParent'; type = 'U8' }
    [ordered]@{ op = 'extend'; parent = 'FoundationExtendParent'; fields = @([ordered]@{ name = 'FoundationFieldForty'; id = 40; type = 'U16' }) }
))
Add-FoundationDocumentFixture -Name 'extend-invalid-parent.json' -Value (New-FoundationCatalog -Entries @([ordered]@{
    op = 'extend'
    parent = 'FoundationMissingParent'
    fields = @([ordered]@{ name = 'FoundationExtension'; id = 40; type = 'U8' })
}))
Add-FoundationDocumentFixture -Name 'extend-lt40.json' -Value (New-FoundationCatalog -Entries @(
    [ordered]@{ op = 'type'; name = 'FoundationExtendLowParent'; production = 'Named' }
    [ordered]@{ op = 'field'; name = 'FoundationExtendLowBase'; parent = 'FoundationExtendLowParent'; type = 'U8' }
    [ordered]@{ op = 'extend'; parent = 'FoundationExtendLowParent'; fields = @([ordered]@{ name = 'FoundationExtendLow'; id = 39; type = 'U8' }) }
))
Add-FoundationDocumentFixture -Name 'extend-missing-literal.json' -Value (New-FoundationCatalog -Entries @(
    [ordered]@{ op = 'type'; name = 'FoundationExtendMissingParent'; production = 'Named' }
    [ordered]@{ op = 'field'; name = 'FoundationExtendMissingBase'; parent = 'FoundationExtendMissingParent'; type = 'U8' }
    [ordered]@{ op = 'extend'; parent = 'FoundationExtendMissingParent'; fields = @([ordered]@{ name = 'FoundationExtendMissing'; type = 'U8' }) }
))
Add-FoundationDocumentFixture -Name 'extend-id-overflow.json' -Value (New-FoundationCatalog -Entries @(
    [ordered]@{ op = 'type'; name = 'FoundationExtendOverflowParent'; production = 'Named' }
    [ordered]@{ op = 'field'; name = 'FoundationExtendOverflowBase'; parent = 'FoundationExtendOverflowParent'; type = 'U8' }
    [ordered]@{ op = 'extend'; parent = 'FoundationExtendOverflowParent'; fields = @([ordered]@{ name = 'FoundationExtendOverflow'; id = 65536; type = 'U8' }) }
))
Add-FoundationDocumentFixture -Name 'extend-dup-name.json' -Value (New-FoundationCatalog -Entries @(
    [ordered]@{ op = 'type'; name = 'FoundationExtendNameParent'; production = 'Named' }
    [ordered]@{ op = 'field'; name = 'FoundationExistingName'; parent = 'FoundationExtendNameParent'; type = 'U8' }
    [ordered]@{ op = 'extend'; parent = 'FoundationExtendNameParent'; fields = @([ordered]@{ name = 'FoundationExistingName'; id = 40; type = 'U8' }) }
))
Add-FoundationDocumentFixture -Name 'extend-dup-id.json' -Value (New-FoundationCatalog -Entries @(
    [ordered]@{ op = 'type'; name = 'FoundationExtendIdParent'; production = 'Named' }
    [ordered]@{ op = 'field'; name = 'FoundationExtendIdBase'; parent = 'FoundationExtendIdParent'; type = 'U8' }
    [ordered]@{
        op = 'extend'
        parent = 'FoundationExtendIdParent'
        fields = @(
            [ordered]@{ name = 'FoundationExtendIdA'; id = 40; type = 'U8' }
            [ordered]@{ name = 'FoundationExtendIdB'; id = 40; type = 'U16' }
        )
    }
))
$unionValid = [ordered]@{
    op = 'union'
    name = 'FoundationUnion'
    discriminator = 'FoundationUnionKind'
    branches = @(
        [ordered]@{ name = 'FoundationUnionA'; fields = @([ordered]@{ name = 'FoundationUnionAValue'; type = 'U8' }) }
        [ordered]@{ name = 'FoundationUnionB'; fields = @([ordered]@{ name = 'FoundationUnionBValue'; type = 'U16' }) }
    )
}
Add-FoundationDocumentFixture -Name 'op-union-ok.json' -Value (New-FoundationCatalog -Entries @($unionValid))
Add-FoundationDocumentFixture -Name 'op-union-empty.json' -Value (New-FoundationCatalog -Entries @([ordered]@{
    op = 'union'
    name = 'FoundationEmptyUnion'
    discriminator = 'FoundationEmptyUnionKind'
    branches = @()
}))
Add-FoundationDocumentFixture -Name 'op-union-duplicate-branch.json' -Value (New-FoundationCatalog -Entries @([ordered]@{
    op = 'union'
    name = 'FoundationDuplicateUnion'
    discriminator = 'FoundationDuplicateUnionKind'
    branches = @(
        [ordered]@{ name = 'FoundationDuplicateBranch'; fields = @([ordered]@{ name = 'FoundationBranchValueA'; type = 'U8' }) }
        [ordered]@{ name = 'FoundationDuplicateBranch'; fields = @([ordered]@{ name = 'FoundationBranchValueB'; type = 'U16' }) }
    )
}))
Add-FoundationDocumentFixture -Name 'op-delete-ok.json' -Value (New-FoundationCatalog -Entries @(
    (New-FoundationNamedEntries -TypeName 'FoundationDeleteKeeper' -FieldName 'FoundationDeleteKeeperValue')
    [ordered]@{ op = 'type'; name = 'FoundationDeleteTarget'; production = 'Named' }
    [ordered]@{ op = 'field'; name = 'FoundationDeleteTargetValue'; parent = 'FoundationDeleteTarget'; type = 'U8' }
    [ordered]@{ op = 'delete'; name = 'FoundationDeleteTarget' }
))
Add-FoundationDocumentFixture -Name 'op-delete-unknown.json' -Value (New-FoundationCatalog -Entries @([ordered]@{ op = 'delete'; name = 'FoundationUnknownDelete' }))
Add-FoundationDocumentFixture -Name 'op-delete-double.json' -Value (New-FoundationCatalog -Entries @(
    [ordered]@{ op = 'type'; name = 'FoundationDoubleDelete'; production = 'Named' }
    [ordered]@{ op = 'delete'; name = 'FoundationDoubleDelete' }
    [ordered]@{ op = 'delete'; name = 'FoundationDoubleDelete' }
))
Add-FoundationDocumentFixture -Name 'op-delete-then-use.json' -Value (New-FoundationCatalog -Entries @(
    [ordered]@{ op = 'type'; name = 'FoundationDeletedUse'; production = 'Named' }
    [ordered]@{ op = 'field'; name = 'FoundationDeletedUseValue'; parent = 'FoundationDeletedUse'; type = 'U8' }
    [ordered]@{ op = 'delete'; name = 'FoundationDeletedUse' }
    [ordered]@{ op = 'type'; name = 'FoundationDeletedHolder'; production = 'Named' }
    [ordered]@{ op = 'field'; name = 'FoundationDeletedReference'; parent = 'FoundationDeletedHolder'; type = 'FoundationDeletedUse' }
))
Add-FoundationDocumentFixture -Name 'op-reserve-ok.json' -Value (New-FoundationCatalog -Entries @(
    (New-FoundationNamedEntries -TypeName 'FoundationReserveKeeper' -FieldName 'FoundationReserveKeeperValue')
    [ordered]@{ op = 'reserve-illegal-type'; name = 'FoundationReserved'; id = 4864 }
))
Add-FoundationDocumentFixture -Name 'op-reserve-missing.json' -Value (New-FoundationCatalog -Entries @([ordered]@{ op = 'reserve-illegal-type'; name = 'FoundationReservedMissing' }))
Add-FoundationDocumentFixture -Name 'op-reserve-out-of-range.json' -Value (New-FoundationCatalog -Entries @([ordered]@{ op = 'reserve-illegal-type'; name = 'FoundationReservedRange'; id = 4863 }))
Add-FoundationDocumentFixture -Name 'op-reserve-illegal-encoded.json' -Value (New-FoundationCatalog -Entries @(
    [ordered]@{ op = 'reserve-illegal-type'; name = 'FoundationReservedEncoded'; id = 4864 }
    [ordered]@{ op = 'type'; name = 'FoundationReservedHolder'; production = 'Named' }
    [ordered]@{ op = 'field'; name = 'FoundationReservedReference'; parent = 'FoundationReservedHolder'; type = 'FoundationReservedEncoded' }
))
Add-FoundationDocumentFixture -Name 'message-two-direction-ok.json' -Value (New-FoundationMessageCatalog -Messages @(
    [ordered]@{ op = 'message'; name = 'FoundationTwoDirection'; channel = 'FoundationAlpha'; direction = 'HostToWorker'; payloadRoot = 'FoundationPayload' }
    [ordered]@{ op = 'message'; name = 'FoundationTwoDirection'; channel = 'FoundationAlpha'; direction = 'WorkerToHost'; payloadRoot = 'FoundationPayload' }
))
Add-FoundationDocumentFixture -Name 'message-cross-channel-ok.json' -Value (New-FoundationMessageCatalog -Messages @(
    [ordered]@{ op = 'message'; name = 'FoundationCrossChannel'; channel = 'FoundationAlpha'; direction = 'HostToWorker'; payloadRoot = 'FoundationPayload' }
    [ordered]@{ op = 'message'; name = 'FoundationCrossChannel'; channel = 'FoundationBeta'; direction = 'HostToWorker'; payloadRoot = 'FoundationPayload' }
))
Add-FoundationDocumentFixture -Name 'message-undefined-payload.json' -Value (New-FoundationCatalog -Entries @([ordered]@{
    op = 'message'
    name = 'FoundationUndefinedPayload'
    channel = 'FoundationAlpha'
    direction = 'HostToWorker'
    payloadRoot = 'FoundationMissingPayload'
}))
Add-FoundationDocumentFixture -Name 'message-conflict.json' -Value (New-FoundationMessageCatalog -Messages @(
    [ordered]@{ op = 'message'; name = 'FoundationConflict'; channel = 'FoundationAlpha'; direction = 'HostToWorker'; payloadRoot = 'FoundationPayload' }
    [ordered]@{ op = 'message'; name = 'FoundationConflict'; channel = 'FoundationAlpha'; direction = 'WorkerToHost'; payloadRoot = 'FoundationOtherPayload' }
) -AdditionalEntries (New-FoundationNamedEntries -TypeName 'FoundationOtherPayload' -FieldName 'FoundationOtherValue'))
Add-FoundationDocumentFixture -Name 'invalid-channel.json' -Value (New-FoundationMessageCatalog -Messages @([ordered]@{
    op = 'message'
    name = 'FoundationInvalidChannel'
    channel = 'FoundationGamma'
    direction = 'HostToWorker'
    payloadRoot = 'FoundationPayload'
}))
Add-FoundationDocumentFixture -Name 'invalid-direction.json' -Value (New-FoundationMessageCatalog -Messages @([ordered]@{
    op = 'message'
    name = 'FoundationInvalidDirection'
    channel = 'FoundationAlpha'
    direction = 'Sideways'
    payloadRoot = 'FoundationPayload'
}))
Add-FoundationDocumentFixture -Name 'invalid-production.json' -Value (New-FoundationCatalog -Entries @([ordered]@{
    op = 'type'
    name = 'FoundationInvalidProduction'
    production = 'Tuple'
}))
Add-FoundationDocumentFixture -Name 'op-unknown.json' -Value (New-FoundationCatalog -Entries @([ordered]@{ op = 'mystery'; name = 'FoundationUnknownOp' }))
Add-FoundationDocumentFixture -Name 'op-replace-forbidden.json' -Value (New-FoundationCatalog -Entries @([ordered]@{ op = 'replace'; name = 'FoundationReplace' }))
Add-FoundationDocumentFixture -Name 'base-literal-id.json' -Value (New-FoundationCatalog -Entries @([ordered]@{
    op = 'type'
    name = 'FoundationLiteral'
    production = 'Named'
    id = 1
}))
Add-FoundationDocumentFixture -Name 'foundation-name-bad.json' -Value (New-FoundationCatalog -Entries @([ordered]@{
    op = 'type'
    name = 'BadFoundationName'
    production = 'Named'
}))
Add-FoundationDocumentFixture -Name 'field-defined-parent-ok.json' -Value (New-FoundationCatalog -Entries (New-FoundationNamedEntries -TypeName 'FoundationDefinedParent' -FieldName 'FoundationDefinedField'))

if ($script:fixtureBytes.Count -ne 52) {
    throw "Generated fixture count mismatch: $($script:fixtureBytes.Count)"
}

$catalogBytes = Read-PspktFoundationBytes -LiteralPath $mainCatalogPath
$mainResult = [Pspkt.Certification.FoundationEngine.FoundationCatalogV1]::Evaluate($catalogBytes)
if (-not $mainResult.Accepted) {
    throw "Main catalog evaluation failed: $($mainResult.Reason)"
}
$schemaPath = Resolve-PspktFoundationPath -Root $OutputRoot -RelativePath $contract.SchemaRelativePath
$mapPath = Resolve-PspktFoundationPath -Root $OutputRoot -RelativePath $contract.MapRelativePath
[IO.Directory]::CreateDirectory((Split-Path -Parent $schemaPath)) | Out-Null
[IO.File]::WriteAllBytes($schemaPath, $mainResult.SchemaBytes)
[IO.File]::WriteAllBytes($mapPath, $mainResult.IdMapBytes)
$metaBytes = Read-PspktFoundationBytes -LiteralPath $MetaPath
$schemaCheck = [Pspkt.Certification.SchemaBootstrap]::Evaluate('schema-against-meta', $mainResult.SchemaBytes, $metaBytes)
if (-not $schemaCheck.Accepted) {
    throw "Main schema validation failed: $($schemaCheck.Reason)"
}
$catalogSha = Get-PspktFoundationSha256 -Bytes $catalogBytes
$schemaSha = Get-PspktFoundationSha256 -Bytes $mainResult.SchemaBytes
$mapSha = Get-PspktFoundationSha256 -Bytes $mainResult.IdMapBytes
$verify = [Pspkt.Certification.FoundationVerify.FoundationVerifier]::Verify(
    $catalogBytes,
    $mainResult.SchemaBytes,
    $mainResult.IdMapBytes,
    $metaBytes)
if (-not $verify.Accepted) {
    throw "Independent verification failed: $($verify.Reason)"
}

$orderOk = [Pspkt.Certification.FoundationEngine.FoundationCatalogV1]::Evaluate($script:fixtureBytes['order-ok.json'])
if (-not $orderOk.Accepted) {
    throw "order-ok generation failed: $($orderOk.Reason)"
}
$cases = @()
foreach ($fixtureName in $contract.FixtureNames) {
    $bytes = $script:fixtureBytes[$fixtureName]
    $expectedReason = [string]$contract.ExpectedReasons[$fixtureName]
    if ($fixtureName -eq 'order-reorder.json') {
        $replay = [Pspkt.Certification.FoundationEngine.FoundationCatalogV1]::Replay(
            $bytes,
            $orderOk.SchemaBytes,
            $orderOk.IdMapBytes)
        $actualReason = $replay.Reason
    }
    else {
        $evaluation = [Pspkt.Certification.FoundationEngine.FoundationCatalogV1]::Evaluate($bytes)
        $actualReason = $evaluation.Reason
        if ($evaluation.Accepted) {
            $fixtureSchemaCheck = [Pspkt.Certification.SchemaBootstrap]::Evaluate('schema-against-meta', $evaluation.SchemaBytes, $metaBytes)
            if (-not $fixtureSchemaCheck.Accepted) {
                throw "$fixtureName emitted invalid schema: $($fixtureSchemaCheck.Reason)"
            }
        }
    }
    if ($actualReason -ne $expectedReason) {
        throw "$fixtureName expected $expectedReason but received $actualReason"
    }
    $case = [ordered]@{
        name = $fixtureName.Substring(0, $fixtureName.Length - 5)
        path = "$($contract.FixtureRoot)/$fixtureName"
        expectedReason = $expectedReason
        length = $bytes.Length
        sha256 = Get-PspktFoundationSha256 -Bytes $bytes
    }
    $cases += $case
}
$manifest = [ordered]@{
    schemaVersion = 1
    schemaId = $contract.ManifestSchemaId
    catalogSha256 = $catalogSha
    schemaSha256 = $schemaSha
    mapSha256 = $mapSha
    cases = $cases
}
$manifestPath = Resolve-PspktFoundationPath -Root $OutputRoot -RelativePath $contract.ManifestRelativePath
[IO.File]::WriteAllBytes($manifestPath, (Get-PspktCanonicalJsonBytes -Value $manifest))

$result = [ordered]@{
    schemaVersion = 1
    schemaId = 'PspktFoundationGeneratorResultV1'
    fixtureCount = 52
    outputCount = 55
    catalogSha256 = $catalogSha
    schemaSha256 = $schemaSha
    mapSha256 = $mapSha
    manifestSha256 = Get-PspktFoundationSha256 -Bytes ([IO.File]::ReadAllBytes($manifestPath))
}
$resultBytes = Get-PspktCanonicalJsonBytes -Value $result
if ([IO.File]::Exists($ResultPath)) {
    throw "Result destination exists: $ResultPath"
}
[IO.File]::WriteAllBytes($ResultPath, $resultBytes)
