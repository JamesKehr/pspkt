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
    [string]$MetaPath
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
$metaBytes = Read-PspktFoundationBytes -LiteralPath $MetaPath
$manifestPath = Resolve-PspktFoundationPath -Root $OutputRoot -RelativePath $contract.ManifestRelativePath
$manifestBytes = Read-PspktFoundationBytes -LiteralPath $manifestPath
$manifestJson = [Text.Encoding]::UTF8.GetString($manifestBytes)
$manifest = $manifestJson | ConvertFrom-Json

function Assert-Foundation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [bool]$Condition,
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    if (-not $Condition) {
        throw $Message
    }
}

function New-TestPolicy {
    [CmdletBinding()]
    param(
        [Pspkt.Certification.FoundationEngine.GeneratedIdRange]$ReservedTypeRange,
        [Pspkt.Certification.FoundationEngine.GeneratedIdRange[]]$ReservedKindRanges = @()
    )

    $messageEnums = [Collections.Generic.Dictionary[string,string]]::new([StringComparer]::Ordinal)
    $messageEnums.Add('WorkerApp', 'WorkerAppMessageKind')
    $kindRanges = [Collections.Generic.Dictionary[string,Pspkt.Certification.FoundationEngine.GeneratedIdRange[]]]::new([StringComparer]::Ordinal)
    $kindRanges.Add('WorkerApp', $ReservedKindRanges)
    return [Pspkt.Certification.FoundationEngine.FoundationPolicyContract]::new(
        '^[A-Z][A-Za-z0-9]*$',
        [string[]]@('WorkerApp'),
        $messageEnums,
        [string[]]@('HostToWorker', 'WorkerToHost'),
        $kindRanges,
        $ReservedTypeRange,
        39,
        $true,
        'GenericCatalogV1',
        'GenericSchemaV1',
        [string[]]@('primitive', 'enum', 'type', 'field', 'message', 'union', 'delete', 'extend', 'reserve-illegal-type'))
}

function New-GenericCatalogBytes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Entries
    )

    return Get-PspktCanonicalJsonBytes -Value ([ordered]@{
        schemaVersion = 1
        schemaId = 'GenericCatalogV1'
        space = 'generic'
        entries = $Entries
    })
}

function Copy-FoundationValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Value
    )

    return ((ConvertTo-PspktCanonicalJson -Value $Value) | ConvertFrom-Json)
}

function Invoke-Generic {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$Bytes,
        [Parameter(Mandatory = $true)]
        [Pspkt.Certification.FoundationEngine.FoundationPolicyContract]$Policy
    )

    $evaluation = [Pspkt.Certification.FoundationEngine.FoundationCatalogEngineV1]::EvaluateJson($Bytes, $Policy)
    if (-not $evaluation.Accepted) {
        return $evaluation
    }
    $expansion = [Pspkt.Certification.FoundationEngine.FoundationCatalogEngineV1]::Expand($evaluation, $Policy)
    if (-not $expansion.Accepted) {
        return $expansion
    }
    $assignment = [Pspkt.Certification.FoundationEngine.FoundationCatalogEngineV1]::Assign($expansion, $Policy)
    if (-not $assignment.Accepted) {
        return $assignment
    }
    return [Pspkt.Certification.FoundationEngine.FoundationCatalogEngineV1]::Emit($assignment, $Policy)
}

Assert-Foundation -Condition ($manifest.schemaVersion -eq 1) -Message 'Manifest schema version mismatch.'
Assert-Foundation -Condition ($manifest.schemaId -eq $contract.ManifestSchemaId) -Message 'Manifest schema identifier mismatch.'
Assert-Foundation -Condition (@($manifest.cases).Count -eq 52) -Message 'Manifest case count mismatch.'
$caseNames = @($manifest.cases | ForEach-Object { "$($_.name).json" })
Assert-Foundation -Condition (@(Compare-Object $contract.FixtureNames $caseNames).Count -eq 0) -Message 'Manifest fixture set mismatch.'

$observedReasons = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$orderOkResult = $null
foreach ($case in $manifest.cases) {
    $fixtureName = "$($case.name).json"
    $fixturePath = Resolve-PspktFoundationPath -Root $OutputRoot -RelativePath ([string]$case.path)
    $fixtureBytes = Read-PspktFoundationBytes -LiteralPath $fixturePath
    Assert-Foundation -Condition ($fixtureBytes.Length -eq [int]$case.length) -Message "$fixtureName length mismatch."
    Assert-Foundation -Condition ((Get-PspktFoundationSha256 -Bytes $fixtureBytes) -eq [string]$case.sha256) -Message "$fixtureName hash mismatch."
    if ($fixtureName -eq 'order-ok.json') {
        $orderOkResult = [Pspkt.Certification.FoundationEngine.FoundationCatalogV1]::Evaluate($fixtureBytes)
    }
    if ($fixtureName -eq 'order-reorder.json') {
        $evaluation = [Pspkt.Certification.FoundationEngine.FoundationCatalogV1]::Evaluate($fixtureBytes)
        Assert-Foundation -Condition $evaluation.Accepted -Message 'order-reorder must be independently valid.'
        $result = [Pspkt.Certification.FoundationEngine.FoundationCatalogV1]::Replay(
            $fixtureBytes,
            $orderOkResult.SchemaBytes,
            $orderOkResult.IdMapBytes)
    }
    else {
        $result = [Pspkt.Certification.FoundationEngine.FoundationCatalogV1]::Evaluate($fixtureBytes)
    }
    Assert-Foundation -Condition ($result.Reason -eq [string]$case.expectedReason) -Message "$fixtureName reason mismatch."
    $observedReasons.Add([string]$result.Reason) | Out-Null
    if ($result.Accepted) {
        $schemaCheck = [Pspkt.Certification.SchemaBootstrap]::Evaluate('schema-against-meta', $result.SchemaBytes, $metaBytes)
        Assert-Foundation -Condition $schemaCheck.Accepted -Message "$fixtureName schema invalid: $($schemaCheck.Reason)"
    }
}

$catalogPath = Resolve-PspktFoundationPath -Root $SourceRoot -RelativePath $contract.CatalogRelativePath
$schemaPath = Resolve-PspktFoundationPath -Root $OutputRoot -RelativePath $contract.SchemaRelativePath
$mapPath = Resolve-PspktFoundationPath -Root $OutputRoot -RelativePath $contract.MapRelativePath
$catalogBytes = Read-PspktFoundationBytes -LiteralPath $catalogPath
$schemaBytes = Read-PspktFoundationBytes -LiteralPath $schemaPath
$mapBytes = Read-PspktFoundationBytes -LiteralPath $mapPath
Assert-Foundation -Condition ((Get-PspktFoundationSha256 -Bytes $catalogBytes) -eq [string]$manifest.catalogSha256) -Message 'Catalog oracle mismatch.'
Assert-Foundation -Condition ((Get-PspktFoundationSha256 -Bytes $schemaBytes) -eq [string]$manifest.schemaSha256) -Message 'Schema oracle mismatch.'
Assert-Foundation -Condition ((Get-PspktFoundationSha256 -Bytes $mapBytes) -eq [string]$manifest.mapSha256) -Message 'Map oracle mismatch.'
$verification = [Pspkt.Certification.FoundationVerify.FoundationVerifier]::Verify(
    $catalogBytes,
    $schemaBytes,
    $mapBytes,
    $metaBytes)
Assert-Foundation -Condition $verification.Accepted -Message "Independent verifier rejected outputs: $($verification.Reason)"
$verifyMethod = [Pspkt.Certification.FoundationVerify.FoundationVerifier].GetMethod('Verify')
Assert-Foundation -Condition ($verifyMethod.GetParameters().Count -eq 4) -Message 'Independent verifier accepts caller-supplied oracles.'
$unrelatedCatalog = New-GenericCatalogBytes -Entries @([ordered]@{
    op = 'enum'
    name = 'Unrelated'
    members = @([ordered]@{ name = 'UnrelatedValue'; value = 0 })
})
$unrelatedVerification = [Pspkt.Certification.FoundationVerify.FoundationVerifier]::Verify(
    $unrelatedCatalog,
    $schemaBytes,
    $mapBytes,
    $metaBytes)
Assert-Foundation -Condition (-not $unrelatedVerification.Accepted) -Message 'Independent verifier accepted an unrelated catalog.'
$verifierMap = [Text.Encoding]::UTF8.GetString($mapBytes) | ConvertFrom-Json
$verifierMap[0] | Add-Member -NotePropertyName extra -NotePropertyValue 1
$verifierExtra = [Pspkt.Certification.FoundationVerify.FoundationVerifier]::Verify(
    $catalogBytes,
    $schemaBytes,
    (Get-PspktCanonicalJsonBytes -Value $verifierMap),
    $metaBytes)
Assert-Foundation -Condition (-not $verifierExtra.Accepted) -Message 'Independent verifier accepted a map extra field.'
$verifierMap = [Text.Encoding]::UTF8.GetString($mapBytes) | ConvertFrom-Json
$verifierMap[0].generatedId = [int]$verifierMap[0].generatedId + 1
$verifierMutation = [Pspkt.Certification.FoundationVerify.FoundationVerifier]::Verify(
    $catalogBytes,
    $schemaBytes,
    (Get-PspktCanonicalJsonBytes -Value $verifierMap),
    $metaBytes)
Assert-Foundation -Condition (-not $verifierMutation.Accepted) -Message 'Independent verifier accepted a mutated map field.'

$verifyAssembly = [Reflection.Assembly]::Load([IO.File]::ReadAllBytes($VerifyAssemblyPath))
Assert-Foundation -Condition (@($verifyAssembly.GetTypes() | Where-Object { $_.FullName -match 'FoundationCatalogEngineV1' }).Count -eq 0) -Message 'Verifier contains engine type.'
$verifySource = [IO.File]::ReadAllText((Join-Path $SourceRoot 'certification\lib\Pspkt.Certification.FoundationVerify.cs'))
Assert-Foundation -Condition ($verifySource -notmatch 'FoundationEngineVersion|ExpandResult|AssignResult') -Message 'Verifier source shares forbidden engine symbols.'
$engineSource = [IO.File]::ReadAllText((Join-Path $SourceRoot 'certification\lib\Pspkt.Certification.FoundationCatalogEngine.cs'))
Assert-Foundation -Condition ($engineSource -notmatch 'FoundationAlpha|FoundationBeta|\^Foundation\[A-Z\]') -Message 'Generic engine contains Foundation policy literals.'
$engineAssembly = [Pspkt.Certification.FoundationEngine.FoundationCatalogEngineV1].Assembly
$nativeMethods = @($engineAssembly.GetTypes() | ForEach-Object { $_.GetMethods([Reflection.BindingFlags]'Public,NonPublic,Static,Instance') } | Where-Object {
    $_.GetCustomAttributes([Runtime.InteropServices.DllImportAttribute], $false).Count -gt 0
})
Assert-Foundation -Condition ($nativeMethods.Count -eq 0) -Message 'Candidate engine assembly contains native filesystem imports.'
$expansionType = [Pspkt.Certification.FoundationEngine.FoundationCatalogExpansion]
Assert-Foundation -Condition ($null -eq $expansionType.GetProperty('TypeNext')) -Message 'Expansion exposes a public type cursor.'
Assert-Foundation -Condition ($null -eq $expansionType.GetMethod('GetKindNext')) -Message 'Expansion exposes a public kind cursor reader.'
Assert-Foundation -Condition ($null -eq $expansionType.GetMethod('SetKindNext')) -Message 'Expansion exposes a public kind cursor writer.'

$genericPolicy = New-TestPolicy
$genericBytes = New-GenericCatalogBytes -Entries @(
    [ordered]@{ op = 'type'; name = 'Payload'; production = 'Named' }
    [ordered]@{ op = 'field'; name = 'Value'; parent = 'Payload'; type = 'U8' }
    [ordered]@{ op = 'message'; name = 'Ping'; channel = 'WorkerApp'; direction = 'HostToWorker'; payloadRoot = 'Payload' }
    [ordered]@{ op = 'message'; name = 'Pong'; channel = 'WorkerApp'; direction = 'WorkerToHost'; payloadRoot = 'Payload' }
)
$genericResult = Invoke-Generic -Bytes $genericBytes -Policy $genericPolicy
Assert-Foundation -Condition $genericResult.Accepted -Message "Generic no-hardcode proof failed: $($genericResult.Reason)"
$invalidChannelBeforeDirection = Invoke-Generic -Bytes (New-GenericCatalogBytes -Entries @(
    [ordered]@{ op = 'type'; name = 'Payload'; production = 'Named' }
    [ordered]@{ op = 'message'; name = 'Invalid'; channel = 'UnknownChannel'; direction = 'UnknownDirection'; payloadRoot = 'Payload' }
)) -Policy $genericPolicy
Assert-Foundation -Condition ($invalidChannelBeforeDirection.Reason -eq 'invalid-channel') -Message 'Invalid channel did not take precedence over invalid direction.'
$nestedExtra = Invoke-Generic -Bytes (New-GenericCatalogBytes -Entries @([ordered]@{
    op = 'enum'
    name = 'NestedExtra'
    members = @([ordered]@{ name = 'NestedExtraValue'; value = 0; extra = 1 })
})) -Policy $genericPolicy
Assert-Foundation -Condition ($nestedExtra.Reason -eq 'extra-key') -Message 'Nested extra key was not rejected.'
$nestedMissing = Invoke-Generic -Bytes (New-GenericCatalogBytes -Entries @([ordered]@{
    op = 'enum'
    name = 'NestedMissing'
    members = @([ordered]@{ value = 0 })
})) -Policy $genericPolicy
Assert-Foundation -Condition ($nestedMissing.Reason -eq 'missing-property') -Message 'Nested missing property was not rejected.'
$productionExtra = Invoke-Generic -Bytes (New-GenericCatalogBytes -Entries @([ordered]@{
    op = 'type'
    name = 'ProductionExtra'
    production = 'Named'
    elementType = 'U8'
})) -Policy $genericPolicy
Assert-Foundation -Condition ($productionExtra.Reason -eq 'extra-key') -Message 'Production-specific extra key was not rejected.'
$semanticStringLiteralId = Invoke-Generic -Bytes (New-GenericCatalogBytes -Entries @([ordered]@{
    op = 'type'
    name = 'SemanticLiteral'
    production = 'SemanticString'
    encoding = 'Utf8'
    grammar = 'None'
    minBytes = 1
    maxBytes = 16
    maxUtf16CodeUnits = 16
    id = 1
})) -Policy $genericPolicy
Assert-Foundation -Condition ($semanticStringLiteralId.Reason -eq 'base-literal-id') -Message 'SemanticString literal identifier reason mismatch.'
$semanticStringExtra = Invoke-Generic -Bytes (New-GenericCatalogBytes -Entries @([ordered]@{
    op = 'type'
    name = 'SemanticExtra'
    production = 'SemanticString'
    encoding = 'Utf8'
    grammar = 'None'
    minBytes = 1
    maxBytes = 16
    maxUtf16CodeUnits = 16
    id = 1
    extra = 1
})) -Policy $genericPolicy
Assert-Foundation -Condition ($semanticStringExtra.Reason -eq 'extra-key') -Message 'SemanticString extra-key precedence mismatch.'
$emptyCatalogBytes = New-GenericCatalogBytes -Entries @()
$emptyCatalogEvaluation = [Pspkt.Certification.FoundationEngine.FoundationCatalogEngineV1]::EvaluateJson($emptyCatalogBytes, $genericPolicy)
Assert-Foundation -Condition $emptyCatalogEvaluation.Accepted -Message "Empty catalog JSON evaluation failed early: $($emptyCatalogEvaluation.Reason)"
$emptyCatalogExpansion = [Pspkt.Certification.FoundationEngine.FoundationCatalogEngineV1]::Expand($emptyCatalogEvaluation, $genericPolicy)
Assert-Foundation -Condition $emptyCatalogExpansion.Accepted -Message "Empty catalog expansion failed early: $($emptyCatalogExpansion.Reason)"
$emptyCatalogAssignment = [Pspkt.Certification.FoundationEngine.FoundationCatalogEngineV1]::Assign($emptyCatalogExpansion, $genericPolicy)
Assert-Foundation -Condition ($emptyCatalogAssignment.Reason -eq 'missing-property') -Message 'Empty catalog final assignment reason mismatch.'
$emptyCatalogResult = Invoke-Generic -Bytes $emptyCatalogBytes -Policy $genericPolicy
Assert-Foundation -Condition ($emptyCatalogResult.Reason -eq 'missing-property') -Message 'Empty catalog final evaluation reason mismatch.'
$emptyCatalogReplay = [Pspkt.Certification.FoundationEngine.FoundationCatalogEngineV1]::Replay(
    $emptyCatalogBytes,
    [Text.Encoding]::UTF8.GetBytes('{}'),
    [Text.Encoding]::UTF8.GetBytes('[]'),
    $genericPolicy)
Assert-Foundation -Condition ($emptyCatalogReplay.Reason -eq 'missing-property') -Message 'Empty catalog Replay reason mismatch.'
$emptyNamedBytes = New-GenericCatalogBytes -Entries @([ordered]@{
    op = 'type'
    name = 'EmptyNamed'
    production = 'Named'
})
$emptyNamedEvaluation = [Pspkt.Certification.FoundationEngine.FoundationCatalogEngineV1]::EvaluateJson($emptyNamedBytes, $genericPolicy)
Assert-Foundation -Condition $emptyNamedEvaluation.Accepted -Message "Empty Named JSON evaluation failed early: $($emptyNamedEvaluation.Reason)"
$emptyNamedExpansion = [Pspkt.Certification.FoundationEngine.FoundationCatalogEngineV1]::Expand($emptyNamedEvaluation, $genericPolicy)
Assert-Foundation -Condition $emptyNamedExpansion.Accepted -Message "Empty Named expansion failed early: $($emptyNamedExpansion.Reason)"
$emptyNamedAssignment = [Pspkt.Certification.FoundationEngine.FoundationCatalogEngineV1]::Assign($emptyNamedExpansion, $genericPolicy)
Assert-Foundation -Condition ($emptyNamedAssignment.Reason -eq 'missing-property') -Message 'Empty Named final assignment reason mismatch.'
$selfCycleBytes = New-GenericCatalogBytes -Entries @(
    [ordered]@{ op = 'type'; name = 'SelfCycle'; production = 'Named' }
    [ordered]@{ op = 'field'; name = 'Self'; parent = 'SelfCycle'; type = 'SelfCycle' }
)
$selfCycleEvaluation = [Pspkt.Certification.FoundationEngine.FoundationCatalogEngineV1]::EvaluateJson($selfCycleBytes, $genericPolicy)
Assert-Foundation -Condition $selfCycleEvaluation.Accepted -Message "Self-cycle JSON evaluation failed early: $($selfCycleEvaluation.Reason)"
$selfCycleExpansion = [Pspkt.Certification.FoundationEngine.FoundationCatalogEngineV1]::Expand($selfCycleEvaluation, $genericPolicy)
Assert-Foundation -Condition $selfCycleExpansion.Accepted -Message "Self-cycle expansion failed early: $($selfCycleExpansion.Reason)"
$selfCycleAssignment = [Pspkt.Certification.FoundationEngine.FoundationCatalogEngineV1]::Assign($selfCycleExpansion, $genericPolicy)
Assert-Foundation -Condition ($selfCycleAssignment.Reason -eq 'type-cycle') -Message 'Self-cycle final assignment reason mismatch.'
$observedReasons.Add($selfCycleAssignment.Reason) | Out-Null
$selfCycleReplay = [Pspkt.Certification.FoundationEngine.FoundationCatalogEngineV1]::Replay(
    $selfCycleBytes,
    [Text.Encoding]::UTF8.GetBytes('{}'),
    [Text.Encoding]::UTF8.GetBytes('[]'),
    $genericPolicy)
Assert-Foundation -Condition ($selfCycleReplay.Reason -eq 'type-cycle') -Message 'Self-cycle Replay reason mismatch.'
$indirectCycleBytes = New-GenericCatalogBytes -Entries @(
    [ordered]@{ op = 'type'; name = 'CycleFirst'; production = 'Named' }
    [ordered]@{ op = 'field'; name = 'Second'; parent = 'CycleFirst'; type = 'CycleSecond' }
    [ordered]@{ op = 'type'; name = 'CycleSecond'; production = 'Named' }
    [ordered]@{ op = 'field'; name = 'First'; parent = 'CycleSecond'; type = 'CycleFirst' }
)
$indirectCycleResult = Invoke-Generic -Bytes $indirectCycleBytes -Policy $genericPolicy
Assert-Foundation -Condition ($indirectCycleResult.Reason -eq 'type-cycle') -Message 'Indirect cycle final reason mismatch.'
$forwardReferenceBytes = New-GenericCatalogBytes -Entries @(
    [ordered]@{ op = 'type'; name = 'ForwardFirst'; production = 'Named' }
    [ordered]@{ op = 'field'; name = 'Second'; parent = 'ForwardFirst'; type = 'ForwardSecond' }
    [ordered]@{ op = 'type'; name = 'ForwardSecond'; production = 'Named' }
    [ordered]@{ op = 'field'; name = 'Value'; parent = 'ForwardSecond'; type = 'U8' }
)
$forwardReference = Invoke-Generic -Bytes $forwardReferenceBytes -Policy $genericPolicy
Assert-Foundation -Condition $forwardReference.Accepted -Message "Valid forward reference failed: $($forwardReference.Reason)"
$collisionMessages = [Collections.Generic.Dictionary[string,string]]::new([StringComparer]::Ordinal)
$collisionMessages.Add('FirstChannel', 'CollisionKind')
$collisionMessages.Add('SecondChannel', 'CollisionKind')
$collisionRanges = [Collections.Generic.Dictionary[string,Pspkt.Certification.FoundationEngine.GeneratedIdRange[]]]::new([StringComparer]::Ordinal)
$collisionRanges.Add('FirstChannel', [Pspkt.Certification.FoundationEngine.GeneratedIdRange[]]@())
$collisionRanges.Add('SecondChannel', [Pspkt.Certification.FoundationEngine.GeneratedIdRange[]]@())
$collisionPolicy = [Pspkt.Certification.FoundationEngine.FoundationPolicyContract]::new(
    '^[A-Z][A-Za-z0-9]*$',
    [string[]]@('FirstChannel', 'SecondChannel'),
    $collisionMessages,
    [string[]]@('HostToWorker'),
    $collisionRanges,
    $null,
    39,
    $true,
    'GenericCatalogV1',
    'GenericSchemaV1',
    [string[]]@('type', 'field', 'message'))
$collisionBytes = New-GenericCatalogBytes -Entries @(
    [ordered]@{ op = 'type'; name = 'Payload'; production = 'Named' }
    [ordered]@{ op = 'field'; name = 'Value'; parent = 'Payload'; type = 'U8' }
    [ordered]@{ op = 'message'; name = 'First'; channel = 'FirstChannel'; direction = 'HostToWorker'; payloadRoot = 'Payload' }
    [ordered]@{ op = 'message'; name = 'Second'; channel = 'SecondChannel'; direction = 'HostToWorker'; payloadRoot = 'Payload' }
)
$collisionResult = Invoke-Generic -Bytes $collisionBytes -Policy $collisionPolicy
Assert-Foundation -Condition ($collisionResult.Reason -eq 'duplicate-identifier') -Message 'Synthesized message enum collision was accepted.'
$boundedUnionBytes = New-GenericCatalogBytes -Entries @([ordered]@{
    op = 'union'
    name = 'BoundedUnion'
    discriminator = 'BoundedUnionKind'
    branches = @([ordered]@{
        name = 'BoundedBranch'
        fields = @([ordered]@{ name = 'BoundedValue'; type = 'BoundedBytes' })
    })
})
$boundedUnion = Invoke-Generic -Bytes $boundedUnionBytes -Policy $genericPolicy
Assert-Foundation -Condition ($boundedUnion.Reason -eq 'missing-property') -Message 'Union BoundedBytes without maxBytes was not rejected.'
$boundedExtendBytes = New-GenericCatalogBytes -Entries @(
    [ordered]@{ op = 'type'; name = 'BoundedParent'; production = 'Named' }
    [ordered]@{ op = 'field'; name = 'BaseValue'; parent = 'BoundedParent'; type = 'U8' }
    [ordered]@{ op = 'extend'; parent = 'BoundedParent'; fields = @([ordered]@{ name = 'BoundedExtension'; id = 40; type = 'BoundedBytes' }) }
)
$boundedExtend = Invoke-Generic -Bytes $boundedExtendBytes -Policy $genericPolicy
Assert-Foundation -Condition ($boundedExtend.Reason -eq 'missing-property') -Message 'Extend BoundedBytes without maxBytes was not rejected.'

$assigned = 0
Assert-Foundation -Condition ([Pspkt.Certification.FoundationEngine.FoundationCatalogEngineV1]::TryAdvanceGeneratedId(65535, [ref]$assigned)) -Message 'Generated identifier 65535 must be assignable.'
Assert-Foundation -Condition ($assigned -eq 65535) -Message 'Generated identifier 65535 assignment mismatch.'
Assert-Foundation -Condition (-not [Pspkt.Certification.FoundationEngine.FoundationCatalogEngineV1]::TryAdvanceGeneratedId(65536, [ref]$assigned)) -Message 'Generated identifier 65536 must overflow.'
Assert-Foundation -Condition ([Pspkt.Certification.FoundationEngine.FoundationCatalogEngineV1]::TestGeneratedIdAllowed('kind', 'WorkerApp', 65535, $genericPolicy)) -Message 'Known-channel checker rejected kind 65535.'
$foundationPolicy = [Pspkt.Certification.FoundationEngine.FoundationPolicy]::Create()
Assert-Foundation -Condition ([Pspkt.Certification.FoundationEngine.FoundationCatalogEngineV1]::TestGeneratedIdAllowed('type', $null, 0x12FF, $foundationPolicy)) -Message 'Foundation type checker rejected 0x12FF.'

$typeOverflowBytes = New-GenericCatalogBytes -Entries @(
    [ordered]@{ op = 'enum'; name = 'First'; members = @([ordered]@{ name = 'FirstValue'; value = 0 }) }
    [ordered]@{ op = 'enum'; name = 'Second'; members = @([ordered]@{ name = 'SecondValue'; value = 0 }) }
)
$typeOverflowEvaluation = [Pspkt.Certification.FoundationEngine.FoundationCatalogEngineV1]::EvaluateJson($typeOverflowBytes, $genericPolicy)
$typeOverflowExpansion = [Pspkt.Certification.FoundationEngine.FoundationCatalogEngineV1]::Expand($typeOverflowEvaluation, $genericPolicy)
$typeNextField = $typeOverflowExpansion.GetType().GetField('_typeNext', [Reflection.BindingFlags]'Instance,NonPublic')
$typeNextField.SetValue($typeOverflowExpansion, 65535)
$typeOverflowAssignment = [Pspkt.Certification.FoundationEngine.FoundationCatalogEngineV1]::Assign($typeOverflowExpansion, $genericPolicy)
Assert-Foundation -Condition ($typeOverflowAssignment.Reason -eq 'generated-id-overflow') -Message 'Type cursor overflow reason mismatch.'
$observedReasons.Add($typeOverflowAssignment.Reason) | Out-Null

$kindOverflowBytes = New-GenericCatalogBytes -Entries @(
    [ordered]@{ op = 'type'; name = 'Payload'; production = 'Named' }
    [ordered]@{ op = 'field'; name = 'Value'; parent = 'Payload'; type = 'U8' }
    [ordered]@{ op = 'message'; name = 'First'; channel = 'WorkerApp'; direction = 'HostToWorker'; payloadRoot = 'Payload' }
    [ordered]@{ op = 'message'; name = 'Second'; channel = 'WorkerApp'; direction = 'HostToWorker'; payloadRoot = 'Payload' }
)
$kindOverflowEvaluation = [Pspkt.Certification.FoundationEngine.FoundationCatalogEngineV1]::EvaluateJson($kindOverflowBytes, $genericPolicy)
$kindOverflowExpansion = [Pspkt.Certification.FoundationEngine.FoundationCatalogEngineV1]::Expand($kindOverflowEvaluation, $genericPolicy)
$kindNextField = $kindOverflowExpansion.GetType().GetField('_kindNext', [Reflection.BindingFlags]'Instance,NonPublic')
$kindNext = [Collections.Generic.Dictionary[string,int]]$kindNextField.GetValue($kindOverflowExpansion)
$kindNext['WorkerApp'] = 65535
$kindOverflowAssignment = [Pspkt.Certification.FoundationEngine.FoundationCatalogEngineV1]::Assign($kindOverflowExpansion, $genericPolicy)
Assert-Foundation -Condition ($kindOverflowAssignment.Reason -eq 'generated-id-overflow') -Message 'Kind cursor overflow reason mismatch.'
Assert-Foundation -Condition ([Text.Encoding]::UTF8.GetString($kindOverflowAssignment.IdMapBytes) -eq '[]') -Message 'Failed kind assignment exposed a partial map.'
$kindOverflowRetry = [Pspkt.Certification.FoundationEngine.FoundationCatalogEngineV1]::Assign($kindOverflowExpansion, $genericPolicy)
Assert-Foundation -Condition ($kindOverflowRetry.Reason -eq 'generated-id-overflow') -Message 'Kind cursor overflow retry reason mismatch.'
Assert-Foundation -Condition ([Text.Encoding]::UTF8.GetString($kindOverflowRetry.IdMapBytes) -eq '[]') -Message 'Failed kind assignment mutated retry state.'

$negativeEnumBytes = [Text.Encoding]::UTF8.GetBytes('{"entries":[{"members":[{"name":"Negative","value":-1}],"name":"NegativeEnum","op":"enum"}],"schemaId":"GenericCatalogV1","schemaVersion":1,"space":"generic"}')
$negativeEnum = Invoke-Generic -Bytes $negativeEnumBytes -Policy $genericPolicy
Assert-Foundation -Condition ($negativeEnum.Reason -eq 'enum-value-overflow') -Message 'Negative enum value reason mismatch.'
$negativeZeroEnumBytes = [Text.Encoding]::UTF8.GetBytes('{"entries":[{"members":[{"name":"NegativeZero","value":-0}],"name":"NegativeZeroEnum","op":"enum"}],"schemaId":"GenericCatalogV1","schemaVersion":1,"space":"generic"}')
$negativeZeroEnum = Invoke-Generic -Bytes $negativeZeroEnumBytes -Policy $genericPolicy
Assert-Foundation -Condition ($negativeZeroEnum.Reason -eq 'enum-value-overflow') -Message 'Negative-zero enum value reason mismatch.'
$hugeEnumBytes = [Text.Encoding]::UTF8.GetBytes('{"entries":[{"members":[{"name":"Huge","value":9223372036854775808}],"name":"HugeEnum","op":"enum"}],"schemaId":"GenericCatalogV1","schemaVersion":1,"space":"generic"}')
$hugeEnum = Invoke-Generic -Bytes $hugeEnumBytes -Policy $genericPolicy
Assert-Foundation -Condition ($hugeEnum.Reason -eq 'enum-value-overflow') -Message 'Huge enum value reason mismatch.'
$hugeProductionBytes = [Text.Encoding]::UTF8.GetBytes('{"entries":[{"elementType":"U8","maxCount":9223372036854775808,"minCount":0,"name":"HugeList","op":"type","production":"List"}],"schemaId":"GenericCatalogV1","schemaVersion":1,"space":"generic"}')
$hugeProduction = Invoke-Generic -Bytes $hugeProductionBytes -Policy $genericPolicy
Assert-Foundation -Condition ($hugeProduction.Reason -eq 'invalid-production') -Message 'Huge production value reason mismatch.'
$hugeBaseIdBytes = [Text.Encoding]::UTF8.GetBytes('{"entries":[{"id":9223372036854775808,"members":[{"name":"Value","value":0}],"name":"HugeBase","op":"enum"}],"schemaId":"GenericCatalogV1","schemaVersion":1,"space":"generic"}')
$hugeBaseId = Invoke-Generic -Bytes $hugeBaseIdBytes -Policy $genericPolicy
Assert-Foundation -Condition ($hugeBaseId.Reason -eq 'base-literal-id') -Message 'Huge base literal reason mismatch.'
$hugeExtendIdBytes = [Text.Encoding]::UTF8.GetBytes('{"entries":[{"name":"ExtendParent","op":"type","production":"Named"},{"name":"Base","op":"field","parent":"ExtendParent","type":"U8"},{"fields":[{"id":9223372036854775808,"name":"Huge","type":"U8"}],"op":"extend","parent":"ExtendParent"}],"schemaId":"GenericCatalogV1","schemaVersion":1,"space":"generic"}')
$hugeExtendId = Invoke-Generic -Bytes $hugeExtendIdBytes -Policy $genericPolicy
Assert-Foundation -Condition ($hugeExtendId.Reason -eq 'extend-id-overflow') -Message 'Huge extend literal reason mismatch.'
$numericParentBytes = [Text.Encoding]::UTF8.GetBytes('{"entries":[{"name":"Parent","op":"type","production":"Named"},{"name":"Value","op":"field","parent":1,"type":"U8"}],"schemaId":"GenericCatalogV1","schemaVersion":1,"space":"generic"}')
$numericParent = Invoke-Generic -Bytes $numericParentBytes -Policy $genericPolicy
Assert-Foundation -Condition ($numericParent.Reason -eq 'missing-property') -Message 'Non-string field parent reason mismatch.'

$unionFieldBytes = New-GenericCatalogBytes -Entries @(
    [ordered]@{
        op = 'union'
        name = 'FieldUnion'
        discriminator = 'FieldUnionKind'
        branches = @([ordered]@{
            name = 'FieldBranch'
            fields = @([ordered]@{ name = 'Initial'; type = 'U8' })
        })
    }
    [ordered]@{ op = 'field'; name = 'Generated'; parent = 'FieldBranch'; type = 'U16' }
    [ordered]@{ op = 'extend'; parent = 'FieldBranch'; fields = @([ordered]@{ name = 'Extended'; id = 40; type = 'U32' }) }
)
$unionFieldResult = Invoke-Generic -Bytes $unionFieldBytes -Policy $genericPolicy
Assert-Foundation -Condition ($unionFieldResult.Accepted) -Message "Union branch field/extend failed: $($unionFieldResult.Reason)"
$unionFieldSchema = [Text.Encoding]::UTF8.GetString($unionFieldResult.SchemaBytes) | ConvertFrom-Json
$unionBranch = @($unionFieldSchema.types | Where-Object { $_.name -eq 'FieldBranch' })[0]
Assert-Foundation -Condition ((@($unionBranch.fields.fieldId) -join ',') -eq '1,2,40') -Message 'Union branch field identifiers were not seeded.'

$unionLateFieldBytes = New-GenericCatalogBytes -Entries @(
    [ordered]@{
        op = 'union'
        name = 'LateFieldUnion'
        discriminator = 'LateFieldUnionKind'
        branches = @([ordered]@{
            name = 'LateFieldBranch'
            fields = @([ordered]@{ name = 'Initial'; type = 'U8' })
        })
    }
    [ordered]@{ op = 'extend'; parent = 'LateFieldBranch'; fields = @([ordered]@{ name = 'Extended'; id = 40; type = 'U32' }) }
    [ordered]@{ op = 'field'; name = 'Generated'; parent = 'LateFieldBranch'; type = 'U16' }
)
$unionLateField = Invoke-Generic -Bytes $unionLateFieldBytes -Policy $genericPolicy
Assert-Foundation -Condition ($unionLateField.Accepted) -Message "Field after union extension failed: $($unionLateField.Reason)"
$unionLateSchema = [Text.Encoding]::UTF8.GetString($unionLateField.SchemaBytes) | ConvertFrom-Json
$unionLateBranch = @($unionLateSchema.types | Where-Object { $_.name -eq 'LateFieldBranch' })[0]
Assert-Foundation -Condition ((@($unionLateBranch.fields.fieldId) -join ',') -eq '1,2,40') -Message 'Field after union extension did not retain field-ID order.'

$typeLateFieldBytes = New-GenericCatalogBytes -Entries @(
    [ordered]@{ op = 'type'; name = 'LateFieldType'; production = 'Named' }
    [ordered]@{ op = 'field'; name = 'Initial'; parent = 'LateFieldType'; type = 'U8' }
    [ordered]@{ op = 'extend'; parent = 'LateFieldType'; fields = @([ordered]@{ name = 'Extended'; id = 40; type = 'U32' }) }
    [ordered]@{ op = 'field'; name = 'Generated'; parent = 'LateFieldType'; type = 'U16' }
)
$typeLateField = Invoke-Generic -Bytes $typeLateFieldBytes -Policy $genericPolicy
Assert-Foundation -Condition ($typeLateField.Accepted) -Message "Field after type extension failed: $($typeLateField.Reason)"
$typeLateSchema = [Text.Encoding]::UTF8.GetString($typeLateField.SchemaBytes) | ConvertFrom-Json
$typeLateDeclaration = @($typeLateSchema.types | Where-Object { $_.name -eq 'LateFieldType' })[0]
Assert-Foundation -Condition ((@($typeLateDeclaration.fields.fieldId) -join ',') -eq '1,2,40') -Message 'Type field after extension did not retain field-ID order.'

$negativeBoundedUnionBytes = [Text.Encoding]::UTF8.GetBytes('{"entries":[{"branches":[{"fields":[{"maxBytes":-1,"name":"Bytes","type":"BoundedBytes"}],"name":"NegativeBoundBranch"}],"discriminator":"NegativeBoundKind","name":"NegativeBoundUnion","op":"union"}],"schemaId":"GenericCatalogV1","schemaVersion":1,"space":"generic"}')
$negativeBoundedUnion = Invoke-Generic -Bytes $negativeBoundedUnionBytes -Policy $genericPolicy
Assert-Foundation -Condition ($negativeBoundedUnion.Reason -eq 'invalid-production') -Message 'Negative union field bound reason mismatch.'

$deletedExtendedBytes = New-GenericCatalogBytes -Entries @(
    [ordered]@{ op = 'type'; name = 'LiveKeeperFirst'; production = 'List'; elementType = 'U8'; minCount = 0; maxCount = 1 }
    [ordered]@{ op = 'type'; name = 'DeletedExtended'; production = 'Named' }
    [ordered]@{ op = 'field'; name = 'Initial'; parent = 'DeletedExtended'; type = 'U8' }
    [ordered]@{ op = 'extend'; parent = 'DeletedExtended'; fields = @([ordered]@{ name = 'Extension'; id = 40; type = 'U16' }) }
    [ordered]@{ op = 'delete'; name = 'DeletedExtended' }
)
$deletedExtended = Invoke-Generic -Bytes $deletedExtendedBytes -Policy $genericPolicy
Assert-Foundation -Condition ($deletedExtended.Accepted) -Message "Deleted extended type failed: $($deletedExtended.Reason)"
Assert-Foundation -Condition ([Text.Encoding]::UTF8.GetString($deletedExtended.SchemaBytes) -notmatch 'DeletedExtended') -Message 'Deleted extended type was emitted.'
Assert-Foundation -Condition ([Text.Encoding]::UTF8.GetString($deletedExtended.IdMapBytes) -notmatch 'DeletedExtended') -Message 'Deleted extended type created map rows.'

$deletedUnionBranchBytes = New-GenericCatalogBytes -Entries @(
    [ordered]@{ op = 'type'; name = 'LiveKeeperSecond'; production = 'List'; elementType = 'U8'; minCount = 0; maxCount = 1 }
    [ordered]@{
        op = 'union'
        name = 'DeletedBranchUnion'
        discriminator = 'DeletedBranchKind'
        branches = @([ordered]@{
            name = 'DeletedBranch'
            fields = @([ordered]@{ name = 'Initial'; type = 'U8' })
        })
    }
    [ordered]@{ op = 'delete'; name = 'DeletedBranch' }
)
$deletedUnionBranch = Invoke-Generic -Bytes $deletedUnionBranchBytes -Policy $genericPolicy
Assert-Foundation -Condition ($deletedUnionBranch.Accepted) -Message "Deleted union branch failed: $($deletedUnionBranch.Reason)"
Assert-Foundation -Condition ([Text.Encoding]::UTF8.GetString($deletedUnionBranch.SchemaBytes) -notmatch 'DeletedBranch"') -Message 'Deleted union branch was emitted.'
Assert-Foundation -Condition ([Text.Encoding]::UTF8.GetString($deletedUnionBranch.IdMapBytes) -notmatch 'DeletedBranch"') -Message 'Deleted union branch created map rows.'
Assert-Foundation -Condition ([Text.Encoding]::UTF8.GetString($deletedUnionBranch.SchemaBytes) -notmatch 'DeletedBranchKind') -Message 'Empty union discriminator was emitted.'

$zeroLiveDeletedBytes = New-GenericCatalogBytes -Entries @(
    [ordered]@{ op = 'type'; name = 'DeletedOnly'; production = 'Named' }
    [ordered]@{ op = 'field'; name = 'Value'; parent = 'DeletedOnly'; type = 'U8' }
    [ordered]@{ op = 'delete'; name = 'DeletedOnly' }
)
$zeroLiveDeleted = Invoke-Generic -Bytes $zeroLiveDeletedBytes -Policy $genericPolicy
Assert-Foundation -Condition ($zeroLiveDeleted.Reason -eq 'missing-property') -Message 'Zero-live deleted catalog reason mismatch.'

$zeroLiveUnionBytes = New-GenericCatalogBytes -Entries @(
    [ordered]@{
        op = 'union'
        name = 'ZeroLiveUnion'
        discriminator = 'ZeroLiveUnionKind'
        branches = @([ordered]@{
            name = 'ZeroLiveBranch'
            fields = @([ordered]@{ name = 'Value'; type = 'U8' })
        })
    }
    [ordered]@{ op = 'delete'; name = 'ZeroLiveBranch' }
)
$zeroLiveUnion = Invoke-Generic -Bytes $zeroLiveUnionBytes -Policy $genericPolicy
Assert-Foundation -Condition ($zeroLiveUnion.Reason -eq 'missing-property') -Message 'Zero-live union catalog reason mismatch.'

$partialUnionDeleteBytes = New-GenericCatalogBytes -Entries @(
    [ordered]@{
        op = 'union'
        name = 'PartialUnion'
        discriminator = 'PartialUnionKind'
        branches = @(
            [ordered]@{ name = 'PartialFirst'; fields = @([ordered]@{ name = 'Value'; type = 'U8' }) }
            [ordered]@{ name = 'PartialDeleted'; fields = @([ordered]@{ name = 'Value'; type = 'U8' }) }
            [ordered]@{ name = 'PartialLast'; fields = @([ordered]@{ name = 'Value'; type = 'U8' }) }
        )
    }
    [ordered]@{ op = 'delete'; name = 'PartialDeleted' }
)
$partialUnionDelete = Invoke-Generic -Bytes $partialUnionDeleteBytes -Policy $genericPolicy
Assert-Foundation -Condition ($partialUnionDelete.Accepted) -Message "Partial union deletion failed: $($partialUnionDelete.Reason)"
$partialUnionSchema = [Text.Encoding]::UTF8.GetString($partialUnionDelete.SchemaBytes) | ConvertFrom-Json
$partialDiscriminator = @($partialUnionSchema.types | Where-Object { $_.name -eq 'PartialUnionKind' })[0]
Assert-Foundation -Condition ((@($partialDiscriminator.members.value) -join ',') -eq '0,1') -Message 'Partial union discriminator values were not compacted.'
$partialUnionMap = [Text.Encoding]::UTF8.GetString($partialUnionDelete.IdMapBytes) | ConvertFrom-Json
Assert-Foundation -Condition ((@($partialUnionMap | Where-Object { $_.category -eq 'enum-member' } | ForEach-Object { $_.memberIndex }) -join ',') -eq '0,1') -Message 'Partial union memberIndex values were not compacted.'
Assert-Foundation -Condition ((@($partialUnionMap | Where-Object { $_.category -eq 'union-branch' } | ForEach-Object { $_.branchIndex }) -join ',') -eq '0,1') -Message 'Partial union branchIndex values were not compacted.'

$allBranchesDeletedBytes = New-GenericCatalogBytes -Entries @(
    [ordered]@{
        op = 'union'
        name = 'AllDeletedUnion'
        discriminator = 'AllDeletedUnionKind'
        branches = @(
            [ordered]@{ name = 'AllDeletedFirst'; fields = @([ordered]@{ name = 'Value'; type = 'U8' }) }
            [ordered]@{ name = 'AllDeletedLast'; fields = @([ordered]@{ name = 'Value'; type = 'U8' }) }
        )
    }
    [ordered]@{ op = 'delete'; name = 'AllDeletedFirst' }
    [ordered]@{ op = 'delete'; name = 'AllDeletedLast' }
    [ordered]@{ op = 'type'; name = 'AllDeletedReference'; production = 'List'; elementType = 'AllDeletedUnionKind'; minCount = 0; maxCount = 1 }
)
$allBranchesDeleted = Invoke-Generic -Bytes $allBranchesDeletedBytes -Policy $genericPolicy
Assert-Foundation -Condition ($allBranchesDeleted.Reason -eq 'delete-then-use') -Message 'All-branches-deleted reference reason mismatch.'

$deletedDiscriminatorBytes = New-GenericCatalogBytes -Entries @(
    [ordered]@{
        op = 'union'
        name = 'DeletedDiscriminatorUnion'
        discriminator = 'DeletedDiscriminatorKind'
        branches = @([ordered]@{
            name = 'DeletedDiscriminatorBranch'
            fields = @([ordered]@{ name = 'Initial'; type = 'U8' })
        })
    }
    [ordered]@{ op = 'delete'; name = 'DeletedDiscriminatorKind' }
    [ordered]@{ op = 'field'; name = 'Later'; parent = 'DeletedDiscriminatorBranch'; type = 'U16' }
)
$deletedDiscriminator = Invoke-Generic -Bytes $deletedDiscriminatorBytes -Policy $genericPolicy
Assert-Foundation -Condition ($deletedDiscriminator.Reason -eq 'delete-then-use') -Message 'Deleted union discriminator later-use reason mismatch.'

$unorderedExtendBytes = New-GenericCatalogBytes -Entries @(
    [ordered]@{ op = 'type'; name = 'SortedExtension'; production = 'Named' }
    [ordered]@{ op = 'field'; name = 'Initial'; parent = 'SortedExtension'; type = 'U8' }
    [ordered]@{
        op = 'extend'
        parent = 'SortedExtension'
        fields = @(
            [ordered]@{ name = 'Later'; id = 41; type = 'U16' }
            [ordered]@{ name = 'Earlier'; id = 40; type = 'U32' }
        )
    }
)
$unorderedExtend = Invoke-Generic -Bytes $unorderedExtendBytes -Policy $genericPolicy
Assert-Foundation -Condition ($unorderedExtend.Accepted) -Message "Unordered extension failed: $($unorderedExtend.Reason)"
$unorderedSchema = [Text.Encoding]::UTF8.GetString($unorderedExtend.SchemaBytes) | ConvertFrom-Json
$sortedExtension = @($unorderedSchema.types | Where-Object { $_.name -eq 'SortedExtension' })[0]
Assert-Foundation -Condition ((@($sortedExtension.fields.fieldId) -join ',') -eq '1,40,41') -Message 'Extension field identifiers were not emitted in ascending order.'

$idempotentEvaluation = [Pspkt.Certification.FoundationEngine.FoundationCatalogEngineV1]::EvaluateJson($unionFieldBytes, $genericPolicy)
$idempotentExpansion = [Pspkt.Certification.FoundationEngine.FoundationCatalogEngineV1]::Expand($idempotentEvaluation, $genericPolicy)
$firstAssignment = [Pspkt.Certification.FoundationEngine.FoundationCatalogEngineV1]::Assign($idempotentExpansion, $genericPolicy)
$secondAssignment = [Pspkt.Certification.FoundationEngine.FoundationCatalogEngineV1]::Assign($idempotentExpansion, $genericPolicy)
Assert-Foundation -Condition ((Get-PspktFoundationSha256 -Bytes $firstAssignment.SchemaBytes) -eq (Get-PspktFoundationSha256 -Bytes $secondAssignment.SchemaBytes)) -Message 'Successful assignment mutated type cursors.'
Assert-Foundation -Condition ((Get-PspktFoundationSha256 -Bytes $firstAssignment.IdMapBytes) -eq (Get-PspktFoundationSha256 -Bytes $secondAssignment.IdMapBytes)) -Message 'Successful assignment mutated map cursors.'

$unionOverflowEvaluation = [Pspkt.Certification.FoundationEngine.FoundationCatalogEngineV1]::EvaluateJson($unionFieldBytes, $genericPolicy)
$unionOverflowExpansion = [Pspkt.Certification.FoundationEngine.FoundationCatalogEngineV1]::Expand($unionOverflowEvaluation, $genericPolicy)
$operationsField = $unionOverflowExpansion.GetType().GetField('Operations', [Reflection.BindingFlags]'Instance,NonPublic')
$unionOperation = $operationsField.GetValue($unionOverflowExpansion)[0]
$branchesField = $unionOperation.GetType().GetField('Branches', [Reflection.BindingFlags]'Instance,NonPublic')
$branches = $branchesField.GetValue($unionOperation)
$firstBranch = $branches[0]
while ($branches.Count -lt 4095) {
    $branches.Add($firstBranch)
}
$unionBudgetAssignment = [Pspkt.Certification.FoundationEngine.FoundationCatalogEngineV1]::Assign($unionOverflowExpansion, $genericPolicy)
Assert-Foundation -Condition ($unionBudgetAssignment.Reason -eq 'enum-value-overflow') -Message 'Union map budget reason mismatch.'
while ($branches.Count -le 65536) {
    $branches.Add($firstBranch)
}
$unionOverflowAssignment = [Pspkt.Certification.FoundationEngine.FoundationCatalogEngineV1]::Assign($unionOverflowExpansion, $genericPolicy)
Assert-Foundation -Condition ($unionOverflowAssignment.Reason -eq 'enum-value-overflow') -Message 'Excessive union discriminator count reason mismatch.'

$nonUnionBudgetEntries = [Collections.Generic.List[object]]::new()
for ($budgetIndex = 0; $budgetIndex -lt 4097; $budgetIndex++) {
    $nonUnionBudgetEntries.Add([ordered]@{
        op = 'type'
        name = "BudgetType$budgetIndex"
        production = 'List'
        elementType = 'U8'
        minCount = 0
        maxCount = 1
    })
}
$nonUnionBudget = Invoke-Generic -Bytes (New-GenericCatalogBytes -Entries $nonUnionBudgetEntries.ToArray()) -Policy $genericPolicy
Assert-Foundation -Condition ($nonUnionBudget.Reason -eq 'generated-id-overflow') -Message 'Non-union output budget reason mismatch.'

$reservedTypePolicy = New-TestPolicy -ReservedTypeRange ([Pspkt.Certification.FoundationEngine.GeneratedIdRange]::new(1, 1))
$reservedTypeBytes = New-GenericCatalogBytes -Entries @([ordered]@{ op = 'enum'; name = 'ReservedType'; members = @([ordered]@{ name = 'ReservedTypeValue'; value = 0 }) })
$reservedTypeEvaluation = [Pspkt.Certification.FoundationEngine.FoundationCatalogEngineV1]::EvaluateJson($reservedTypeBytes, $reservedTypePolicy)
$reservedTypeExpansion = [Pspkt.Certification.FoundationEngine.FoundationCatalogEngineV1]::Expand($reservedTypeEvaluation, $reservedTypePolicy)
$reservedTypeAssignment = [Pspkt.Certification.FoundationEngine.FoundationCatalogEngineV1]::Assign($reservedTypeExpansion, $reservedTypePolicy)
Assert-Foundation -Condition ($reservedTypeAssignment.Reason -eq 'reserved-type-range') -Message 'Reserved type assignment reason mismatch.'
Assert-Foundation -Condition ([Text.Encoding]::UTF8.GetString($reservedTypeAssignment.IdMapBytes) -eq '[]') -Message 'Reserved type assignment mutated map.'
$observedReasons.Add($reservedTypeAssignment.Reason) | Out-Null

$reservedKindPolicy = New-TestPolicy -ReservedKindRanges @([Pspkt.Certification.FoundationEngine.GeneratedIdRange]::new(1, 1))
$reservedKindEvaluation = [Pspkt.Certification.FoundationEngine.FoundationCatalogEngineV1]::EvaluateJson($genericBytes, $reservedKindPolicy)
$reservedKindExpansion = [Pspkt.Certification.FoundationEngine.FoundationCatalogEngineV1]::Expand($reservedKindEvaluation, $reservedKindPolicy)
$reservedKindAssignment = [Pspkt.Certification.FoundationEngine.FoundationCatalogEngineV1]::Assign($reservedKindExpansion, $reservedKindPolicy)
Assert-Foundation -Condition ($reservedKindAssignment.Reason -eq 'reserved-kind-range') -Message 'Reserved kind assignment reason mismatch.'
Assert-Foundation -Condition ([Text.Encoding]::UTF8.GetString($reservedKindAssignment.IdMapBytes) -notmatch '"category":"kind"') -Message 'Reserved kind assignment added a kind row.'
$observedReasons.Add($reservedKindAssignment.Reason) | Out-Null

foreach ($primitive in @('I16', 'I32', 'I64', 'OpaqueUtf16')) {
    $primitiveResult = Invoke-Generic -Bytes (New-GenericCatalogBytes -Entries @([ordered]@{ op = 'primitive'; name = $primitive })) -Policy $genericPolicy
    Assert-Foundation -Condition ($primitiveResult.Reason -eq 'primitive-forbidden') -Message "$primitive procedural reason mismatch."
}

$mapObjects = @($mapBytes | ForEach-Object { $_ })
$mapDocument = [Text.Encoding]::UTF8.GetString($mapBytes) | ConvertFrom-Json
$requiredColumns = @('schemaId', 'category', 'catalogOrdinal', 'name', 'generatedId')
foreach ($column in $requiredColumns) {
    $tampered = @($mapDocument | ForEach-Object { Copy-FoundationValue -Value $_ })
    $tampered[0].PSObject.Properties.Remove($column)
    $tamperedBytes = Get-PspktCanonicalJsonBytes -Value $tampered
    $tamperResult = [Pspkt.Certification.FoundationEngine.FoundationCatalogV1]::Replay($catalogBytes, $schemaBytes, $tamperedBytes)
    Assert-Foundation -Condition ($tamperResult.Reason -eq 'map-tamper') -Message "Map removal tamper missed: $column"
}
foreach ($row in $mapDocument) {
    $category = [string]$row.category
    if ($category -eq 'kind') {
        $required = 'channel'
    }
    elseif ($category -eq 'enum-member') {
        $required = 'memberIndex'
    }
    elseif ($category -eq 'union-branch') {
        $required = 'branchIndex'
    }
    else {
        continue
    }
    $tampered = @($mapDocument | ForEach-Object { Copy-FoundationValue -Value $_ })
    $target = @($tampered | Where-Object { $_.category -eq $category })[0]
    $target.PSObject.Properties.Remove($required)
    $tamperedBytes = Get-PspktCanonicalJsonBytes -Value $tampered
    $tamperResult = [Pspkt.Certification.FoundationEngine.FoundationCatalogV1]::Replay($catalogBytes, $schemaBytes, $tamperedBytes)
    Assert-Foundation -Condition ($tamperResult.Reason -eq 'map-tamper') -Message "Map category tamper missed: $required"
}
$tampered = @($mapDocument | ForEach-Object { Copy-FoundationValue -Value $_ })
$typeRow = @($tampered | Where-Object { $_.category -eq 'type' })[0]
$typeRow | Add-Member -NotePropertyName channel -NotePropertyValue 'FoundationAlpha'
$tamperedBytes = Get-PspktCanonicalJsonBytes -Value $tampered
$tamperResult = [Pspkt.Certification.FoundationEngine.FoundationCatalogV1]::Replay($catalogBytes, $schemaBytes, $tamperedBytes)
Assert-Foundation -Condition ($tamperResult.Reason -eq 'map-tamper') -Message 'Map forbidden-key tamper missed.'
$observedReasons.Add('map-tamper') | Out-Null

$schemaDocument = [Text.Encoding]::UTF8.GetString($schemaBytes) | ConvertFrom-Json
$schemaTamperReasons = [Collections.Generic.List[string]]::new()
$tamperedSchema = Copy-FoundationValue -Value $schemaDocument
$tamperedSchema.types[0].PSObject.Properties.Remove('production')
$schemaTamperReasons.Add([Pspkt.Certification.SchemaBootstrap]::Evaluate('schema-against-meta', (Get-PspktCanonicalJsonBytes -Value $tamperedSchema), $metaBytes).Reason)
$tamperedSchema = Copy-FoundationValue -Value $schemaDocument
$tamperedSchema.types[0] | Add-Member -NotePropertyName extra -NotePropertyValue 1
$schemaTamperReasons.Add([Pspkt.Certification.SchemaBootstrap]::Evaluate('schema-against-meta', (Get-PspktCanonicalJsonBytes -Value $tamperedSchema), $metaBytes).Reason)
$tamperedSchema = Copy-FoundationValue -Value $schemaDocument
$tamperedSchema.types[1].typeId = $tamperedSchema.types[0].typeId
$schemaTamperReasons.Add([Pspkt.Certification.SchemaBootstrap]::Evaluate('schema-against-meta', (Get-PspktCanonicalJsonBytes -Value $tamperedSchema), $metaBytes).Reason)
$tamperedSchema = Copy-FoundationValue -Value $schemaDocument
$tamperedSchema.types[0].name = 'Fóundation'
$schemaTamperReasons.Add([Pspkt.Certification.SchemaBootstrap]::Evaluate('schema-against-meta', (Get-PspktCanonicalJsonBytes -Value $tamperedSchema), $metaBytes).Reason)
$namedType = @($schemaDocument.types | Where-Object { $_.production -eq 'Named' -and @($_.fields).Count -ge 2 })[0]
$tamperedSchema = Copy-FoundationValue -Value $schemaDocument
$namedTamper = @($tamperedSchema.types | Where-Object { $_.name -eq $namedType.name })[0]
$fieldSwap = $namedTamper.fields[0].fieldId
$namedTamper.fields[0].fieldId = $namedTamper.fields[1].fieldId
$namedTamper.fields[1].fieldId = $fieldSwap
$schemaTamperReasons.Add([Pspkt.Certification.SchemaBootstrap]::Evaluate('schema-against-meta', (Get-PspktCanonicalJsonBytes -Value $tamperedSchema), $metaBytes).Reason)
$tamperedSchema = Copy-FoundationValue -Value $schemaDocument
$namedTamper = @($tamperedSchema.types | Where-Object { $_.production -eq 'Named' })[0]
$namedTamper.fields[0].PSObject.Properties.Remove('fieldId')
$schemaTamperReasons.Add([Pspkt.Certification.SchemaBootstrap]::Evaluate('schema-against-meta', (Get-PspktCanonicalJsonBytes -Value $tamperedSchema), $metaBytes).Reason)
$tamperedSchema = Copy-FoundationValue -Value $schemaDocument
$boundedType = @($tamperedSchema.types | Where-Object { $_.production -eq 'Named' -and @($_.fields | Where-Object { $_.type -eq 'BoundedBytes' }).Count -gt 0 })[0]
$boundedField = @($boundedType.fields | Where-Object { $_.type -eq 'BoundedBytes' })[0]
$boundedField.PSObject.Properties.Remove('maxBytes')
$schemaTamperReasons.Add([Pspkt.Certification.SchemaBootstrap]::Evaluate('schema-against-meta', (Get-PspktCanonicalJsonBytes -Value $tamperedSchema), $metaBytes).Reason)
$tamperedSchema = Copy-FoundationValue -Value $schemaDocument
$semanticType = @($tamperedSchema.types | Where-Object { $_.production -eq 'SemanticString' })[0]
$semanticType.PSObject.Properties.Remove('maxUtf16CodeUnits')
$schemaTamperReasons.Add([Pspkt.Certification.SchemaBootstrap]::Evaluate('schema-against-meta', (Get-PspktCanonicalJsonBytes -Value $tamperedSchema), $metaBytes).Reason)
$tamperedSchema = Copy-FoundationValue -Value $schemaDocument
$enumType = @($tamperedSchema.types | Where-Object { $_.production -eq 'EnumU16' })[0]
$enumType.members[0] | Add-Member -NotePropertyName extra -NotePropertyValue 1
$schemaTamperReasons.Add([Pspkt.Certification.SchemaBootstrap]::Evaluate('schema-against-meta', (Get-PspktCanonicalJsonBytes -Value $tamperedSchema), $metaBytes).Reason)
$tamperedSchema = Copy-FoundationValue -Value $schemaDocument
$tamperedSchema.PSObject.Properties.Remove('schemaId')
$schemaTamperReasons.Add([Pspkt.Certification.SchemaBootstrap]::Evaluate('schema-against-meta', (Get-PspktCanonicalJsonBytes -Value $tamperedSchema), $metaBytes).Reason)
$tamperedSchema = Copy-FoundationValue -Value $schemaDocument
$tamperedSchema | Add-Member -NotePropertyName fourth -NotePropertyValue 1
$schemaTamperReasons.Add([Pspkt.Certification.SchemaBootstrap]::Evaluate('schema-against-meta', (Get-PspktCanonicalJsonBytes -Value $tamperedSchema), $metaBytes).Reason)
Assert-Foundation -Condition (@($schemaTamperReasons | Where-Object { $_ -eq 'ok' }).Count -eq 0) -Message 'A schema tamper was accepted.'

$schemaObject = [Text.Encoding]::UTF8.GetString($schemaBytes) | ConvertFrom-Json
$alphaEnum = @($schemaObject.types | Where-Object { $_.name -eq 'FoundationAlphaMessageKind' })[0]
$betaEnum = @($schemaObject.types | Where-Object { $_.name -eq 'FoundationBetaMessageKind' })[0]
Assert-Foundation -Condition ($alphaEnum.typeId -eq 2) -Message 'FoundationAlpha message enum type order mismatch.'
Assert-Foundation -Condition ($betaEnum.typeId -eq 3) -Message 'FoundationBeta message enum type order mismatch.'
Assert-Foundation -Condition (@($alphaEnum.members).Count -eq 1) -Message 'FoundationAlpha message enum synthesis mismatch.'
Assert-Foundation -Condition (@($betaEnum.members).Count -eq 1) -Message 'FoundationBeta message enum synthesis mismatch.'
Assert-Foundation -Condition (@($schemaObject.types | Where-Object { $_.name -eq 'FoundationDeleted' }).Count -eq 0) -Message 'Deleted type was emitted.'
Assert-Foundation -Condition (@($schemaObject.types | Where-Object { $_.name -eq 'FoundationReservedIllegal' }).Count -eq 0) -Message 'Reserved type was emitted.'
Assert-Foundation -Condition (@($mapDocument | Where-Object { $_.name -eq 'FoundationDeleted' -or $_.name -eq 'FoundationReservedIllegal' }).Count -eq 0) -Message 'Delete or reserve created a type map row.'

$expectedReasonSet = @($contract.ApplicableReasonCodes | Where-Object { $_ -notin @('init-precondition', 'init-recovery-required', 'init-already') } | Sort-Object -Unique)
$actualReasonSet = @($observedReasons | Sort-Object)
$missingReasons = @(Compare-Object $expectedReasonSet $actualReasonSet | Where-Object { $_.SideIndicator -eq '<=' })
$extraReasons = @(Compare-Object $expectedReasonSet $actualReasonSet | Where-Object { $_.SideIndicator -eq '=>' })
$missingText = @($missingReasons | ForEach-Object { $_.InputObject }) -join ','
$extraText = @($extraReasons | ForEach-Object { $_.InputObject }) -join ','
Assert-Foundation -Condition ($missingReasons.Count -eq 0 -and $extraReasons.Count -eq 0) -Message "Applicable reason-set mismatch. Missing=$missingText Extra=$extraText"

[pscustomobject]@{
    FixtureCount = 52
    ReasonCount = $actualReasonSet.Count
    CatalogSha256 = Get-PspktFoundationSha256 -Bytes $catalogBytes
    SchemaSha256 = Get-PspktFoundationSha256 -Bytes $schemaBytes
    MapSha256 = Get-PspktFoundationSha256 -Bytes $mapBytes
    ManifestSha256 = Get-PspktFoundationSha256 -Bytes $manifestBytes
} | ConvertTo-Json -Compress
