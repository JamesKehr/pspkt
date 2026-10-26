Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'

function Invoke-PspktSignatureReferenceCiGuard {
    param([scriptblock]$Action)
    try { & $Action }
    catch {
        $reason='validation:unexpected'
        if($_.Exception.Message -cin @(Get-PspktSignatureReferenceValidatorReasons)) { $reason=$_.Exception.Message }
        [Console]::Error.WriteLine($reason)
        exit 1
    }
}

function Write-PspktSignatureReferenceGitHubOutput {
    param([string]$Name,[byte[]]$Bytes,[int]$MaximumBytes)
    if($Name -cnotin @('receipt','probe','probes') -or $Bytes.Length -gt $MaximumBytes) { throw 'validation:receipt-size' }
    $path=[Environment]::GetEnvironmentVariable('GITHUB_OUTPUT','Process')
    if([string]::IsNullOrEmpty($path) -or -not [IO.Path]::IsPathRooted($path)) { throw 'validation:workflow-binding' }
    $text=[Text.UTF8Encoding]::new($false,$true).GetString($Bytes)
    if($text.Contains("`r") -or $text.Contains("`n")) { throw 'validation:receipt-json' }
    $line=[Text.UTF8Encoding]::new($false,$true).GetBytes($Name+'='+$text+"`n")
    $stream=[IO.File]::Open($path,[IO.FileMode]::Append,[IO.FileAccess]::Write,[IO.FileShare]::Read)
    try { $stream.Write($line,0,$line.Length);$stream.Flush($true) }
    finally { $stream.Dispose() }
}

function Install-PspktSignatureReferencePesterPackage {
    [CmdletBinding(PositionalBinding=$false)]
    param([string]$WorkBase)
    try {
        if(-not [IO.Path]::IsPathRooted($WorkBase)) { throw 'validation:pester-package' }
        $root=Join-Path $WorkBase 'tools'
        if([IO.Directory]::Exists($root) -or [IO.File]::Exists($root)) { throw 'validation:pester-package' }
        [void][IO.Directory]::CreateDirectory($root)
        $path=Join-Path $root 'pester.zip'
        [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri 'https://www.powershellgallery.com/api/v2/package/Pester/5.3.3' -UseBasicParsing -OutFile $path -ErrorAction Stop
        $bytes=Read-PspktSignatureReferenceBoundedFile $path 271297
        $digest=Get-PspktSignatureReferenceBytesDigest -Bytes $bytes
        Assert-PspktSignatureReferencePesterPackage $bytes.Length $digest
        Expand-Archive -LiteralPath $path -DestinationPath (Join-Path $root 'Pester') -ErrorAction Stop
        $manifest=Join-Path $root 'Pester\Pester.psd1'
        if(-not [IO.File]::Exists($manifest)) { throw 'validation:pester-package' }
        return [pscustomobject]@{Length=$bytes.Length;Sha256=$digest}
    }
    catch { throw 'validation:pester-package' }
}

function Get-PspktSignatureReferenceExpectedSourceSets {
    param([object]$Source)
    . ([scriptblock]::Create($Source.Texts['certification\evidence-signature-reference\lib\Pspkt.Certification.EvidenceSignatureReferenceCompilation.ps1']))
    $bootstrapNames=@('certification\lib\Pspkt.Certification.SchemaBootstrap.cs')
    $structuralNames=@(Get-PspktSignatureReferenceStructuralNames | ForEach-Object {'certification\evidence-runtime\lib\'+$_})
    $runtimeNames=@(Get-PspktSignatureReferenceRuntimeNames | ForEach-Object {'certification\evidence-signature-reference\lib\'+$_})
    $runtimeTexts=@($runtimeNames | ForEach-Object {$Source.Texts[$_]})
    $sourceSets=@(
        (Get-PspktSignatureReferenceSourceSetHash $bootstrapNames @($Source.Texts[$bootstrapNames[0]])),
        (Get-PspktSignatureReferenceSourceSetHash $structuralNames @($structuralNames | ForEach-Object {$Source.Texts[$_]})),
        (Get-PspktSignatureReferenceSourceSetHash $runtimeNames $runtimeTexts))
    $transforms=@()
    foreach($role in @('M1','M2','M3','M4','M5')) {
        $mutation=Get-PspktSignatureReferenceMutantSource -Role $role -Names $runtimeNames -Texts $runtimeTexts
        $sourceSets+=$mutation.MutatedSourceSetSha256
        $transforms+=$mutation.TransformationSha256
    }
    return [pscustomobject]@{SourceSets=$sourceSets;TransformHashes=$transforms}
}

function Get-PspktSignatureReferenceReceiptExpectations {
    param([object]$Receipt,[object]$Source)
    $null=Assert-PspktSignatureReferenceCiShape $Receipt
    $sets=Get-PspktSignatureReferenceExpectedSourceSets $Source
    return [pscustomobject]@{callId=$Receipt.callId;hostEdition=$Receipt.hostEdition;hostVersion=$Receipt.hostVersion;
        sourceManifestSha256=$Source.ManifestSha256;fixtureManifestSha256='4b5a7a1ae3a3494c2e869c8f062082e01ee4d1b97bcc5f0842b20a5ad9c1c943';
        frameworkManifestSha256=$Receipt.frameworkManifestSha256;policySha256='06fe309693f30348f9de46d0d2998fca5e23f08e6b578d742f4e72cbcce51c17';
        SourceSets=$sets.SourceSets;TransformHashes=$sets.TransformHashes;Mutants=$Source.Fixtures.Expectations.mutants;
        ReferenceSets=@($Receipt.compilationRecords | ForEach-Object {$_.referenceSetSha256});
        ImageHashes=@($Receipt.compilationRecords | ForEach-Object {$_.imageSha256})}
}

function Invoke-PspktSignatureReferenceCiCall {
    [CmdletBinding(PositionalBinding=$false)]
    param([object]$Source,[string]$RepositoryRoot,[string]$WorkBase,[object]$Binding)
    Assert-PspktSignatureReferenceWorkflowBinding $Binding $PSVersionTable.PSEdition
    $root=$RepositoryRoot;$leaf='checkout'
    if($Binding.Slot.EndsWith('/export',[StringComparison]::Ordinal)) {
        $leaf='export'
        $exportRoot=Join-Path $WorkBase 'source-export'
        $Source=Export-PspktSignatureReferenceSourceSnapshot -Source $Source -Destination $exportRoot
        $root=$exportRoot
    }
    $work=Join-Path $WorkBase ('validation-'+$leaf)
    $manifest=Join-Path $WorkBase 'tools\Pester\Pester.psd1'
    $validationExpected=$null
    $validator=[scriptblock]::Create($Source.Texts['certification\evidence-signature-reference\validators\Invoke-PspktPhase4EvidenceSignatureReferenceValidators.ps1'])
    $captured=@(. $validator -RepositoryRoot $root -WorkRoot $work -PesterManifestPath $manifest)
    if($null -eq $validationExpected) { throw 'validation:result-identity' }
    $completed=Complete-PspktSignatureReferenceResult -Captured $captured -Expected $validationExpected
    $receipt=New-PspktSignatureReferenceCiReceipt -Result $completed -Expected $validationExpected -Binding $Binding
    $bytes=ConvertTo-PspktSignatureReferenceJsonBytes $receipt
    $null=Read-PspktSignatureReferenceCiReceipt -Bytes $bytes -Binding $Binding -Expected $validationExpected
    Write-PspktSignatureReferenceGitHubOutput -Name receipt -Bytes $bytes -MaximumBytes 16384
}

function Get-PspktSignatureReferenceProbeContracts {
    return @(
        [pscustomobject]@{Id='returned-failure';Reason='validation:returned-failure';Diagnostics=1},
        [pscustomobject]@{Id='malformed-result';Reason='validation:result-shape';Diagnostics=0},
        [pscustomobject]@{Id='missing-result';Reason='validation:result-cardinality';Diagnostics=0},
        [pscustomobject]@{Id='multiple-results';Reason='validation:result-cardinality';Diagnostics=0},
        [pscustomobject]@{Id='count-mismatch';Reason='validation:result-counts';Diagnostics=0})
}

function Get-PspktSignatureReferenceEnvironmentBinding {
    param([string]$Slot)
    return [pscustomobject]@{WorkflowRunId=$env:GITHUB_RUN_ID;WorkflowRunAttempt=$env:GITHUB_RUN_ATTEMPT;Revision=$env:GITHUB_SHA;Slot=$Slot}
}

function Invoke-PspktSignatureReferenceRawProbeStep {
    [CmdletBinding(PositionalBinding=$false)]
    param([object]$Source,[string]$HostSlot,[string]$CaseId)
    $contract=@(Get-PspktSignatureReferenceProbeContracts | Where-Object {$_.Id -ceq $CaseId})
    if($contract.Count -ne 1 -or $HostSlot -cnotin @('windows_ps51','powershell_7')) { throw 'validation:probe' }
    $baseline=[Environment]::GetEnvironmentVariable('PSPKT_STAGE3_BASELINE','Process')
    if([string]::IsNullOrEmpty($baseline) -or $baseline.Length -gt 16384) { throw 'validation:probe' }
    $bytes=[Text.UTF8Encoding]::new($false,$true).GetBytes($baseline)
    $parsed=ConvertFrom-PspktSignatureReferenceCanonicalJson -Bytes $bytes
    $expected=Get-PspktSignatureReferenceReceiptExpectations $parsed $Source
    $binding=Get-PspktSignatureReferenceEnvironmentBinding ($HostSlot+'/checkout')
    $receipt=Read-PspktSignatureReferenceCiReceipt -Bytes $bytes -Binding $binding -Expected $expected
    $local=ConvertTo-PspktSignatureReferenceLocalResult $receipt
    $positive=@(Complete-PspktSignatureReferenceResult -Captured @($local) -Expected $expected)
    if($positive.Count -ne 1 -or $positive[0].outcome -cne 'ValidationSucceeded') { throw 'validation:probe' }
    $candidates=@()
    switch -CaseSensitive ($CaseId) {
        'returned-failure' {
            $candidates=@([pscustomobject][ordered]@{schemaId='PspktEvidenceSignatureReferenceValidationResultV1';schemaVersion=1;
                outcome='ValidationFailed';callId=$local.callId;reasonCode='validation:oracle';cleanupComplete=$true})
        }
        'malformed-result' { $candidates=@([pscustomobject]@{outcome='ValidationSucceeded'}) }
        'missing-result' { $candidates=@() }
        'multiple-results' { $candidates=@($local,$local) }
        'count-mismatch' { $local.counts.passedCount=47;$candidates=@($local) }
    }
    $forwarded=[Collections.Generic.List[object]]::new()
    $wrapperReason=$null
    try { Complete-PspktSignatureReferenceResult -Captured $candidates -Expected $expected | ForEach-Object {$forwarded.Add($_)} }
    catch {
        if($_.Exception.Message -cin @(Get-PspktSignatureReferenceValidatorReasons)) { $wrapperReason=$_.Exception.Message }
    }
    $stepReason=$wrapperReason
    $successCount=@($forwarded | Where-Object {$_.outcome -ceq 'ValidationSucceeded'}).Count
    $diagnostics=@($forwarded | Where-Object {$_.outcome -ceq 'ValidationFailed'}).Count
    if($wrapperReason -cne $contract[0].Reason -or $stepReason -cne $contract[0].Reason -or $successCount -ne 0 -or $diagnostics -ne $contract[0].Diagnostics) {
        throw 'validation:probe'
    }
    $probe=[pscustomobject][ordered]@{schemaId='PspktEvidenceSignatureReferenceProbeReceiptV1';schemaVersion=1;
        workflowRunId=$binding.WorkflowRunId;workflowRunAttempt=$binding.WorkflowRunAttempt;revision=$binding.Revision;hostSlot=$HostSlot;
        caseId=$CaseId;positiveControl=$true;wrapperReason=$wrapperReason;stepReason=$stepReason;successObjectsEmitted=$successCount;diagnosticCount=$diagnostics}
    $probeBytes=ConvertTo-PspktSignatureReferenceJsonBytes -Value $probe -MaximumBytes 1024
    Write-PspktSignatureReferenceGitHubOutput -Name probe -Bytes $probeBytes -MaximumBytes 1024
    [Console]::Error.WriteLine($stepReason)
    exit 1
}

function New-PspktSignatureReferenceConfirmedProbeGroup {
    param([string]$HostSlot,[object[]]$ProbeJson,[object[]]$RawOutcomes,[object]$Binding)
    if($HostSlot -cnotin @('windows_ps51','powershell_7') -or $ProbeJson.Count -ne 5 -or $RawOutcomes.Count -ne 5) { throw 'validation:probe' }
    $edition='Core'
    if($HostSlot -ceq 'windows_ps51') { $edition='Desktop' }
    Assert-PspktSignatureReferenceWorkflowBinding $Binding $edition
    $contracts=@(Get-PspktSignatureReferenceProbeContracts)
    $rows=@()
    for($index=0;$index -lt 5;$index++) {
        Assert-PspktSignatureReferenceRawOutcome $RawOutcomes[$index]
        if($ProbeJson[$index] -isnot [string] -or $ProbeJson[$index].Length -gt 1024) { throw 'validation:probe' }
        $probe=ConvertFrom-PspktSignatureReferenceCanonicalJson -Bytes ([Text.UTF8Encoding]::new($false,$true).GetBytes($ProbeJson[$index])) -MaximumBytes 1024
        try {
            Assert-PspktSignatureReferenceRecordShape $probe @('schemaId','schemaVersion','workflowRunId','workflowRunAttempt','revision','hostSlot','caseId',
                'positiveControl','wrapperReason','stepReason','successObjectsEmitted','diagnosticCount')
            Assert-PspktSignatureReferenceIntegerShape $probe.schemaVersion 1 1
            Assert-PspktSignatureReferenceIntegerShape $probe.successObjectsEmitted 0 0
            Assert-PspktSignatureReferenceIntegerShape $probe.diagnosticCount 0 1
        }
        catch { throw 'validation:probe' }
        if($probe.schemaId -isnot [string] -or $probe.hostSlot -isnot [string] -or
            $probe.schemaId -cne 'PspktEvidenceSignatureReferenceProbeReceiptV1' -or $probe.workflowRunId -isnot [string] -or
            $probe.workflowRunAttempt -isnot [string] -or $probe.revision -isnot [string] -or
            $probe.workflowRunId -cne $Binding.WorkflowRunId -or $probe.workflowRunAttempt -cne $Binding.WorkflowRunAttempt -or
            $probe.revision -cne $Binding.Revision -or $probe.hostSlot -cne $HostSlot) { throw 'validation:workflow-binding' }
        $contract=$contracts[$index]
        if($probe.caseId -isnot [string] -or $probe.wrapperReason -isnot [string] -or $probe.stepReason -isnot [string] -or
            $probe.caseId -cne $contract.Id -or $probe.positiveControl -isnot [bool] -or -not $probe.positiveControl -or
            $probe.wrapperReason -cne $contract.Reason -or $probe.stepReason -cne $contract.Reason -or
            $probe.diagnosticCount -ne $contract.Diagnostics) { throw 'validation:probe' }
        $rows+=[pscustomobject][ordered]@{caseId=$probe.caseId;positiveControl=$probe.positiveControl;wrapperReason=$probe.wrapperReason;
            stepReason=$probe.stepReason;successObjectsEmitted=$probe.successObjectsEmitted;diagnosticCount=$probe.diagnosticCount;rawOutcome=$RawOutcomes[$index]}
    }
    return [pscustomobject][ordered]@{schemaId='PspktEvidenceSignatureReferenceProbeGroupV1';schemaVersion=1;workflowRunId=$Binding.WorkflowRunId;
        workflowRunAttempt=$Binding.WorkflowRunAttempt;revision=$Binding.Revision;hostSlot=$HostSlot;probes=$rows}
}

function Confirm-PspktSignatureReferenceProbes {
    [CmdletBinding(PositionalBinding=$false)]
    param([string]$HostSlot,[object[]]$ProbeJson,[object[]]$RawOutcomes)
    $binding=Get-PspktSignatureReferenceEnvironmentBinding ($HostSlot+'/checkout')
    $group=New-PspktSignatureReferenceConfirmedProbeGroup -HostSlot $HostSlot -ProbeJson $ProbeJson -RawOutcomes $RawOutcomes -Binding $binding
    Write-PspktSignatureReferenceGitHubOutput -Name probes -Bytes (ConvertTo-PspktSignatureReferenceJsonBytes -Value $group -MaximumBytes 4096) -MaximumBytes 4096
}

function Read-PspktSignatureReferenceProbeGroup {
    param([byte[]]$Bytes,[string]$HostSlot,[object]$Binding)
    $group=ConvertFrom-PspktSignatureReferenceCanonicalJson -Bytes $Bytes -MaximumBytes 4096
    try {
        Assert-PspktSignatureReferenceRecordShape $group @('schemaId','schemaVersion','workflowRunId','workflowRunAttempt','revision','hostSlot','probes')
        Assert-PspktSignatureReferenceIntegerShape $group.schemaVersion 1 1
        Assert-PspktSignatureReferenceArrayShape $group.probes 5
    }
    catch { throw 'validation:probe' }
    if($group.schemaId -isnot [string] -or $group.hostSlot -isnot [string] -or
        $group.schemaId -cne 'PspktEvidenceSignatureReferenceProbeGroupV1' -or $group.hostSlot -cne $HostSlot -or $group.probes.Count -ne 5 -or
        $group.workflowRunId -isnot [string] -or $group.workflowRunAttempt -isnot [string] -or $group.revision -isnot [string] -or
        $group.workflowRunId -cne $Binding.WorkflowRunId -or $group.workflowRunAttempt -cne $Binding.WorkflowRunAttempt -or
        $group.revision -cne $Binding.Revision) { throw 'validation:workflow-binding' }
    $contracts=@(Get-PspktSignatureReferenceProbeContracts)
    for($index=0;$index -lt 5;$index++) {
        $probe=$group.probes[$index];$contract=$contracts[$index]
        try {
            Assert-PspktSignatureReferenceRecordShape $probe @('caseId','positiveControl','wrapperReason','stepReason','successObjectsEmitted','diagnosticCount','rawOutcome')
            Assert-PspktSignatureReferenceIntegerShape $probe.successObjectsEmitted 0 0
            Assert-PspktSignatureReferenceIntegerShape $probe.diagnosticCount 0 1
            Assert-PspktSignatureReferenceRawOutcome $probe.rawOutcome
        }
        catch { throw 'validation:probe' }
        if($probe.caseId -isnot [string] -or $probe.wrapperReason -isnot [string] -or $probe.stepReason -isnot [string] -or
            $probe.caseId -cne $contract.Id -or $probe.positiveControl -isnot [bool] -or -not $probe.positiveControl -or
            $probe.wrapperReason -cne $contract.Reason -or $probe.stepReason -cne $contract.Reason -or $probe.diagnosticCount -ne $contract.Diagnostics) {
            throw 'validation:probe'
        }
    }
    return $group
}

function Invoke-PspktSignatureReferenceAggregate {
    [CmdletBinding(PositionalBinding=$false)]
    param([object]$Source,[string]$ArtifactRoot)
    $environmentNames=@([Environment]::GetEnvironmentVariables('Process').Keys | Where-Object {
        [string]$_ -cmatch '\APSPKT_STAGE3_(?:PAYLOAD|RECEIPT(?:_.*)?|GROUP(?:_.*)?)\z'
    })
    if($environmentNames.Count -ne 0) { throw 'validation:workflow-contract' }
    $slots=@('windows_ps51/checkout','windows_ps51/export','powershell_7/checkout','powershell_7/export')
    $fileNames=@('windows_ps51_checkout.json','windows_ps51_export.json','powershell_7_checkout.json','powershell_7_export.json',
        'windows_ps51_probes.json','powershell_7_probes.json')
    $entries=@(Get-PspktSignatureReferenceOwnedEntries -Path $ArtifactRoot -Root $ArtifactRoot)
    if($entries.Count -ne 6 -or @($entries | Where-Object {$_.Directory -or $_.RelativePath -cnotin $fileNames}).Count -ne 0) {
        throw 'validation:workflow-binding'
    }
    $calls=@();$callIds=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    for($index=0;$index -lt 4;$index++) {
        $bytes=Read-PspktSignatureReferenceBoundedFile (Join-Path $ArtifactRoot $fileNames[$index]) 16384
        $candidate=ConvertFrom-PspktSignatureReferenceCanonicalJson -Bytes $bytes
        $expected=Get-PspktSignatureReferenceReceiptExpectations $candidate $Source
        $binding=Get-PspktSignatureReferenceEnvironmentBinding $slots[$index]
        $receipt=Read-PspktSignatureReferenceCiReceipt -Bytes $bytes -Binding $binding -Expected $expected
        if(-not $callIds.Add($receipt.callId)) { throw 'validation:workflow-binding' }
        $calls+=,$receipt
    }
    foreach($offset in @(0,2)) {
        if($calls[$offset].hostVersion -cne $calls[$offset+1].hostVersion -or
            $calls[$offset].frameworkManifestSha256 -cne $calls[$offset+1].frameworkManifestSha256) { throw 'validation:result-identity' }
    }
    $probeCount=0
    for($index=0;$index -lt 2;$index++) {
        $hostSlot=@('windows_ps51','powershell_7')[$index]
        $bytes=Read-PspktSignatureReferenceBoundedFile (Join-Path $ArtifactRoot $fileNames[$index+4]) 4096
        $group=Read-PspktSignatureReferenceProbeGroup -Bytes $bytes -HostSlot $hostSlot -Binding (Get-PspktSignatureReferenceEnvironmentBinding ($hostSlot+'/checkout'))
        $probeCount+=$group.probes.Count
    }
    $compiled=0;$loaded=0;$killed=0;$containers=0;$passed=0
    foreach($call in $calls) {
        $compiled+=$call.compilationRecords.Count;$loaded+=$call.loadRecords.Count
        $killed+=@($call.mutantResults | Where-Object {$_.initialized -and $_.oracleKilled}).Count
        $containers+=$call.counts.containerCount;$passed+=$call.counts.passedCount
    }
    if($compiled -ne 32 -or $loaded -ne 32 -or $killed -ne 20 -or $containers -ne 4 -or $passed -ne 192 -or $probeCount -ne 10) {
        throw 'validation:result-counts'
    }
    return [pscustomobject][ordered]@{outcome='ValidationSucceeded';compilationCount=$compiled;loadCount=$loaded;
        initializedMutantKillCount=$killed;containerCount=$containers;passedCount=$passed;rawFailureProbeCount=$probeCount;
        sourceManifestSha256=$Source.ManifestSha256}
}

function Assert-PspktSignatureReferenceReceiptDescriptor {
    param([byte[]]$Bytes)
    $descriptor=ConvertFrom-PspktSignatureReferenceCanonicalJson -Bytes $Bytes -MaximumBytes 65536 -MaximumDepth 9
    $properties=@('schemaId','schemaVersion','bounds','records','constants','roles','sourceCounts','editions','compilers','loadContexts',
        'slots','hostSlots','mutantRoles','probeIds','probeReasons','probeDiagnosticCounts','rules')
    try {
        Assert-PspktSignatureReferenceRecordShape $descriptor $properties
        if($descriptor.schemaId -cne 'PspktEvidenceSignatureReferenceReceiptSchemaV1' -or $descriptor.schemaVersion -ne 1) { throw 'validation:contract' }
        Assert-PspktSignatureReferenceRecordShape $descriptor.bounds @('receiptBytes','probeBytes','probeGroupBytes','instanceDepth','descriptorDepth')
        if($descriptor.bounds.receiptBytes -ne 16384 -or $descriptor.bounds.probeBytes -ne 1024 -or $descriptor.bounds.probeGroupBytes -ne 4096 -or
            $descriptor.bounds.instanceDepth -ne 8 -or $descriptor.bounds.descriptorDepth -ne 9) { throw 'validation:contract' }
        $layouts=[ordered]@{
            CiReceipt='schemaId:CiIdentity|schemaVersion:One|outcome:Success|workflowRunId:Decimal20Nonzero|workflowRunAttempt:Decimal10Nonzero|revision:Hex40|slot:Slot|callId:Hex32|baseCommit:BaseCommit|hostEdition:Edition|hostVersion:DigitsDots32|pesterVersion:PesterVersion|sourceManifestSha256:Hex64|fixtureManifestSha256:Hex64|frameworkManifestSha256:Hex64|policySha256:Hex64|compilationRecords:CompilationRecord[8]|loadRecords:LoadRecord[8]|mutantResults:MutantResult[5]|counts:Counts|testIds:CaseId[48]|checks:Check[13]|cleanup:Cleanup[9]'
            ValidationResult='schemaId:LocalIdentity|schemaVersion:One|outcome:Success|callId:Hex32|baseCommit:BaseCommit|hostEdition:Edition|hostVersion:DigitsDots32|pesterVersion:PesterVersion|sourceManifestSha256:Hex64|fixtureManifestSha256:Hex64|frameworkManifestSha256:Hex64|policySha256:Hex64|compilationRecords:CompilationRecord[8]|loadRecords:LoadRecord[8]|mutantResults:MutantResult[5]|counts:Counts|testIds:CaseId[48]|checks:Check[13]|cleanup:Cleanup[9]'
            ValidationFailure='schemaId:LocalIdentity|schemaVersion:One|outcome:Failure|callId:Hex32|reasonCode:ValidatorReason|cleanupComplete:Boolean'
            CompilationRecord='role:Role|imageName:RoleCallImageName|imageLength:PositiveImageLength|imageSha256:Hex64|sourceCount:RoleSourceCount|sourceSetSha256:Hex64|referenceSetSha256:Hex64|language:CSharp5|compiler:Compiler'
            LoadRecord='role:Role|imageSha256:Hex64|context:LoadContext|initialized:True'
            MutantResult='role:MutantRole|initialized:True|controlId:ControlId|controlOutcome:Ok|challengeId:ChallengeId|baseReason:BaseReason|mutantObservation:MutantObservation|transformationSha256:Hex64|oracleKilled:True'
            Counts='compilationCount:Eight|loadCount:Eight|initializedMutantKillCount:Five|containerCount:One|totalCount:FortyEight|selectedCount:FortyEight|executedCount:FortyEight|passedCount:FortyEight|failedCount:Zero|skippedCount:Zero|notRunCount:Zero|failedBlocksCount:Zero|failedContainersCount:Zero'
            ProbeReceipt='schemaId:ProbeIdentity|schemaVersion:One|workflowRunId:Decimal20Nonzero|workflowRunAttempt:Decimal10Nonzero|revision:Hex40|hostSlot:HostSlot|caseId:ProbeId|positiveControl:True|wrapperReason:ProbeReason|stepReason:ProbeReason|successObjectsEmitted:Zero|diagnosticCount:ProbeDiagnosticCount'
            ProbeGroup='schemaId:GroupIdentity|schemaVersion:One|workflowRunId:Decimal20Nonzero|workflowRunAttempt:Decimal10Nonzero|revision:Hex40|hostSlot:HostSlot|probes:ConfirmedProbe[5]'
            ConfirmedProbe='caseId:ProbeId|positiveControl:True|wrapperReason:ProbeReason|stepReason:ProbeReason|successObjectsEmitted:Zero|diagnosticCount:ProbeDiagnosticCount|rawOutcome:FailureString'
        }
        Assert-PspktSignatureReferenceRecordShape $descriptor.records @($layouts.Keys)
        foreach($name in $layouts.Keys) {
            if(($descriptor.records.$name -join '|') -cne $layouts[$name]) { throw 'validation:contract' }
        }
        $lists=[ordered]@{roles='Bootstrap|Structural|Checker|M1|M2|M3|M4|M5';sourceCounts='1|7|17|17|17|17|17|17';
            editions='Desktop|Core';compilers='CodeDom|Roslyn';loadContexts='LoadFrom|Default';
            slots='windows_ps51/checkout|windows_ps51/export|powershell_7/checkout|powershell_7/export';
            hostSlots='windows_ps51|powershell_7';mutantRoles='M1|M2|M3|M4|M5';
            probeIds='returned-failure|malformed-result|missing-result|multiple-results|count-mismatch';
            probeReasons='validation:returned-failure|validation:result-shape|validation:result-cardinality|validation:result-cardinality|validation:result-counts';
            probeDiagnosticCounts='1|0|0|0|0'}
        foreach($name in $lists.Keys) {
            if(($descriptor.$name -join '|') -cne $lists[$name]) { throw 'validation:contract' }
        }
        if($descriptor.constants.CiIdentity -cne 'PspktEvidenceSignatureReferenceCiReceiptV1' -or
            $descriptor.constants.LocalIdentity -cne 'PspktEvidenceSignatureReferenceValidationResultV1' -or
            $descriptor.constants.ProbeIdentity -cne 'PspktEvidenceSignatureReferenceProbeReceiptV1' -or
            $descriptor.constants.GroupIdentity -cne 'PspktEvidenceSignatureReferenceProbeGroupV1' -or
            $descriptor.constants.BaseCommit -cne 'ad0bf32da25271ba7354bd1d276e56b8b34654ec' -or $descriptor.constants.PesterVersion -cne '5.3.3') {
            throw 'validation:contract'
        }
    }
    catch { throw 'validation:contract' }
}

function Read-PspktSignatureReferenceJsonString {
    param([hashtable]$State,[int]$MaximumLength)
    if($State.Position -ge $State.Bytes.Length -or $State.Bytes[$State.Position] -ne 34) { throw 'validation:receipt-json' }
    $State.Position++
    $start=$State.Position
    while($State.Position -lt $State.Bytes.Length -and $State.Bytes[$State.Position] -ne 34) {
        $value=$State.Bytes[$State.Position]
        if($value -lt 32 -or $value -gt 126 -or $value -eq 92 -or $State.Position-$start -ge $MaximumLength) {
            throw 'validation:receipt-json'
        }
        $State.Position++
    }
    if($State.Position -ge $State.Bytes.Length) { throw 'validation:receipt-json' }
    $text=[Text.Encoding]::ASCII.GetString($State.Bytes,$start,$State.Position-$start)
    $State.Position++
    return $text
}

function Read-PspktSignatureReferenceJsonValue {
    param([hashtable]$State,[int]$Depth)
    $State.Nodes++
    if($Depth -gt $State.MaximumDepth -or $State.Nodes -gt 4096 -or $State.Position -ge $State.Bytes.Length) {
        throw 'validation:receipt-json'
    }
    $token=$State.Bytes[$State.Position]
    if($token -eq 34) { return (Read-PspktSignatureReferenceJsonString $State 1024) }
    if($token -ge 48 -and $token -le 57) {
        $start=$State.Position
        while($State.Position -lt $State.Bytes.Length -and $State.Bytes[$State.Position] -ge 48 -and $State.Bytes[$State.Position] -le 57) {
            $State.Position++
        }
        $length=$State.Position-$start
        if($length -gt 20 -or ($length -gt 1 -and $token -eq 48)) { throw 'validation:receipt-json' }
        $text=[Text.Encoding]::ASCII.GetString($State.Bytes,$start,$length)
        $number=[uint64]0
        if(-not [uint64]::TryParse($text,[Globalization.NumberStyles]::None,[Globalization.CultureInfo]::InvariantCulture,[ref]$number)) {
            throw 'validation:receipt-json'
        }
        return $number
    }
    if($token -eq 116 -or $token -eq 102) {
        $literal='false'
        if($token -eq 116) { $literal='true' }
        if($State.Bytes.Length-$State.Position -lt $literal.Length -or
            [Text.Encoding]::ASCII.GetString($State.Bytes,$State.Position,$literal.Length) -cne $literal) { throw 'validation:receipt-json' }
        $State.Position+=$literal.Length
        return ($token -eq 116)
    }
    if($token -ne 123 -and $token -ne 91) { throw 'validation:receipt-json' }
    $object=$token -eq 123
    $closing=93
    if($object) { $closing=125 }
    $State.Position++
    $members=[ordered]@{}
    $names=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $items=[Collections.Generic.List[object]]::new()
    if($State.Position -lt $State.Bytes.Length -and $State.Bytes[$State.Position] -eq $closing) {
        $State.Position++
        if($object) { return [pscustomobject]$members }
        return ,$items.ToArray()
    }
    while($true) {
        if($object) {
            $name=Read-PspktSignatureReferenceJsonString $State 64
            if(-not $names.Add($name) -or $State.Position -ge $State.Bytes.Length -or $State.Bytes[$State.Position] -ne 58) {
                throw 'validation:receipt-json'
            }
            $State.Position++
        }
        elseif($items.Count -ge 256) { throw 'validation:receipt-json' }
        $value=Read-PspktSignatureReferenceJsonValue $State ($Depth+1)
        if($object) { $members.Add($name,$value) } else { $items.Add($value) }
        if($State.Position -ge $State.Bytes.Length) { throw 'validation:receipt-json' }
        $separator=$State.Bytes[$State.Position]
        $State.Position++
        if($separator -eq $closing) { break }
        if($separator -ne 44) { throw 'validation:receipt-json' }
    }
    if($object) { return [pscustomobject]$members }
    return ,$items.ToArray()
}

function ConvertFrom-PspktSignatureReferenceCanonicalJson {
    param([byte[]]$Bytes,[int]$MaximumBytes=16384,[int]$MaximumDepth=8)
    if($null -eq $Bytes -or $Bytes.Length -eq 0) { throw 'validation:receipt-json' }
    if($Bytes.Length -gt $MaximumBytes) { throw 'validation:receipt-size' }
    $state=@{Bytes=$Bytes;Position=0;Nodes=0;MaximumDepth=$MaximumDepth}
    try {
        $value=Read-PspktSignatureReferenceJsonValue $state 1
        if($state.Position -ne $Bytes.Length) { throw 'validation:receipt-json' }
        return $value
    }
    catch { throw 'validation:receipt-json' }
}

function Assert-PspktSignatureReferenceWorkflowBinding {
    param([object]$Binding,[string]$HostEdition)
    if($Binding.WorkflowRunId -isnot [string] -or $Binding.WorkflowRunId -cnotmatch '\A[1-9][0-9]{0,19}\z' -or
        $Binding.WorkflowRunAttempt -isnot [string] -or $Binding.WorkflowRunAttempt -cnotmatch '\A[1-9][0-9]{0,9}\z' -or
        $Binding.Revision -isnot [string] -or $Binding.Revision -cnotmatch '\A[0-9a-f]{40}\z' -or
        $Binding.Slot -isnot [string] -or $Binding.Slot -cnotin @('windows_ps51/checkout','windows_ps51/export','powershell_7/checkout','powershell_7/export')) {
        throw 'validation:workflow-binding'
    }
    $expectedEdition='Core'
    if($Binding.Slot.StartsWith('windows_ps51/',[StringComparison]::Ordinal)) { $expectedEdition='Desktop' }
    if($HostEdition -cne $expectedEdition) { throw 'validation:workflow-binding' }
}

function New-PspktSignatureReferenceCiReceipt {
    [CmdletBinding(PositionalBinding=$false)]
    param([object]$Result,[object]$Expected,[object]$Binding)
    $local=Complete-PspktSignatureReferenceResult -Captured @($Result) -Expected $Expected
    Assert-PspktSignatureReferenceWorkflowBinding $Binding $local.hostEdition
    $values=[ordered]@{schemaId='PspktEvidenceSignatureReferenceCiReceiptV1';schemaVersion=1;outcome='ValidationSucceeded';
        workflowRunId=$Binding.WorkflowRunId;workflowRunAttempt=$Binding.WorkflowRunAttempt;revision=$Binding.Revision;slot=$Binding.Slot}
    foreach($property in $local.PSObject.Properties) {
        if($property.Name -cin @('schemaId','schemaVersion','outcome')) { continue }
        $values.Add($property.Name,$property.Value)
    }
    $receipt=[pscustomobject]$values
    $null=ConvertTo-PspktSignatureReferenceJsonBytes $receipt
    return $receipt
}

function ConvertTo-PspktSignatureReferenceLocalResult {
    param([object]$Receipt)
    $values=[ordered]@{schemaId='PspktEvidenceSignatureReferenceValidationResultV1'}
    foreach($property in $Receipt.PSObject.Properties) {
        if($property.Name -cin @('schemaId','workflowRunId','workflowRunAttempt','revision','slot')) { continue }
        $values.Add($property.Name,$property.Value)
    }
    return [pscustomobject]$values
}

function Read-PspktSignatureReferenceCiReceipt {
    [CmdletBinding(PositionalBinding=$false)]
    param([byte[]]$Bytes,[object]$Binding,[object]$Expected)
    $receipt=ConvertFrom-PspktSignatureReferenceCanonicalJson -Bytes $Bytes
    $local=Assert-PspktSignatureReferenceCiShape $receipt
    Assert-PspktSignatureReferenceWorkflowBinding $Binding $receipt.hostEdition
    if($receipt.workflowRunId -cne $Binding.WorkflowRunId -or $receipt.workflowRunAttempt -cne $Binding.WorkflowRunAttempt -or
        $receipt.revision -cne $Binding.Revision -or $receipt.slot -cne $Binding.Slot) { throw 'validation:workflow-binding' }
    $null=Complete-PspktSignatureReferenceResult -Captured @($local) -Expected $Expected
    return $receipt
}

function Assert-PspktSignatureReferenceCiShape {
    param([object]$Receipt)
    try {
        Assert-PspktSignatureReferenceRecordShape $Receipt @('schemaId','schemaVersion','outcome','workflowRunId','workflowRunAttempt','revision','slot',
            'callId','baseCommit','hostEdition','hostVersion','pesterVersion','sourceManifestSha256','fixtureManifestSha256','frameworkManifestSha256',
            'policySha256','compilationRecords','loadRecords','mutantResults','counts','testIds','checks','cleanup')
        if($Receipt.schemaId -isnot [string] -or $Receipt.schemaId -cne 'PspktEvidenceSignatureReferenceCiReceiptV1') { throw 'validation:receipt-json' }
        foreach($name in @('workflowRunId','workflowRunAttempt','revision','slot')) {
            if($Receipt.$name -isnot [string]) { throw 'validation:receipt-json' }
        }
        $local=ConvertTo-PspktSignatureReferenceLocalResult $Receipt
        Assert-PspktSignatureReferenceLocalShape $local
        return $local
    }
    catch { throw 'validation:receipt-json' }
}

function Assert-PspktSignatureReferenceRawOutcome {
    param([object]$Outcome)
    if($Outcome -isnot [string] -or $Outcome -cne 'failure') { throw 'validation:probe' }
}

function Assert-PspktSignatureReferenceTransportEnvironment {
    $names=@([Environment]::GetEnvironmentVariables('Process').Keys | Where-Object {
        [string]$_ -cmatch '\APSPKT_STAGE3_(?:PAYLOAD|RECEIPT(?:_.*)?|GROUP(?:_.*)?)\z'
    })
    if($names.Count -ne 1 -or $names[0] -cne 'PSPKT_STAGE3_PAYLOAD') { throw 'validation:workflow-contract' }
}

function Write-PspktSignatureReferenceTransport {
    [CmdletBinding(PositionalBinding=$false)]
    param([Parameter(Mandatory=$true)][string]$Destination,[int]$MaximumBytes=16384)
    Assert-PspktSignatureReferenceTransportEnvironment
    $text=[Environment]::GetEnvironmentVariable('PSPKT_STAGE3_PAYLOAD','Process')
    if([string]::IsNullOrEmpty($text)) { throw 'validation:workflow-binding' }
    if($text.Length -gt $MaximumBytes) { throw 'validation:receipt-size' }
    $bytes=[Text.UTF8Encoding]::new($false,$true).GetBytes($text)
    if($bytes.Length -gt $MaximumBytes) { throw 'validation:receipt-size' }
    $null=ConvertFrom-PspktSignatureReferenceCanonicalJson -Bytes $bytes -MaximumBytes $MaximumBytes
    if(-not [IO.Path]::IsPathRooted($Destination)) { throw 'validation:work-root' }
    $parent=[IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($Destination))
    [void][IO.Directory]::CreateDirectory($parent)
    $stream=[IO.File]::Open($Destination,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try { $stream.Write($bytes,0,$bytes.Length);$stream.Flush($true) }
    finally { $stream.Dispose() }
}

function Assert-PspktSignatureReferencePesterPackage {
    param([long]$Length,[string]$Sha256)
    if($Length -ne 271297 -or $Sha256 -cne 'bf450611b92dee8de7dd5e69809d5b37f86bff9f8f3b6eb3129d2fbdd889b579') {
        throw 'validation:pester-package'
    }
}

function Assert-PspktSignatureReferenceWorkflow {
    param([string]$Text,[string]$Attributes)
    $expectedAttributes="/.gitattributes text eol=lf -filter -ident -working-tree-encoding`n"+
        "/workflows/ci-evidence-signature-reference.yml text eol=lf -filter -ident -working-tree-encoding`n"
    if($Text.Contains([string][char]13) -or $Text.Contains([string][char]65279) -or $Attributes -cne $expectedAttributes -or
        $Text -match '(?i)pull_request_target|secrets[.\[]|matrix[.]shell|always\s*\(|self-hosted|Import-Module\s+pspkt' -or
        [regex]::Matches($Text,'(?m)^      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1$').Count -ne 3 -or
        [regex]::Matches($Text,'(?m)^          persist-credentials: false$').Count -ne 3 -or
        [regex]::Matches($Text,'(?m)^\s+- uses: ').Count -ne 3 -or
        [regex]::Matches($Text,'(?m)^permissions:$').Count -ne 1 -or
        $Text -cnotmatch '(?m)^permissions:\n  contents: read\n' -or
        $Text -match '(?m)^\s+(?:repository|ref|token):|\b(?:GH_TOKEN|GITHUB_TOKEN)\b') { throw 'validation:workflow-contract' }
    $eventBlock="on:`n  pull_request:`n  workflow_dispatch:`n  push:`n    branches: [main, master]`npermissions:"
    if(-not $Text.Contains($eventBlock)) { throw 'validation:workflow-contract' }
    if(-not $Text.Contains('PSPKT_STAGE3_WORK_BASE: ''${{ github.workspace }}-pspkt-stage3''') -or
        $Text.Contains('${{ runner.workspace }}')) { throw 'validation:workflow-contract' }
    $jobs=[regex]::Matches($Text,'(?m)^  (windows_ps51|powershell_7|evidence_signature_reference_acceptance):$')
    if($jobs.Count -ne 3) { throw 'validation:workflow-contract' }
    $expectedJobs=@('windows_ps51','powershell_7','evidence_signature_reference_acceptance')
    $jobText=$Text.Substring($Text.IndexOf("jobs:`n",[StringComparison]::Ordinal)+6)
    if([regex]::Matches($jobText,'(?m)^  [a-zA-Z0-9_-]+:$').Count -ne 3) { throw 'validation:workflow-contract' }
    for($index=0;$index -lt 3;$index++) {
        if($jobs[$index].Groups[1].Value -cne $expectedJobs[$index]) { throw 'validation:workflow-contract' }
        $end=$Text.Length
        if($index -lt 2) { $end=$jobs[$index+1].Index }
        $body=$Text.Substring($jobs[$index].Index,$end-$jobs[$index].Index)
        $shells=[regex]::Matches($body,'(?m)^        shell: (\S+)$')
        $shell='pwsh'
        if($index -eq 0) { $shell='powershell' }
        if($shells.Count -ne 1 -or $shells[0].Groups[1].Value -cne $shell -or $body -cnotmatch '(?m)^    runs-on: windows-latest$') {
            throw 'validation:workflow-contract'
        }
        if($index -lt 2) {
            $probeNames=@('returned_failure','malformed_result','missing_result','multiple_results','count_mismatch')
            for($probeIndex=0;$probeIndex -lt 5;$probeIndex++) {
                $outcome='RAW_'+($probeIndex+1)+': ${{ steps.probe_'+$probeNames[$probeIndex]+'.outcome }}'
                $receipt='PROBE_'+($probeIndex+1)+': ${{ steps.probe_'+$probeNames[$probeIndex]+'.outputs.probe }}'
                if([regex]::Matches($body,[regex]::Escape($outcome)).Count -ne 1 -or
                    [regex]::Matches($body,[regex]::Escape($receipt)).Count -ne 1) { throw 'validation:workflow-contract' }
            }
        }
    }
    if([regex]::Matches($Text,'(?m)^        continue-on-error: true$').Count -ne 10 -or
        [regex]::Matches($Text,'(?m)^      - id: stage_(?:windows_checkout|windows_export|core_checkout|core_export|windows_probes|core_probes)$').Count -ne 6 -or
        [regex]::Matches($Text,'(?m)^          PSPKT_STAGE3_PAYLOAD: \$\{\{ needs\.[a-z0-9_]+\.outputs\.[a-z0-9_]+ \}\}$').Count -ne 6 -or
        [regex]::Matches($Text,'(?m)^          RAW_[1-5]: \$\{\{ steps\.probe_[a-z_]+\.outcome \}\}$').Count -ne 10) {
        throw 'validation:workflow-contract'
    }
    foreach($segment in [regex]::Split($Text,'(?m)^      - ')) {
        if([regex]::Matches($segment,'(?m)^\s+PSPKT_STAGE3_(?:PAYLOAD|RECEIPT[^:]*|GROUP[^:]*):').Count -gt 1 -or
            [regex]::Matches($segment,'\$\{\{ needs\.[a-z0-9_]+\.outputs\.(?:checkout|export|probes) \}\}').Count -gt 1) {
            throw 'validation:workflow-contract'
        }
    }
    foreach($required in @('pull_request:','workflow_dispatch:','branches: [main, master]','contents: read',
        'GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT','GITHUB_SHA','if: ${{ !cancelled() }}','Invoke-PspktSignatureReferenceRawProbeStep',
        'Confirm-PspktSignatureReferenceProbes','Write-PspktSignatureReferenceTransport','Invoke-PspktSignatureReferenceAggregate',
        'Assert-PspktSignatureReferencePesterPackage')) {
        if(-not $Text.Contains($required)) { throw 'validation:workflow-contract' }
    }
}

function Get-PspktSignatureReferenceCaseIds {
    return @('authority-pins','authority-routing','frozen-dependency-closure','public-surface','snapshot-pin-and-owner',
        'snapshot-canonical-json','snapshot-row-shape','snapshot-count-and-size','snapshot-context-and-skew','snapshot-rsa-envelope',
        'snapshot-key-id','snapshot-all-rows','snapshot-uint64','signature-kind-profile','signature-preimages','signature-payload-digest',
        'signature-key-selection','signature-role','signature-evaluation-time','signature-range-and-endian','signature-strict-emsa',
        'signature-algorithm','schema-protocol-binding','schema-evidence-binding','schema-scope','structural-kind-coverage',
        'graph-conditional-edges','graph-target-category','graph-missing-target','graph-cardinality','graph-duplicates',
        'join-burned-operation','join-burned-semantic','join-successor-operation','outer-metadata','subject-and-producer-residuals',
        'key-time-and-ledger-residuals','kind-token-transitions','input-bounds-and-copies','atomicity-and-diagnostics',
        'independent-fixtures','initialized-mutants','compiler-and-load-custody','retained-pester-container',
        'result-boundary-rejections','workflow-and-attempt-binding','receipt-size-and-census','cleanup-and-registry')
}

function Get-PspktSignatureReferenceCompletionChecks {
    return @('authority-pins','snapshot-policy','cryptographic-oracles','schema-bindings','references-and-joins','token-contract',
        'public-api','frozen-source-closure','compiler-references','caller-scope','workflow-contract','receipt-budget','complete-population')
}

function Get-PspktSignatureReferenceCleanupChecks {
    return @('hashes-disposed','streams-closed','compiler-staging-removed','testdrive-removed','testregistry-absent',
        'environment-restored','locations-restored','loaded-images-declared','no-unowned-residue')
}

function Get-PspktSignatureReferenceCountValues {
    return [ordered]@{compilationCount=8;loadCount=8;initializedMutantKillCount=5;containerCount=1;totalCount=48;selectedCount=48;
        executedCount=48;passedCount=48;failedCount=0;skippedCount=0;notRunCount=0;failedBlocksCount=0;failedContainersCount=0}
}

function Get-PspktSignatureReferenceValidatorReasons {
    return @('validation:contract','validation:work-root','validation:invocation-repeat','validation:source-length','validation:source-pin',
        'validation:source-membership','validation:source-policy','validation:source-export','validation:authority-routing','validation:public-surface',
        'validation:residual-contract','validation:fixture-pin','validation:generator-isolation','validation:oracle','validation:mutant-transform',
        'validation:mutant-control','validation:mutant-observation','validation:compilation','validation:reference','validation:preload',
        'validation:assembly-custody','validation:pester-manifest','validation:pester-version','validation:pester-package','validation:pester-container',
        'validation:pester-result','validation:result-cardinality','validation:result-shape','validation:returned-failure','validation:result-counts',
        'validation:result-identity','validation:workflow-contract','validation:workflow-binding','validation:receipt-json','validation:receipt-size',
        'validation:probe','validation:registry','validation:cleanup','validation:unexpected')
}

function Assert-PspktSignatureReferenceRecordShape {
    param([object]$Value,[string[]]$Names)
    if($null -eq $Value -or $Value -isnot [pscustomobject]) { throw 'validation:result-shape' }
    $actual=@($Value.PSObject.Properties.Name)
    if($actual.Count -ne $Names.Count) { throw 'validation:result-shape' }
    for($index=0;$index -lt $Names.Count;$index++) {
        if($actual[$index] -cne $Names[$index]) { throw 'validation:result-shape' }
    }
}

function Assert-PspktSignatureReferenceStringShape {
    param([object]$Value,[string]$Pattern,[int]$MaximumLength=128)
    if($Value -isnot [string] -or $Value.Length -gt $MaximumLength -or $Value -cnotmatch $Pattern) {
        throw 'validation:result-shape'
    }
}

function Assert-PspktSignatureReferenceIntegerShape {
    param([object]$Value,[uint64]$Minimum=0,[uint64]$Maximum=16777216)
    if($Value -isnot [byte] -and $Value -isnot [sbyte] -and $Value -isnot [int16] -and $Value -isnot [uint16] -and
        $Value -isnot [int32] -and $Value -isnot [uint32] -and $Value -isnot [int64] -and $Value -isnot [uint64]) {
        throw 'validation:result-shape'
    }
    if($Value -lt 0 -or [uint64]$Value -lt $Minimum -or [uint64]$Value -gt $Maximum) { throw 'validation:result-shape' }
}

function Assert-PspktSignatureReferenceArrayShape {
    param([object]$Value,[int]$Maximum=256)
    if($null -eq $Value -or -not $Value.GetType().IsArray -or $Value.Length -gt $Maximum) { throw 'validation:result-shape' }
}

function Assert-PspktSignatureReferenceLocalShape {
    param([object]$Value)
    if($null -eq $Value -or $Value -isnot [pscustomobject] -or $null -eq $Value.PSObject.Properties['outcome'] -or
        $Value.outcome -isnot [string]) { throw 'validation:result-shape' }
    if($Value.outcome -ceq 'ValidationFailed') {
        Assert-PspktSignatureReferenceRecordShape $Value @('schemaId','schemaVersion','outcome','callId','reasonCode','cleanupComplete')
        if($Value.schemaId -isnot [string] -or $Value.schemaId -cne 'PspktEvidenceSignatureReferenceValidationResultV1' -or $Value.cleanupComplete -isnot [bool] -or
            $Value.reasonCode -isnot [string] -or $Value.reasonCode -cnotin @(Get-PspktSignatureReferenceValidatorReasons)) { throw 'validation:result-shape' }
        Assert-PspktSignatureReferenceIntegerShape $Value.schemaVersion 1 1
        Assert-PspktSignatureReferenceStringShape $Value.callId '\A[0-9a-f]{32}\z'
        return
    }
    Assert-PspktSignatureReferenceRecordShape $Value @('schemaId','schemaVersion','outcome','callId','baseCommit','hostEdition','hostVersion','pesterVersion',
        'sourceManifestSha256','fixtureManifestSha256','frameworkManifestSha256','policySha256','compilationRecords','loadRecords','mutantResults',
        'counts','testIds','checks','cleanup')
    if($Value.schemaId -isnot [string] -or $Value.schemaId -cne 'PspktEvidenceSignatureReferenceValidationResultV1' -or $Value.outcome -cne 'ValidationSucceeded') {
        throw 'validation:result-shape'
    }
    Assert-PspktSignatureReferenceIntegerShape $Value.schemaVersion 1 1
    Assert-PspktSignatureReferenceStringShape $Value.callId '\A[0-9a-f]{32}\z'
    Assert-PspktSignatureReferenceStringShape $Value.baseCommit '\A[0-9a-f]{40}\z'
    Assert-PspktSignatureReferenceStringShape $Value.hostEdition '\A(?:Desktop|Core)\z'
    Assert-PspktSignatureReferenceStringShape $Value.hostVersion '\A[0-9.]{1,32}\z' 32
    Assert-PspktSignatureReferenceStringShape $Value.pesterVersion '\A[0-9.]{1,32}\z' 32
    foreach($name in @('sourceManifestSha256','fixtureManifestSha256','frameworkManifestSha256','policySha256')) {
        Assert-PspktSignatureReferenceStringShape $Value.$name '\A[0-9a-f]{64}\z'
    }
    foreach($name in @('compilationRecords','loadRecords','mutantResults','testIds','checks','cleanup')) {
        Assert-PspktSignatureReferenceArrayShape $Value.$name
    }
    foreach($record in $Value.compilationRecords) {
        Assert-PspktSignatureReferenceRecordShape $record @('role','imageName','imageLength','imageSha256','sourceCount','sourceSetSha256','referenceSetSha256','language','compiler')
        Assert-PspktSignatureReferenceStringShape $record.role '\A(?:Bootstrap|Structural|Checker|M[1-5])\z'
        Assert-PspktSignatureReferenceStringShape $record.imageName '\A[A-Za-z0-9_.]{1,128}\z'
        Assert-PspktSignatureReferenceIntegerShape $record.imageLength 1 16777216
        Assert-PspktSignatureReferenceIntegerShape $record.sourceCount 0 256
        foreach($name in @('imageSha256','sourceSetSha256','referenceSetSha256')) {
            Assert-PspktSignatureReferenceStringShape $record.$name '\A[0-9a-f]{64}\z'
        }
        if($record.language -isnot [string] -or $record.compiler -isnot [string] -or
            $record.language -cne 'CSharp5' -or $record.compiler -cnotin @('CodeDom','Roslyn')) { throw 'validation:result-shape' }
    }
    foreach($record in $Value.loadRecords) {
        Assert-PspktSignatureReferenceRecordShape $record @('role','imageSha256','context','initialized')
        Assert-PspktSignatureReferenceStringShape $record.role '\A(?:Bootstrap|Structural|Checker|M[1-5])\z'
        Assert-PspktSignatureReferenceStringShape $record.imageSha256 '\A[0-9a-f]{64}\z'
        if($record.context -isnot [string] -or $record.context -cnotin @('LoadFrom','Default') -or $record.initialized -isnot [bool]) { throw 'validation:result-shape' }
    }
    foreach($record in $Value.mutantResults) {
        Assert-PspktSignatureReferenceRecordShape $record @('role','initialized','controlId','controlOutcome','challengeId','baseReason','mutantObservation','transformationSha256','oracleKilled')
        Assert-PspktSignatureReferenceStringShape $record.role '\AM[1-5]\z'
        foreach($name in @('controlId','challengeId','baseReason','mutantObservation','controlOutcome')) {
            Assert-PspktSignatureReferenceStringShape $record.$name '\A[a-z0-9:-]{1,48}\z' 48
        }
        Assert-PspktSignatureReferenceStringShape $record.transformationSha256 '\A[0-9a-f]{64}\z'
        if($record.initialized -isnot [bool] -or $record.oracleKilled -isnot [bool]) { throw 'validation:result-shape' }
    }
    $counts=Get-PspktSignatureReferenceCountValues
    Assert-PspktSignatureReferenceRecordShape $Value.counts @($counts.Keys)
    foreach($name in $counts.Keys) { Assert-PspktSignatureReferenceIntegerShape $Value.counts.$name 0 16777216 }
    foreach($name in @('testIds','checks','cleanup')) {
        foreach($item in $Value.$name) { Assert-PspktSignatureReferenceStringShape $item '\A[a-z0-9-]{1,64}\z' 64 }
    }
}

function Assert-PspktSignatureReferenceResultIdentity {
    param([object]$Value,[object]$Expected)
    if($Value.baseCommit -cne 'ad0bf32da25271ba7354bd1d276e56b8b34654ec' -or $Value.pesterVersion -cne '5.3.3') {
        throw 'validation:result-identity'
    }
    foreach($name in @('callId','hostEdition','hostVersion','sourceManifestSha256','fixtureManifestSha256','frameworkManifestSha256','policySha256')) {
        if($Value.$name -cne $Expected.$name) { throw 'validation:result-identity' }
    }
}

function Assert-PspktSignatureReferenceResultCensus {
    param([object]$Value,[object]$Expected)
    $roles=@('Bootstrap','Structural','Checker','M1','M2','M3','M4','M5')
    if($Value.compilationRecords.Count -ne 8 -or $Value.loadRecords.Count -ne 8 -or $Value.mutantResults.Count -ne 5) {
        throw 'validation:result-counts'
    }
    $compiler='Roslyn';$context='Default'
    if($Value.hostEdition -ceq 'Desktop') { $compiler='CodeDom';$context='LoadFrom' }
    for($index=0;$index -lt 8;$index++) {
        $record=$Value.compilationRecords[$index];$load=$Value.loadRecords[$index]
        $sourceCount=17
        if($index -eq 0) { $sourceCount=1 } elseif($index -eq 1) { $sourceCount=7 }
        if($record.role -cne $roles[$index] -or $load.role -cne $roles[$index] -or $record.sourceCount -ne $sourceCount -or
            $record.imageName -cne ('PspktEvidenceSignatureReference_'+$Value.callId+'_'+$roles[$index]+'.dll') -or
            $record.compiler -cne $compiler -or $load.context -cne $context -or -not $load.initialized -or
            $load.imageSha256 -cne $record.imageSha256) { throw 'validation:result-counts' }
        if($record.sourceSetSha256 -cne $Expected.SourceSets[$index] -or $record.referenceSetSha256 -cne $Expected.ReferenceSets[$index] -or
            $record.imageSha256 -cne $Expected.ImageHashes[$index]) { throw 'validation:result-identity' }
    }
    for($index=0;$index -lt 5;$index++) {
        $record=$Value.mutantResults[$index];$recipe=$Expected.Mutants[$index]
        if($record.role -cne $recipe.role -or -not $record.initialized -or -not $record.oracleKilled -or
            $record.controlOutcome -cne 'ok' -or $record.controlId -cne $recipe.controlId -or
            $record.challengeId -cne $recipe.challengeId -or $record.baseReason -cne $recipe.baseReason -or
            $record.mutantObservation -cne $recipe.observation -or $record.transformationSha256 -cne $Expected.TransformHashes[$index]) {
            throw 'validation:result-counts'
        }
    }
    $counts=Get-PspktSignatureReferenceCountValues
    foreach($name in $counts.Keys) {
        if($Value.counts.$name -ne $counts[$name]) { throw 'validation:result-counts' }
    }
    $ids=@(Get-PspktSignatureReferenceCaseIds)
    if($Value.testIds.Count -ne 48) { throw 'validation:result-counts' }
    for($index=0;$index -lt 48;$index++) {
        if($Value.testIds[$index] -cne $ids[$index]) { throw 'validation:result-counts' }
    }
    $checks=@(Get-PspktSignatureReferenceCompletionChecks)
    if($Value.checks.Count -ne $checks.Count) { throw 'validation:result-counts' }
    for($index=0;$index -lt $checks.Count;$index++) {
        if($Value.checks[$index] -cne $checks[$index]) { throw 'validation:result-counts' }
    }
    $cleanup=@(Get-PspktSignatureReferenceCleanupChecks)
    if($Value.cleanup.Count -ne $cleanup.Count) { throw 'validation:cleanup' }
    for($index=0;$index -lt $cleanup.Count;$index++) {
        if($Value.cleanup[$index] -cne $cleanup[$index]) { throw 'validation:cleanup' }
    }
}

function ConvertTo-PspktSignatureReferenceJsonBytes {
    param([object]$Value,[int]$MaximumBytes=16384)
    $json=ConvertTo-Json -InputObject $Value -Depth 12 -Compress
    $bytes=[Text.UTF8Encoding]::new($false,$true).GetBytes($json)
    if($bytes.Length -gt $MaximumBytes) { throw 'validation:receipt-size' }
    return ,$bytes
}

function Complete-PspktSignatureReferenceResult {
    [CmdletBinding(PositionalBinding=$false)]
    param([AllowEmptyCollection()][object[]]$Captured,[Parameter(Mandatory=$true)][object]$Expected)
    if($null -eq $Captured -or $Captured.Count -ne 1) { throw 'validation:result-cardinality' }
    $value=$Captured[0]
    Assert-PspktSignatureReferenceLocalShape $value
    if($value.outcome -ceq 'ValidationFailed') {
        $value
        throw 'validation:returned-failure'
    }
    Assert-PspktSignatureReferenceResultIdentity $value $Expected
    Assert-PspktSignatureReferenceResultCensus $value $Expected
    $null=ConvertTo-PspktSignatureReferenceJsonBytes $value
    return $value
}
