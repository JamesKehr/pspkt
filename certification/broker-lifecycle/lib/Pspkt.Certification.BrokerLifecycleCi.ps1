Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'

function Assert-PspktBrokerLifecycleProperties {
    param([object]$Value,[string[]]$Names,[string]$Reason='validation:result-shape')
    if($null -eq $Value -or ($Value.PSObject.Properties.Name -join '|') -cne ($Names -join '|')){throw $Reason}
}

function Assert-PspktBrokerLifecycleInteger {
    param([object]$Value,[UInt64]$Minimum,[UInt64]$Maximum,[string]$Reason='validation:result-shape')
    if($Value -isnot [byte] -and $Value -isnot [UInt16] -and $Value -isnot [UInt32] -and $Value -isnot [UInt64] -and
        $Value -isnot [int] -and $Value -isnot [long]){throw $Reason}
    if($Value -lt 0 -or [UInt64]$Value -lt $Minimum -or [UInt64]$Value -gt $Maximum){throw $Reason}
}

function Assert-PspktBrokerLifecycleHex {
    param([object]$Value,[int]$Length,[string]$Reason='validation:result-shape')
    if($Value -isnot [string] -or $Value -cnotmatch ('\A[0-9a-f]{'+$Length+'}\z')){throw $Reason}
}

function ConvertTo-PspktBrokerLifecycleReceiptJson {
    param([object]$Value,[int]$MaximumBytes=16384)
    if($null -eq $Value){throw 'validation:receipt'}
    try{$text=ConvertTo-Json -InputObject $Value -Depth 20 -Compress}catch{throw 'validation:receipt'}
    Assert-PspktBrokerLifecycleReceiptText $text $MaximumBytes
    return $text
}

function ConvertFrom-PspktBrokerLifecycleReceiptJson {
    param([string]$Json,[int]$MaximumBytes=16384)
    Assert-PspktBrokerLifecycleReceiptText $Json $MaximumBytes
    try{
        $value=ConvertFrom-Json -InputObject $Json -ErrorAction Stop
        $canonical=ConvertTo-PspktBrokerLifecycleReceiptJson $value $MaximumBytes
        if($canonical -cne $Json){throw 'validation:receipt'}
        return $value
    }
    catch{throw 'validation:receipt'}
}

function Assert-PspktBrokerLifecycleReceiptText {
    param([string]$Json,[int]$MaximumBytes)
    if([string]::IsNullOrEmpty($Json) -or $Json.Length -gt $MaximumBytes -or $Json -cmatch '[\x00-\x1f\x7f-\uffff\\]'){throw 'validation:receipt'}
    $depth=0
    $quoted=$false
    $nodes=0
    foreach($character in $Json.ToCharArray()){
        if($character -eq '"'){$quoted=-not $quoted;continue}
        if($quoted){continue}
        if($character -eq ' '){throw 'validation:receipt'}
        if($character -eq '{' -or $character -eq '['){$depth++;$nodes++;if($depth -gt 12 -or $nodes -gt 1024){throw 'validation:receipt'}}
        elseif($character -eq '}' -or $character -eq ']'){$depth--;if($depth -lt 0){throw 'validation:receipt'}}
    }
    if($depth -ne 0 -or $quoted){throw 'validation:receipt'}
}

function Get-PspktBrokerLifecycleSuccessProperties {
    return @('schemaId','schemaVersion','outcome','callId','baseCommit','hostEdition','hostVersion','pesterVersion','trustCeiling',
        'sourceManifestSha256','fixtureManifestSha256','framingAddendumSchemaSha256','framingAddendumSha256',
        'designReviewActivationSha256','lifecyclePolicySha256','frameworkManifestSha256','compilationRecords',
        'loadRecords','mutantResults','counts','caseIds','completionChecks','cleanupChecks')
}

function Read-PspktBrokerLifecycleReceiptFile {
    param([string]$Path,[int]$MaximumBytes=16384)
    try {
        $bytes=Read-PspktBrokerLifecycleSourceFile $Path $MaximumBytes
        $json=[Text.UTF8Encoding]::new($false,$true).GetString($bytes)
        return ConvertFrom-PspktBrokerLifecycleReceiptJson $json $MaximumBytes
    }
    catch {throw 'validation:receipt'}
}

function Assert-PspktBrokerLifecycleResult {
    param([object[]]$Results,[object]$Expected)
    if($null -eq $Results -or $Results.Length -ne 1){throw 'validation:result-cardinality'}
    try {
        $result=$Results[0]
        if($null -ne $result -and $null -ne $result.PSObject.Properties['outcome'] -and $result.outcome -ceq 'ValidationFailed'){
            throw 'validation:result-failed'
        }
        Assert-PspktBrokerLifecycleProperties $result (Get-PspktBrokerLifecycleSuccessProperties)
        if($result.schemaId -cne 'PspktBrokerLifecycleValidationResultV1' -or $result.outcome -cne 'ValidationSucceeded' -or
            $result.trustCeiling -cne 'StructuralInProcessOnly' -or $result.baseCommit -cne '46dc63bb1bd537037c32edd2cb9e5151e0ad96ad' -or
            $result.pesterVersion -cne '5.3.3' -or $result.hostEdition -cnotin @('Desktop','Core') -or
            $result.hostVersion -cnotmatch '\A[0-9]+(?:\.[0-9]+){1,3}\z' -or $result.hostVersion.Length -gt 32){throw 'validation:result-shape'}
        Assert-PspktBrokerLifecycleInteger $result.schemaVersion 1 1
        Assert-PspktBrokerLifecycleHex $result.callId 32
        foreach($name in @('sourceManifestSha256','fixtureManifestSha256','framingAddendumSchemaSha256','framingAddendumSha256',
            'designReviewActivationSha256','lifecyclePolicySha256','frameworkManifestSha256')){
            Assert-PspktBrokerLifecycleHex $result.$name 64
        }
        foreach($property in $Expected.Bindings.PSObject.Properties){
            if($result.($property.Name) -cne $property.Value){throw 'validation:workflow-binding'}
        }
        $countNames=@('compilationCount','loadCount','initializedMutantKillCount','containerCount','totalCount','selectedCount',
            'executedCount','passedCount','failedCount','skippedCount','notRunCount','failedBlocksCount','failedContainersCount')
        $counts=@(8,8,6,1,32,32,32,32,0,0,0,0,0)
        Assert-PspktBrokerLifecycleProperties $result.counts $countNames 'validation:result-counts'
        for($index=0;$index -lt $counts.Count;$index++){Assert-PspktBrokerLifecycleInteger $result.counts.($countNames[$index]) $counts[$index] $counts[$index] 'validation:result-counts'}
        Assert-PspktBrokerLifecycleCasePopulation -Actual ([string[]]$result.caseIds) -Expected ([string[]]$Expected.CaseIds)
        if(($result.completionChecks -join '|') -cne ($Expected.CompletionChecks -join '|') -or
            ($result.cleanupChecks -join '|') -cne ($Expected.CleanupChecks -join '|')){throw 'validation:result-counts'}
        $roles=@('Bootstrap','Runtime','M1','M2','M3','M4','M5','M6')
        if(@($result.compilationRecords).Count -ne 8 -or @($result.loadRecords).Count -ne 8 -or @($result.mutantResults).Count -ne 6){throw 'validation:result-counts'}
        for($index=0;$index -lt 8;$index++){
            $record=$result.compilationRecords[$index]
            Assert-PspktBrokerLifecycleProperties $record @('role','imageName','imageLength','imageSha256','sourceCount','sourceSetSha256','referenceSetSha256','language','compiler')
            $role=$roles[$index]
            if($record.role -cne $role -or $record.imageName -cne ('PspktBrokerLifecycle_'+$result.callId+'_'+$role+'.dll') -or
                $record.language -cne 'CSharp5' -or $record.compiler -cne $(if($result.hostEdition -ceq 'Desktop'){'CodeDom'}else{'Roslyn'})){throw 'validation:result-shape'}
            Assert-PspktBrokerLifecycleInteger $record.imageLength 1 16777216
            $sources=31
            if($role -ceq 'Bootstrap'){$sources=1}
            Assert-PspktBrokerLifecycleInteger $record.sourceCount $sources $sources 'validation:result-counts'
            foreach($name in @('imageSha256','sourceSetSha256','referenceSetSha256')){Assert-PspktBrokerLifecycleHex $record.$name 64}
            if($record.sourceSetSha256 -cne $Expected.SourceSets.$role){throw 'validation:workflow-binding'}
            $load=$result.loadRecords[$index]
            Assert-PspktBrokerLifecycleProperties $load @('role','imageSha256','context','initialized')
            if($load.role -cne $role -or $load.imageSha256 -cne $record.imageSha256 -or $load.initialized -isnot [bool] -or
                -not $load.initialized -or $load.context -cne $(if($result.hostEdition -ceq 'Desktop'){'LoadFrom'}else{'Default'})){throw 'validation:result-shape'}
        }
        $oracles=@('header-length-endian','local-signature-domain','bootstrap-wrapped-three','local-record-limit','generation-owner','close-quiescence')
        for($index=0;$index -lt 6;$index++){
            $record=$result.mutantResults[$index]
            $role='M'+($index+1)
            Assert-PspktBrokerLifecycleProperties $record @('role','initialized','positiveControl','oracleKilled','oracleId',
                'originalSourceSetSha256','mutatedSourceSetSha256','transformationSha256')
            if($record.role -cne $role -or $record.initialized -isnot [bool] -or -not $record.initialized -or
                $record.oracleKilled -isnot [bool] -or -not $record.oracleKilled -or $record.positiveControl -cne 'Passed' -or
                $record.oracleId -cne $oracles[$index] -or $record.originalSourceSetSha256 -cne $Expected.SourceSets.Runtime -or
                $record.mutatedSourceSetSha256 -cne $Expected.SourceSets.$role -or
                $record.transformationSha256 -cne $Expected.Transformations.$role){throw 'validation:result-shape'}
        }
        [void](ConvertTo-PspktBrokerLifecycleReceiptJson $result)
        return $result
    }
    catch {
        $reason=$_.Exception.Message
        if($reason -cin @('validation:result-failed','validation:result-shape','validation:result-cardinality','validation:result-counts','validation:workflow-binding')){throw $reason}
        throw 'validation:result-shape'
    }
}

function Assert-PspktBrokerLifecycleWorkflowContext {
    param([object]$Context)
    if($Context.RunId -isnot [string] -or $Context.RunId -cnotmatch '\A[1-9][0-9]{0,19}\z' -or
        $Context.Attempt -isnot [string] -or $Context.Attempt -cnotmatch '\A[1-9][0-9]{0,9}\z' -or
        $Context.Revision -isnot [string] -or $Context.Revision -cnotmatch '\A[0-9a-f]{40}\z' -or
        $Context.Slot -cnotin @('windows_ps51/checkout','windows_ps51/export','powershell_7/checkout','powershell_7/export')){
        throw 'validation:workflow-binding'
    }
}

function New-PspktBrokerLifecycleCiReceipt {
    param([object]$Result,[object]$Expected,[object]$Context)
    Assert-PspktBrokerLifecycleWorkflowContext $Context
    $result=Assert-PspktBrokerLifecycleResult @($Result) $Expected
    if(($result.hostEdition -ceq 'Desktop') -ne $Context.Slot.StartsWith('windows_ps51/',[StringComparison]::Ordinal)){throw 'validation:workflow-binding'}
    $receipt=[ordered]@{schemaId='PspktBrokerLifecycleCiReceiptV1';schemaVersion=1;outcome='ValidationSucceeded';
        workflowRunId=$Context.RunId;workflowRunAttempt=$Context.Attempt;revision=$Context.Revision;slot=$Context.Slot}
    foreach($name in (Get-PspktBrokerLifecycleSuccessProperties)|Select-Object -Skip 3){$receipt[$name]=$result.$name}
    return [pscustomobject]$receipt
}

function Assert-PspktBrokerLifecycleCiReceipt {
    param([string]$Json,[object]$Expected,[object]$Context)
    Assert-PspktBrokerLifecycleWorkflowContext $Context
    $receipt=ConvertFrom-PspktBrokerLifecycleReceiptJson $Json 16384
    $names=@('schemaId','schemaVersion','outcome','workflowRunId','workflowRunAttempt','revision','slot')+
        @((Get-PspktBrokerLifecycleSuccessProperties)|Select-Object -Skip 3)
    Assert-PspktBrokerLifecycleProperties $receipt $names 'validation:receipt'
    if($receipt.schemaId -cne 'PspktBrokerLifecycleCiReceiptV1' -or $receipt.workflowRunId -cne $Context.RunId -or
        $receipt.workflowRunAttempt -cne $Context.Attempt -or $receipt.revision -cne $Context.Revision -or
        $receipt.slot -cne $Context.Slot){throw 'validation:workflow-binding'}
    $local=[ordered]@{schemaId='PspktBrokerLifecycleValidationResultV1';schemaVersion=$receipt.schemaVersion;outcome=$receipt.outcome}
    foreach($name in (Get-PspktBrokerLifecycleSuccessProperties)|Select-Object -Skip 3){$local[$name]=$receipt.$name}
    [void](Assert-PspktBrokerLifecycleResult @([pscustomobject]$local) $Expected)
    if(($receipt.hostEdition -ceq 'Desktop') -ne $Context.Slot.StartsWith('windows_ps51/',[StringComparison]::Ordinal)){throw 'validation:workflow-binding'}
    return $receipt
}

function Export-PspktBrokerLifecycleSource {
    param([object]$SourceSnapshot,[string]$DestinationRoot)
    if($SourceSnapshot.Files.Count -ne 67 -or $SourceSnapshot.Records.Count -ne 67 -or
        $DestinationRoot -cnotmatch '\A[A-Za-z]:\\'){throw 'validation:source-membership'}
    $destination=[IO.Path]::GetFullPath($DestinationRoot).TrimEnd([char]92)
    $source=[IO.Path]::GetFullPath($SourceSnapshot.RepositoryRoot).TrimEnd([char]92)
    if([IO.File]::Exists($destination) -or [IO.Directory]::Exists($destination) -or
        ($destination+'\').StartsWith($source+'\',[StringComparison]::OrdinalIgnoreCase) -or
        ($source+'\').StartsWith($destination+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'validation:work-root'}
    $current=$destination
    while(-not [string]::IsNullOrEmpty($current)){
        if(([IO.File]::Exists($current) -or [IO.Directory]::Exists($current)) -and
            ([IO.File]::GetAttributes($current) -band [IO.FileAttributes]::ReparsePoint)){throw 'validation:work-root'}
        $parent=[IO.Directory]::GetParent($current)
        if($null -eq $parent){break}
        $current=$parent.FullName
    }
    $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach($record in $SourceSnapshot.Records){
        if($record.Path -cnotmatch '\A(?:[A-Za-z0-9._-]+\\)*[A-Za-z0-9._-]+\z' -or
            @($record.Path.Split([char]92)|Where-Object {$_ -cin @('.','..','.git')}).Count -ne 0 -or
            -not $seen.Add($record.Path) -or -not $SourceSnapshot.Files.ContainsKey($record.Path)){throw 'validation:source-membership'}
        $bytes=[byte[]]$SourceSnapshot.Files[$record.Path]
        if($bytes.Length -ne $record.Length -or (Get-PspktBrokerLifecycleBytesDigest $bytes) -cne $record.Sha256){throw 'validation:source-pin'}
    }
    [void][IO.Directory]::CreateDirectory($destination)
    foreach($record in $SourceSnapshot.Records){
        $path=Join-Path $destination $record.Path
        [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($path))
        $stream=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        try{$bytes=[byte[]]$SourceSnapshot.Files[$record.Path];$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}
        finally{$stream.Dispose()}
    }
    return ,@($SourceSnapshot.Records)
}

function Remove-PspktBrokerLifecycleOwnedExport {
    param([object]$SourceSnapshot,[string]$DestinationRoot)
    $root=[IO.Path]::GetFullPath($DestinationRoot).TrimEnd([char]92)
    $allowed=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach($record in $SourceSnapshot.Records){[void]$allowed.Add([IO.Path]::GetFullPath((Join-Path $root $record.Path)))}
    $directories=[Collections.Generic.List[string]]::new()
    $pending=[Collections.Generic.Queue[string]]::new()
    $pending.Enqueue($root)
    $files=[Collections.Generic.List[string]]::new()
    while($pending.Count -ne 0){
        $directory=$pending.Dequeue()
        $directories.Add($directory)
        foreach($entry in [IO.Directory]::GetFileSystemEntries($directory)){
            if([IO.File]::GetAttributes($entry) -band [IO.FileAttributes]::ReparsePoint){throw 'validation:cleanup'}
            if([IO.Directory]::Exists($entry)){$pending.Enqueue($entry)}
            elseif(-not $allowed.Contains([IO.Path]::GetFullPath($entry))){throw 'validation:cleanup'}
            else{$files.Add($entry)}
        }
    }
    if($files.Count -ne 67){throw 'validation:cleanup'}
    foreach($file in $files){[IO.File]::Delete($file)}
    foreach($directory in @($directories|Sort-Object Length -Descending)){[IO.Directory]::Delete($directory,$false)}
}

function ConvertTo-PspktBrokerLifecycleTransport {
    param([object]$Value,[int]$MaximumBytes=16384)
    $json=ConvertTo-PspktBrokerLifecycleReceiptJson $Value $MaximumBytes
    return [Convert]::ToBase64String([Text.UTF8Encoding]::new($false,$true).GetBytes($json))
}

function ConvertFrom-PspktBrokerLifecycleTransport {
    param([string]$Encoded,[int]$MaximumBytes=16384)
    if([string]::IsNullOrEmpty($Encoded) -or $Encoded.Length -gt [int]([Math]::Ceiling($MaximumBytes/3.0)*4) -or
        $Encoded -cnotmatch '\A[A-Za-z0-9+/]*={0,2}\z'){throw 'validation:receipt'}
    try {
        $bytes=[Convert]::FromBase64String($Encoded)
        if($bytes.Length -gt $MaximumBytes -or [Convert]::ToBase64String($bytes) -cne $Encoded){throw 'validation:receipt'}
        $text=[Text.UTF8Encoding]::new($false,$true).GetString($bytes)
        return ConvertFrom-PspktBrokerLifecycleReceiptJson $text $MaximumBytes
    }
    catch {throw 'validation:receipt'}
}

function Invoke-PspktBrokerLifecycleBoundaryProbe {
    param([object]$Result,[object]$Expected,[object]$Context,[string]$CaseId)
    Assert-PspktBrokerLifecycleWorkflowContext $Context
    [void](Assert-PspktBrokerLifecycleResult @($Result) $Expected)
    $candidate=ConvertFrom-PspktBrokerLifecycleReceiptJson (ConvertTo-PspktBrokerLifecycleReceiptJson $Result)
    $objects=@($candidate)
    $diagnostics=0
    switch -CaseSensitive ($CaseId){
        'ReturnedFailure' {
            $objects=@([pscustomobject][ordered]@{schemaId='PspktBrokerLifecycleValidationResultV1';schemaVersion=1;outcome='ValidationFailed';
                callId=$Result.callId;reasonCode='validation:unexpected';cleanupComplete=$false})
            $expectedReason='validation:result-failed'
            $diagnostics=1
        }
        'MalformedResult' {$candidate.PSObject.Properties.Remove('trustCeiling');$expectedReason='validation:result-shape'}
        'MissingResult' {$objects=@();$expectedReason='validation:result-cardinality'}
        'MultipleResults' {$objects=@($candidate,$candidate);$expectedReason='validation:result-cardinality'}
        'CountMismatch' {$candidate.counts.passedCount=31;$expectedReason='validation:result-counts'}
        default {throw 'validation:receipt'}
    }
    $reason=$null
    $successes=@()
    try {$successes=@(Assert-PspktBrokerLifecycleResult $objects $Expected)}
    catch {$reason=$_.Exception.Message}
    if($reason -cne $expectedReason -or $successes.Count -ne 0){throw 'validation:receipt'}
    $receipt=[pscustomobject][ordered]@{schemaId='PspktBrokerLifecycleProbeReceiptV1';schemaVersion=1;workflowRunId=$Context.RunId;
        workflowRunAttempt=$Context.Attempt;revision=$Context.Revision;hostSlot=$Context.Slot.Split('/')[0];caseId=$CaseId;
        positiveControl=$true;reasonCode=$reason;successObjectsEmitted=0;diagnosticObjectsEmitted=$diagnostics}
    [void](ConvertTo-PspktBrokerLifecycleReceiptJson $receipt 1024)
    return $receipt
}

function Confirm-PspktBrokerLifecycleBoundaryGroup {
    param([object[]]$Receipts,[object[]]$RawOutcomes,[object]$Context)
    Assert-PspktBrokerLifecycleWorkflowContext $Context
    $ids=@('ReturnedFailure','MalformedResult','MissingResult','MultipleResults','CountMismatch')
    $reasons=@('validation:result-failed','validation:result-shape','validation:result-cardinality','validation:result-cardinality','validation:result-counts')
    if($Receipts.Count -ne 5 -or $RawOutcomes.Count -ne 5){throw 'validation:receipt'}
    $confirmed=@()
    for($index=0;$index -lt 5;$index++){
        $receipt=$Receipts[$index]
        Assert-PspktBrokerLifecycleProperties $receipt @('schemaId','schemaVersion','workflowRunId','workflowRunAttempt','revision','hostSlot',
            'caseId','positiveControl','reasonCode','successObjectsEmitted','diagnosticObjectsEmitted') 'validation:receipt'
        if($receipt.schemaId -cne 'PspktBrokerLifecycleProbeReceiptV1' -or $receipt.workflowRunId -cne $Context.RunId -or
            $receipt.workflowRunAttempt -cne $Context.Attempt -or $receipt.revision -cne $Context.Revision -or
            $receipt.hostSlot -cne $Context.Slot.Split('/')[0] -or $receipt.caseId -cne $ids[$index] -or
            $receipt.positiveControl -isnot [bool] -or -not $receipt.positiveControl -or $receipt.reasonCode -cne $reasons[$index] -or
            $RawOutcomes[$index] -isnot [string] -or $RawOutcomes[$index] -cne 'failure'){throw 'validation:workflow-binding'}
        Assert-PspktBrokerLifecycleInteger $receipt.schemaVersion 1 1 'validation:receipt'
        Assert-PspktBrokerLifecycleInteger $receipt.successObjectsEmitted 0 0 'validation:receipt'
        $diagnostics=0
        if($index -eq 0){$diagnostics=1}
        Assert-PspktBrokerLifecycleInteger $receipt.diagnosticObjectsEmitted $diagnostics $diagnostics 'validation:receipt'
        $confirmed+=,[pscustomobject][ordered]@{caseId=$receipt.caseId;positiveControl=$true;reasonCode=$receipt.reasonCode;
            successObjectsEmitted=0;diagnosticObjectsEmitted=$diagnostics;rawOutcome=$RawOutcomes[$index]}
    }
    $group=[pscustomobject][ordered]@{schemaId='PspktBrokerLifecycleProbeGroupV1';schemaVersion=1;workflowRunId=$Context.RunId;
        workflowRunAttempt=$Context.Attempt;revision=$Context.Revision;hostSlot=$Context.Slot.Split('/')[0];probes=$confirmed}
    [void](ConvertTo-PspktBrokerLifecycleReceiptJson $group 4096)
    return $group
}

function Confirm-PspktBrokerLifecyclePreflightGroup {
    param([object]$Receipt,[object]$RawOutcome,[object]$Context)
    Assert-PspktBrokerLifecycleWorkflowContext $Context
    Assert-PspktBrokerLifecycleProperties $Receipt @('schemaId','schemaVersion','workflowRunId','workflowRunAttempt','revision','hostSlot','probeId',
        'positiveControl','firstReasonCode','secondReasonCode','markerRemainsConsumed','compilationCount','loadCount','successObjectsEmitted',
        'secondWorkRootCreated','cleanupComplete') 'validation:preflight-probe'
    if($Receipt.schemaId -cne 'PspktBrokerLifecyclePreflightProbeV1' -or $Receipt.workflowRunId -cne $Context.RunId -or
        $Receipt.workflowRunAttempt -cne $Context.Attempt -or $Receipt.revision -cne $Context.Revision -or
        $Receipt.hostSlot -cne $Context.Slot.Split('/')[0] -or $Receipt.probeId -cne 'FailedPreflightConsumesHost' -or
        $Receipt.firstReasonCode -cne 'validation:work-root' -or $Receipt.secondReasonCode -cne 'validation:invocation-repeat' -or
        $RawOutcome -isnot [string] -or $RawOutcome -cne 'failure'){throw 'validation:preflight-probe'}
    foreach($name in @('positiveControl','markerRemainsConsumed','cleanupComplete')){
        if($Receipt.$name -isnot [bool] -or -not $Receipt.$name){throw 'validation:preflight-probe'}
    }
    if($Receipt.secondWorkRootCreated -isnot [bool] -or $Receipt.secondWorkRootCreated){throw 'validation:preflight-probe'}
    Assert-PspktBrokerLifecycleInteger $Receipt.schemaVersion 1 1 'validation:preflight-probe'
    foreach($name in @('compilationCount','loadCount','successObjectsEmitted')){Assert-PspktBrokerLifecycleInteger $Receipt.$name 0 0 'validation:preflight-probe'}
    $group=[pscustomobject][ordered]@{schemaId='PspktBrokerLifecyclePreflightProbeGroupV1';schemaVersion=1;workflowRunId=$Context.RunId;
        workflowRunAttempt=$Context.Attempt;revision=$Context.Revision;hostSlot=$Context.Slot.Split('/')[0];probe=$Receipt;rawOutcome=$RawOutcome}
    [void](ConvertTo-PspktBrokerLifecycleReceiptJson $group 4096)
    return $group
}

function Get-PspktBrokerLifecycleReceiptExpectation {
    param([object]$Source,[object]$Receipt)
    $expectations=Assert-PspktBrokerLifecycleFixtures $Source
    $runtime=[ordered]@{}
    foreach($name in Get-PspktBrokerLifecycleRuntimeNames){
        $path='certification\broker-lifecycle\lib\'+$name
        $runtime[$path]=$Source.Files[$path]
    }
    $bootstrap=[ordered]@{}
    $bootstrap['certification\lib\Pspkt.Certification.SchemaBootstrap.cs']=$Source.Files['certification\lib\Pspkt.Certification.SchemaBootstrap.cs']
    $sets=[ordered]@{Bootstrap=(Get-PspktBrokerLifecycleSourceSetDigest 'Bootstrap' $bootstrap);Runtime=(Get-PspktBrokerLifecycleSourceSetDigest 'Runtime' $runtime)}
    $transformations=[ordered]@{}
    foreach($role in @('M1','M2','M3','M4','M5','M6')){
        $mutation=Get-PspktBrokerLifecycleMutantSource $role $runtime
        $sets[$role]=$mutation.MutatedSourceSetSha256
        $transformations[$role]=$mutation.TransformationSha256
    }
    $bindings=[ordered]@{callId=$Receipt.callId;baseCommit='46dc63bb1bd537037c32edd2cb9e5151e0ad96ad';
        hostEdition=$Receipt.hostEdition;hostVersion=$Receipt.hostVersion;pesterVersion='5.3.3';trustCeiling='StructuralInProcessOnly';
        sourceManifestSha256=$Source.ManifestSha256;
        fixtureManifestSha256=(Get-PspktBrokerLifecycleBytesDigest $Source.Files['certification\broker-lifecycle\vectors\hand-authored\manifest.v1.json']);
        framingAddendumSchemaSha256=(Get-PspktBrokerLifecycleBytesDigest $Source.Files['certification\broker-lifecycle\schema\framing-addendum-schema.v1.json']);
        framingAddendumSha256=(Get-PspktBrokerLifecycleBytesDigest $Source.Files['certification\broker-lifecycle\authority\framing-addendum.v1.json']);
        designReviewActivationSha256=(Get-PspktBrokerLifecycleBytesDigest $Source.Files['certification\broker-lifecycle\authority\design-review-activation.v1.json']);
        lifecyclePolicySha256=(Get-PspktBrokerLifecycleBytesDigest $Source.Files['certification\broker-lifecycle\schema\lifecycle-policy.v1.json']);
        frameworkManifestSha256=$Receipt.frameworkManifestSha256}
    return [pscustomobject]@{Bindings=[pscustomobject]$bindings;SourceSets=[pscustomobject]$sets;Transformations=[pscustomobject]$transformations;
        CaseIds=$expectations.caseIds;CompletionChecks=$expectations.completionChecks;CleanupChecks=$expectations.cleanupChecks}
}

function Get-PspktBrokerLifecycleWorkflowContext {
    param([string]$HostSlot,[string]$SourceSlot='checkout')
    $context=[pscustomobject]@{RunId=$env:GITHUB_RUN_ID;Attempt=$env:GITHUB_RUN_ATTEMPT;Revision=$env:GITHUB_SHA;Slot=($HostSlot+'/'+$SourceSlot)}
    Assert-PspktBrokerLifecycleWorkflowContext $context
    return $context
}

function Initialize-PspktBrokerLifecycleWorkflowTools {
    param([string]$ToolsRoot)
    if([IO.File]::Exists($ToolsRoot) -or [IO.Directory]::Exists($ToolsRoot)){throw 'validation:work-root'}
    [void][IO.Directory]::CreateDirectory($ToolsRoot)
    $archive=Join-Path $ToolsRoot 'Pester.5.3.3.nupkg'
    Invoke-WebRequest -UseBasicParsing -Uri 'https://www.powershellgallery.com/api/v2/package/Pester/5.3.3' -OutFile $archive
    $bytes=[IO.File]::ReadAllBytes($archive)
    if($bytes.Length -ne 271297 -or (Get-PspktBrokerLifecycleBytesDigest $bytes) -cne 'bf450611b92dee8de7dd5e69809d5b37f86bff9f8f3b6eb3129d2fbdd889b579'){throw 'validation:pester'}
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $directory=Join-Path $ToolsRoot 'Pester'
    [IO.Compression.ZipFile]::ExtractToDirectory($archive,$directory)
    return Join-Path $directory 'Pester.psd1'
}

function Write-PspktBrokerLifecycleWorkflowOutput {
    param([string]$Name,[object]$Value,[int]$MaximumBytes=16384)
    if($Name -cnotmatch '\A[a-z]+\z' -or [string]::IsNullOrEmpty($env:GITHUB_OUTPUT)){throw 'validation:workflow-binding'}
    $encoded=ConvertTo-PspktBrokerLifecycleTransport $Value $MaximumBytes
    [IO.File]::AppendAllText($env:GITHUB_OUTPUT,$Name+'='+$encoded+"`n",[Text.UTF8Encoding]::new($false))
}

function Invoke-PspktBrokerLifecycleWorkflowCall {
    param([string]$RepositoryRoot,[string]$WorkRoot,[string]$PesterManifestPath,[string]$HostSlot,[string]$SourceSlot,[string]$ResultPath)
    $context=Get-PspktBrokerLifecycleWorkflowContext $HostSlot $SourceSlot
    $contractPath=Join-Path $RepositoryRoot 'certification\broker-lifecycle\lib\Pspkt.Certification.BrokerLifecycleContract.ps1'
    $source=Get-PspktBrokerLifecycleSourceSnapshot $RepositoryRoot ([IO.File]::ReadAllBytes($contractPath))
    $validator=Join-Path $RepositoryRoot 'certification\broker-lifecycle\validators\Invoke-PspktPhase4BrokerLifecycleValidators.ps1'
    $objects=@(& $validator -RepositoryRoot $RepositoryRoot -WorkRoot $WorkRoot -PesterManifestPath $PesterManifestPath)
    if($objects.Count -ne 1){throw 'validation:result-cardinality'}
    $expected=Get-PspktBrokerLifecycleReceiptExpectation $source $objects[0]
    $result=Assert-PspktBrokerLifecycleResult $objects $expected
    $receipt=New-PspktBrokerLifecycleCiReceipt $result $expected $context
    if([IO.File]::Exists($ResultPath)){throw 'validation:work-root'}
    [IO.File]::WriteAllText($ResultPath,(ConvertTo-PspktBrokerLifecycleReceiptJson $result),[Text.UTF8Encoding]::new($false))
    Write-PspktBrokerLifecycleWorkflowOutput 'receipt' $receipt
}

function Invoke-PspktBrokerLifecycleWorkflowBoundary {
    param([string]$RepositoryRoot,[string]$ResultPath,[string]$HostSlot,[string]$CaseId)
    $context=Get-PspktBrokerLifecycleWorkflowContext $HostSlot 'checkout'
    $contractPath=Join-Path $RepositoryRoot 'certification\broker-lifecycle\lib\Pspkt.Certification.BrokerLifecycleContract.ps1'
    $source=Get-PspktBrokerLifecycleSourceSnapshot $RepositoryRoot ([IO.File]::ReadAllBytes($contractPath))
    $result=Read-PspktBrokerLifecycleReceiptFile $ResultPath 16384
    $expected=Get-PspktBrokerLifecycleReceiptExpectation $source $result
    $receipt=Invoke-PspktBrokerLifecycleBoundaryProbe $result $expected $context $CaseId
    Write-PspktBrokerLifecycleWorkflowOutput 'probe' $receipt 1024
}

function Save-PspktBrokerLifecycleTransportPart {
    param([string]$Directory,[string]$Part,[string]$Encoded)
    $parts=@('windows-checkout','windows-export','core-checkout','core-export','windows-boundaries','core-boundaries','windows-preflight','core-preflight')
    if($Part -cnotin $parts){throw 'validation:receipt'}
    $maximum=4096
    if($Part.EndsWith('checkout',[StringComparison]::Ordinal) -or $Part.EndsWith('export',[StringComparison]::Ordinal)){$maximum=16384}
    $value=ConvertFrom-PspktBrokerLifecycleTransport $Encoded $maximum
    [void][IO.Directory]::CreateDirectory($Directory)
    $path=Join-Path $Directory ($Part+'.json')
    $bytes=[Text.Encoding]::ASCII.GetBytes((ConvertTo-PspktBrokerLifecycleReceiptJson $value $maximum))
    $stream=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try{$stream.Write($bytes,0,$bytes.Length)}finally{$stream.Dispose()}
}

function Invoke-PspktBrokerLifecycleAggregate {
    param([string]$RepositoryRoot,[string]$InputDirectory)
    $parts=@('windows-checkout','windows-export','core-checkout','core-export','windows-boundaries','core-boundaries','windows-preflight','core-preflight')
    $actual=@([IO.Directory]::GetFiles($InputDirectory)|ForEach-Object {[IO.Path]::GetFileNameWithoutExtension($_)}|Sort-Object)
    if(($actual -join '|') -cne (@($parts|Sort-Object) -join '|') -or [IO.Directory]::GetDirectories($InputDirectory).Count -ne 0){throw 'validation:receipt'}
    $contractPath=Join-Path $RepositoryRoot 'certification\broker-lifecycle\lib\Pspkt.Certification.BrokerLifecycleContract.ps1'
    $source=Get-PspktBrokerLifecycleSourceSnapshot $RepositoryRoot ([IO.File]::ReadAllBytes($contractPath))
    $slots=@('windows_ps51/checkout','windows_ps51/export','powershell_7/checkout','powershell_7/export')
    $callIds=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $receipts=@()
    for($index=0;$index -lt 4;$index++){
        $value=Read-PspktBrokerLifecycleReceiptFile (Join-Path $InputDirectory ($parts[$index]+'.json')) 16384
        $json=ConvertTo-PspktBrokerLifecycleReceiptJson $value 16384
        $context=[pscustomobject]@{RunId=$env:GITHUB_RUN_ID;Attempt=$env:GITHUB_RUN_ATTEMPT;Revision=$env:GITHUB_SHA;Slot=$slots[$index]}
        $expected=Get-PspktBrokerLifecycleReceiptExpectation $source $value
        $receipts+=,(Assert-PspktBrokerLifecycleCiReceipt $json $expected $context)
        if(-not $callIds.Add($value.callId)){throw 'validation:workflow-binding'}
    }
    foreach($pair in @(@(0,1),@(2,3))){
        if($receipts[$pair[0]].hostVersion -cne $receipts[$pair[1]].hostVersion -or
            $receipts[$pair[0]].frameworkManifestSha256 -cne $receipts[$pair[1]].frameworkManifestSha256){throw 'validation:workflow-binding'}
    }
    $boundaryCount=0
    $preflightCount=0
    foreach($hostIndex in @(0,1)){
        $hostSlot=@('windows_ps51','powershell_7')[$hostIndex]
        $context=Get-PspktBrokerLifecycleWorkflowContext $hostSlot 'checkout'
        $group=Read-PspktBrokerLifecycleReceiptFile (Join-Path $InputDirectory ($parts[4+$hostIndex]+'.json')) 4096
        Assert-PspktBrokerLifecycleProperties $group @('schemaId','schemaVersion','workflowRunId','workflowRunAttempt','revision','hostSlot','probes') 'validation:receipt'
        if($group.schemaId -cne 'PspktBrokerLifecycleProbeGroupV1'){throw 'validation:receipt'}
        $probes=@()
        $outcomes=@()
        foreach($row in $group.probes){
            Assert-PspktBrokerLifecycleProperties $row @('caseId','positiveControl','reasonCode','successObjectsEmitted','diagnosticObjectsEmitted','rawOutcome') 'validation:receipt'
            $probes+=,[pscustomobject][ordered]@{schemaId='PspktBrokerLifecycleProbeReceiptV1';schemaVersion=$group.schemaVersion;
                workflowRunId=$group.workflowRunId;workflowRunAttempt=$group.workflowRunAttempt;revision=$group.revision;hostSlot=$group.hostSlot;
                caseId=$row.caseId;positiveControl=$row.positiveControl;reasonCode=$row.reasonCode;successObjectsEmitted=$row.successObjectsEmitted;
                diagnosticObjectsEmitted=$row.diagnosticObjectsEmitted}
            $outcomes+=,$row.rawOutcome
        }
        [void](Confirm-PspktBrokerLifecycleBoundaryGroup $probes $outcomes $context)
        $boundaryCount+=$probes.Count
        $preflight=Read-PspktBrokerLifecycleReceiptFile (Join-Path $InputDirectory ($parts[6+$hostIndex]+'.json')) 4096
        Assert-PspktBrokerLifecycleProperties $preflight @('schemaId','schemaVersion','workflowRunId','workflowRunAttempt','revision','hostSlot','probe','rawOutcome') 'validation:preflight-probe'
        if($preflight.schemaId -cne 'PspktBrokerLifecyclePreflightProbeGroupV1' -or $preflight.workflowRunId -cne $context.RunId -or
            $preflight.workflowRunAttempt -cne $context.Attempt -or $preflight.revision -cne $context.Revision -or
            $preflight.hostSlot -cne $hostSlot){throw 'validation:preflight-probe'}
        [void](Confirm-PspktBrokerLifecyclePreflightGroup $preflight.probe $preflight.rawOutcome $context)
        $preflightCount++
    }
    $compilations=0;$loads=0;$kills=0;$passed=0
    foreach($receipt in $receipts){$compilations+=$receipt.counts.compilationCount;$loads+=$receipt.counts.loadCount;$kills+=$receipt.counts.initializedMutantKillCount;$passed+=$receipt.counts.passedCount}
    if($compilations -ne 32 -or $loads -ne 32 -or $kills -ne 24 -or $passed -ne 128 -or $boundaryCount -ne 10 -or $preflightCount -ne 2){throw 'validation:result-counts'}
    return [pscustomobject][ordered]@{schemaId='PspktBrokerLifecycleCiAggregateV1';schemaVersion=1;outcome='ValidationSucceeded';
        workflowRunId=$env:GITHUB_RUN_ID;workflowRunAttempt=$env:GITHUB_RUN_ATTEMPT;revision=$env:GITHUB_SHA;
        trustCeiling='StructuralInProcessOnly';sourceManifestSha256=$source.ManifestSha256;completeCalls=4;
        compilationCount=$compilations;loadCount=$loads;initializedMutantKillCount=$kills;passedCount=$passed;
        boundaryRedCount=$boundaryCount;preflightRedCount=$preflightCount}
}
