Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'

function New-PspktBrokerLifecycleOracleUnsigned {
    param([int]$Width,[System.Numerics.BigInteger]$Value)
    if($Value -lt 0 -or $Width -lt 1 -or $Width -gt 8){throw 'validation:oracle'}
    $bytes=[byte[]]::new($Width)
    for($index=$Width-1;$index -ge 0;$index--){
        $bytes[$index]=[byte][System.Numerics.BigInteger]::Remainder($Value,256)
        $Value=[System.Numerics.BigInteger]::Divide($Value,256)
    }
    if($Value -ne 0){throw 'validation:oracle'}
    return ,$bytes
}

function Read-PspktBrokerLifecycleOracleUnsigned {
    param([byte[]]$Bytes,[int]$Offset,[int]$Width)
    if($Offset -lt 0 -or $Width -lt 1 -or $Offset -gt $Bytes.Length-$Width){throw 'validation:oracle'}
    $value=[System.Numerics.BigInteger]::Zero
    for($index=0;$index -lt $Width;$index++){$value=$value*256+$Bytes[$Offset+$index]}
    return $value
}

function Join-PspktBrokerLifecycleOracleBytes {
    param([object[]]$Parts)
    $stream=[IO.MemoryStream]::new()
    try{
        foreach($part in $Parts){$bytes=[byte[]]$part;$stream.Write($bytes,0,$bytes.Length)}
        return ,$stream.ToArray()
    }
    finally{$stream.Dispose()}
}

function New-PspktBrokerLifecycleOraclePattern {
    param([int]$Length,[byte]$Value)
    $bytes=[byte[]]::new($Length)
    for($index=0;$index -lt $Length;$index++){$bytes[$index]=$Value}
    return ,$bytes
}

function Copy-PspktBrokerLifecycleOracleSwappedRanges {
    param([byte[]]$Bytes,[int]$FirstOffset,[int]$SecondOffset,[int]$Width)
    if($null -eq $Bytes -or $Width -lt 1 -or $FirstOffset -lt 0 -or
        $FirstOffset -gt $Bytes.Length-$Width -or $SecondOffset -lt $FirstOffset+$Width -or
        $SecondOffset -gt $Bytes.Length-$Width){throw 'validation:oracle'}
    $copy=[byte[]]$Bytes.Clone()
    [Array]::Copy($Bytes,$SecondOffset,$copy,$FirstOffset,$Width)
    [Array]::Copy($Bytes,$FirstOffset,$copy,$SecondOffset,$Width)
    return ,$copy
}

function Set-PspktBrokerLifecycleOraclePayloadField {
    param([byte[]]$Payload,[int[]]$FieldPath,[byte[]]$Value)
    if($FieldPath.Length -eq 0){throw 'validation:oracle'}
    $parts=[Collections.Generic.List[object]]::new()
    $position=0
    $found=$false
    while($position -lt $Payload.Length){
        $identifier=[int](Read-PspktBrokerLifecycleOracleUnsigned $Payload $position 2)
        $length=[int](Read-PspktBrokerLifecycleOracleUnsigned $Payload ($position+2) 4)
        $position+=6
        if($length -lt 0 -or $position -gt $Payload.Length-$length){throw 'validation:oracle'}
        $field=[byte[]]::new($length)
        [Array]::Copy($Payload,$position,$field,0,$length)
        if($identifier -eq $FieldPath[0]){
            if($FieldPath.Length -eq 1){$field=$Value}
            else{$field=Set-PspktBrokerLifecycleOraclePayloadField $field $FieldPath[1..($FieldPath.Length-1)] $Value}
            $found=$true
        }
        $parts.Add((New-PspktBrokerLifecycleOracleUnsigned 2 $identifier))
        $parts.Add((New-PspktBrokerLifecycleOracleUnsigned 4 $field.Length))
        $parts.Add($field)
        $position+=$length
    }
    if(-not $found){throw 'validation:oracle'}
    return ,(Join-PspktBrokerLifecycleOracleBytes $parts.ToArray())
}

function Set-PspktBrokerLifecycleOracleFramePayload {
    param([byte[]]$Frame,[byte[]]$Payload)
    $header=[byte[]]::new(24)
    [Array]::Copy($Frame,0,$header,0,24)
    [Array]::Copy((New-PspktBrokerLifecycleOracleUnsigned 4 $Payload.Length),0,$header,20,4)
    $signature=[byte[]]::new(384)
    [Array]::Copy($Frame,$Frame.Length-384,$signature,0,384)
    return ,(Join-PspktBrokerLifecycleOracleBytes @($header,$Payload,$signature))
}

function Set-PspktBrokerLifecycleOracleFrameField {
    param([byte[]]$Frame,[int[]]$FieldPath,[byte[]]$Value)
    $length=[int](Read-PspktBrokerLifecycleOracleUnsigned $Frame 20 4)
    $payload=[byte[]]::new($length)
    [Array]::Copy($Frame,24,$payload,0,$length)
    $replacement=Set-PspktBrokerLifecycleOraclePayloadField $payload $FieldPath $Value
    return ,(Set-PspktBrokerLifecycleOracleFramePayload $Frame $replacement)
}

function Invoke-PspktBrokerLifecycleInternal {
    param([Reflection.Assembly]$Assembly,[string]$MemberId,[object[]]$Arguments)
    switch -CaseSensitive ($MemberId){
        'ValidateLogicalBudget' {$typeName='ProtocolPayloadCodec';$parameters=[type[]]@([UInt64],[UInt64],[int],[int])}
        'ValidateCompleteFrameLength' {$typeName='FrameCodec';$parameters=[type[]]@([UInt64],[UInt64])}
        'ValidateLocalQuota' {$typeName='ConnectionState';$parameters=[type[]]@([UInt64],[UInt64],[UInt64])}
        'ValidateQueueCapacity' {$typeName='InMemoryDuplexTransport';$parameters=[type[]]@([int],[UInt64],[int])}
        default {throw 'validation:public-surface'}
    }
    if($null -eq $Assembly -or $Arguments.Length -ne $parameters.Length){throw 'validation:public-surface'}
    $type=$Assembly.GetType(('Pspkt.Certification.BrokerLifecycle.'+$typeName),$false)
    if($null -eq $type -or $type.IsPublic -or -not [object]::ReferenceEquals($type.Assembly,$Assembly)){throw 'validation:public-surface'}
    $method=$type.GetMethod($MemberId,([Reflection.BindingFlags]'Static,NonPublic,DeclaredOnly'),$null,$parameters,$null)
    if($null -eq $method -or -not $method.IsAssembly -or $method.ReturnType -ne [void]){throw 'validation:public-surface'}
    for($index=0;$index -lt $parameters.Length;$index++){
        if($null -eq $Arguments[$index] -or $Arguments[$index].GetType() -ne $parameters[$index]){throw 'validation:public-surface'}
    }
    return $method.Invoke($null,$Arguments)
}

function Get-PspktBrokerLifecycleOracleDigest {
    param([byte[]]$Bytes)
    $hasher=[Security.Cryptography.SHA256]::Create()
    try{return [BitConverter]::ToString($hasher.ComputeHash($Bytes)).Replace('-','').ToLowerInvariant()}
    finally{$hasher.Dispose()}
}

function Invoke-PspktBrokerLifecycleTestMember {
    param([Reflection.Assembly]$Assembly,[string]$MemberId,[object]$Target,[object[]]$Arguments=@())
    $prefix='Pspkt.Certification.BrokerLifecycle.'
    $scriptType=$Assembly.GetType(($prefix+'TransportOutcomeScript'),$false)
    $driverType=$Assembly.GetType(($prefix+'LifecycleTestDriver'),$false)
    $controllerType=$Assembly.GetType(($prefix+'CheckpointServiceLifecycle'),$false)
    $outcomeType=$Assembly.GetType(($prefix+'TransportOutcomeScript+OutcomeKind'),$false)
    if($null -eq $scriptType -or $null -eq $driverType -or $null -eq $outcomeType){throw 'validation:public-surface'}
    $static=$false
    $getter=$false
    switch -CaseSensitive ($MemberId){
        'ScriptCreate' {$type=$scriptType;$name='Create';$static=$true;$parameters=[type[]]@($outcomeType.MakeArrayType(),[int[]]);$resultType=$scriptType}
        'ScriptCopyOutcomes' {$type=$scriptType;$name='CopyOutcomes';$parameters=[type[]]@();$resultType=$outcomeType.MakeArrayType()}
        'ScriptCopyByteIncrements' {$type=$scriptType;$name='CopyByteIncrements';$parameters=[type[]]@();$resultType=[int[]]}
        'ScriptStepCount' {$type=$scriptType;$name='StepCount';$parameters=[type[]]@();$resultType=[int];$getter=$true}
        'DriverCreate' {$type=$driverType;$name='Create';$static=$true;$parameters=[type[]]@($controllerType,$controllerType);$resultType=$driverType}
        'BindPrimaryWrite' {$type=$driverType;$name=$MemberId;$parameters=[type[]]@([string],$scriptType);$resultType=[void]}
        'BindForeignWrite' {$type=$driverType;$name=$MemberId;$parameters=[type[]]@([string],$scriptType);$resultType=[void]}
        'DeliverPrimaryCompletion' {$type=$driverType;$name=$MemberId;$parameters=[type[]]@([string]);$resultType=[void]}
        'DeliverForeignCompletion' {$type=$driverType;$name=$MemberId;$parameters=[type[]]@([string]);$resultType=[void]}
        'DeliverForeignCompletionToPrimary' {$type=$driverType;$name=$MemberId;$parameters=[type[]]@([string]);$resultType=[void]}
        'CopyConsumedPrimaryOutcomes' {$type=$driverType;$name=$MemberId;$parameters=[type[]]@();$resultType=$outcomeType.MakeArrayType()}
        'CopyConsumedForeignOutcomes' {$type=$driverType;$name=$MemberId;$parameters=[type[]]@();$resultType=$outcomeType.MakeArrayType()}
        'DriverDispose' {$type=$driverType;$name='Dispose';$parameters=[type[]]@();$resultType=[void]}
        'HasPrimaryHeldCompletion' {$type=$driverType;$name=$MemberId;$parameters=[type[]]@();$resultType=[bool];$getter=$true}
        'HasForeignHeldCompletion' {$type=$driverType;$name=$MemberId;$parameters=[type[]]@();$resultType=[bool];$getter=$true}
        'PrimaryWriteRetirementReason' {$type=$driverType;$name=$MemberId;$parameters=[type[]]@();$resultType=[string];$getter=$true}
        default {throw 'validation:public-surface'}
    }
    if($type.IsPublic -or -not $type.IsSealed -or -not [object]::ReferenceEquals($type.Assembly,$Assembly) -or $Arguments.Length -ne $parameters.Length){throw 'validation:public-surface'}
    if(-not $static -and ($null -eq $Target -or $Target.GetType() -ne $type)){throw 'validation:public-surface'}
    for($index=0;$index -lt $parameters.Length;$index++){
        if($null -ne $Arguments[$index] -and -not $parameters[$index].IsInstanceOfType($Arguments[$index])){throw 'validation:public-surface'}
    }
    $flags=[Reflection.BindingFlags]'NonPublic,DeclaredOnly'
    if($static){$flags=$flags -bor [Reflection.BindingFlags]::Static}else{$flags=$flags -bor [Reflection.BindingFlags]::Instance}
    if($getter){
        $property=$type.GetProperty($name,$flags)
        if($null -eq $property -or $property.PropertyType -ne $resultType -or $null -ne $property.GetSetMethod($true)){throw 'validation:public-surface'}
        $method=$property.GetGetMethod($true)
    }
    else{$method=$type.GetMethod($name,$flags,$null,$parameters,$null)}
    if($null -eq $method -or -not $method.IsAssembly -or $method.ReturnType -ne $resultType){throw 'validation:public-surface'}
    $result=$method.Invoke($Target,$Arguments)
    if($resultType -ne [void]){return ,$result}
}

function New-PspktBrokerLifecycleOutcomeScript {
    param([Reflection.Assembly]$Assembly,[int[]]$Kinds,[int[]]$Increments)
    $type=$Assembly.GetType('Pspkt.Certification.BrokerLifecycle.TransportOutcomeScript+OutcomeKind',$false)
    if($null -eq $type -or -not $type.IsEnum -or -not $type.IsNestedAssembly){throw 'validation:public-surface'}
    $outcomes=[Array]::CreateInstance($type,$Kinds.Length)
    for($index=0;$index -lt $Kinds.Length;$index++){$outcomes.SetValue([Enum]::ToObject($type,$Kinds[$index]),$index)}
    return Invoke-PspktBrokerLifecycleTestMember $Assembly 'ScriptCreate' $null ([object[]]@($outcomes,$Increments))
}

function New-TestResultFixture {
    param([object]$Expectations)
    $bindings=[ordered]@{callId='0123456789abcdef0123456789abcdef';baseCommit='46dc63bb1bd537037c32edd2cb9e5151e0ad96ad';
        hostEdition=$PSVersionTable.PSEdition;hostVersion=$PSVersionTable.PSVersion.ToString();pesterVersion='5.3.3';trustCeiling='StructuralInProcessOnly';
        sourceManifestSha256=('a'*64);fixtureManifestSha256=('b'*64);
        framingAddendumSchemaSha256='9f00101faf660e1ea3c10904a6358ae16fe1bef4577c0e05f1af9fea86357213';
        framingAddendumSha256='ae2a255f0a45f9a33fe958e9c728ff535550ea09aec8fcf11398f426f56f0a0f';
        designReviewActivationSha256='fee195e7a19a9502330b3e2691c53258130dfbb0b5c1b40eb2a5f81bfdbca24c';
        lifecyclePolicySha256='011e43d50fc6c4b00576ec8c6d08fd3636228f84509966216bba1fa1d284a536';frameworkManifestSha256=('c'*64)}
    $sourceSets=[ordered]@{}
    $transforms=[ordered]@{}
    $compilations=@()
    $loads=@()
    for($index=0;$index -lt 8;$index++){
        $role=$Expectations.images[$index]
        $sourceSets[$role]=(($index+1).ToString('x')*64)
        $imageHash=(($index+1).ToString('x')*64)
        $compilations+=,[pscustomobject][ordered]@{role=$role;imageName=('PspktBrokerLifecycle_'+$bindings.callId+'_'+$role+'.dll');
            imageLength=1024;imageSha256=$imageHash;sourceCount=$(if($role -ceq 'Bootstrap'){1}else{31});
            sourceSetSha256=$sourceSets[$role];referenceSetSha256=('d'*64);language='CSharp5';
            compiler=$(if($PSVersionTable.PSEdition -ceq 'Desktop'){'CodeDom'}else{'Roslyn'})}
        $loads+=,[pscustomobject][ordered]@{role=$role;imageSha256=$imageHash;
            context=$(if($PSVersionTable.PSEdition -ceq 'Desktop'){'LoadFrom'}else{'Default'});initialized=$true}
    }
    $mutants=@()
    foreach($row in $Expectations.mutants){
        $transforms[$row.role]=('e'*64)
        $mutants+=,[pscustomobject][ordered]@{role=$row.role;initialized=$true;positiveControl='Passed';oracleKilled=$true;oracleId=$row.oracleId;
            originalSourceSetSha256=$sourceSets.Runtime;mutatedSourceSetSha256=$sourceSets[$row.role];transformationSha256=$transforms[$row.role]}
    }
    $result=[ordered]@{schemaId='PspktBrokerLifecycleValidationResultV1';schemaVersion=1;outcome='ValidationSucceeded'}
    foreach($name in $bindings.Keys){$result[$name]=$bindings[$name]}
    $result.compilationRecords=$compilations
    $result.loadRecords=$loads
    $result.mutantResults=$mutants
    $result.counts=$Expectations.completeCallCounts
    $result.caseIds=$Expectations.caseIds
    $result.completionChecks=$Expectations.completionChecks
    $result.cleanupChecks=$Expectations.cleanupChecks
    return [pscustomobject]@{Result=[pscustomobject]$result;Expected=[pscustomobject]@{Bindings=[pscustomobject]$bindings;
        SourceSets=[pscustomobject]$sourceSets;Transformations=[pscustomobject]$transforms;CaseIds=$Expectations.caseIds;
        CompletionChecks=$Expectations.completionChecks;CleanupChecks=$Expectations.cleanupChecks}}
}
