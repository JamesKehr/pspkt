Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-PspktSignatureReferenceOracleSizingBytes {
    param([object]$Expectations)
    $fixture=New-PspktSignatureReferenceOracleBoundaryFixture 'Desktop' $Expectations
    $result=$fixture.Result
    $result.callId='f'*32
    $result.hostVersion='9'*32
    foreach($name in @('sourceManifestSha256','fixtureManifestSha256','frameworkManifestSha256','policySha256')) { $result.$name='f'*64 }
    foreach($record in $result.compilationRecords) {
        $record.imageName='PspktEvidenceSignatureReference_'+$result.callId+'_'+$record.role+'.dll'
        $record.imageLength=16777216
        foreach($name in @('imageSha256','sourceSetSha256','referenceSetSha256')) { $record.$name='f'*64 }
    }
    foreach($record in $result.loadRecords) { $record.imageSha256='f'*64 }
    foreach($record in $result.mutantResults) {
        $record.controlId='c'*48;$record.challengeId='i'*48;$record.baseReason='r'*48;$record.mutantObservation='o'*48
        $record.transformationSha256='f'*64
    }
    $values=[ordered]@{schemaId='PspktEvidenceSignatureReferenceCiReceiptV1';schemaVersion=1;outcome='ValidationSucceeded';
        workflowRunId=('9'*20);workflowRunAttempt=('9'*10);revision=('f'*40);slot='windows_ps51/checkout'}
    foreach($property in $result.PSObject.Properties) {
        if($property.Name -cin @('schemaId','schemaVersion','outcome')) { continue }
        $values.Add($property.Name,$property.Value)
    }
    $receipt=[pscustomobject]$values
    $encoding=[Text.UTF8Encoding]::new($false,$true)
    $width=$encoding.GetBytes((ConvertTo-Json -InputObject $receipt -Depth 8 -Compress))
    for($index=0;$index -lt 5;$index++) {
        $record=$receipt.mutantResults[$index];$expected=$Expectations.mutants[$index]
        $record.controlId=$expected.controlId;$record.challengeId=$expected.challengeId
        $record.baseReason=$expected.baseReason;$record.mutantObservation=$expected.observation
    }
    $literal=$encoding.GetBytes((ConvertTo-Json -InputObject $receipt -Depth 8 -Compress))
    return [pscustomobject]@{Width=$width;Literal=$literal}
}

function New-PspktSignatureReferenceOracleBoundaryFixture {
    param([string]$Edition,[object]$Expectations)
    $callId='1'*32
    $roles=@('Bootstrap','Structural','Checker','M1','M2','M3','M4','M5')
    $sourceSymbols='01234567';$imageSymbols='89abcdef';$transformSymbols='abcde'
    $sourceSets=@();$referenceSets=@();$imageHashes=@();$transformHashes=@()
    $compilation=@();$loads=@();$mutants=@()
    $compiler='Roslyn';$context='Default';$version='7.0.0'
    if($Edition -ceq 'Desktop') { $compiler='CodeDom';$context='LoadFrom';$version='5.1.0' }
    for($index=0;$index -lt 8;$index++) {
        $sourceSets+=([string]$sourceSymbols[$index])*64
        $referenceSets+='9'*64
        $imageHashes+=([string]$imageSymbols[$index])*64
        $count=17
        if($index -eq 0) {$count=1} elseif($index -eq 1) {$count=7}
        $compilation+=[pscustomobject][ordered]@{role=$roles[$index];imageName=('PspktEvidenceSignatureReference_'+$callId+'_'+$roles[$index]+'.dll');
            imageLength=(4096+$index*512);imageSha256=$imageHashes[$index];sourceCount=$count;sourceSetSha256=$sourceSets[$index];
            referenceSetSha256=$referenceSets[$index];language='CSharp5';compiler=$compiler}
        $loads+=[pscustomobject][ordered]@{role=$roles[$index];imageSha256=$imageHashes[$index];context=$context;initialized=$true}
    }
    for($index=0;$index -lt 5;$index++) {
        $recipe=$Expectations.mutants[$index]
        $transformHashes+=([string]$transformSymbols[$index])*64
        $mutants+=[pscustomobject][ordered]@{role=$recipe.role;initialized=$true;controlId=$recipe.controlId;controlOutcome='ok';
            challengeId=$recipe.challengeId;baseReason=$recipe.baseReason;mutantObservation=$recipe.observation;
            transformationSha256=$transformHashes[$index];oracleKilled=$true}
    }
    $counts=[pscustomobject][ordered]@{compilationCount=8;loadCount=8;initializedMutantKillCount=5;containerCount=1;totalCount=48;
        selectedCount=48;executedCount=48;passedCount=48;failedCount=0;skippedCount=0;notRunCount=0;failedBlocksCount=0;failedContainersCount=0}
    $result=[pscustomobject][ordered]@{schemaId='PspktEvidenceSignatureReferenceValidationResultV1';schemaVersion=1;outcome='ValidationSucceeded';
        callId=$callId;baseCommit='ad0bf32da25271ba7354bd1d276e56b8b34654ec';hostEdition=$Edition;hostVersion=$version;pesterVersion='5.3.3';
        sourceManifestSha256=('1'*64);fixtureManifestSha256='4b5a7a1ae3a3494c2e869c8f062082e01ee4d1b97bcc5f0842b20a5ad9c1c943';
        frameworkManifestSha256=('2'*64);policySha256='06fe309693f30348f9de46d0d2998fca5e23f08e6b578d742f4e72cbcce51c17';
        compilationRecords=@($compilation);loadRecords=@($loads);mutantResults=@($mutants);counts=$counts;testIds=@($Expectations.caseIds);
        checks=@('authority-pins','snapshot-policy','cryptographic-oracles','schema-bindings','references-and-joins','token-contract',
            'public-api','frozen-source-closure','compiler-references','caller-scope','workflow-contract','receipt-budget','complete-population');
        cleanup=@('hashes-disposed','streams-closed','compiler-staging-removed','testdrive-removed','testregistry-absent',
            'environment-restored','locations-restored','loaded-images-declared','no-unowned-residue')}
    $expected=[pscustomobject]@{callId=$callId;hostEdition=$Edition;hostVersion=$version;sourceManifestSha256=('1'*64);
        fixtureManifestSha256='4b5a7a1ae3a3494c2e869c8f062082e01ee4d1b97bcc5f0842b20a5ad9c1c943';
        frameworkManifestSha256=('2'*64);policySha256='06fe309693f30348f9de46d0d2998fca5e23f08e6b578d742f4e72cbcce51c17';
        SourceSets=$sourceSets;ReferenceSets=$referenceSets;ImageHashes=$imageHashes;TransformHashes=$transformHashes;Mutants=$Expectations.mutants}
    return [pscustomobject]@{Result=$result;Expected=$expected}
}

function Get-PspktSignatureReferenceOracleDigest {
    param([byte[]]$Bytes)
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try { return ,$algorithm.ComputeHash($Bytes) }
    finally { $algorithm.Dispose() }
}

function Get-PspktSignatureReferenceOracleUnsigned {
    param([byte[]]$Bytes)
    $number = [Numerics.BigInteger]::Zero
    foreach($value in $Bytes) { $number = $number * [Numerics.BigInteger]256 + [Numerics.BigInteger]$value }
    return $number
}

function ConvertTo-PspktSignatureReferenceOracleBytes {
    param([Numerics.BigInteger]$Number,[int]$Width)
    $bytes = [byte[]]::new($Width)
    for($index=$Width-1;$index -ge 0;$index--) {
        $remainder = [Numerics.BigInteger]::Zero
        $Number = [Numerics.BigInteger]::DivRem($Number,[Numerics.BigInteger]256,[ref]$remainder)
        $bytes[$index] = [byte]$remainder
    }
    if($Number -ne [Numerics.BigInteger]::Zero) { throw 'validation:oracle' }
    return ,$bytes
}

function Get-PspktSignatureReferenceOracleCoveredBytes {
    param([byte[]]$Envelope)
    $kind = [int]$Envelope[6]*256 + $Envelope[7]
    $domain = switch($kind) {
        16 { 'pspkt/evidence/v1/LocalEvidenceReceiptV1' }
        17 { 'pspkt/evidence/v1/LocalEvidenceProofV1' }
        20 { 'pspkt/evidence/v1/OperationRehabilitationAuthorizationV1' }
        default { throw 'validation:oracle' }
    }
    $length = if($kind -eq 20) { 246 } else { 254 }
    $prefix = [Text.Encoding]::ASCII.GetBytes($domain+[char]0)
    $covered = [byte[]]::new($prefix.Length+$length)
    [Array]::Copy($prefix,0,$covered,0,$prefix.Length)
    [Array]::Copy($Envelope,47,$covered,$prefix.Length,$length)
    return ,$covered
}

function Get-PspktSignatureReferenceOracleSignatureReason {
    param([byte[]]$Envelope,[byte[]]$PublicBlob)
    $kind = [int]$Envelope[6]*256 + $Envelope[7]
    $coveredLength = if($kind -eq 20) { 246 } else { 254 }
    $signatureBytes = [byte[]]::new(384)
    [Array]::Copy($Envelope,47+$coveredLength+6,$signatureBytes,0,384)
    $signature = Get-PspktSignatureReferenceOracleUnsigned $signatureBytes
    $modulus = Get-PspktSignatureReferenceOracleUnsigned ([byte[]]$PublicBlob[28..411])
    if($signature -ge $modulus) { return 'signature:range' }
    $decoded = ConvertTo-PspktSignatureReferenceOracleBytes ([Numerics.BigInteger]::ModPow($signature,[Numerics.BigInteger]65537,$modulus)) 384
    $expected = [byte[]]::new(384)
    $expected[1] = 1
    for($index=2;$index -le 331;$index++) { $expected[$index]=255 }
    $prefix = [byte[]]@(48,49,48,13,6,9,96,134,72,1,101,3,4,2,1,5,0,4,32)
    [Array]::Copy($prefix,0,$expected,333,19)
    [Array]::Copy((Get-PspktSignatureReferenceOracleDigest (Get-PspktSignatureReferenceOracleCoveredBytes $Envelope)),0,$expected,352,32)
    if([Convert]::ToBase64String($decoded) -cne [Convert]::ToBase64String($expected)) { return 'signature:emsa' }
    return 'ok'
}

function Set-PspktSignatureReferenceOracleDigest {
    param([byte[]]$Envelope)
    $result = [byte[]]$Envelope.Clone()
    $kind = [int]$result[6]*256 + $result[7]
    $domain = switch($kind) {
        9 { 'pspkt/evidence/v1/LocalTranscriptChunkV1' }
        16 { 'pspkt/evidence/v1/LocalEvidenceReceiptV1' }
        17 { 'pspkt/evidence/v1/LocalEvidenceProofV1' }
        18 { 'pspkt/evidence/v1/OperationBurnReceiptV1' }
        20 { 'pspkt/evidence/v1/OperationRehabilitationAuthorizationV1' }
        21 { 'pspkt/evidence/v1/OperationRehabilitationReceiptV1' }
        default { throw 'validation:oracle' }
    }
    $prefix = [Text.Encoding]::ASCII.GetBytes($domain+[char]0)
    $payloadLength = $result.Length-85
    $covered = [byte[]]::new($prefix.Length+$payloadLength)
    [Array]::Copy($prefix,0,$covered,0,$prefix.Length)
    [Array]::Copy($result,47,$covered,$prefix.Length,$payloadLength)
    [Array]::Copy((Get-PspktSignatureReferenceOracleDigest $covered),0,$result,$result.Length-32,32)
    return ,$result
}

function Get-PspktSignatureReferenceOraclePayloadDigest {
    param([byte[]]$Envelope)
    $kind = [int]$Envelope[6]*256 + $Envelope[7]
    $domain = switch($kind) {
        9 { 'pspkt/evidence/v1/LocalTranscriptChunkV1' }
        16 { 'pspkt/evidence/v1/LocalEvidenceReceiptV1' }
        17 { 'pspkt/evidence/v1/LocalEvidenceProofV1' }
        18 { 'pspkt/evidence/v1/OperationBurnReceiptV1' }
        20 { 'pspkt/evidence/v1/OperationRehabilitationAuthorizationV1' }
        21 { 'pspkt/evidence/v1/OperationRehabilitationReceiptV1' }
        default { throw 'validation:oracle' }
    }
    $length = [long]$Envelope[43]*16777216 + [long]$Envelope[44]*65536 +
        [long]$Envelope[45]*256 + $Envelope[46]
    if($length -ne $Envelope.Length-85) { throw 'validation:oracle' }
    $stream = [IO.MemoryStream]::new()
    try {
        $prefix = [Text.Encoding]::ASCII.GetBytes($domain)
        $stream.Write($prefix,0,$prefix.Length)
        $stream.WriteByte(0)
        $stream.Write($Envelope,47,[int]$length)
        return ,(Get-PspktSignatureReferenceOracleDigest $stream.ToArray())
    }
    finally { $stream.Dispose() }
}

function Test-PspktSignatureReferenceOracleEligibility {
    param([uint64]$NotBefore,[uint64]$EvaluationTime,[uint64]$NotAfter,[switch]$SignedCast)
    $values = @([Numerics.BigInteger]$NotBefore,[Numerics.BigInteger]$EvaluationTime,[Numerics.BigInteger]$NotAfter)
    if($SignedCast) {
        $boundary = [Numerics.BigInteger]::Pow(2,63)
        $modulus = [Numerics.BigInteger]::Pow(2,64)
        for($index=0;$index -lt $values.Length;$index++) {
            if($values[$index] -ge $boundary) { $values[$index] -= $modulus }
        }
    }
    return ($values[0] -le $values[1] -and $values[1] -lt $values[2])
}

function Test-PspktSignatureReferenceOraclePss {
    param([byte[]]$EncodedMessage,[byte[]]$MessageDigest)
    if($EncodedMessage.Length -ne 384 -or $MessageDigest.Length -ne 32 -or
        $EncodedMessage[383] -ne 188 -or ($EncodedMessage[0] -band 128) -ne 0) { return $false }
    $digest = [byte[]]$EncodedMessage[351..382]
    $decoded = [byte[]]::new(351)
    for($counter=0;$counter -lt 11;$counter++) {
        $inputBytes = [byte[]]::new(36)
        [Array]::Copy($digest,0,$inputBytes,0,32)
        $inputBytes[35] = [byte]$counter
        $block = Get-PspktSignatureReferenceOracleDigest $inputBytes
        for($index=0;$index -lt 32 -and ($counter*32+$index) -lt 351;$index++) {
            $position=$counter*32+$index
            $decoded[$position]=$EncodedMessage[$position] -bxor $block[$index]
        }
    }
    $decoded[0] = $decoded[0] -band 127
    $delimiter = 0
    while($delimiter -lt $decoded.Length -and $decoded[$delimiter] -eq 0) { $delimiter++ }
    if($delimiter -ge $decoded.Length -or $decoded[$delimiter] -ne 1) { return $false }
    $saltLength = $decoded.Length-$delimiter-1
    $message = [byte[]]::new(40+$saltLength)
    [Array]::Copy($MessageDigest,0,$message,8,32)
    [Array]::Copy($decoded,$delimiter+1,$message,40,$saltLength)
    return ([Convert]::ToBase64String((Get-PspktSignatureReferenceOracleDigest $message)) -ceq [Convert]::ToBase64String($digest))
}

function New-PspktSignatureReferenceOracleTranscriptEnvelope {
    param([byte[]]$Template,[int]$Length,[int]$Index)
    if($Length -lt 256 -or $Length -gt 262228) { throw 'validation:oracle' }
    $fields = Get-PspktSignatureReferenceOracleFields $Template
    $fields[5] = ConvertTo-PspktSignatureReferenceOracleBytes ([Numerics.BigInteger]$Index) 4
    $recordLength = $Length-256
    $fields[10] = [byte[]]::new($recordLength+4)
    [Array]::Copy((ConvertTo-PspktSignatureReferenceOracleBytes ([Numerics.BigInteger]$recordLength) 4),0,$fields[10],0,4)
    $stream = [IO.MemoryStream]::new()
    try {
        foreach($tag in @($fields.Keys | Sort-Object)) {
            $header = [byte[]]::new(6)
            [Array]::Copy((ConvertTo-PspktSignatureReferenceOracleBytes ([Numerics.BigInteger]$tag) 2),0,$header,0,2)
            [Array]::Copy((ConvertTo-PspktSignatureReferenceOracleBytes ([Numerics.BigInteger]$fields[$tag].Length) 4),0,$header,2,4)
            $stream.Write($header,0,6)
            $stream.Write($fields[$tag],0,$fields[$tag].Length)
        }
        $payload = $stream.ToArray()
    }
    finally { $stream.Dispose() }
    if($payload.Length+85 -ne $Length) { throw 'validation:oracle' }
    $envelope = [byte[]]::new($Length)
    [Array]::Copy($Template,0,$envelope,0,47)
    [Array]::Copy((ConvertTo-PspktSignatureReferenceOracleBytes ([Numerics.BigInteger]($payload.Length+4)) 4),0,$envelope,39,4)
    [Array]::Copy((ConvertTo-PspktSignatureReferenceOracleBytes ([Numerics.BigInteger]$payload.Length) 4),0,$envelope,43,4)
    [Array]::Copy($payload,0,$envelope,47,$payload.Length)
    [Array]::Copy($Template,$Template.Length-38,$envelope,$Length-38,6)
    return ,(Set-PspktSignatureReferenceOracleDigest $envelope)
}

function Get-PspktSignatureReferenceOracleFields {
    param([byte[]]$Envelope)
    if($null -eq $Envelope -or $Envelope.Length -lt 85) { throw 'validation:oracle' }
    $length = [long]$Envelope[43]*16777216 + [long]$Envelope[44]*65536 +
        [long]$Envelope[45]*256 + $Envelope[46]
    if($length -ne $Envelope.Length-85) { throw 'validation:oracle' }
    $fields = [Collections.Generic.Dictionary[int,byte[]]]::new()
    $end = 47 + [int]$length
    $offset = 47
    $previous = 0
    while($offset -lt $end) {
        if($end-$offset -lt 6) { throw 'validation:oracle' }
        $tag = [int]$Envelope[$offset]*256+$Envelope[$offset+1]
        $count = [long]$Envelope[$offset+2]*16777216 + [long]$Envelope[$offset+3]*65536 +
            [long]$Envelope[$offset+4]*256 + $Envelope[$offset+5]
        if($tag -le $previous -or $count -gt $end-$offset-6) { throw 'validation:oracle' }
        $value = [byte[]]::new([int]$count)
        [Array]::Copy($Envelope,$offset+6,$value,0,[int]$count)
        $fields.Add($tag,$value)
        $previous = $tag
        $offset += 6+[int]$count
    }
    return ,$fields
}
