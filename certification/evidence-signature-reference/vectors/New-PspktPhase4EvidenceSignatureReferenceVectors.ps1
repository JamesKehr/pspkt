[CmdletBinding(PositionalBinding = $false)]
param(
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$RepositoryRoot,
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$OutputRoot
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$encoding = [Text.UTF8Encoding]::new($false, $true)
$script:privateKeys = @()
$script:privateParameters = @()
Write-Verbose 'NONDETERMINISTIC, TEST-ONLY, NOT AN ENROLLMENT TOOL'
if(-not [IO.Path]::IsPathRooted($RepositoryRoot) -or -not [IO.Path]::IsPathRooted($OutputRoot)) { throw 'validation:work-root' }
$RepositoryRoot = [IO.Path]::GetFullPath($RepositoryRoot)
$OutputRoot = [IO.Path]::GetFullPath($OutputRoot)
foreach($root in @($RepositoryRoot,$OutputRoot)) {
    $current = $root.TrimEnd([char]92)
    while(-not [string]::IsNullOrEmpty($current)) {
        if([IO.File]::Exists($current)) { throw 'validation:work-root' }
        if([IO.Directory]::Exists($current) -and ([IO.File]::GetAttributes($current) -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'validation:work-root'
        }
        $parent = [IO.Directory]::GetParent($current)
        if($null -eq $parent) { break }
        $current = $parent.FullName
    }
}
if(-not [IO.Directory]::Exists($RepositoryRoot) -or
    [string]::Equals($OutputRoot.TrimEnd([char]92),$RepositoryRoot.TrimEnd([char]92),[StringComparison]::OrdinalIgnoreCase) -or
    [IO.Directory]::GetParent($OutputRoot) -eq $null) { throw 'validation:work-root' }
$script:kindNames = @('WorkerSessionKeyCertificateV1','BrokerSessionKeyCertificateBodyV1','BrokerSessionKeyCertificateEnvelopeV1','WorkerProcessIsolationAdmissionReceiptV1','WorkerProcessIsolationReceiptV1','ServiceLaunchProofV1','ServiceEnrollmentInstallProofV1','WorkerProcessDaclAccessPolicyProofV1','LiveCandidateAccessProbeV1','LocalTranscriptChunkV1','LocalTranscriptRootV1','LocalTranscriptProofV1','LocalTranscriptRootAcceptedV1','BrokerServiceLaunchProofV1','CreatorPermitInstallationBodyV1','CreatorPermitInstallationV1','LocalEvidenceReceiptV1','LocalEvidenceProofV1','OperationBurnReceiptV1','OperationBurnDeferralReceiptV1','OperationRehabilitationAuthorizationV1','OperationRehabilitationReceiptV1')
$script:authorityPins = @(
    @('certification\schema\protocol-schema-meta.v1.json',4533,'ca08bcb5164acb4522729dc98b2a1bd5ee348a79a14cef95dd852ae1958dcc85'),
    @('certification\schema\protocol-inventory.v1.json',46479,'d67cb37777eaa5fee07404894b0d1f4a20bf11d4a4c95085bc60e350805f265f'),
    @('certification\evidence-ledger\schema\evidence-schema.v1.json',22001,'49b07b1a401e686ce1bb05fbffb6923f6ef12a9d74deae5a06c840e2abf1fda6'),
    @('certification\evidence-ledger\schema\evidence-ledger-inventory.v1.json',47347,'07b39559f1b581dd78623314d3ec44b04a37e278a3e4c90cf2ff9037f46e3dc9'),
    @('certification\schema\protocol-schema.v1.json',66838,'6d76911009b64e52417b3ca519d3b3166cfdf675a4d4deede5ab0dce449c9db4'),
    @('certification\trusted-control\schema\trusted-control-authority.v1.json',55414,'f72d4175e0a94bf9a4cb86823b7f7595df81f96af39d15aef2497d7d89f29eab'),
    @('certification\trusted-control\schema\trust-roots-schema.v1.json',984,'2f18159cc6229d23f3b7ecca0edd820b1c15bd9d2fed8ad906f63a0829717be5')
)
function Get-Digest([byte[]]$Bytes) {
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try { return ,$algorithm.ComputeHash($Bytes) } finally { $algorithm.Dispose() }
}

function Get-Hex([byte[]]$Bytes) { return [BitConverter]::ToString($Bytes).Replace('-','').ToLowerInvariant() }

function Read-Hex([string]$Text) {
    $bytes = [byte[]]::new($Text.Length / 2)
    for($index=0;$index-lt$bytes.Length;$index++){ $bytes[$index]=[Convert]::ToByte($Text.Substring($index*2,2),16) }
    return ,$bytes
}

function Join-Bytes([object[]]$Parts) {
    $stream=[IO.MemoryStream]::new()
    try { foreach($part in $Parts){ $bytes=[byte[]]$part; $stream.Write($bytes,0,$bytes.Length) }; return ,$stream.ToArray() } finally { $stream.Dispose() }
}

function Get-BigEndian([UInt64]$Value,[int]$Width) {
    $bytes=[byte[]]::new($Width)
    for($index=$Width-1;$index-ge0;$index--){ $bytes[$index]=[byte]($Value-band[uint64]255); $Value=$Value-shr8 }
    return ,$bytes
}

function Read-Unsigned([byte[]]$Bytes) {
    $value=[Numerics.BigInteger]::Zero
    foreach($octet in $Bytes){ $value=$value*[Numerics.BigInteger]256+[Numerics.BigInteger]$octet }
    return $value
}

function Write-Unsigned([Numerics.BigInteger]$Value,[int]$Width) {
    $bytes=[byte[]]::new($Width)
    for($index=$Width-1;$index-ge0;$index--){ $remainder=[Numerics.BigInteger]::Zero; $Value=[Numerics.BigInteger]::DivRem($Value,[Numerics.BigInteger]256,[ref]$remainder);$bytes[$index]=[byte]$remainder }
    if($Value-ne[Numerics.BigInteger]::Zero){throw 'oracle-width'}
    return ,$bytes
}

function Get-GuidBytes([string]$Value) { return ,(Read-Hex $Value.Replace('-','')) }

function New-Tlv([int]$Tag,[byte[]]$Value) { return ,(Join-Bytes @((Get-BigEndian ([uint64]$Tag) 2),(Get-BigEndian ([uint64]$Value.Length) 4),$Value)) }

function New-Payload([object[]]$Fields) {
    $parts=[Collections.Generic.List[object]]::new()
    for($index=0;$index-lt$Fields.Count;$index++){ $parts.Add((New-Tlv ($index+1) ([byte[]]$Fields[$index]))) }
    return ,(Join-Bytes $parts.ToArray())
}

function Read-TlvFields([byte[]]$Bytes) {
    $fields=[Collections.Generic.List[object]]::new(); $offset=0; $tag=0
    while($offset-lt$Bytes.Length){
        if($Bytes.Length-$offset-lt6){throw 'oracle-tlv'}
        $actual=([int]$Bytes[$offset]*256)+$Bytes[$offset+1]
        $length=([long]$Bytes[$offset+2]*16777216)+([long]$Bytes[$offset+3]*65536)+([long]$Bytes[$offset+4]*256)+$Bytes[$offset+5]
        if($actual-le$tag-or$length-gt$Bytes.Length-$offset-6){throw 'oracle-tlv'}
        $value=[byte[]]::new([int]$length);[Array]::Copy($Bytes,$offset+6,$value,0,[int]$length);$fields.Add($value);$offset+=6+[int]$length;$tag=$actual
    }
    return ,$fields.ToArray()
}

function Get-Domain([int]$Kind) { return ,[Text.Encoding]::ASCII.GetBytes('pspkt/evidence/v1/'+$script:kindNames[$Kind]+[char]0) }

function New-Envelope([int]$Kind,[object[]]$Fields,[int]$Profile=1) {
    $payload=New-Payload $Fields
    $digest=Get-Digest (Join-Bytes @((Get-Domain $Kind),$payload))
    return ,(New-Payload @((Get-BigEndian ([uint64]$Kind) 2),(Get-GuidBytes 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee'),([byte[]]@($Profile)),(Join-Bytes @((Get-BigEndian ([uint64]$payload.Length) 4),$payload)),$digest))
}

function Get-PayloadFields([byte[]]$Envelope) {
    $outer=Read-TlvFields $Envelope
    $payload=[byte[]]::new($outer[3].Length-4);[Array]::Copy($outer[3],4,$payload,0,$payload.Length)
    return ,(Read-TlvFields $payload)
}

function Get-EnvelopeDigest([byte[]]$Envelope) { $fields=Read-TlvFields $Envelope; return ,[byte[]]$fields[4] }

function Get-Covered([int]$Kind,[object[]]$Fields) { return ,(Join-Bytes @((Get-Domain $Kind),(New-Payload @($Fields[0..8])))) }

function New-EncodedMessage([byte[]]$Covered,[string]$Mode='valid') {
    $prefix=Read-Hex '3031300d060960864801650304020105000420'
    $digest=Get-Digest $Covered
    $padding=330
    if($Mode-ceq'null-omitted'){ $prefix=Read-Hex '302f300b06096086480165030402010420';$padding=332 }
    if($Mode-ceq'sha1'){
        $prefix=Read-Hex '3021300906052b0e03021a05000414';$padding=346
        $algorithm=[Security.Cryptography.SHA1]::Create();try{$digest=$algorithm.ComputeHash($Covered)}finally{$algorithm.Dispose()}
    }
    if($Mode-ceq'trailing'){ $padding=329 }
    $pad=[byte[]]::new($padding);for($index=0;$index-lt$pad.Length;$index++){$pad[$index]=255}
    $message=Join-Bytes @(([byte[]]@(0,1)),$pad,([byte[]]@(0)),$prefix,$digest)
    if($Mode-ceq'trailing'){$message=Join-Bytes @($message,([byte[]]@(0)))}
    return ,$message
}

function New-SignedEnvelope([int]$Kind,[object[]]$Fields,[object]$Key,[int]$Profile=1,[byte[]]$EncodedMessage=$null) {
    $covered=Get-Covered $Kind $Fields
    if($null-eq$EncodedMessage){$EncodedMessage=New-EncodedMessage $covered}
    $representative=Read-Unsigned $EncodedMessage
    if($representative-ge$Key.Modulus){throw 'generator-message-range'}
    $signature=Write-Unsigned ([Numerics.BigInteger]::ModPow($representative,$Key.PrivateExponent,$Key.Modulus)) 384
    return ,(New-Envelope $Kind (@($Fields[0..8])+@(,$signature)) $Profile)
}

function New-LocalFields([object]$Key,[int]$Counter=0,[byte]$Family=1) {
    $subject=Get-GuidBytes '22222222-2222-4222-8222-222222222222';$subject[0]=$Family
    [Array]::Copy((Get-BigEndian ([uint64]$Counter) 4),0,$subject,12,4)
    return ,@((Get-GuidBytes '11111111-1111-4111-8111-111111111111'),$subject,(Get-GuidBytes '33333333-3333-4333-8333-333333333333'),(Get-GuidBytes '44444444-4444-4444-8444-444444444444'),(Read-Hex $script:authorityPins[4][2]),(Read-Hex $script:authorityPins[2][2]),(Read-Hex ('22'*32)),(Get-BigEndian 0 8),(Read-Hex $Key.KeyId))
}

function New-SnapshotText([object[]]$Rows,[UInt64]$Skew=0,[string]$Ledger='11111111-2222-4333-8444-555555555555') {
    return (ConvertTo-Json -InputObject ([ordered]@{schemaId='PspktEvidenceKeyBindingSnapshotV1';schemaVersion=1;ledgerIdentity=$Ledger;keys=@($Rows);maximumSkewHundredNanoseconds=$Skew}) -Depth 8 -Compress)
}

function New-KeyRow([object]$Key,[string]$Role,[UInt64]$Before=1000,[UInt64]$After=2000) {
    return [ordered]@{keyId=$Key.KeyId;publicBlob=(Get-Hex $Key.PublicBlob);algorithm='RSA3072PKCS1SHA256';role=$Role;notBefore=$Before;notAfter=$After;hostInventoryPolicyDigest=('11'*32)}
}

function Write-PublicFile([string]$Path,[byte[]]$Bytes) {
    $stream=[IO.File]::Open($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try{$stream.Write($Bytes,0,$Bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
}

function Assert-PublicBytes([byte[]]$Bytes) {
    $text=[Text.Encoding]::ASCII.GetString($Bytes)
    if($text.Contains('-----BEGIN ')-or$text.Contains('-----END ')-or$text.Contains('RSA2')-or$text-match'(?i)0x(?:32415352|33415352)|"(?:DP|DQ|InverseQ)"\s*:|<(?:DP|DQ|InverseQ)>'){throw 'validation:fixture-pin'}
    if($Bytes.Length-ge8){
        $head=Get-Hex ([byte[]]$Bytes[0..7])
        if($head-ceq'52534132000c0000'-or$head-ceq'52534133000c0000'){throw 'validation:fixture-pin'}
    }
}

function Invoke-Generate {
    if($PSVersionTable.PSEdition-cne'Core'-or$PSVersionTable.PSVersion.Major-lt7-or
        [Environment]::OSVersion.Platform-ne[PlatformID]::Win32NT){throw 'validation:fixture-pin'}
    $destination=$OutputRoot
    if([IO.Directory]::Exists($destination) -and [IO.Directory]::GetFileSystemEntries($destination).Length -ne 0){throw 'validation:work-root'}
    [void][IO.Directory]::CreateDirectory($destination)
    $providers=[Collections.Generic.List[object]]::new()
    $identifiers=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    try{
        for($index=0;$index-lt3;$index++){
            $provider=[Security.Cryptography.RSACng]::new(3072);$providers.Add($provider)
            if(-not$provider.Key.IsEphemeral-or$provider.KeySize-ne3072){throw 'validation:fixture-pin'}
            $parameters=$provider.ExportParameters($true)
            $script:privateParameters+=,$parameters
            if((Get-Hex $parameters.Exponent)-cne'010001'-or$parameters.Modulus.Length-ne384-or$parameters.Modulus[0]-lt128){throw 'generator-key-format'}
            $public=[byte[]]::new(512);$header=Read-Hex '52534131000c0000040000008001000000000000000000000000';[Array]::Copy($header,0,$public,0,24);$public[25]=1;$public[27]=1;[Array]::Copy($parameters.Modulus,0,$public,28,384)
            $script:privateKeys+=[pscustomobject]@{PublicBlob=$public;KeyId=(Get-Hex (Get-Digest $public));Modulus=(Read-Unsigned $parameters.Modulus);PrivateExponent=(Read-Unsigned $parameters.D);Parameters=$parameters}
            if(-not$identifiers.Add($script:privateKeys[$index].KeyId)){throw 'validation:fixture-pin'}
        }
        $keyA=$script:privateKeys[0];$keyB=$script:privateKeys[1];$keyC=$script:privateKeys[2]
        if($keyA.Modulus-lt$keyB.Modulus){$saved=$keyA;$keyA=$keyB;$keyB=$saved}
        $vectors=[ordered]@{};$power=[Numerics.BigInteger]::Pow([Numerics.BigInteger]2,3071)
        $highCounter=-1
        for($counter=0;$counter-lt4096;$counter++){
            $fields=New-LocalFields $keyA $counter 1;$candidate=New-SignedEnvelope 16 $fields $keyA
            if((Get-PayloadFields $candidate)[9][0]-ge128){$vectors['positive-k16-p1']=$candidate;$highCounter=$counter;break}
        }
        if($highCounter-lt0){throw 'generator-high-search'}
        $highSignature=Read-Unsigned ([byte[]](Get-PayloadFields $vectors['positive-k16-p1'])[9])
        if([Numerics.BigInteger]::ModPow($highSignature,[Numerics.BigInteger]65537,$keyA.Modulus)-ne
            (Read-Unsigned (New-EncodedMessage (Get-Covered 16 $fields)))){throw 'validation:fixture-pin'}
        $vectors['positive-k16-p2']=New-Envelope 16 (Get-PayloadFields $vectors['positive-k16-p1']) 2
        $proofFields=New-LocalFields $keyA 0 3
        $vectors['positive-k17-p1']=New-SignedEnvelope 17 $proofFields $keyA
        $vectors['positive-k17-p2']=New-Envelope 17 (Get-PayloadFields $vectors['positive-k17-p1']) 2
        $burnFields=@((Get-GuidBytes '55555555-5555-4555-8555-555555555555'),(Read-Hex ('22'*32)),(Read-Hex ('44'*32)),(Read-Hex ('55'*32)),(Get-BigEndian 0 8),(Read-Hex ('66'*32)),(Get-BigEndian 1 4))
        $vectors['positive-k18-p1']=New-Envelope 18 $burnFields
        $vectors['positive-k18-p2']=New-Envelope 18 $burnFields 2
        $authorizationFields=@((Get-EnvelopeDigest $vectors['positive-k18-p1']),$burnFields[0],$burnFields[1],(Get-GuidBytes '66666666-6666-4666-8666-666666666666'),(Get-GuidBytes '77777777-7777-4777-8777-777777777777'),(Read-Hex ('33'*32)),(Get-BigEndian 800 8),(Get-BigEndian 0 8),(Read-Hex $keyC.KeyId))
        $vectors['positive-k20-p1']=New-SignedEnvelope 20 $authorizationFields $keyC
        $vectors['positive-k20-p2']=New-Envelope 20 (Get-PayloadFields $vectors['positive-k20-p1']) 2
        $receiptFields=@((Get-EnvelopeDigest $vectors['positive-k20-p1']),$authorizationFields[3],(Read-Hex ('77'*32)),(Get-BigEndian 0 8),(Read-Hex ('88'*32)))
        $vectors['positive-k21-p1']=New-Envelope 21 $receiptFields
        $vectors['positive-k21-p2']=New-Envelope 21 $receiptFields 2
        $vectors['wrong-key-signed-by-b']=New-SignedEnvelope 16 (New-LocalFields $keyA 0 4) $keyB
        $wrongFields=Get-PayloadFields $vectors['wrong-key-signed-by-b']
        if([Numerics.BigInteger]::ModPow((Read-Unsigned ([byte[]]$wrongFields[9])),[Numerics.BigInteger]65537,$keyA.Modulus)-eq
            (Read-Unsigned (New-EncodedMessage (Get-Covered 16 $wrongFields)))){throw 'validation:fixture-pin'}
        foreach($kind in @(16,17)){foreach($field in @(4,5)){$changed=New-LocalFields $keyA 0 5;$changed[$field]=Read-Hex ('ff'*32);$label=if($field-eq4){'protocol'}else{'evidence'};$vectors['wrong-'+$label+'-schema-k'+$kind]=New-SignedEnvelope $kind $changed $keyA}}
        $changed=[object[]]$authorizationFields.Clone();$changed[1]=Get-GuidBytes '99999999-9999-4999-8999-999999999999';$vectors['wrong-burned-operation']=New-SignedEnvelope 20 $changed $keyC
        $changed=[object[]]$authorizationFields.Clone();$changed[2]=Read-Hex ('ab'*32);$vectors['wrong-burned-semantic']=New-SignedEnvelope 20 $changed $keyC
        $changed=[object[]]$receiptFields.Clone();$changed[1]=Get-GuidBytes '99999999-9999-4999-8999-999999999999';$vectors['wrong-successor-operation']=New-Envelope 21 $changed
        $rangeCounter=-1
        for($counter=0;$counter-lt4096;$counter++){
            $fields=New-LocalFields $keyA $counter 2;$candidate=New-SignedEnvelope 16 $fields $keyA;$signature=[byte[]](Get-PayloadFields $candidate)[9];$number=Read-Unsigned $signature
            if($number+$keyA.Modulus-ge($power*2)){continue}
            $reversed=[byte[]]$signature.Clone();[Array]::Reverse($reversed);$reverseNumber=Read-Unsigned $reversed
            if($reversed[0]-lt128-or$reverseNumber-ge$keyA.Modulus){continue}
            $recovered=[Numerics.BigInteger]::ModPow($reverseNumber,[Numerics.BigInteger]65537,$keyA.Modulus)
            if($recovered-lt$power){continue}
            $vectors['range-control-k16']=$candidate
            $vectors['range-plus-n-k16']=New-Envelope 16 (@($fields)+@(,(Write-Unsigned ($number+$keyA.Modulus) 384)))
            $vectors['signature-little-endian-k16']=New-Envelope 16 (@($fields)+@(,$reversed));$rangeCounter=$counter;break
        }
        if($rangeCounter-lt0){throw 'generator-range-search'}
        $local=New-LocalFields $keyA 0 6;$covered=Get-Covered 16 $local
        foreach($mode in @('leading-octet','padding-octet','early-separator','missing-separator','der-oid','der-null-omitted','trailing-octet','wrong-digest','pss','sha1')){
            $em=New-EncodedMessage $covered
            switch($mode){
                'leading-octet'{$em[0]=1}
                'padding-octet'{$em[2]=254}
                'early-separator'{$em[16]=0}
                'missing-separator'{$em[332]=255}
                'der-oid'{$em[345]=$em[345]-bxor1}
                'der-null-omitted'{$em=New-EncodedMessage $covered 'null-omitted'}
                'trailing-octet'{$em=New-EncodedMessage $covered 'trailing'}
                'wrong-digest'{$em[383]=$em[383]-bxor1}
                'sha1'{$em=New-EncodedMessage $covered 'sha1'}
                'pss'{
                    $salt=[byte[]](0..31);$hash=Get-Digest (Join-Bytes @(([byte[]]::new(8)),(Get-Digest $covered),$salt));$database=Join-Bytes @(([byte[]]::new(318)),([byte[]]@(1)),$salt)
                    $mask=[byte[]]::new(352);for($part=0;$part-lt11;$part++){$block=Get-Digest (Join-Bytes @($hash,(Get-BigEndian ([uint64]$part) 4)));[Array]::Copy($block,0,$mask,$part*32,32)}
                    for($part=0;$part-lt351;$part++){$database[$part]=$database[$part]-bxor$mask[$part]};$database[0]=$database[0]-band127;$em=Join-Bytes @($database,$hash,([byte[]]@(188)))
                }
            }
            if($em.Length-ne384){throw 'generator-emsa-width'}
            $vectors['emsa-'+$mode]=New-SignedEnvelope 16 $local $keyA 1 $em
        }
        $changed=[object[]]$authorizationFields.Clone();$changed[3]=Get-GuidBytes '88888888-8888-4888-8888-888888888888';$vectors['fanout-authorization-2']=New-SignedEnvelope 20 $changed $keyC
        $changedReceipt=[object[]]$receiptFields.Clone();$changedReceipt[3]=Get-BigEndian 1 8;$vectors['fanout-receipt-2']=New-Envelope 21 $changedReceipt
        $changedReceipt[0]=Get-EnvelopeDigest $vectors['fanout-authorization-2'];$changedReceipt[1]=$changed[3];$vectors['fanout-receipt-3']=New-Envelope 21 $changedReceipt
        $changedBurn=[object[]]$burnFields.Clone();$changedBurn[3]=Read-Hex ('ab'*32);$vectors['branch-burn-2']=New-Envelope 18 $changedBurn
        $changed=[object[]]$authorizationFields.Clone();$changed[0]=Get-EnvelopeDigest $vectors['branch-burn-2'];$vectors['branch-authorization-2']=New-SignedEnvelope 20 $changed $keyC
        $changedReceipt=[object[]]$receiptFields.Clone();$changedReceipt[0]=Get-EnvelopeDigest $vectors['branch-authorization-2'];$vectors['branch-receipt-2']=New-Envelope 21 $changedReceipt
        $snapshots=[ordered]@{}
        $snapshots['eligible-three']=New-SnapshotText @((New-KeyRow $keyA 'HostEvidence'),(New-KeyRow $keyB 'HostEvidence'),(New-KeyRow $keyC 'RecoveryAuthority'))
        $snapshots['unused-expired']=New-SnapshotText @((New-KeyRow $keyA 'HostEvidence'),(New-KeyRow $keyB 'HostEvidence' 1 2),(New-KeyRow $keyC 'RecoveryAuthority'))
        $snapshots['unused-future']=New-SnapshotText @((New-KeyRow $keyA 'HostEvidence'),(New-KeyRow $keyB 'HostEvidence' 3000 4000),(New-KeyRow $keyC 'RecoveryAuthority'))
        $snapshots['wrong-role-a']=New-SnapshotText @((New-KeyRow $keyA 'RecoveryAuthority'),(New-KeyRow $keyB 'HostEvidence'),(New-KeyRow $keyC 'RecoveryAuthority'))
        $snapshots['zero-rows']=New-SnapshotText @()
        $orderedIds=@('positive-k16-p1','positive-k16-p2','positive-k17-p1','positive-k17-p2','positive-k20-p1','positive-k20-p2','positive-k18-p1','positive-k18-p2','positive-k21-p1','positive-k21-p2','wrong-key-signed-by-b','wrong-protocol-schema-k16','wrong-evidence-schema-k16','wrong-protocol-schema-k17','wrong-evidence-schema-k17','wrong-burned-operation','wrong-burned-semantic','wrong-successor-operation','range-control-k16','range-plus-n-k16','signature-little-endian-k16','emsa-leading-octet','emsa-padding-octet','emsa-early-separator','emsa-missing-separator','emsa-der-oid','emsa-der-null-omitted','emsa-trailing-octet','emsa-wrong-digest','emsa-pss','emsa-sha1','fanout-authorization-2','fanout-receipt-2','fanout-receipt-3','branch-burn-2','branch-authorization-2','branch-receipt-2')
        $envelopeItems=@();foreach($id in $orderedIds){Assert-PublicBytes $vectors[$id];$envelopeItems+=[ordered]@{id=$id;bytesHex=(Get-Hex $vectors[$id])}}
        $snapshotItems=@();foreach($id in $snapshots.Keys){$bytes=$encoding.GetBytes($snapshots[$id]);Assert-PublicBytes $bytes;foreach($row in ($snapshots[$id]|ConvertFrom-Json).keys){Assert-PublicBytes (Read-Hex $row.publicBlob)};$snapshotItems+=[ordered]@{id=$id;bytesHex=(Get-Hex $bytes)}}
        if($envelopeItems.Count-ne37-or$snapshotItems.Count-ne5){throw 'generator-membership'}
        $files=[ordered]@{'public-key-a.bin'=$keyA.PublicBlob;'public-key-b.bin'=$keyB.PublicBlob;'public-key-c.bin'=$keyC.PublicBlob}
        $files['synthetic-key-snapshots.v1.json']=$encoding.GetBytes((ConvertTo-Json -InputObject ([ordered]@{schemaId='PspktEvidenceSignatureReferenceSnapshotFixturesV1';schemaVersion=1;syntheticNonEnrolled=$true;items=$snapshotItems}) -Depth 8 -Compress))
        $files['evidence-envelopes.v1.json']=$encoding.GetBytes((ConvertTo-Json -InputObject ([ordered]@{schemaId='PspktEvidenceSignatureReferenceEnvelopeFixturesV1';schemaVersion=1;syntheticNonEnrolled=$true;items=$envelopeItems}) -Depth 8 -Compress))
        $records=@();foreach($name in $files.Keys){$bytes=$files[$name];Assert-PublicBytes $bytes;if($bytes.Length-gt524288){throw 'validation:fixture-pin'};$records+=[ordered]@{path=$name;length=$bytes.Length;sha256=(Get-Hex (Get-Digest $bytes))}}
        $fixtureRecords=@()
        foreach($id in $snapshots.Keys){
            $bytes=$encoding.GetBytes($snapshots[$id])
            $fixtureRecords+=[ordered]@{id=$id;bundle='synthetic-key-snapshots.v1.json';length=$bytes.Length;sha256=(Get-Hex(Get-Digest $bytes));expectedReason='ok'}
        }
        foreach($id in $orderedIds){
            $reason='ok'
            if($id-ceq'wrong-key-signed-by-b'-or$id-ceq'signature-little-endian-k16'-or$id.StartsWith('emsa-',[StringComparison]::Ordinal)){$reason='signature:emsa'}
            elseif($id.StartsWith('wrong-protocol-schema-',[StringComparison]::Ordinal)){$reason='schema:protocol-digest'}
            elseif($id.StartsWith('wrong-evidence-schema-',[StringComparison]::Ordinal)){$reason='schema:evidence-digest'}
            elseif($id-ceq'wrong-burned-operation'){$reason='reference:burned-operation'}
            elseif($id-ceq'wrong-burned-semantic'){$reason='reference:burned-semantic'}
            elseif($id-ceq'wrong-successor-operation'){$reason='reference:successor-operation'}
            elseif($id-ceq'range-plus-n-k16'){$reason='signature:range'}
            $fixtureRecords+=[ordered]@{id=$id;bundle='evidence-envelopes.v1.json';length=$vectors[$id].Length;sha256=(Get-Hex(Get-Digest $vectors[$id]));expectedReason=$reason}
        }
        $manifest=$encoding.GetBytes((ConvertTo-Json -InputObject ([ordered]@{schemaId='PspktEvidenceSignatureReferenceVectorsV1';schemaVersion=1;syntheticNonEnrolled=$true;files=$records;fixtures=$fixtureRecords}) -Depth 8 -Compress))
        if($manifest.Length-gt65536){throw 'validation:fixture-pin'}
        Assert-PublicBytes $manifest
        $files['manifest.v1.json']=$manifest
        foreach($name in $files.Keys){Write-PublicFile (Join-Path $destination $name) $files[$name]}
        $generationResult=[pscustomobject]@{GeneratedFiles=6;EnvelopeCount=37;SnapshotCount=5;ManifestSha256=(Get-Hex (Get-Digest $manifest))}
    }finally{
        foreach($privateParameters in $script:privateParameters){foreach($name in @('D','P','Q','DP','DQ','InverseQ')){$bytes=$privateParameters.$name;if($null-ne$bytes){[Array]::Clear($bytes,0,$bytes.Length)}}}
        foreach($key in $script:privateKeys){$key.PrivateExponent=[Numerics.BigInteger]::Zero}
        $cleanupFailed=$false
        foreach($provider in $providers){try{$provider.Dispose()}catch{$cleanupFailed=$true}}
        $script:privateKeys=@()
        $script:privateParameters=@()
        if($cleanupFailed){throw 'validation:fixture-pin'}
    }
    return $generationResult
}

try {
    foreach($pin in $script:authorityPins) {
        $stream = [IO.File]::Open((Join-Path $RepositoryRoot $pin[0]),[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        try {
            if($stream.Length -ne $pin[1]) { throw 'validation:source-length' }
            $bytes=[byte[]]::new([int]$pin[1]);$offset=0
            while($offset -lt $bytes.Length) {
                $count=$stream.Read($bytes,$offset,$bytes.Length-$offset)
                if($count -le 0) { throw 'validation:source-length' }
                $offset+=$count
            }
        }
        finally { $stream.Dispose() }
        if($bytes.Length -ne $pin[1] -or (Get-Hex (Get-Digest $bytes)) -cne $pin[2]) { throw 'validation:source-pin' }
    }
    Invoke-Generate
}
catch {
    [Console]::Error.WriteLine('validation:fixture-pin')
    exit 1
}
