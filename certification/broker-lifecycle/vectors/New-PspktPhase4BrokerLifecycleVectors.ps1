param([Parameter(Mandatory=$true)][string]$RepositoryRoot)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'

function Get-VectorDigest {
    param([byte[]]$Bytes)
    $hasher=[Security.Cryptography.SHA256]::Create()
    try{return [BitConverter]::ToString($hasher.ComputeHash($Bytes)).Replace('-','').ToLowerInvariant()}
    finally{$hasher.Dispose()}
}

function Convert-VectorHex {
    param([string]$Text)
    $bytes=[byte[]]::new($Text.Length/2)
    for($index=0;$index -lt $bytes.Length;$index++){$bytes[$index]=[Convert]::ToByte($Text.Substring($index*2,2),16)}
    return ,$bytes
}

function New-VectorUnsigned {
    param([int]$Width,[System.Numerics.BigInteger]$Value)
    if($Value -lt 0){throw 'validation:fixture'}
    $bytes=[byte[]]::new($Width)
    for($index=$Width-1;$index -ge 0;$index--){
        $bytes[$index]=[byte][System.Numerics.BigInteger]::Remainder($Value,256)
        $Value=[System.Numerics.BigInteger]::Divide($Value,256)
    }
    if($Value -ne 0){throw 'validation:fixture'}
    return ,$bytes
}

function New-VectorPattern {
    param([int]$Count,[byte]$Value)
    $bytes=[byte[]]::new($Count)
    for($index=0;$index -lt $Count;$index++){$bytes[$index]=$Value}
    return ,$bytes
}

function Join-VectorBytes {
    param([object[]]$Parts)
    $stream=[IO.MemoryStream]::new()
    try{
        foreach($part in $Parts){$bytes=[byte[]]$part;$stream.Write($bytes,0,$bytes.Length)}
        return ,$stream.ToArray()
    }
    finally{$stream.Dispose()}
}

function New-VectorPayload {
    param([string]$TypeName)
    if(-not $script:TypeMap.ContainsKey($TypeName)){throw 'validation:fixture'}
    $definition=$script:TypeMap[$TypeName]
    if($definition.production -cne 'Named'){throw 'validation:fixture'}
    $parts=[Collections.Generic.List[object]]::new()
    foreach($field in $definition.fields){
        if($null -ne $field.PSObject.Properties['profile'] -and $field.profile -cne 'NonInteractiveElevated'){continue}
        if($null -ne $field.PSObject.Properties['status'] -and $field.status -ceq 'Forbidden'){continue}
        if($script:TypeMap.ContainsKey($field.type)){$value=New-VectorPayload $field.type}
        elseif($field.name -ceq 'protocolSchemaMetaDigest'){$value=Convert-VectorHex $script:MetaDigest}
        elseif($field.name -ceq 'protocolSchemaDigest'){$value=Convert-VectorHex $script:SchemaDigest}
        else{
            switch -CaseSensitive ($field.type){
                'U8' {if($field.name -ceq 'profile'){$value=[byte[]]@(2)}else{$value=[byte[]]@(1)}}
                'U16' {$value=New-VectorUnsigned 2 1}
                'U32' {$value=New-VectorUnsigned 4 1}
                'U64' {$value=New-VectorUnsigned 8 1}
                'FILETIME' {$value=New-VectorUnsigned 8 1}
                'QPC' {$value=New-VectorUnsigned 8 1}
                'GUID' {$value=[byte[]](1..16)}
                'SHA-256' {$value=New-VectorPattern 32 33}
                'Opaque32' {$value=New-VectorPattern 32 49}
                'AsciiIdentifier' {$value=[Text.Encoding]::ASCII.GetBytes('A')}
                'BinarySid' {$value=[byte[]]@(1,0,0,0,0,0,0,5)}
                'Rsa3072PublicBlob' {$value=New-VectorPattern 24 1}
                'Rsa3072Signature' {$value=New-VectorPattern 384 193}
                'BoundedBytes' {$value=New-VectorUnsigned 4 0}
                default {throw 'validation:fixture'}
            }
        }
        $parts.Add((New-VectorUnsigned 2 $field.fieldId))
        $parts.Add((New-VectorUnsigned 4 $value.Length))
        $parts.Add($value)
    }
    return ,(Join-VectorBytes $parts.ToArray())
}

$inputs=[ordered]@{
    'protocol-schema-meta.v1.json'='ca08bcb5164acb4522729dc98b2a1bd5ee348a79a14cef95dd852ae1958dcc85'
    'protocol-inventory.v1.json'='d67cb37777eaa5fee07404894b0d1f4a20bf11d4a4c95085bc60e350805f265f'
    'protocol-schema.v1.json'='6d76911009b64e52417b3ca519d3b3166cfdf675a4d4deede5ab0dce449c9db4'
    'protocol-message-association.v1.json'='031bf566279871cd79db696ff436aa6d9383f1bb26a62467c3364880a012c5af'
    'generated-base-id-map.v1.json'='66884fb48fcd5ebc3949957c57906614ce3d0d3a6644c6808b1d1796afb45c91'
    'mandatory-tail-schedule.v1.json'='9852528ea500edc054a0380afa03f20993ed9aaae876e54025178106b4e50312'
}
$retained=@{}
foreach($name in $inputs.Keys){
    $bytes=[IO.File]::ReadAllBytes((Join-Path $RepositoryRoot ('certification\schema\'+$name)))
    if((Get-VectorDigest $bytes) -cne $inputs[$name]){throw 'validation:source-pin'}
    $retained[$name]=$bytes
}
$addendum=[IO.File]::ReadAllBytes((Join-Path $RepositoryRoot 'certification\broker-lifecycle\authority\framing-addendum.v1.json'))
if((Get-VectorDigest $addendum) -cne 'ae2a255f0a45f9a33fe958e9c728ff535550ea09aec8fcf11398f426f56f0a0f'){throw 'validation:source-pin'}
$script:MetaDigest=$inputs['protocol-schema-meta.v1.json']
$script:SchemaDigest=$inputs['protocol-schema.v1.json']
$schema=[Text.Encoding]::UTF8.GetString($retained['protocol-schema.v1.json'])|ConvertFrom-Json
$associations=[Text.Encoding]::UTF8.GetString($retained['protocol-message-association.v1.json'])|ConvertFrom-Json
$script:TypeMap=@{}
foreach($definition in $schema.types){$script:TypeMap[$definition.name]=$definition}
if($script:TypeMap.Count -ne 107){throw 'validation:fixture'}
$rows=[Collections.Generic.List[object]]::new()
foreach($association in $associations.rows){
    if($association.channel -cnotin @('BrokerControl','LocalIpc')){continue}
    if($association.profile -cne 'NonInteractiveElevated'){throw 'validation:fixture'}
    $payload=New-VectorPayload $association.payloadRoot
    $sequence=1
    if($association.kindId -in @(4353,4354,4355,4356,4609,4610)){$sequence=0}
    $frame=Join-VectorBytes @([Text.Encoding]::ASCII.GetBytes('PSP4'),(New-VectorUnsigned 2 1),
        (New-VectorUnsigned 2 $association.kindId),(New-VectorUnsigned 2 0),(New-VectorUnsigned 2 0),
        (New-VectorUnsigned 8 $sequence),(New-VectorUnsigned 4 $payload.Length),$payload,(New-VectorPattern 384 ([byte](161+$rows.Count))))
    $rows.Add([ordered]@{id=('row'+($rows.Count+1).ToString('00'));channel=$association.channel;direction=$association.direction;
        profile=2;kind=$association.kindId;sequence=$sequence;payloadRoot=$association.payloadRoot;
        frameLength=$frame.Length;frameSha256=(Get-VectorDigest $frame);frameHex=[BitConverter]::ToString($frame).Replace('-','').ToLowerInvariant()})
}
if($rows.Count -ne 22){throw 'validation:fixture'}
$encoding=[Text.UTF8Encoding]::new($false,$true)
$bundle=[ordered]@{schemaId='PspktBrokerLifecycleGeneratedFramesV1';schemaVersion=1;trustCeiling='StructuralInProcessOnly';rows=$rows.ToArray()}
$bundleBytes=$encoding.GetBytes(($bundle|ConvertTo-Json -Depth 20 -Compress))
$manifest=[ordered]@{schemaId='PspktBrokerLifecycleGeneratedManifestV1';schemaVersion=1;
    file=[ordered]@{path='frames.v1.json';bytes=$bundleBytes.Length;sha256=(Get-VectorDigest $bundleBytes)};
    rows=@($rows|ForEach-Object {[ordered]@{id=$_.id;bytes=$_.frameLength;sha256=$_.frameSha256}})}
$outputRoot=Join-Path $RepositoryRoot 'certification\broker-lifecycle\vectors\generated'
[void][IO.Directory]::CreateDirectory($outputRoot)
[IO.File]::WriteAllBytes((Join-Path $outputRoot 'frames.v1.json'),$bundleBytes)
[IO.File]::WriteAllText((Join-Path $outputRoot 'manifest.v1.json'),($manifest|ConvertTo-Json -Depth 20 -Compress),$encoding)
