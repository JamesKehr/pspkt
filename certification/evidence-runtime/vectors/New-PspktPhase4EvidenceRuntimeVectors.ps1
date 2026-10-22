[CmdletBinding(PositionalBinding = $false)]
param(
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$RepositoryRoot,
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$OutputRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$sourceRoot = [IO.Path]::GetFullPath($RepositoryRoot)
$destination = [IO.Path]::GetFullPath($OutputRoot)
if (-not [IO.Path]::IsPathRooted($RepositoryRoot) -or -not [IO.Path]::IsPathRooted($OutputRoot)) {
    throw 'Vector roots must be absolute.'
}
if ([IO.Directory]::Exists($destination) -and [IO.Directory]::GetFileSystemEntries($destination).Length -ne 0) {
    throw 'Vector output directory must be empty.'
}
$pins = @(
    @('certification\schema\protocol-schema-meta.v1.json', 4533, 'ca08bcb5164acb4522729dc98b2a1bd5ee348a79a14cef95dd852ae1958dcc85'),
    @('certification\schema\protocol-inventory.v1.json', 46479, 'd67cb37777eaa5fee07404894b0d1f4a20bf11d4a4c95085bc60e350805f265f'),
    @('certification\evidence-ledger\schema\evidence-schema.v1.json', 22001, '49b07b1a401e686ce1bb05fbffb6923f6ef12a9d74deae5a06c840e2abf1fda6'),
    @('certification\evidence-ledger\schema\evidence-ledger-inventory.v1.json', 47347, '07b39559f1b581dd78623314d3ec44b04a37e278a3e4c90cf2ff9037f46e3dc9')
)
function Get-VectorDigest([byte[]]$Bytes) {
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try { [BitConverter]::ToString($algorithm.ComputeHash($Bytes)).Replace('-', '').ToLowerInvariant() }
    finally { $algorithm.Dispose() }
}
$documents = @()
foreach ($pin in $pins) {
    $bytes = [IO.File]::ReadAllBytes((Join-Path $sourceRoot $pin[0]))
    if ($bytes.Length -ne $pin[1] -or (Get-VectorDigest $bytes) -cne $pin[2]) { throw 'Vector authority pin differs.' }
    $documents += ([Text.UTF8Encoding]::new($false, $true).GetString($bytes) | ConvertFrom-Json)
}
$declarations = @{}
foreach ($declaration in $documents[2].types) { $declarations.Add($declaration.name, $declaration) }
$primitiveMaxima = $documents[1].primitiveValueMaxima
$domains = $documents[3].evidenceDomains

function Get-VectorProperty([object]$Value, [string]$Name, [object]$Fallback) {
    $property = $Value.PSObject.Properties[$Name]
    if ($null -eq $property) { return $Fallback }
    return $property.Value
}
function Write-VectorLength([IO.Stream]$Stream, [uint32]$Length) {
    $remaining = [long]$Length
    foreach ($divisor in @(16777216L, 65536L, 256L, 1L)) {
        $digit = [Math]::Floor($remaining / $divisor)
        $Stream.WriteByte([byte]$digit)
        $remaining = $remaining % $divisor
    }
}
function Write-VectorField([IO.Stream]$Stream, [int]$Tag, [byte[]]$Value) {
    $Stream.WriteByte([byte][Math]::Floor($Tag / 256))
    $Stream.WriteByte([byte]($Tag % 256))
    Write-VectorLength $Stream ([uint32]$Value.Length)
    $Stream.Write($Value, 0, $Value.Length)
}
function New-VectorPayload([object]$Declaration, [byte]$Profile) {
    $profileName = if ($Profile -eq 1) { 'InteractiveSeat' } else { 'NonInteractiveElevated' }
    $stream = [IO.MemoryStream]::new()
    try {
        foreach ($field in @($Declaration.fields | Sort-Object fieldId)) {
            $status = Get-VectorProperty $field 'status' 'Required'
            $scope = Get-VectorProperty $field 'profile' 'Any'
            if ($status -ne 'Required' -or ($scope -ne 'Any' -and $scope -ne $profileName)) { continue }
            if ($declarations.ContainsKey($field.type)) {
                $value = New-VectorPayload $declarations[$field.type] $Profile
            }
            elseif ($field.type -eq 'BoundedBytes') {
                $body = [byte[]]::new([int]$field.maxBytes)
                $bounded = [IO.MemoryStream]::new()
                try {
                    Write-VectorLength $bounded ([uint32]$body.Length)
                    $bounded.Write($body, 0, $body.Length)
                    $value = $bounded.ToArray()
                }
                finally { $bounded.Dispose() }
            }
            else {
                $width = [int]$primitiveMaxima.PSObject.Properties[$field.type].Value
                $value = [byte[]]::new($width)
                if ($field.type -eq 'AsciiIdentifier') {
                    for ($index = 0; $index -lt $value.Length; $index++) { $value[$index] = 88 }
                }
                elseif ($field.type -eq 'BinarySid') {
                    $value[0] = 1
                    $value[1] = 15
                    $value[7] = 5
                }
                elseif ($field.name -eq 'profile') { $value[0] = $Profile }
            }
            Write-VectorField $stream ([int]$field.fieldId) $value
        }
        return ,$stream.ToArray()
    }
    finally { $stream.Dispose() }
}
function Write-VectorBytes([string]$Path, [byte[]]$Bytes) {
    $stream = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $stream.Write($Bytes, 0, $Bytes.Length) }
    finally { $stream.Dispose() }
}
[void][IO.Directory]::CreateDirectory($destination)
$records = @()
foreach ($member in @($declarations.EvidenceArtifactKind.members | Sort-Object value)) {
    for ($profile = 1; $profile -le 2; $profile++) {
        $payload = New-VectorPayload $declarations[$member.name] ([byte]$profile)
        if ($payload.Length -gt 262143) { throw 'Vector evidence payload exceeds its cap.' }
        $domainBytes = [Text.Encoding]::ASCII.GetBytes($domains.PSObject.Properties[$member.name].Value)
        $digestInput = [byte[]]($domainBytes + @(0) + $payload)
        $digestHex = Get-VectorDigest $digestInput
        $digestBytes = [byte[]]::new(32)
        for ($index = 0; $index -lt 32; $index++) { $digestBytes[$index] = [Convert]::ToByte($digestHex.Substring($index * 2, 2), 16) }
        $bounded = [IO.MemoryStream]::new()
        $envelope = [IO.MemoryStream]::new()
        try {
            Write-VectorLength $bounded ([uint32]$payload.Length)
            $bounded.Write($payload, 0, $payload.Length)
            Write-VectorField $envelope 1 ([byte[]]@(0, [byte]$member.value))
            Write-VectorField $envelope 2 ([byte[]]::new(16))
            Write-VectorField $envelope 3 ([byte[]]@($profile))
            Write-VectorField $envelope 4 $bounded.ToArray()
            Write-VectorField $envelope 5 $digestBytes
            $bytes = $envelope.ToArray()
        }
        finally { $bounded.Dispose(); $envelope.Dispose() }
        $identifier = 'kind-{0:D2}-profile-{1}' -f [int]$member.value, $profile
        Write-VectorBytes (Join-Path $destination ($identifier + '.bin')) $bytes
        $records += [pscustomobject][ordered]@{
            id = $identifier
            file = $identifier + '.bin'
            kind = [int]$member.value
            profile = $profile
            payloadLength = $payload.Length
            length = $bytes.Length
            sha256 = Get-VectorDigest $bytes
        }
    }
}
$manifest = [pscustomobject][ordered]@{
    schemaId = 'PspktEvidenceRuntimeVectorsV1'
    schemaVersion = 1
    fixtures = $records
}
Write-VectorBytes (Join-Path $destination 'manifest.v1.json') (
    [Text.UTF8Encoding]::new($false, $true).GetBytes(($manifest | ConvertTo-Json -Depth 6 -Compress) + "`n"))
[pscustomobject]@{ OutputRoot = $destination; FixtureCount = $records.Count }
