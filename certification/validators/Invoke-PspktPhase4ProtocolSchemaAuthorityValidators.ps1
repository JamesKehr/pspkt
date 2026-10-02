[CmdletBinding()]
param(
    [ValidateSet('Filter','Generate','Validate','Compile')]
    [string]$Mode = 'Validate',
    [string]$RepositoryRoot,
    [string]$BaseCatalogPath,
    [string]$OverlayCatalogPath,
    [string]$OutputRoot,
    [switch]$Worker,
    [string]$AssemblyRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Resolve-PspktProtocolPath {
    param(
        [string]$Path,
        [string]$ParameterName
    )

    if (-not $Path) { return $Path }
    if ($Path -match '^[\\/]{2}[?.][\\/]' -or $Path -match '^[A-Za-z]:(?![\\/])') {
        throw "$ParameterName is not a supported filesystem path."
    }

    $provider = $null
    $drive = $null
    try {
        $resolvedPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath(
            $Path, [ref]$provider, [ref]$drive)
    }
    catch {
        throw "$ParameterName could not be resolved: $($_.Exception.Message)"
    }
    if ($resolvedPath -match '^[\\/]{2}[?.][\\/]' -or $provider.Name -cne 'FileSystem') {
        throw "$ParameterName is not a supported filesystem path."
    }
    $isDrivePath = $resolvedPath -match '^[A-Za-z]:[\\/]'
    $isUncPath = $resolvedPath -match '^[\\/]{2}[^\\/]+[\\/][^\\/]+'
    if (-not $isDrivePath -and -not $isUncPath) {
        throw "$ParameterName must resolve to an absolute filesystem path."
    }

    $namePath = if ($isDrivePath) { $resolvedPath.Substring(2) } else { $resolvedPath.TrimStart([char[]]@('\','/')) }
    $invalidNameCharacters = [IO.Path]::GetInvalidFileNameChars()
    foreach ($component in $namePath.Split([char[]]@('\','/'), [StringSplitOptions]::RemoveEmptyEntries)) {
        if ($component.EndsWith(' ', [StringComparison]::Ordinal) -or
            $component.EndsWith('.', [StringComparison]::Ordinal)) {
            throw "$ParameterName contains a normalization-sensitive path component."
        }
        if ($component.IndexOfAny($invalidNameCharacters) -ge 0) {
            throw "$ParameterName contains an invalid filesystem path component."
        }
    }

    try { $fullPath = [IO.Path]::GetFullPath($resolvedPath) }
    catch { throw "$ParameterName could not be normalized: $($_.Exception.Message)" }
    if ($fullPath -match '^[\\/]{2}[?.][\\/]') {
        throw "$ParameterName is not a supported filesystem path."
    }
    $isDriveRoot = $fullPath -match '^[A-Za-z]:[\\/]+$'
    $normalizedPath = if ($isDriveRoot) { [IO.Path]::GetPathRoot($fullPath) } else { $fullPath.TrimEnd([char[]]@('\','/')) }
    $pathComponents = $normalizedPath.Split([char[]]@('\','/'), [StringSplitOptions]::RemoveEmptyEntries)
    $baseName = $pathComponents[$pathComponents.Length - 1].TrimEnd([char[]]@(' ','.')).Split('.')[0].ToUpperInvariant()
    $reservedNames = @('CON','PRN','AUX','NUL','CLOCK$','CONIN$','CONOUT$')
    $reservedNames += 1..9 | ForEach-Object { 'COM' + $_; 'LPT' + $_ }
    foreach ($superscript in @([char]0x00B9,[char]0x00B2,[char]0x00B3)) {
        $reservedNames += 'COM' + $superscript
        $reservedNames += 'LPT' + $superscript
    }
    if ($reservedNames -ccontains $baseName) {
        throw "$ParameterName is not a supported filesystem path."
    }
    return $normalizedPath
}

function Write-PspktProtocolFileAtomically {
    param(
        [string]$Path,
        [byte[]]$Bytes
    )

    $temporaryPath = $Path + '.' + [Guid]::NewGuid().ToString('N') + '.tmp'
    try {
        $stream = [IO.FileStream]::new(
            $temporaryPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try {
            $stream.Write($Bytes, 0, $Bytes.Length)
            $stream.Flush($true)
        }
        finally {
            $stream.Dispose()
        }
        if ([IO.File]::Exists($Path)) { [IO.File]::Replace($temporaryPath, $Path, [NullString]::Value) }
        else { [IO.File]::Move($temporaryPath, $Path) }
    }
    finally {
        if ([IO.File]::Exists($temporaryPath)) { [IO.File]::Delete($temporaryPath) }
    }
}

if (-not $RepositoryRoot) { $RepositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..')) }
$RepositoryRoot = Resolve-PspktProtocolPath -Path $RepositoryRoot -ParameterName 'RepositoryRoot'
$BaseCatalogPath = Resolve-PspktProtocolPath -Path $BaseCatalogPath -ParameterName 'BaseCatalogPath'
$OverlayCatalogPath = Resolve-PspktProtocolPath -Path $OverlayCatalogPath -ParameterName 'OverlayCatalogPath'
$OutputRoot = Resolve-PspktProtocolPath -Path $OutputRoot -ParameterName 'OutputRoot'
$AssemblyRoot = Resolve-PspktProtocolPath -Path $AssemblyRoot -ParameterName 'AssemblyRoot'

if (-not $Worker) {
    if ($AssemblyRoot) { throw 'AssemblyRoot is valid only in worker mode.' }
    $scratch = Join-Path ([IO.Path]::GetTempPath()) ('pp-' + [Guid]::NewGuid().ToString('N'))
    [void][IO.Directory]::CreateDirectory($scratch)
    try {
        $hostName = if ($PSVersionTable.PSEdition -eq 'Desktop') { 'powershell.exe' } else { 'pwsh.exe' }
        $arguments = @('-NoLogo','-NoProfile','-File',$PSCommandPath,'-Worker','-Mode',$Mode,'-RepositoryRoot',$RepositoryRoot,'-AssemblyRoot',$scratch)
        if ($BaseCatalogPath) { $arguments += @('-BaseCatalogPath',$BaseCatalogPath) }
        if ($OverlayCatalogPath) { $arguments += @('-OverlayCatalogPath',$OverlayCatalogPath) }
        if ($OutputRoot) { $arguments += @('-OutputRoot',$OutputRoot) }
        & (Join-Path $PSHOME $hostName) @arguments
        if ($LASTEXITCODE -ne 0) { throw "Protocol authority child failed with exit code $LASTEXITCODE." }
    }
    finally {
        if ([IO.Directory]::Exists($scratch)) { [IO.Directory]::Delete($scratch, $true) }
    }
    return
}

if (-not $AssemblyRoot -or -not [IO.Directory]::Exists($AssemblyRoot)) { throw 'A fresh assembly directory is required.' }
$env:TEMP = $AssemblyRoot
$env:TMP = $AssemblyRoot
$libraryRoot = Join-Path $RepositoryRoot 'certification\lib'
. (Join-Path $libraryRoot 'Pspkt.Certification.ProtocolSchemaContract.ps1')
$contract = Get-PspktProtocolSchemaContract
foreach ($path in $contract.FrozenSha256ByPath.Keys) {
    $actual = (Get-FileHash -LiteralPath (Join-Path $RepositoryRoot $path.Replace('/', '\')) -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -cne $contract.FrozenSha256ByPath[$path]) { throw "Pinned frozen source hash differs: $path" }
}
foreach ($path in $contract.AttributeSha256ByPath.Keys) {
    $actual = (Get-FileHash -LiteralPath (Join-Path $RepositoryRoot $path.Replace('/', '\')) -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -cne $contract.AttributeSha256ByPath[$path]) { throw "Pinned attribute hash differs: $path" }
}
$schemaAssembly = Join-Path $AssemblyRoot 'SchemaBootstrap.dll'
$engineAssembly = Join-Path $AssemblyRoot 'FoundationEngine.dll'
$authorityAssembly = Join-Path $AssemblyRoot 'ProtocolAuthority.dll'
$verifyAssembly = Join-Path $AssemblyRoot 'ProtocolVerify.dll'
foreach ($assemblyPath in @($schemaAssembly,$engineAssembly,$authorityAssembly,$verifyAssembly)) {
    if ([IO.File]::Exists($assemblyPath)) { throw "Assembly path is not fresh: $assemblyPath" }
}
$frameworkReferences = if ($PSVersionTable.PSEdition -eq 'Desktop') {
    @('System.dll','System.Core.dll','System.Xml.dll','System.Runtime.Serialization.dll')
}
else {
    @(Get-ChildItem -LiteralPath (Join-Path $PSHOME 'ref') -Filter '*.dll' | ForEach-Object { $_.FullName })
}
Add-Type -Path (Join-Path $libraryRoot 'Pspkt.Certification.SchemaBootstrap.cs') -OutputAssembly $schemaAssembly -ReferencedAssemblies $frameworkReferences
Add-Type -Path $schemaAssembly
Add-Type -Path (Join-Path $libraryRoot 'Pspkt.Certification.ProtocolSchemaVerify.cs') -OutputAssembly $verifyAssembly -ReferencedAssemblies @($frameworkReferences + $schemaAssembly)
Add-Type -Path $verifyAssembly
Add-Type -Path @(
    (Join-Path $libraryRoot 'Pspkt.Certification.FoundationCatalogEngine.cs'),
    (Join-Path $libraryRoot 'Pspkt.Certification.FoundationPolicy.cs')) -OutputAssembly $engineAssembly -ReferencedAssemblies @($frameworkReferences + $schemaAssembly)
Add-Type -Path $engineAssembly
Add-Type -Path (Join-Path $libraryRoot 'Pspkt.Certification.ProtocolSchemaAuthority.cs') -OutputAssembly $authorityAssembly -ReferencedAssemblies @($frameworkReferences + $schemaAssembly + $engineAssembly)
Add-Type -Path $authorityAssembly
$bootstrapAssemblyIdentity = [Pspkt.Certification.SchemaBootstrap].Assembly.GetName().FullName
$forbiddenAssemblyNames = [string[]]@(
    [Pspkt.Certification.FoundationEngine.ProtocolCatalogEngineV2].Assembly.GetName().Name,
    [Pspkt.Certification.Protocol.ProtocolSchemaAuthority].Assembly.GetName().Name)
if (-not $BaseCatalogPath) { $BaseCatalogPath = Join-Path $RepositoryRoot 'certification\schema\catalog\protocol-base.catalog.v1.json' }
if (-not $OverlayCatalogPath) { $OverlayCatalogPath = Join-Path $RepositoryRoot 'certification\schema\catalog\overlay.catalog.v1.json' }
if ($Mode -eq 'Filter') {
    $projection = [Pspkt.Certification.Protocol.ProtocolSchemaAuthority]::Filter(
        [IO.File]::ReadAllBytes($BaseCatalogPath),
        [IO.File]::ReadAllBytes($OverlayCatalogPath),
        $contract.DeferredSeedTypeNames,
        $contract.DeferredSeedMessageKeys)
    [Text.Encoding]::UTF8.GetString($projection)
    return
}

if (-not $OutputRoot) {
    if ($Mode -eq 'Generate') { throw 'Generation requires an explicit output root.' }
    $OutputRoot = $RepositoryRoot
}
$pins = [Collections.Generic.Dictionary[string,string]]::new([StringComparer]::Ordinal)
foreach ($path in $contract.InputSha256ByPath.Keys) {
    $pins.Add([IO.Path]::GetFileName($path.Replace('/', '\')), $contract.InputSha256ByPath[$path])
}
foreach ($path in $contract.OutputSha256ByPath.Keys) {
    $pins.Add([IO.Path]::GetFileName($path.Replace('/', '\')), $contract.OutputSha256ByPath[$path])
}
foreach ($name in $contract.FilteredSha256ByName.Keys) { $pins.Add($name, $contract.FilteredSha256ByName[$name]) }
foreach ($name in $contract.SourceSha256ByPath.Keys) { $pins.Add($name, $contract.SourceSha256ByPath[$name]) }
foreach ($name in $contract.UnionMappingSha256ByName.Keys) { $pins.Add($name, $contract.UnionMappingSha256ByName[$name]) }
$baseBytes = [IO.File]::ReadAllBytes($BaseCatalogPath)
$overlayBytes = [IO.File]::ReadAllBytes($OverlayCatalogPath)
$inventoryBytes = [IO.File]::ReadAllBytes((Join-Path $RepositoryRoot 'certification\schema\protocol-inventory.v1.json'))
$metaBytes = [IO.File]::ReadAllBytes((Join-Path $RepositoryRoot 'certification\schema\protocol-schema-meta.v1.json'))
$snapshots = [ordered]@{
    'protocol-base.catalog.v1.json' = $baseBytes
    'overlay.catalog.v1.json' = $overlayBytes
    'protocol-inventory.v1.json' = $inventoryBytes
}
$hash = [Security.Cryptography.SHA256]::Create()
try {
    foreach ($name in $snapshots.Keys) {
        $actual = [BitConverter]::ToString($hash.ComputeHash($snapshots[$name])).Replace('-', '').ToLowerInvariant()
        if ($actual -cne $pins[$name]) { throw "Pinned input hash differs: $name" }
    }
}
finally {
    $hash.Dispose()
}
if ($Mode -eq 'Validate') {
    $outputs = [Collections.Generic.Dictionary[string,byte[]]]::new([StringComparer]::Ordinal)
    foreach ($path in $contract.OutputPathSet) {
        $relativePath = $path.Replace('/', '\')
        $outputs.Add([IO.Path]::GetFileName($relativePath), [IO.File]::ReadAllBytes((Join-Path $OutputRoot $relativePath)))
    }
    [Pspkt.Certification.Protocol.ProtocolSchemaVerify]::Verify(
        $baseBytes, $overlayBytes, $inventoryBytes, $metaBytes, $outputs, $pins, $contract.LiteralExtensionParentNames,
        $bootstrapAssemblyIdentity, $forbiddenAssemblyNames)
    'Verified 107 types, 681 map rows, 31 associations, 842 schedule rows; verifier assembly is engine-free.'
    return
}
$messageEnums = [Collections.Generic.Dictionary[string,string]]::new([StringComparer]::Ordinal)
$directions = [Collections.Generic.Dictionary[string,string[]]]::new([StringComparer]::Ordinal)
$kindRanges = [Collections.Generic.Dictionary[string,Pspkt.Certification.FoundationEngine.GeneratedIdRange[]]]::new([StringComparer]::Ordinal)
foreach ($channel in $contract.Channels) {
    $messageEnums.Add($channel, $contract.MessageEnumNameByChannel[$channel])
    $directions.Add($channel, $contract.PermittedDirectionsByChannel[$channel])
    $ranges = @($contract.OverlayKindRangesByChannel[$channel] | ForEach-Object {
        [Pspkt.Certification.FoundationEngine.GeneratedIdRange]::new($_.Start, $_.End)
    })
    $kindRanges.Add($channel, [Pspkt.Certification.FoundationEngine.GeneratedIdRange[]]$ranges)
}
$catalogContract = [Pspkt.Certification.FoundationEngine.ProtocolCatalogContractV2]::new(
    $contract.NamePredicate, $contract.BaseCatalogSchemaId, $contract.BaseCatalogSpace,
    $contract.OverlayCatalogSchemaId, $contract.OverlayCatalogSpace, $contract.EmitSchemaId, $contract.MapSchemaId,
    $contract.Channels, $messageEnums, $directions, $kindRanges,
    [Pspkt.Certification.FoundationEngine.GeneratedIdRange]::new($contract.OverlayTypeRange.Start, $contract.OverlayTypeRange.End),
    $contract.GeneratedFieldIdMax, $contract.LiteralExtensionParentNames)
if ($Mode -eq 'Compile') { return $catalogContract }
$outputs = [Pspkt.Certification.Protocol.ProtocolSchemaAuthority]::Generate(
    $baseBytes, $overlayBytes, $inventoryBytes, $metaBytes, $catalogContract)
[Pspkt.Certification.Protocol.ProtocolSchemaVerify]::Verify(
    $baseBytes, $overlayBytes, $inventoryBytes, $metaBytes, $outputs, $pins, $contract.LiteralExtensionParentNames,
    $bootstrapAssemblyIdentity, $forbiddenAssemblyNames)
$destination = Join-Path $OutputRoot 'certification\schema'
[void][IO.Directory]::CreateDirectory($destination)
foreach ($name in $outputs.Keys) {
    Write-PspktProtocolFileAtomically -Path (Join-Path $destination $name) -Bytes $outputs[$name]
}
