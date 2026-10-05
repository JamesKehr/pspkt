[CmdletBinding()]
param(
    [ValidateSet('Generate','Validate','Compile')][string]$Mode = 'Validate',
    [string]$RepositoryRoot,
    [string]$OutputRoot,
    [switch]$Worker,
    [string]$AssemblyRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-PspktEvidenceLedgerPins {
    param([string]$RepositoryRoot, $Contract)

    foreach ($path in $Contract.Sha256ByPath.Keys) {
        $actual = (Get-FileHash -LiteralPath (Join-Path $RepositoryRoot $path.Replace('/', '\')) -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actual -cne $Contract.Sha256ByPath[$path]) {
            throw "Pinned evidence ledger hash differs: $path"
        }
    }
}

function Resolve-PspktEvidenceLedgerPath {
    param([string]$Path,[string]$ParameterName)

    if (-not $Path) { return $Path }
    if ($Path -match '^[\\/]{2}[?.][\\/]' -or $Path -match '^[A-Za-z]:(?![\\/])') {
        throw "$ParameterName is not a supported filesystem path."
    }
    $provider = $null
    $drive = $null
    try {
        $resolvedPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path,[ref]$provider,[ref]$drive)
    }
    catch { throw "$ParameterName could not be resolved: $($_.Exception.Message)" }
    if ($resolvedPath -match '^[\\/]{2}[?.][\\/]' -or $provider.Name -cne 'FileSystem') {
        throw "$ParameterName is not a supported filesystem path."
    }
    $isDrivePath = $resolvedPath -match '^[A-Za-z]:[\\/]'
    $isUncPath = $resolvedPath -match '^[\\/]{2}[^\\/]+[\\/][^\\/]+'
    if (-not $isDrivePath -and -not $isUncPath) { throw "$ParameterName must resolve to an absolute filesystem path." }
    $namePath = if ($isDrivePath) { $resolvedPath.Substring(2) } else { $resolvedPath.TrimStart([char[]]@('\','/')) }
    $invalidNameCharacters = [IO.Path]::GetInvalidFileNameChars()
    foreach ($component in $namePath.Split([char[]]@('\','/'),[StringSplitOptions]::RemoveEmptyEntries)) {
        if ($component.EndsWith(' ',[StringComparison]::Ordinal) -or $component.EndsWith('.',[StringComparison]::Ordinal)) {
            throw "$ParameterName contains a normalization-sensitive path component."
        }
        if ($component.IndexOfAny($invalidNameCharacters) -ge 0) { throw "$ParameterName contains an invalid filesystem path component." }
    }
    try { $fullPath = [IO.Path]::GetFullPath($resolvedPath) }
    catch { throw "$ParameterName could not be normalized: $($_.Exception.Message)" }
    if ($fullPath -match '^[\\/]{2}[?.][\\/]') { throw "$ParameterName is not a supported filesystem path." }
    $isDriveRoot = $fullPath -match '^[A-Za-z]:[\\/]+$'
    $normalizedPath = if ($isDriveRoot) { [IO.Path]::GetPathRoot($fullPath) } else { $fullPath.TrimEnd([char[]]@('\','/')) }
    $components = $normalizedPath.Split([char[]]@('\','/'),[StringSplitOptions]::RemoveEmptyEntries)
    $baseName = $components[$components.Length-1].TrimEnd([char[]]@(' ','.')).Split('.')[0].ToUpperInvariant()
    $reservedNames = @('CON','PRN','AUX','NUL','CLOCK$','CONIN$','CONOUT$')
    $reservedNames += 1..9 | ForEach-Object { 'COM' + $_; 'LPT' + $_ }
    foreach ($superscript in @([char]0x00B9,[char]0x00B2,[char]0x00B3)) {
        $reservedNames += 'COM' + $superscript
        $reservedNames += 'LPT' + $superscript
    }
    if ($reservedNames -ccontains $baseName) { throw "$ParameterName is not a supported filesystem path." }
    return $normalizedPath
}

function Write-PspktEvidenceLedgerFileAtomically {
    param([string]$Path,[byte[]]$Bytes,[scriptblock]$BeforeReplace)

    $temporaryPath = $Path + '.' + [Guid]::NewGuid().ToString('N') + '.tmp'
    try {
        $stream = [IO.FileStream]::new($temporaryPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        try {
            $stream.Write($Bytes,0,$Bytes.Length)
            $stream.Flush($true)
        }
        finally { $stream.Dispose() }
        if ($null -ne $BeforeReplace) { & $BeforeReplace $temporaryPath $Path }
        if ([IO.File]::Exists($Path)) { [IO.File]::Replace($temporaryPath,$Path,[NullString]::Value) }
        else { [IO.File]::Move($temporaryPath,$Path) }
    }
    finally {
        if ([IO.File]::Exists($temporaryPath)) { [IO.File]::Delete($temporaryPath) }
    }
}

if (-not $RepositoryRoot) { $RepositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\..')) }
$RepositoryRoot = Resolve-PspktEvidenceLedgerPath -Path $RepositoryRoot -ParameterName 'RepositoryRoot'
$OutputRoot = Resolve-PspktEvidenceLedgerPath -Path $OutputRoot -ParameterName 'OutputRoot'
$AssemblyRoot = Resolve-PspktEvidenceLedgerPath -Path $AssemblyRoot -ParameterName 'AssemblyRoot'
. (Join-Path $RepositoryRoot 'certification\evidence-ledger\lib\Pspkt.Certification.EvidenceLedgerContract.ps1')
$contract = Get-PspktEvidenceLedgerContract
Assert-PspktEvidenceLedgerPins -RepositoryRoot $RepositoryRoot -Contract $contract
if (-not $Worker) {
    if ($AssemblyRoot) { throw 'AssemblyRoot is valid only in worker mode.' }
    $scratch = Join-Path ([IO.Path]::GetTempPath()) ('pspkt-evidence-' + [Guid]::NewGuid().ToString('N'))
    [void][IO.Directory]::CreateDirectory($scratch)
    try {
        $hostName = if ($PSVersionTable.PSEdition -eq 'Desktop') { 'powershell.exe' } else { 'pwsh.exe' }
        $arguments = @('-NoProfile','-File',$PSCommandPath,'-Mode',$Mode,'-Worker','-RepositoryRoot',$RepositoryRoot,'-AssemblyRoot',$scratch)
        if ($OutputRoot) { $arguments += @('-OutputRoot',$OutputRoot) }
        & (Join-Path $PSHOME $hostName) @arguments
        if ($LASTEXITCODE -ne 0) { throw "Evidence ledger child failed with exit code $LASTEXITCODE." }
    }
    finally {
        if ([IO.Directory]::Exists($scratch)) { [IO.Directory]::Delete($scratch, $true) }
    }
    return
}
if (-not $AssemblyRoot -or -not [IO.Directory]::Exists($AssemblyRoot)) { throw 'A fresh assembly directory is required.' }
$env:TEMP = $AssemblyRoot
$env:TMP = $AssemblyRoot
$frameworkReferences = if ($PSVersionTable.PSEdition -eq 'Desktop') {
    @('System.dll','System.Core.dll','System.Xml.dll','System.Runtime.Serialization.dll','System.Numerics.dll')
} else {
    @(Get-ChildItem -LiteralPath (Join-Path $PSHOME 'ref') -Filter '*.dll' | ForEach-Object { $_.FullName })
}
$bootstrapAssembly = Join-Path $AssemblyRoot 'SchemaBootstrap.dll'
$verifierAssembly = Join-Path $AssemblyRoot 'EvidenceLedgerVerify.dll'
$authorityAssembly = Join-Path $AssemblyRoot 'EvidenceLedgerAuthority.dll'
foreach ($path in @($bootstrapAssembly,$verifierAssembly,$authorityAssembly)) {
    if ([IO.File]::Exists($path)) { throw "Assembly path is not fresh: $path" }
}
$libraryRoot = Join-Path $RepositoryRoot 'certification\evidence-ledger\lib'
Push-Location -LiteralPath $AssemblyRoot
try {
    Add-Type -LiteralPath (Join-Path $RepositoryRoot 'certification\lib\Pspkt.Certification.SchemaBootstrap.cs') -OutputAssembly ([IO.Path]::GetFileName($bootstrapAssembly)) -ReferencedAssemblies $frameworkReferences
    Add-Type -LiteralPath $bootstrapAssembly
    Add-Type -LiteralPath (Join-Path $libraryRoot 'Pspkt.Certification.EvidenceLedgerVerify.cs') -OutputAssembly ([IO.Path]::GetFileName($verifierAssembly)) -ReferencedAssemblies @($frameworkReferences + $bootstrapAssembly)
    Add-Type -LiteralPath $verifierAssembly
    Add-Type -LiteralPath (Join-Path $libraryRoot 'Pspkt.Certification.EvidenceLedgerAuthority.cs') -OutputAssembly ([IO.Path]::GetFileName($authorityAssembly)) -ReferencedAssemblies @($frameworkReferences + $bootstrapAssembly)
    Add-Type -LiteralPath $authorityAssembly
}
finally { Pop-Location }
if ($Mode -eq 'Compile') { return $contract }
if (-not $OutputRoot) {
    if ($Mode -eq 'Generate') { throw 'Generation requires an explicit output root.' }
    $OutputRoot = $RepositoryRoot
}
$pins = [Collections.Generic.Dictionary[string,string]]::new([StringComparer]::Ordinal)
foreach ($path in $contract.OutputPathSet) {
    $pins.Add([IO.Path]::GetFileName($path.Replace('/', '\')), $contract.Sha256ByPath[$path])
}
foreach ($path in @('certification/schema/protocol-schema.v1.json','certification/schema/protocol-inventory.v1.json',
    'certification/schema/protocol-schema-meta.v1.json','certification/evidence-ledger/schema/evidence-ledger-inventory.v1.json',
    'certification/evidence-ledger/README.md')) {
    $pins.Add([IO.Path]::GetFileName($path.Replace('/', '\')), $contract.Sha256ByPath[$path])
}
if ($Mode -eq 'Validate') {
    $outputs = [Collections.Generic.Dictionary[string,byte[]]]::new([StringComparer]::Ordinal)
    foreach ($path in $contract.OutputPathSet) {
        $relativePath = $path.Replace('/', '\')
        $outputs.Add([IO.Path]::GetFileName($relativePath), [IO.File]::ReadAllBytes((Join-Path $OutputRoot $relativePath)))
    }
} else {
    $outputs = [Pspkt.Certification.EvidenceLedger.EvidenceLedgerAuthority]::Generate(
        [IO.File]::ReadAllBytes((Join-Path $RepositoryRoot 'certification\schema\protocol-schema.v1.json')),
        [IO.File]::ReadAllBytes((Join-Path $RepositoryRoot 'certification\schema\protocol-inventory.v1.json')),
        [IO.File]::ReadAllBytes((Join-Path $RepositoryRoot 'certification\evidence-ledger\schema\evidence-ledger-inventory.v1.json')),
        [IO.File]::ReadAllBytes((Join-Path $RepositoryRoot 'certification\schema\protocol-schema-meta.v1.json')),
        [IO.File]::ReadAllBytes((Join-Path $RepositoryRoot 'certification\evidence-ledger\README.md')))
}
[Pspkt.Certification.EvidenceLedger.EvidenceLedgerVerify]::Verify(
    [IO.File]::ReadAllBytes((Join-Path $RepositoryRoot 'certification\schema\protocol-schema.v1.json')),
    [IO.File]::ReadAllBytes((Join-Path $RepositoryRoot 'certification\schema\protocol-inventory.v1.json')),
    [IO.File]::ReadAllBytes((Join-Path $RepositoryRoot 'certification\evidence-ledger\schema\evidence-ledger-inventory.v1.json')),
    [IO.File]::ReadAllBytes((Join-Path $RepositoryRoot 'certification\schema\protocol-schema-meta.v1.json')),
    $outputs, $pins,
    [Pspkt.Certification.SchemaBootstrap].Assembly.GetName().FullName,
    [Pspkt.Certification.EvidenceLedger.EvidenceLedgerAuthority].Assembly.GetName().FullName,
    [IO.File]::ReadAllBytes((Join-Path $RepositoryRoot 'certification\evidence-ledger\README.md')))
if ($Mode -eq 'Generate') {
    $destination = Join-Path $OutputRoot 'certification\evidence-ledger\schema'
    [void][IO.Directory]::CreateDirectory($destination)
    foreach ($path in $contract.OutputPathSet) {
        $name = [IO.Path]::GetFileName($path.Replace('/','\'))
        Write-PspktEvidenceLedgerFileAtomically -Path (Join-Path $destination $name) -Bytes $outputs[$name]
    }
}
