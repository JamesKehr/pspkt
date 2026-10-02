[CmdletBinding()]
param(
    [string]$OutputRoot
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

if (-not $OutputRoot) { $OutputRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..')) }
$OutputRoot = Resolve-PspktProtocolPath -Path $OutputRoot -ParameterName 'OutputRoot'
$validator = Join-Path $PSScriptRoot '..\validators\Invoke-PspktPhase4ProtocolSchemaAuthorityValidators.ps1'
$hostName = if ($PSVersionTable.PSEdition -eq 'Desktop') { 'powershell.exe' } else { 'pwsh.exe' }
& (Join-Path $PSHOME $hostName) -NoLogo -NoProfile -File $validator -OutputRoot $OutputRoot -Mode Generate
if ($LASTEXITCODE -ne 0) { throw "Protocol generation failed with exit code $LASTEXITCODE." }
