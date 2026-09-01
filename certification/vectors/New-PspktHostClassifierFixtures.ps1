[CmdletBinding()]
param(
    [Parameter(DontShow = $true)]
    [ValidateRange(-1, 11)]
    [int]$SimulateFailureAfterRepairCount = -1
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:PspktParityPrefix = 'host-classifier-vector-parity: '
$script:PspktNativeNamespaceDeclaration = 'namespace Pspkt.Certification'
$script:PspktNativeTypeLeafName = 'HostClassifierVectorNativeV1'
$script:PspktNativeHelperType = $null
$script:PspktNativeBuildMarker = 'pspkt-host-classifier-vector-native-5'
$script:PspktNativeTypeVersion = '1'
$script:PspktNativeSourceLength = 22637
$script:PspktNativeSourceSha256 = '666e71c53ed6572db5d7b1c7e21bae3a938fea045bc03bf22e8e84ac9a6439be'
$script:PspktCanonicalSourceLength = 8689
$script:PspktCanonicalSourceSha256 = '414975df1d4b5d04d9b72a95fcaad7e8fc922b17ee0e969da856c463fc3718c3'
$script:PspktMathSourceLength = 6746
$script:PspktMathSourceSha256 = '8d9403b8436eb92cc0646cdb82d4924dcd648a9b69eb150225b4fc0be52f1bb8'
$script:PspktClassifierSourceLength = 7294
$script:PspktClassifierSourceSha256 = 'fdc9cd70a504c3591e3afb81e2fe1b4a287868f2af28dc126bf0f7220909474e'

$script:PspktExpectedRelativePaths = @(
    'host-classifier/negative-ambiguous-ancestry.json',
    'host-classifier/negative-missing-window.json',
    'host-classifier/negative-openconsole.json',
    'host-classifier/negative-spoofed-environment.json',
    'host-classifier/negative-stale-wt-session.json',
    'host-classifier/seat-conhost-powershell-7.json',
    'host-classifier/seat-conhost-windows-powershell-5.1.json',
    'host-classifier/seat-windows-terminal-powershell-7.json',
    'host-classifier/seat-windows-terminal-windows-powershell-5.1.json',
    'certification-result/sample-artifact.v1.json',
    'certification-result/sample-attestation.v1.json'
)

$script:PspktHostClassifierNames = @(
    'negative-ambiguous-ancestry.json',
    'negative-missing-window.json',
    'negative-openconsole.json',
    'negative-spoofed-environment.json',
    'negative-stale-wt-session.json',
    'seat-conhost-powershell-7.json',
    'seat-conhost-windows-powershell-5.1.json',
    'seat-windows-terminal-powershell-7.json',
    'seat-windows-terminal-windows-powershell-5.1.json'
)

$script:PspktFrozenOracle = @{
    'host-classifier/negative-ambiguous-ancestry.json' = @{ Length = 648; Sha256 = '4c98d09f60c3824964205018577ef3e8d7e1ca1ee5e0577d6b50acebaa846b56' }
    'host-classifier/negative-missing-window.json' = @{ Length = 540; Sha256 = '5fdcdc70449ad85aab60d0932eaf892c55109b03bf5a4d9fd84e77bf3bc82d4f' }
    'host-classifier/negative-openconsole.json' = @{ Length = 649; Sha256 = '92b0993d613ad673a61d4e3e679c8c66993e4a3a47bd7ea71f1fc21e91a95568' }
    'host-classifier/negative-spoofed-environment.json' = @{ Length = 608; Sha256 = 'd04061c4a44a6997329e122c285ac1d9b0f69ce5913aa8790b533b614cf9fffc' }
    'host-classifier/negative-stale-wt-session.json' = @{ Length = 662; Sha256 = 'f1e940dff9b0a3c24012789db6039411c9d916d45e106a7901393c5ff274700d' }
    'host-classifier/seat-conhost-powershell-7.json' = @{ Length = 696; Sha256 = '569f7f1a5c47d7314ed54c7a636962eeeb3b858d95d6fd4709c1b14bd0b9b288' }
    'host-classifier/seat-conhost-windows-powershell-5.1.json' = @{ Length = 638; Sha256 = '6b08dc8782e278233b5dfc48ccc580c06d585e1a51288a7256376f62e7108660' }
    'host-classifier/seat-windows-terminal-powershell-7.json' = @{ Length = 730; Sha256 = '6e906074e737805eb34f5a3094f6d8e188b6cfb9d620291f836746d684d95c14' }
    'host-classifier/seat-windows-terminal-windows-powershell-5.1.json' = @{ Length = 722; Sha256 = 'cdc1b866c5c55cf76dbf0a55fb2f6ff86346d1dc9224147b719bc8d1d00dc3af' }
    'certification-result/sample-artifact.v1.json' = @{ Length = 10124; Sha256 = '9eb691fd0411acf2a029630f0a2ef7ba82dfa5083527d3b5453b708cce3a7f2d' }
    'certification-result/sample-attestation.v1.json' = @{ Length = 629; Sha256 = 'ad6b01e3261c5a19e26a840893be93c10a355fa1a993ad248bd02ad4a0411fc0' }
}

function Throw-PspktParity {
    param([Parameter(Mandatory = $true)][string]$Message)
    throw ($script:PspktParityPrefix + $Message)
}

function Get-PspktSha256HexLocal {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hash = $sha.ComputeHash($Bytes)
    }
    finally {
        $sha.Dispose()
    }
    $builder = [System.Text.StringBuilder]::new($hash.Length * 2)
    foreach ($b in $hash) {
        [void]$builder.Append(('{0:x2}' -f [int]$b))
    }
    return $builder.ToString()
}

function Test-PspktBytesEqual {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Left,
        [Parameter(Mandatory = $true)][byte[]]$Right
    )
    if ($Left.Length -ne $Right.Length) {
        return $false
    }
    for ($index = 0; $index -lt $Left.Length; $index++) {
        if ($Left[$index] -ne $Right[$index]) {
            return $false
        }
    }
    return $true
}

function Test-PspktStringArrayEqual {
    param($Left, $Right)
    if ($null -eq $Left -and $null -eq $Right) {
        return $true
    }
    if ($null -eq $Left -or $null -eq $Right) {
        return $false
    }
    $leftItems = @($Left)
    $rightItems = @($Right)
    if ($leftItems.Count -ne $rightItems.Count) {
        return $false
    }
    for ($index = 0; $index -lt $leftItems.Count; $index++) {
        if ([string]$leftItems[$index] -cne [string]$rightItems[$index]) {
            return $false
        }
    }
    return $true
}

function Get-PspktBclFullPath {
    param([Parameter(Mandatory = $true)][string]$Path)
    if ([string]::IsNullOrEmpty($Path) -or $Path.IndexOfAny([System.IO.Path]::GetInvalidPathChars()) -ge 0) {
        Throw-PspktParity ('path is empty or contains invalid characters: {0}' -f $Path)
    }
    return [System.IO.Path]::GetFullPath($Path)
}

function Test-PspktPathContained {
    param(
        [Parameter(Mandatory = $true)][string]$Parent,
        [Parameter(Mandatory = $true)][string]$Child
    )
    $prefix = $Parent.TrimEnd([char[]]@('\', '/')) + [System.IO.Path]::DirectorySeparatorChar
    return $Child.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)
}

function Assert-PspktOrdinaryDirectory {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Parent
    )
    $sameRoot = $Path.Equals($Parent, [System.StringComparison]::OrdinalIgnoreCase)
    if (-not $sameRoot -and -not (Test-PspktPathContained -Parent $Parent -Child $Path)) {
        Throw-PspktParity ('directory escapes certification root: {0}' -f $Path)
    }
    if (-not [System.IO.Directory]::Exists($Path)) {
        Throw-PspktParity ('directory missing: {0}' -f $Path)
    }
    $attributes = [System.IO.File]::GetAttributes($Path)
    if (($attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        Throw-PspktParity ('reparse point rejected for ''{0}''' -f $Path)
    }
    if (($attributes -band [System.IO.FileAttributes]::Directory) -eq 0) {
        Throw-PspktParity ('not a directory: {0}' -f $Path)
    }
}

function Assert-PspktOrdinaryFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Parent
    )
    if (-not (Test-PspktPathContained -Parent $Parent -Child $Path)) {
        Throw-PspktParity ('file escapes certification root: {0}' -f $Path)
    }
    if (-not [System.IO.File]::Exists($Path)) {
        Throw-PspktParity ('file missing: {0}' -f $Path)
    }
    $attributes = [System.IO.File]::GetAttributes($Path)
    if (($attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        Throw-PspktParity ('reparse point rejected for ''{0}''' -f $Path)
    }
    if (($attributes -band [System.IO.FileAttributes]::Directory) -ne 0) {
        Throw-PspktParity ('not an ordinary file: {0}' -f $Path)
    }
}

function Assert-PspktGeneratedRelativePath {
    param([Parameter(Mandatory = $true)][string]$Path)
    if ([string]::IsNullOrEmpty($Path)) {
        Throw-PspktParity 'generated path is empty'
    }
    if ([System.IO.Path]::IsPathRooted($Path)) {
        Throw-PspktParity ('rooted path rejected: {0}' -f $Path)
    }
    if ($Path.Contains('\')) {
        Throw-PspktParity ('backslash rejected: {0}' -f $Path)
    }
    $segments = $Path.Split([char]'/')
    if ($segments.Count -lt 1) {
        Throw-PspktParity ('invalid generated path: {0}' -f $Path)
    }
    foreach ($segment in $segments) {
        if ([string]::IsNullOrEmpty($segment) -or $segment -ceq '.' -or $segment -ceq '..') {
            Throw-PspktParity ('path segment .{0}. rejected in {1}' -f $segment, $Path)
        }
    }
}

function Assert-PspktNativePublicSurface {
    param([Parameter(Mandatory = $true)][type]$HelperType)
    $versionProperty = $HelperType.GetProperty('TypeVersion', [System.Reflection.BindingFlags]'Public,Static')
    if ($null -eq $versionProperty) {
        Throw-PspktParity 'native helper conflict: public API mismatch (missing TypeVersion)'
    }
    $version = $versionProperty.GetValue($null, $null)
    if ([string]$version -cne $script:PspktNativeTypeVersion) {
        Throw-PspktParity ('native helper conflict: type version ''{0}'' (expected ''{1}'')' -f $version, $script:PspktNativeTypeVersion)
    }
    $markerProperty = $HelperType.GetProperty('BuildMarker', [System.Reflection.BindingFlags]'Public,Static')
    if ($null -eq $markerProperty) {
        Throw-PspktParity 'native helper conflict: public API mismatch (missing BuildMarker)'
    }
    $marker = $markerProperty.GetValue($null, $null)
    if ([string]$marker -cne $script:PspktNativeBuildMarker) {
        Throw-PspktParity 'native helper conflict: build marker mismatch'
    }
    $declaredMethods = @($HelperType.GetMethods([System.Reflection.BindingFlags]'Public,Static,Instance,DeclaredOnly') | ForEach-Object { $_.Name })
    $declaredProperties = @($HelperType.GetProperties([System.Reflection.BindingFlags]'Public,Static,Instance,DeclaredOnly') | ForEach-Object { $_.Name })
    $requiredMethods = @('CreateProcessJob', 'OpenDirectory', 'OpenFile', 'ReadStreamCappedAsync', 'ReadExact', 'ReplaceExact', 'Dispose')
    $requiredProperties = @('BuildMarker', 'TypeVersion', 'IsReparsePoint', 'VolumeSerialNumber', 'FileIndex', 'NumberOfLinks', 'Length')
    foreach ($requiredMethod in $requiredMethods) {
        $found = $false
        foreach ($declaredMethod in $declaredMethods) {
            if ($declaredMethod -ceq $requiredMethod) { $found = $true; break }
        }
        if (-not $found) {
            Throw-PspktParity ('native helper conflict: public API mismatch (missing {0})' -f $requiredMethod)
        }
    }
    foreach ($requiredProperty in $requiredProperties) {
        $found = $false
        foreach ($declaredProperty in $declaredProperties) {
            if ($declaredProperty -ceq $requiredProperty) { $found = $true; break }
        }
        if (-not $found) {
            Throw-PspktParity ('native helper conflict: public API mismatch (missing {0})' -f $requiredProperty)
        }
    }
    $allowedGetters = @()
    foreach ($requiredProperty in $requiredProperties) {
        $allowedGetters += ,('get_' + $requiredProperty)
    }
    foreach ($methodName in $declaredMethods) {
        $allowed = $false
        foreach ($requiredMethod in $requiredMethods) {
            if ($methodName -ceq $requiredMethod) { $allowed = $true; break }
        }
        if (-not $allowed) {
            foreach ($getterName in $allowedGetters) {
                if ($methodName -ceq $getterName) { $allowed = $true; break }
            }
        }
        if (-not $allowed) {
            Throw-PspktParity ('native helper conflict: public API mismatch (unexpected {0})' -f $methodName)
        }
    }
    foreach ($propertyName in $declaredProperties) {
        $allowed = $false
        foreach ($requiredProperty in $requiredProperties) {
            if ($propertyName -ceq $requiredProperty) { $allowed = $true; break }
        }
        if (-not $allowed) {
            Throw-PspktParity ('native helper conflict: public API mismatch (unexpected {0})' -f $propertyName)
        }
    }
    $processJobType = $HelperType.GetNestedType('ProcessJobV1', [System.Reflection.BindingFlags]'Public')
    if ($null -eq $processJobType) {
        Throw-PspktParity 'native helper conflict: public API mismatch (missing ProcessJobV1)'
    }
    $publicNestedTypes = @($HelperType.GetNestedTypes([System.Reflection.BindingFlags]'Public'))
    if ($publicNestedTypes.Count -ne 1 -or $publicNestedTypes[0] -ne $processJobType) {
        Throw-PspktParity 'native helper conflict: public API mismatch (unexpected public nested type)'
    }
    $methodSpecs = @(
        @{ Name = 'CreateProcessJob'; Static = $true; ReturnType = $processJobType; ParameterTypes = @() },
        @{ Name = 'OpenDirectory'; Static = $true; ReturnType = $HelperType; ParameterTypes = @([string]) },
        @{ Name = 'OpenFile'; Static = $true; ReturnType = $HelperType; ParameterTypes = @([string], [bool]) },
        @{ Name = 'ReadStreamCappedAsync'; Static = $true; ReturnType = [System.Threading.Tasks.Task[byte[]]]; ParameterTypes = @([System.IO.Stream], [int]) },
        @{ Name = 'ReadExact'; Static = $false; ReturnType = [byte[]]; ParameterTypes = @() },
        @{ Name = 'ReplaceExact'; Static = $false; ReturnType = [byte[]]; ParameterTypes = @([byte[]]) },
        @{ Name = 'Dispose'; Static = $false; ReturnType = [void]; ParameterTypes = @() }
    )
    $methodInfos = @($HelperType.GetMethods([System.Reflection.BindingFlags]'Public,Static,Instance,DeclaredOnly'))
    foreach ($methodSpec in $methodSpecs) {
        $matches = @($methodInfos | Where-Object { $_.Name -ceq $methodSpec.Name })
        if ($matches.Count -ne 1) {
            Throw-PspktParity ('native helper conflict: public API mismatch (method {0} count={1})' -f $methodSpec.Name, $matches.Count)
        }
        $method = $matches[0]
        if ($method.IsStatic -ne [bool]$methodSpec.Static -or $method.ReturnType -ne $methodSpec.ReturnType) {
            Throw-PspktParity ('native helper conflict: public API mismatch (method {0} signature)' -f $methodSpec.Name)
        }
        $parameters = @($method.GetParameters())
        $expectedParameters = @($methodSpec.ParameterTypes)
        if ($parameters.Count -ne $expectedParameters.Count) {
            Throw-PspktParity ('native helper conflict: public API mismatch (method {0} parameters)' -f $methodSpec.Name)
        }
        for ($parameterIndex = 0; $parameterIndex -lt $parameters.Count; $parameterIndex++) {
            if ($parameters[$parameterIndex].ParameterType -ne $expectedParameters[$parameterIndex]) {
                Throw-PspktParity ('native helper conflict: public API mismatch (method {0} parameter {1})' -f $methodSpec.Name, $parameterIndex)
            }
        }
    }
    $propertySpecs = @(
        @{ Name = 'BuildMarker'; Static = $true; PropertyType = [string] },
        @{ Name = 'TypeVersion'; Static = $true; PropertyType = [string] },
        @{ Name = 'IsReparsePoint'; Static = $false; PropertyType = [bool] },
        @{ Name = 'VolumeSerialNumber'; Static = $false; PropertyType = [uint32] },
        @{ Name = 'FileIndex'; Static = $false; PropertyType = [uint64] },
        @{ Name = 'NumberOfLinks'; Static = $false; PropertyType = [uint32] },
        @{ Name = 'Length'; Static = $false; PropertyType = [int64] }
    )
    $propertyInfos = @($HelperType.GetProperties([System.Reflection.BindingFlags]'Public,Static,Instance,DeclaredOnly'))
    foreach ($propertySpec in $propertySpecs) {
        $matches = @($propertyInfos | Where-Object { $_.Name -ceq $propertySpec.Name })
        if ($matches.Count -ne 1) {
            Throw-PspktParity ('native helper conflict: public API mismatch (property {0} count={1})' -f $propertySpec.Name, $matches.Count)
        }
        $property = $matches[0]
        $getter = $property.GetGetMethod()
        if ($null -eq $getter -or $getter.IsStatic -ne [bool]$propertySpec.Static -or $property.PropertyType -ne $propertySpec.PropertyType) {
            Throw-PspktParity ('native helper conflict: public API mismatch (property {0} signature)' -f $propertySpec.Name)
        }
    }
    if (@($HelperType.GetFields([System.Reflection.BindingFlags]'Public,Static,Instance,DeclaredOnly')).Count -ne 0 -or
        @($HelperType.GetEvents([System.Reflection.BindingFlags]'Public,Static,Instance,DeclaredOnly')).Count -ne 0) {
        Throw-PspktParity 'native helper conflict: public API mismatch (unexpected public field or event)'
    }
    $jobMethods = @($processJobType.GetMethods([System.Reflection.BindingFlags]'Public,Static,Instance,DeclaredOnly'))
    $assignMethods = @($jobMethods | Where-Object { $_.Name -ceq 'AssignProcess' })
    $disposeMethods = @($jobMethods | Where-Object { $_.Name -ceq 'Dispose' })
    if ($assignMethods.Count -ne 1 -or $disposeMethods.Count -ne 1 -or $jobMethods.Count -ne 2) {
        Throw-PspktParity 'native helper conflict: ProcessJobV1 public API mismatch'
    }
    $assignParameters = @($assignMethods[0].GetParameters())
    if ($assignMethods[0].ReturnType -ne [void] -or $assignParameters.Count -ne 1 -or $assignParameters[0].ParameterType -ne [IntPtr] -or
        $disposeMethods[0].ReturnType -ne [void] -or @($disposeMethods[0].GetParameters()).Count -ne 0) {
        Throw-PspktParity 'native helper conflict: ProcessJobV1 signature mismatch'
    }
    if (@($processJobType.GetConstructors([System.Reflection.BindingFlags]'Public,Instance')).Count -ne 0 -or
        @($processJobType.GetProperties([System.Reflection.BindingFlags]'Public,Static,Instance,DeclaredOnly')).Count -ne 0 -or
        @($processJobType.GetFields([System.Reflection.BindingFlags]'Public,Static,Instance,DeclaredOnly')).Count -ne 0 -or
        @($processJobType.GetEvents([System.Reflection.BindingFlags]'Public,Static,Instance,DeclaredOnly')).Count -ne 0) {
        Throw-PspktParity 'native helper conflict: ProcessJobV1 exposes unexpected public members'
    }
    $publicConstructors = @($HelperType.GetConstructors([System.Reflection.BindingFlags]'Public,Instance'))
    if ($publicConstructors.Count -ne 0) {
        Throw-PspktParity 'native helper conflict: public API mismatch (public constructor)'
    }
}

function Import-PspktNativeHelper {
    param(
        [Parameter(Mandatory = $true)][byte[]]$SourceBytes,
        [Parameter(Mandatory = $true)][string]$SourcePath
    )
    $utf8 = [System.Text.UTF8Encoding]::new($false, $true)
    $sourceText = $utf8.GetString($SourceBytes)
    $namespaceIndex = $sourceText.IndexOf(
        $script:PspktNativeNamespaceDeclaration,
        [System.StringComparison]::Ordinal)
    if ($namespaceIndex -lt 0 -or
        $sourceText.IndexOf(
            $script:PspktNativeNamespaceDeclaration,
            $namespaceIndex + $script:PspktNativeNamespaceDeclaration.Length,
            [System.StringComparison]::Ordinal) -ge 0) {
        Throw-PspktParity 'native helper source namespace declaration is not unique'
    }
    $generatedNamespace = 'Pspkt.Certification.Generated' + [guid]::NewGuid().ToString('N')
    $generatedNamespaceDeclaration = 'namespace ' + $generatedNamespace
    $compiledSource = $sourceText.Substring(0, $namespaceIndex) +
        $generatedNamespaceDeclaration +
        $sourceText.Substring($namespaceIndex + $script:PspktNativeNamespaceDeclaration.Length)
    $compiledTypeName = $generatedNamespace + '.' + $script:PspktNativeTypeLeafName
    Add-Type -TypeDefinition $compiledSource -Language CSharp
    $compiled = $compiledTypeName -as [type]
    if ($null -eq $compiled) {
        Throw-PspktParity ('native helper compile did not produce {0} from {1}' -f $compiledTypeName, $SourcePath)
    }
    Assert-PspktNativePublicSurface -HelperType $compiled
    $script:PspktNativeHelperType = $compiled
    return $compiled
}

function Assert-PspktRetainedDirectory {
    param(
        $Handle,
        [Parameter(Mandatory = $true)][string]$Path
    )
    if ($Handle.IsReparsePoint) {
        Throw-PspktParity ('reparse point rejected for ''{0}''' -f $Path)
    }
}

function Assert-PspktRetainedFile {
    param(
        $Handle,
        [Parameter(Mandatory = $true)][string]$RelativePath
    )
    if ($Handle.IsReparsePoint) {
        Throw-PspktParity ('reparse point rejected for ''{0}''' -f $RelativePath)
    }
    if ($Handle.NumberOfLinks -ne 1) {
        Throw-PspktParity ('hardlink rejected for ''{0}'' (nNumberOfLinks={1})' -f $RelativePath, $Handle.NumberOfLinks)
    }
}

function New-PspktPinnedSourceScriptBlock {
    param(
        [Parameter(Mandatory = $true)]$Handle,
        [Parameter(Mandatory = $true)][int]$ExpectedLength,
        [Parameter(Mandatory = $true)][string]$ExpectedSha256,
        [Parameter(Mandatory = $true)][string]$Label
    )
    [byte[]]$bytes = $Handle.ReadExact()
    if ($bytes.Length -ne $ExpectedLength) {
        Throw-PspktParity ('{0} source length mismatch' -f $Label)
    }
    if ((Get-PspktSha256HexLocal -Bytes $bytes) -cne $ExpectedSha256) {
        Throw-PspktParity ('{0} source digest mismatch' -f $Label)
    }
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
        Throw-PspktParity ('{0} source contains a UTF-8 BOM' -f $Label)
    }
    foreach ($sourceByte in $bytes) {
        if ($sourceByte -eq 13) {
            Throw-PspktParity ('{0} source is not LF-only' -f $Label)
        }
    }
    $text = [System.Text.UTF8Encoding]::new($false, $true).GetString($bytes)
    return [scriptblock]::Create($text)
}

function Assert-PspktHostClassifierInventory {
    param([Parameter(Mandatory = $true)][string]$DirectoryPath)
    $inventory = @(Get-ChildItem -LiteralPath $DirectoryPath -Force)
    if ($inventory.Count -ne 9) {
        Throw-PspktParity ('host-classifier inventory is not the exact nine ordinary JSON files (count={0})' -f $inventory.Count)
    }
    $inventoryNames = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
    foreach ($entry in $inventory) {
        if ($entry.PSIsContainer) {
            Throw-PspktParity ('host-classifier inventory is not the exact nine ordinary JSON files (directory={0})' -f $entry.Name)
        }
        $entryAttributes = $entry.Attributes
        if (($entryAttributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            Throw-PspktParity ('host-classifier inventory is not the exact nine ordinary JSON files (reparse={0})' -f $entry.Name)
        }
        if (($entryAttributes -band [System.IO.FileAttributes]::Hidden) -ne 0 -or
            ($entryAttributes -band [System.IO.FileAttributes]::System) -ne 0) {
            Throw-PspktParity ('host-classifier inventory is not the exact nine ordinary JSON files (hidden-system={0})' -f $entry.Name)
        }
        if (-not $entry.Name.EndsWith('.json', [System.StringComparison]::Ordinal)) {
            Throw-PspktParity ('host-classifier inventory is not the exact nine ordinary JSON files (non-json={0})' -f $entry.Name)
        }
        if (-not $inventoryNames.Add($entry.Name)) {
            Throw-PspktParity ('host-classifier inventory is not the exact nine ordinary JSON files (duplicate={0})' -f $entry.Name)
        }
    }
    foreach ($expectedName in $script:PspktHostClassifierNames) {
        if (-not $inventoryNames.Contains($expectedName)) {
            Throw-PspktParity ('host-classifier inventory is not the exact nine ordinary JSON files (missing={0})' -f $expectedName)
        }
    }
}

$owned = New-Object 'System.Collections.Generic.List[object]'
$nativeStream = $null
try {
    $scriptPath = $MyInvocation.MyCommand.Path
    if ([string]::IsNullOrEmpty($scriptPath)) {
        Throw-PspktParity 'generator script path is missing'
    }
    $scriptPath = Get-PspktBclFullPath -Path $scriptPath
    $vectorsDir = [System.IO.Path]::GetDirectoryName($scriptPath)
    $certRoot = Get-PspktBclFullPath -Path ([System.IO.Path]::Combine($vectorsDir, '..'))
    $libDir = Get-PspktBclFullPath -Path ([System.IO.Path]::Combine($certRoot, 'lib'))
    $hostClassifierDir = Get-PspktBclFullPath -Path ([System.IO.Path]::Combine($vectorsDir, 'host-classifier'))
    $resultDir = Get-PspktBclFullPath -Path ([System.IO.Path]::Combine($vectorsDir, 'certification-result'))
    $nativePath = Get-PspktBclFullPath -Path ([System.IO.Path]::Combine($libDir, 'Pspkt.Certification.HostClassifierVectorNative.cs'))
    $canonicalPath = Get-PspktBclFullPath -Path ([System.IO.Path]::Combine($libDir, 'Pspkt.Certification.CanonicalJson.ps1'))
    $mathPath = Get-PspktBclFullPath -Path ([System.IO.Path]::Combine($libDir, 'Pspkt.Certification.Math.ps1'))
    $classifierPath = Get-PspktBclFullPath -Path ([System.IO.Path]::Combine($libDir, 'Pspkt.Certification.HostClassifier.ps1'))

    if (-not [System.IO.Directory]::Exists($certRoot)) {
        Throw-PspktParity ('certification root missing: {0}' -f $certRoot)
    }
    $certAttributes = [System.IO.File]::GetAttributes($certRoot)
    if (($certAttributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        Throw-PspktParity ('reparse point rejected for ''{0}''' -f $certRoot)
    }
    if (($certAttributes -band [System.IO.FileAttributes]::Directory) -eq 0) {
        Throw-PspktParity ('certification root is not a directory: {0}' -f $certRoot)
    }

    Assert-PspktOrdinaryDirectory -Path $libDir -Parent $certRoot
    Assert-PspktOrdinaryDirectory -Path $vectorsDir -Parent $certRoot
    Assert-PspktOrdinaryDirectory -Path $hostClassifierDir -Parent $certRoot
    Assert-PspktOrdinaryDirectory -Path $resultDir -Parent $certRoot
    Assert-PspktOrdinaryFile -Path $nativePath -Parent $certRoot
    Assert-PspktOrdinaryFile -Path $canonicalPath -Parent $certRoot
    Assert-PspktOrdinaryFile -Path $mathPath -Parent $certRoot
    Assert-PspktOrdinaryFile -Path $classifierPath -Parent $certRoot
    Assert-PspktOrdinaryFile -Path $scriptPath -Parent $certRoot

    $nativeStream = [System.IO.File]::Open($nativePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
    $nativeLength = $nativeStream.Length
    if ($nativeLength -lt 0 -or $nativeLength -gt [int]::MaxValue) {
        Throw-PspktParity ('native helper source length is invalid: {0}' -f $nativeLength)
    }
    $nativeBytes = New-Object byte[] ([int]$nativeLength)
    $nativeRead = 0
    while ($nativeRead -lt $nativeBytes.Length) {
        $chunk = $nativeStream.Read($nativeBytes, $nativeRead, $nativeBytes.Length - $nativeRead)
        if ($chunk -le 0) {
            Throw-PspktParity 'native helper source short read'
        }
        $nativeRead += $chunk
    }
    if ($nativeBytes.Length -ge 3 -and $nativeBytes[0] -eq 0xEF -and $nativeBytes[1] -eq 0xBB -and $nativeBytes[2] -eq 0xBF) {
        Throw-PspktParity 'native helper source is not strict UTF-8 LF'
    }
    $sawLf = $false
    foreach ($nativeByte in $nativeBytes) {
        if ($nativeByte -eq 13) {
            Throw-PspktParity 'native helper source is not strict UTF-8 LF'
        }
        if ($nativeByte -eq 10) {
            $sawLf = $true
        }
    }
    if (-not $sawLf) {
        Throw-PspktParity 'native helper source is not strict UTF-8 LF'
    }
    if ($nativeBytes.Length -ne $script:PspktNativeSourceLength) {
        Throw-PspktParity 'native helper source length mismatch'
    }
    $nativeSha = Get-PspktSha256HexLocal -Bytes $nativeBytes
    if ($nativeSha -cne $script:PspktNativeSourceSha256) {
        Throw-PspktParity 'native helper source digest mismatch'
    }

    $helperType = Import-PspktNativeHelper -SourceBytes $nativeBytes -SourcePath $nativePath

    $certDirHandle = $helperType::OpenDirectory($certRoot)
    [void]$owned.Add($certDirHandle)
    Assert-PspktRetainedDirectory -Handle $certDirHandle -Path $certRoot
    $vectorsHandle = $helperType::OpenDirectory($vectorsDir)
    [void]$owned.Add($vectorsHandle)
    Assert-PspktRetainedDirectory -Handle $vectorsHandle -Path $vectorsDir
    $hostDirHandle = $helperType::OpenDirectory($hostClassifierDir)
    [void]$owned.Add($hostDirHandle)
    Assert-PspktRetainedDirectory -Handle $hostDirHandle -Path $hostClassifierDir
    $resultDirHandle = $helperType::OpenDirectory($resultDir)
    [void]$owned.Add($resultDirHandle)
    Assert-PspktRetainedDirectory -Handle $resultDirHandle -Path $resultDir

    $canonicalHandle = $helperType::OpenFile($canonicalPath, $false)
    [void]$owned.Add($canonicalHandle)
    Assert-PspktRetainedFile -Handle $canonicalHandle -RelativePath 'lib/Pspkt.Certification.CanonicalJson.ps1'
    $mathHandle = $helperType::OpenFile($mathPath, $false)
    [void]$owned.Add($mathHandle)
    Assert-PspktRetainedFile -Handle $mathHandle -RelativePath 'lib/Pspkt.Certification.Math.ps1'
    $classifierHandle = $helperType::OpenFile($classifierPath, $false)
    [void]$owned.Add($classifierHandle)
    Assert-PspktRetainedFile -Handle $classifierHandle -RelativePath 'lib/Pspkt.Certification.HostClassifier.ps1'

    $canonicalScript = New-PspktPinnedSourceScriptBlock -Handle $canonicalHandle `
        -ExpectedLength $script:PspktCanonicalSourceLength -ExpectedSha256 $script:PspktCanonicalSourceSha256 `
        -Label 'canonical writer'
    $mathScript = New-PspktPinnedSourceScriptBlock -Handle $mathHandle `
        -ExpectedLength $script:PspktMathSourceLength -ExpectedSha256 $script:PspktMathSourceSha256 `
        -Label 'math'
    $classifierScript = New-PspktPinnedSourceScriptBlock -Handle $classifierHandle `
        -ExpectedLength $script:PspktClassifierSourceLength -ExpectedSha256 $script:PspktClassifierSourceSha256 `
        -Label 'host classifier'
    . $canonicalScript
    . $mathScript
    . $classifierScript

    $fixtures = @(
        @{
            File = 'seat-windows-terminal-powershell-7.json'
            Name = 'seat-windows-terminal-powershell-7'
            Description = 'Windows Terminal seat hosting PowerShell 7: valid WT_SESSION GUID plus WindowsTerminal.exe ancestor.'
            Probe = [ordered]@{ WtSession = '3f2504e0-4f89-41d3-9a0c-0305e82c3301'; ConsoleWindow = 65784; OwnerImagePath = 'C:\WINDOWS\System32\OpenConsole.exe'; Ancestry = @('pwsh.exe', 'WindowsTerminal.exe', 'explorer.exe'); ShellEdition = 'Core'; ShellVersionMajor = 7; ShellVersionMinor = 6; Architecture = 'x64'; SystemRoot = 'C:\WINDOWS' }
            ExpectedTerminalKind = 'windows-terminal'
            ExpectedShellKind = 'powershell-7'
            ExpectedArchitecture = 'x64'
            ExpectedStatus = 'pass'
            ExpectedReason = 'windows-terminal-signature'
            ExpectedHostKey = @('windows-terminal', 'powershell-7', 'x64')
        },
        @{
            File = 'seat-windows-terminal-windows-powershell-5.1.json'
            Name = 'seat-windows-terminal-windows-powershell-5.1'
            Description = 'Windows Terminal seat hosting Windows PowerShell 5.1.'
            Probe = [ordered]@{ WtSession = '3f2504e0-4f89-41d3-9a0c-0305e82c3301'; ConsoleWindow = 65784; OwnerImagePath = 'C:\WINDOWS\System32\OpenConsole.exe'; Ancestry = @('powershell.exe', 'WindowsTerminal.exe', 'explorer.exe'); ShellEdition = 'Desktop'; ShellVersionMajor = 5; ShellVersionMinor = 1; Architecture = 'x64'; SystemRoot = 'C:\WINDOWS' }
            ExpectedTerminalKind = 'windows-terminal'
            ExpectedShellKind = 'windows-powershell-5.1'
            ExpectedArchitecture = 'x64'
            ExpectedStatus = 'pass'
            ExpectedReason = 'windows-terminal-signature'
            ExpectedHostKey = @('windows-terminal', 'windows-powershell-5.1', 'x64')
        },
        @{
            File = 'seat-conhost-powershell-7.json'
            Name = 'seat-conhost-powershell-7'
            Description = 'Classic conhost seat hosting PowerShell 7: console window owned by canonical conhost.exe with a conhost.exe ancestor and no WindowsTerminal ancestor.'
            Probe = [ordered]@{ WtSession = ''; ConsoleWindow = 132048; OwnerImagePath = 'C:\WINDOWS\System32\conhost.exe'; Ancestry = @('pwsh.exe', 'conhost.exe', 'explorer.exe'); ShellEdition = 'Core'; ShellVersionMajor = 7; ShellVersionMinor = 6; Architecture = 'x64'; SystemRoot = 'C:\WINDOWS' }
            ExpectedTerminalKind = 'conhost'
            ExpectedShellKind = 'powershell-7'
            ExpectedArchitecture = 'x64'
            ExpectedStatus = 'pass'
            ExpectedReason = 'conhost-signature'
            ExpectedHostKey = @('conhost', 'powershell-7', 'x64')
        },
        @{
            File = 'seat-conhost-windows-powershell-5.1.json'
            Name = 'seat-conhost-windows-powershell-5.1'
            Description = 'Classic conhost seat hosting Windows PowerShell 5.1.'
            Probe = [ordered]@{ WtSession = ''; ConsoleWindow = 132048; OwnerImagePath = 'C:\WINDOWS\System32\conhost.exe'; Ancestry = @('powershell.exe', 'conhost.exe', 'explorer.exe'); ShellEdition = 'Desktop'; ShellVersionMajor = 5; ShellVersionMinor = 1; Architecture = 'x64'; SystemRoot = 'C:\WINDOWS' }
            ExpectedTerminalKind = 'conhost'
            ExpectedShellKind = 'windows-powershell-5.1'
            ExpectedArchitecture = 'x64'
            ExpectedStatus = 'pass'
            ExpectedReason = 'conhost-signature'
            ExpectedHostKey = @('conhost', 'windows-powershell-5.1', 'x64')
        },
        @{
            File = 'negative-stale-wt-session.json'
            Name = 'negative-stale-wt-session'
            Description = 'Inherited / stale WT_SESSION does not defeat a positive conhost classification.'
            Probe = [ordered]@{ WtSession = '3f2504e0-4f89-41d3-9a0c-0305e82c3301'; ConsoleWindow = 132048; OwnerImagePath = 'C:\WINDOWS\System32\conhost.exe'; Ancestry = @('pwsh.exe', 'conhost.exe', 'explorer.exe'); ShellEdition = 'Core'; ShellVersionMajor = 7; ShellVersionMinor = 6; Architecture = 'x64'; SystemRoot = 'C:\WINDOWS' }
            ExpectedTerminalKind = 'conhost'
            ExpectedShellKind = 'powershell-7'
            ExpectedArchitecture = 'x64'
            ExpectedStatus = 'pass'
            ExpectedReason = 'conhost-signature'
            ExpectedHostKey = @('conhost', 'powershell-7', 'x64')
        },
        @{
            File = 'negative-openconsole.json'
            Name = 'negative-openconsole'
            Description = 'OpenConsole.exe is never sufficient for the conhost seat and, without a Windows Terminal match, classifies as unknown.'
            Probe = [ordered]@{ WtSession = ''; ConsoleWindow = 132048; OwnerImagePath = 'C:\WINDOWS\System32\OpenConsole.exe'; Ancestry = @('pwsh.exe', 'OpenConsole.exe'); ShellEdition = 'Core'; ShellVersionMajor = 7; ShellVersionMinor = 6; Architecture = 'x64'; SystemRoot = 'C:\WINDOWS' }
            ExpectedTerminalKind = 'unknown'
            ExpectedShellKind = 'powershell-7'
            ExpectedArchitecture = 'x64'
            ExpectedStatus = 'unknown'
            ExpectedReason = 'openconsole-not-sufficient-for-conhost'
            ExpectedHostKey = $null
        },
        @{
            File = 'negative-spoofed-environment.json'
            Name = 'negative-spoofed-environment'
            Description = 'Spoofed environment: a console window with an unexpected owner image fails before artifact production.'
            Probe = [ordered]@{ WtSession = ''; ConsoleWindow = 132048; OwnerImagePath = 'C:\Temp\fake-conhost.exe'; Ancestry = @('pwsh.exe', 'conhost.exe'); ShellEdition = 'Core'; ShellVersionMajor = 7; ShellVersionMinor = 6; Architecture = 'x64'; SystemRoot = 'C:\WINDOWS' }
            ExpectedTerminalKind = 'unknown'
            ExpectedShellKind = 'powershell-7'
            ExpectedArchitecture = 'x64'
            ExpectedStatus = 'fail'
            ExpectedReason = 'unexpected-console-owner'
            ExpectedHostKey = $null
        },
        @{
            File = 'negative-missing-window.json'
            Name = 'negative-missing-window'
            Description = 'No console window (headless / redirected) fails the seat classification.'
            Probe = [ordered]@{ WtSession = ''; ConsoleWindow = 0; OwnerImagePath = ''; Ancestry = @('pwsh.exe', 'conhost.exe'); ShellEdition = 'Core'; ShellVersionMajor = 7; ShellVersionMinor = 6; Architecture = 'x64'; SystemRoot = 'C:\WINDOWS' }
            ExpectedTerminalKind = 'unknown'
            ExpectedShellKind = 'powershell-7'
            ExpectedArchitecture = 'x64'
            ExpectedStatus = 'fail'
            ExpectedReason = 'missing-console-window'
            ExpectedHostKey = $null
        },
        @{
            File = 'negative-ambiguous-ancestry.json'
            Name = 'negative-ambiguous-ancestry'
            Description = 'A WindowsTerminal.exe ancestor without a valid WT_SESSION GUID is ambiguous and fails.'
            Probe = [ordered]@{ WtSession = ''; ConsoleWindow = 132048; OwnerImagePath = 'C:\WINDOWS\System32\conhost.exe'; Ancestry = @('pwsh.exe', 'WindowsTerminal.exe', 'conhost.exe'); ShellEdition = 'Core'; ShellVersionMajor = 7; ShellVersionMinor = 6; Architecture = 'x64'; SystemRoot = 'C:\WINDOWS' }
            ExpectedTerminalKind = 'unknown'
            ExpectedShellKind = 'powershell-7'
            ExpectedArchitecture = 'x64'
            ExpectedStatus = 'fail'
            ExpectedReason = 'ambiguous-ancestry-windows-terminal-without-session'
            ExpectedHostKey = $null
        }
    )

    $ordinalPaths = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
    $ignoreCasePaths = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $records = New-Object 'System.Collections.Generic.List[object]'

    foreach ($fixture in $fixtures) {
        $relativePath = 'host-classifier/' + $fixture.File
        Assert-PspktGeneratedRelativePath -Path $relativePath
        if ($ordinalPaths.Contains($relativePath)) {
            Throw-PspktParity ('duplicate exact path: {0}' -f $relativePath)
        }
        if ($ignoreCasePaths.Contains($relativePath)) {
            Throw-PspktParity ('case alias rejected: {0}' -f $relativePath)
        }
        [void]$ordinalPaths.Add($relativePath)
        [void]$ignoreCasePaths.Add($relativePath)

        $probe = @{}
        foreach ($key in $fixture.Probe.Keys) {
            $probe[$key] = $fixture.Probe[$key]
        }
        $seat = Resolve-PspktHostSeat -Probe $probe
        if ([string]$seat.TerminalKind -cne [string]$fixture.ExpectedTerminalKind -or
            [string]$seat.ShellKind -cne [string]$fixture.ExpectedShellKind -or
            [string]$seat.Architecture -cne [string]$fixture.ExpectedArchitecture -or
            [string]$seat.Status -cne [string]$fixture.ExpectedStatus -or
            [string]$seat.Reason -cne [string]$fixture.ExpectedReason -or
            -not (Test-PspktStringArrayEqual -Left $seat.HostKey -Right $fixture.ExpectedHostKey)) {
            Throw-PspktParity ('classifier expectation mismatch for ''{0}''' -f $relativePath)
        }

        $expected = [ordered]@{
            terminalKind = $fixture.ExpectedTerminalKind
            shellKind    = $fixture.ExpectedShellKind
            architecture = $fixture.ExpectedArchitecture
            status       = $fixture.ExpectedStatus
            reason       = $fixture.ExpectedReason
            hostKey      = $fixture.ExpectedHostKey
        }
        $document = [ordered]@{
            schemaVersion = 1
            kind          = 'host-classifier-fixture'
            name          = $fixture.Name
            description   = $fixture.Description
            probe         = $fixture.Probe
            expected      = $expected
        }
        [byte[]]$canonicalBytes = Get-PspktCanonicalJsonBytes -Value $document
        $records.Add([pscustomobject]@{
            RelativePath = $relativePath
            FullPath     = [System.IO.Path]::Combine($hostClassifierDir, $fixture.File)
            Bytes        = $canonicalBytes
        })
    }

    function New-CpuPhaseFields {
        param($ThreadId, $KernelStart, $UserStart, $KernelEnd, $UserEnd, $QpcStart, $QpcEnd, $QpcFreq)
        $wall = Convert-PspktQpcDeltaTo100ns -DeltaTicks ([System.Numerics.BigInteger]$QpcEnd - [System.Numerics.BigInteger]$QpcStart) -FrequencyHz $QpcFreq
        $cpu = [System.Numerics.BigInteger]$KernelEnd + [System.Numerics.BigInteger]$UserEnd - ([System.Numerics.BigInteger]$KernelStart + [System.Numerics.BigInteger]$UserStart)
        $ppm = Get-PspktCpuUtilizationPpm -Cpu100ns $cpu -WallElapsed100ns $wall
        return [ordered]@{
            analysisLoopThreadId          = [int64]$ThreadId
            kernelStart100ns              = [int64]$KernelStart
            userStart100ns                = [int64]$UserStart
            kernelEnd100ns                = [int64]$KernelEnd
            userEnd100ns                  = [int64]$UserEnd
            qpcStart                      = [int64]$QpcStart
            qpcEnd                        = [int64]$QpcEnd
            qpcFrequencyHz                = [int64]$QpcFreq
            wallElapsed100ns              = [int64]$wall
            analysisLoopCpu100ns          = [int64]$cpu
            analysisLoopCpuUtilizationPpm = [int64]$ppm
        }
    }

    function New-Phase {
        param([string]$PhaseId, [string]$PhaseKind, $CpuFields, $Produced, $Dropped, $Rejected)
        $offeredClicks = 140
        $acceptedClicks = $offeredClicks - $Rejected
        $offeredWheels = 140
        $acceptedWheels = $offeredWheels - $Rejected
        $phase = [ordered]@{
            phaseId                          = $PhaseId
            phaseKind                        = $PhaseKind
            packetCeilingWithAcceptedActions = 256
            packetCeilingIdle                = 256
            effectivePacketCeiling           = 256
        }
        foreach ($k in $CpuFields.Keys) { $phase[$k] = $CpuFields[$k] }
        $phase['producedPackets']  = [int64]$Produced
        $phase['droppedPackets']   = [int64]$Dropped
        $phase['writerDrops']      = 0
        $phase['fileDrops']        = 0
        $phase['producerFailures'] = 0
        $phase['rentCount']        = [int64]$Produced
        $phase['returnCount']      = [int64]$Produced
        $phase['offeredClicks']    = $offeredClicks
        $phase['acceptedClicks']   = $acceptedClicks
        $phase['rejectedClicks']   = [int64]$Rejected
        $phase['offeredWheels']    = $offeredWheels
        $phase['acceptedWheels']   = $acceptedWheels
        $phase['rejectedWheels']   = [int64]$Rejected
        $phase['clickLatencyP50Microseconds'] = 8000
        $phase['clickLatencyP95Microseconds'] = 21000
        $phase['wheelLatencyP50Microseconds'] = 7000
        $phase['wheelLatencyP95Microseconds'] = 19000
        return $phase
    }

    $phases = @()
    $pairs = @()
    $baselineData = @(
        @{ produced = 500000; bDrop = 10; pDrop = 12; bThread = 7100; pThread = 7100 },
        @{ produced = 500000; bDrop = 8;  pDrop = 8;  bThread = 7100; pThread = 7100 },
        @{ produced = 400000; bDrop = 5;  pDrop = 4;  bThread = 7100; pThread = 7100 },
        @{ produced = 600000; bDrop = 20; pDrop = 25; bThread = 7100; pThread = 7100 },
        @{ produced = 550000; bDrop = 12; pDrop = 11; bThread = 7100; pThread = 7100 }
    )
    $qpcFreq = 10000000
    for ($i = 0; $i -lt $baselineData.Count; $i++) {
        $d = $baselineData[$i]
        $baseCpu = New-CpuPhaseFields -ThreadId $d.bThread -KernelStart 1000000 -UserStart 500000 -KernelEnd 2200000 -UserEnd 1100000 -QpcStart 1000000000 -QpcEnd 1010000000 -QpcFreq $qpcFreq
        $ptrCpu  = New-CpuPhaseFields -ThreadId $d.pThread -KernelStart 1000000 -UserStart 500000 -KernelEnd 2300000 -UserEnd 1150000 -QpcStart 2000000000 -QpcEnd 2010000000 -QpcFreq $qpcFreq
        $baselinePhaseId = ('baseline-{0}' -f ($i + 1))
        $pointerPhaseId  = ('pointer-{0}' -f ($i + 1))
        $basePhase = New-Phase -PhaseId $baselinePhaseId -PhaseKind 'baseline' -CpuFields $baseCpu -Produced $d.produced -Dropped $d.bDrop -Rejected 1
        $ptrPhase  = New-Phase -PhaseId $pointerPhaseId  -PhaseKind 'pointer'  -CpuFields $ptrCpu  -Produced $d.produced -Dropped $d.pDrop -Rejected 2
        $phases += ,$basePhase
        $phases += ,$ptrPhase
        $dropBudget = [System.Numerics.BigInteger]::Max([System.Numerics.BigInteger]1, [System.Numerics.BigInteger]::Divide(([System.Numerics.BigInteger]$d.produced + 999), [System.Numerics.BigInteger]1000))
        $pairs += ,([ordered]@{
            baselinePhaseId = $baselinePhaseId
            pointerPhaseId  = $pointerPhaseId
            dropBudget      = [int64]$dropBudget
            signedDropDelta = [int64]($d.pDrop - $d.bDrop)
            signedCpuDeltaPpm = [int64]($ptrCpu['analysisLoopCpuUtilizationPpm'] - $baseCpu['analysisLoopCpuUtilizationPpm'])
        })
    }

    $artifact = [ordered]@{
        schemaVersion             = 1
        artifactKind              = 'mouse-certification'
        testedCommit              = '0123456789abcdef0123456789abcdef01234567'
        interactiveManifestDigest = ('a' * 64)
        interactiveManifestDefinitionDigest = ('b' * 64)
        producer                  = [ordered]@{
            workflowPath = '.github/workflows/mouse-certification-produce.yml'
            workflowRef  = 'refs/heads/main'
            workflowCommit = 'abcdefabcdefabcdefabcdefabcdefabcdefabcd'
            runId        = '15000000001'
            runAttempt   = '1'
        }
        hostKey                   = [ordered]@{
            terminalKind = 'windows-terminal'
            shellKind    = 'powershell-7'
            architecture = 'x64'
        }
        hostDiagnostics           = [ordered]@{
            processImagePath = 'C:/Program Files/PowerShell/7/pwsh.exe'
            processVersion   = '7.6.4'
            osBuild          = '10.0.26100.4652'
            machineId        = 'c0ffee00-1111-2222-3333-444455556666'
        }
        sessionIdentities         = @(
            '11111111-1111-4111-8111-111111111111',
            '22222222-2222-4222-8222-222222222222',
            '33333333-3333-4333-8333-333333333333',
            '44444444-4444-4444-8444-444444444444'
        )
        saturation                = [ordered]@{
            certMatchedSaturation = @(256, 256)
        }
        thresholds                = [ordered]@{
            maxRejectionFractionPpm = 20000
            maxLatencyMicroseconds  = 50000
            maxCpuUtilizationPpm    = 900000
            minAcceptedActions      = 100
        }
        phases                    = $phases
        pairs                     = $pairs
        outcome                   = 'pass'
    }

    $artifactRelative = 'certification-result/sample-artifact.v1.json'
    Assert-PspktGeneratedRelativePath -Path $artifactRelative
    if ($ordinalPaths.Contains($artifactRelative) -or $ignoreCasePaths.Contains($artifactRelative)) {
        Throw-PspktParity ('duplicate or case-alias path: {0}' -f $artifactRelative)
    }
    [void]$ordinalPaths.Add($artifactRelative)
    [void]$ignoreCasePaths.Add($artifactRelative)
    [byte[]]$artifactBytes = Get-PspktCanonicalJsonBytes -Value $artifact
    $artifactSha = Get-PspktSha256Hex -Bytes $artifactBytes
    $records.Add([pscustomobject]@{
        RelativePath = $artifactRelative
        FullPath     = [System.IO.Path]::Combine($resultDir, 'sample-artifact.v1.json')
        Bytes        = $artifactBytes
    })

    $attestation = [ordered]@{
        schemaVersion        = 1
        kind                 = 'certification-attestation-metadata'
        predicateType        = 'https://pspkt.dev/attestations/mouse-certification/v1'
        subjectName          = 'mouse-certification-windows-terminal-powershell-7-x64'
        subjectDigestSha256  = $artifactSha
        repositoryOwner      = 'JamesKehr'
        repositoryName       = 'pspkt'
        producerWorkflowPath = '.github/workflows/mouse-certification-produce.yml'
        producerWorkflowRef  = 'refs/heads/main'
        producerWorkflowCommit = $artifact.producer.workflowCommit
        runId                = $artifact.producer.runId
        runAttempt           = $artifact.producer.runAttempt
        testedCommit         = $artifact.testedCommit
    }
    $attestationRelative = 'certification-result/sample-attestation.v1.json'
    Assert-PspktGeneratedRelativePath -Path $attestationRelative
    if ($ordinalPaths.Contains($attestationRelative) -or $ignoreCasePaths.Contains($attestationRelative)) {
        Throw-PspktParity ('duplicate or case-alias path: {0}' -f $attestationRelative)
    }
    [void]$ordinalPaths.Add($attestationRelative)
    [void]$ignoreCasePaths.Add($attestationRelative)
    [byte[]]$attestationBytes = Get-PspktCanonicalJsonBytes -Value $attestation
    $records.Add([pscustomobject]@{
        RelativePath = $attestationRelative
        FullPath     = [System.IO.Path]::Combine($resultDir, 'sample-attestation.v1.json')
        Bytes        = $attestationBytes
    })

    if ($ordinalPaths.Count -ne 11 -or $records.Count -ne 11) {
        Throw-PspktParity ('generated set count is {0}, expected 11' -f $ordinalPaths.Count)
    }
    foreach ($expectedPath in $script:PspktExpectedRelativePaths) {
        if (-not $ordinalPaths.Contains($expectedPath)) {
            Throw-PspktParity ('generated set missing {0}' -f $expectedPath)
        }
    }
    foreach ($generatedPath in $ordinalPaths) {
        $foundExpected = $false
        foreach ($expectedPath in $script:PspktExpectedRelativePaths) {
            if ($generatedPath -ceq $expectedPath) {
                $foundExpected = $true
                break
            }
        }
        if (-not $foundExpected) {
            Throw-PspktParity ('generated set has extra path {0}' -f $generatedPath)
        }
    }

    foreach ($record in $records) {
        $oracle = $script:PspktFrozenOracle[$record.RelativePath]
        if ($null -eq $oracle) {
            Throw-PspktParity ('missing frozen oracle for {0}' -f $record.RelativePath)
        }
        if ($record.Bytes.Length -ne [int]$oracle.Length) {
            Throw-PspktParity ('frozen length mismatch for ''{0}''' -f $record.RelativePath)
        }
        $recordSha = Get-PspktSha256Hex -Bytes $record.Bytes
        if ($recordSha -cne [string]$oracle.Sha256) {
            Throw-PspktParity ('frozen hash mismatch for ''{0}''' -f $record.RelativePath)
        }
    }
    if ($artifactSha -cne [string]$script:PspktFrozenOracle['certification-result/sample-artifact.v1.json'].Sha256) {
        Throw-PspktParity 'artifact attestation digest mismatch'
    }
    $attestationDoc = $attestation
    if ([string]$attestationDoc.subjectDigestSha256 -cne $artifactSha) {
        Throw-PspktParity 'artifact attestation digest mismatch'
    }

    foreach ($record in $records) {
        if (-not [System.IO.File]::Exists($record.FullPath)) {
            Throw-PspktParity ('missing leaf ''{0}''' -f $record.RelativePath)
        }
    }

    Assert-PspktHostClassifierInventory -DirectoryPath $hostClassifierDir

    $sampleArtifactPath = [System.IO.Path]::Combine($resultDir, 'sample-artifact.v1.json')
    $sampleAttestationPath = [System.IO.Path]::Combine($resultDir, 'sample-attestation.v1.json')
    Assert-PspktOrdinaryFile -Path $sampleArtifactPath -Parent $certRoot
    Assert-PspktOrdinaryFile -Path $sampleAttestationPath -Parent $certRoot

    $unchanged = 0
    $repaired = New-Object 'System.Collections.Generic.List[string]'
    $pendingWrites = New-Object 'System.Collections.Generic.List[object]'
    foreach ($record in $records) {
        $outputHandle = $helperType::OpenFile($record.FullPath, $true)
        [void]$owned.Add($outputHandle)
        Assert-PspktRetainedFile -Handle $outputHandle -RelativePath $record.RelativePath
        [byte[]]$existingBytes = $outputHandle.ReadExact()
        if (Test-PspktBytesEqual -Left $existingBytes -Right $record.Bytes) {
            $unchanged++
        }
        else {
            [void]$pendingWrites.Add([pscustomobject]@{
                Record        = $record
                Handle        = $outputHandle
                OriginalBytes = $existingBytes
            })
        }
    }
    Assert-PspktHostClassifierInventory -DirectoryPath $hostClassifierDir

    try {
        foreach ($pendingWrite in $pendingWrites) {
            $record = $pendingWrite.Record
            $outputHandle = $pendingWrite.Handle
            [byte[]]$written = $outputHandle.ReplaceExact($record.Bytes)
            if (-not (Test-PspktBytesEqual -Left $written -Right $record.Bytes)) {
                Throw-PspktParity ('post-write mismatch for ''{0}''' -f $record.RelativePath)
            }
            if ($outputHandle.Length -ne $record.Bytes.Length) {
                Throw-PspktParity ('post-write length mismatch for ''{0}''' -f $record.RelativePath)
            }
            $writtenSha = Get-PspktSha256Hex -Bytes $written
            if ($writtenSha -cne [string]$script:PspktFrozenOracle[$record.RelativePath].Sha256) {
                Throw-PspktParity ('post-write hash mismatch for ''{0}''' -f $record.RelativePath)
            }
            [void]$repaired.Add($record.RelativePath)
            if ($SimulateFailureAfterRepairCount -ge 0 -and $repaired.Count -eq $SimulateFailureAfterRepairCount) {
                Throw-PspktParity ('simulated write failure after {0} repairs' -f $repaired.Count)
            }
        }
        Assert-PspktHostClassifierInventory -DirectoryPath $hostClassifierDir
    }
    catch {
        $primaryException = $_.Exception
        $rollbackErrors = New-Object 'System.Collections.Generic.List[System.Exception]'
        foreach ($pendingWrite in $pendingWrites) {
            try {
                [byte[]]$currentBytes = $pendingWrite.Handle.ReadExact()
                if (-not (Test-PspktBytesEqual -Left $currentBytes -Right $pendingWrite.OriginalBytes)) {
                    [byte[]]$restoredBytes = $pendingWrite.Handle.ReplaceExact($pendingWrite.OriginalBytes)
                    if (-not (Test-PspktBytesEqual -Left $restoredBytes -Right $pendingWrite.OriginalBytes)) {
                        Throw-PspktParity ('rollback mismatch for ''{0}''' -f $pendingWrite.Record.RelativePath)
                    }
                }
            }
            catch {
                [void]$rollbackErrors.Add($_.Exception)
            }
        }
        if ($rollbackErrors.Count -gt 0) {
            $allErrors = New-Object 'System.Collections.Generic.List[System.Exception]'
            [void]$allErrors.Add($primaryException)
            foreach ($rollbackError in $rollbackErrors) {
                [void]$allErrors.Add($rollbackError)
            }
            throw [System.AggregateException]::new(
                'host-classifier vector write and rollback failed.',
                [System.Collections.Generic.IEnumerable[System.Exception]]$allErrors)
        }
        [System.Runtime.ExceptionServices.ExceptionDispatchInfo]::Capture($primaryException).Throw()
    }

    Write-Host ($script:PspktParityPrefix + ('{0} of 11 unchanged' -f $unchanged))
    if ($repaired.Count -gt 0) {
        Write-Host ($script:PspktParityPrefix + ('repaired {0}' -f ($repaired -join ',')))
    }
}
finally {
    for ($ownedIndex = $owned.Count - 1; $ownedIndex -ge 0; $ownedIndex--) {
        $ownedItem = $owned[$ownedIndex]
        if ($null -ne $ownedItem) {
            $ownedItem.Dispose()
        }
    }
    if ($null -ne $nativeStream) {
        $nativeStream.Dispose()
    }
}
