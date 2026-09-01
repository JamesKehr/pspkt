[CmdletBinding(DefaultParameterSetName = 'Validate', PositionalBinding = $false)]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Validate')]
    [string]$CertificationRoot,

    [Parameter(ParameterSetName = 'Validate')]
    [string]$RepositoryRoot,

    [Parameter(Mandatory = $true, ParameterSetName = 'SelfTest')]
    [switch]$SelfTest,

    [Parameter(Mandatory = $true, ParameterSetName = 'SelfTest')]
    [string]$ScratchRoot
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
$script:PspktClassifierSourceLength = 7294
$script:PspktClassifierSourceSha256 = 'fdc9cd70a504c3591e3afb81e2fe1b4a287868f2af28dc126bf0f7220909474e'
$script:PspktReadmeSizeCap = 262144
$script:PspktGitTimeoutMilliseconds = 60000
$script:PspktProcessOutputCap = 1048576
$script:PspktGitExecutableAuthority = $null

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

$script:PspktSliceRepoPaths = @(
    'certification/.gitattributes',
    'certification/lib/Pspkt.Certification.Math.ps1',
    'certification/lib/Pspkt.Certification.HostClassifier.ps1',
    'certification/lib/Pspkt.Certification.HostClassifierVectorNative.cs',
    'certification/validators/Test-PspktHostClassifierVectorParity.ps1',
    'certification/vectors/New-PspktHostClassifierFixtures.ps1',
    'certification/vectors/host-classifier/negative-ambiguous-ancestry.json',
    'certification/vectors/host-classifier/negative-missing-window.json',
    'certification/vectors/host-classifier/negative-openconsole.json',
    'certification/vectors/host-classifier/negative-spoofed-environment.json',
    'certification/vectors/host-classifier/negative-stale-wt-session.json',
    'certification/vectors/host-classifier/seat-conhost-powershell-7.json',
    'certification/vectors/host-classifier/seat-conhost-windows-powershell-5.1.json',
    'certification/vectors/host-classifier/seat-windows-terminal-powershell-7.json',
    'certification/vectors/host-classifier/seat-windows-terminal-windows-powershell-5.1.json',
    'certification/vectors/certification-result/sample-artifact.v1.json',
    'certification/vectors/certification-result/sample-attestation.v1.json',
    'tests/.gitattributes',
    'tests/pspkt.HostClassifierVectorParity.Tests.ps1'
)

$script:PspktTextAttributePaths = @(
    'certification/.gitattributes',
    'certification/lib/Pspkt.Certification.Math.ps1',
    'certification/lib/Pspkt.Certification.HostClassifier.ps1',
    'certification/lib/Pspkt.Certification.HostClassifierVectorNative.cs',
    'certification/validators/Test-PspktHostClassifierVectorParity.ps1',
    'certification/vectors/New-PspktHostClassifierFixtures.ps1',
    'tests/.gitattributes',
    'tests/pspkt.HostClassifierVectorParity.Tests.ps1'
)

$script:PspktBinaryVectorRepoPaths = @(
    'certification/vectors/host-classifier/negative-ambiguous-ancestry.json',
    'certification/vectors/host-classifier/negative-missing-window.json',
    'certification/vectors/host-classifier/negative-openconsole.json',
    'certification/vectors/host-classifier/negative-spoofed-environment.json',
    'certification/vectors/host-classifier/negative-stale-wt-session.json',
    'certification/vectors/host-classifier/seat-conhost-powershell-7.json',
    'certification/vectors/host-classifier/seat-conhost-windows-powershell-5.1.json',
    'certification/vectors/host-classifier/seat-windows-terminal-powershell-7.json',
    'certification/vectors/host-classifier/seat-windows-terminal-windows-powershell-5.1.json',
    'certification/vectors/certification-result/sample-artifact.v1.json',
    'certification/vectors/certification-result/sample-attestation.v1.json'
)

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

function Remove-PspktOwnedDirectoryTree {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not [System.IO.Directory]::Exists($Path)) {
        return
    }
    $rootAttributes = [System.IO.File]::GetAttributes($Path)
    if (($rootAttributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        Throw-PspktParity ('cleanup root is a reparse point: {0}' -f $Path)
    }
    $directory = [System.IO.DirectoryInfo]::new($Path)
    foreach ($entry in $directory.GetFileSystemInfos()) {
        if (($entry.Attributes -band [System.IO.FileAttributes]::Directory) -ne 0) {
            if (($entry.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                [System.IO.Directory]::Delete($entry.FullName)
            }
            else {
                Remove-PspktOwnedDirectoryTree -Path $entry.FullName
            }
        }
        else {
            [System.IO.File]::SetAttributes($entry.FullName, [System.IO.FileAttributes]::Normal)
            [System.IO.File]::Delete($entry.FullName)
        }
    }
    [System.IO.Directory]::Delete($Path)
    if ([System.IO.Directory]::Exists($Path)) {
        Throw-PspktParity ('cleanup directory still exists: {0}' -f $Path)
    }
}

function ConvertTo-PspktLfBytes {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)
    $list = New-Object 'System.Collections.Generic.List[byte]'
    for ($index = 0; $index -lt $Bytes.Length; $index++) {
        if ($Bytes[$index] -eq 13) {
            if (($index + 1) -lt $Bytes.Length -and $Bytes[$index + 1] -eq 10) {
                continue
            }
            [void]$list.Add(10)
            continue
        }
        [void]$list.Add($Bytes[$index])
    }
    return ,$list.ToArray()
}

function ConvertTo-PspktLocalProbeHashtable {
    param([Parameter(Mandatory = $true)]$ProbeObject)
    $table = @{}
    foreach ($property in $ProbeObject.PSObject.Properties) {
        if ($property.Name -ceq 'Ancestry') {
            if ($null -eq $property.Value) {
                $table[$property.Name] = @()
            }
            else {
                $table[$property.Name] = @($property.Value)
            }
        }
        else {
            $table[$property.Name] = $property.Value
        }
    }
    return $table
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

function Read-PspktNativeSourceBytes {
    param(
        [Parameter(Mandatory = $true)][string]$NativePath,
        [Parameter(Mandatory = $true)][ref]$Stream
    )
    $fileStream = [System.IO.File]::Open($NativePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
    $Stream.Value = $fileStream
    $nativeLength = $fileStream.Length
    if ($nativeLength -lt 0 -or $nativeLength -gt [int]::MaxValue) {
        Throw-PspktParity ('native helper source length is invalid: {0}' -f $nativeLength)
    }
    $nativeBytes = New-Object byte[] ([int]$nativeLength)
    $nativeRead = 0
    while ($nativeRead -lt $nativeBytes.Length) {
        $chunk = $fileStream.Read($nativeBytes, $nativeRead, $nativeBytes.Length - $nativeRead)
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
    return ,$nativeBytes
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

function Format-PspktWindowsArgument {
    param([AllowEmptyString()][AllowNull()][string]$Value)
    if ($null -eq $Value) {
        $Value = ''
    }
    $needsQuotes = ($Value.Length -eq 0)
    if (-not $needsQuotes) {
        foreach ($character in $Value.ToCharArray()) {
            if ($character -eq ' ' -or $character -eq [char]9 -or $character -eq '"') {
                $needsQuotes = $true
                break
            }
        }
    }
    if (-not $needsQuotes) {
        return $Value
    }
    $builder = [System.Text.StringBuilder]::new($Value.Length + 2)
    [void]$builder.Append('"')
    $slashCount = 0
    foreach ($character in $Value.ToCharArray()) {
        if ($character -eq [char]92) {
            $slashCount++
            continue
        }
        if ($character -eq '"') {
            for ($slashIndex = 0; $slashIndex -lt ((2 * $slashCount) + 1); $slashIndex++) {
                [void]$builder.Append([char]92)
            }
            [void]$builder.Append('"')
            $slashCount = 0
            continue
        }
        for ($slashIndex = 0; $slashIndex -lt $slashCount; $slashIndex++) {
            [void]$builder.Append([char]92)
        }
        $slashCount = 0
        [void]$builder.Append($character)
    }
    for ($slashIndex = 0; $slashIndex -lt (2 * $slashCount); $slashIndex++) {
        [void]$builder.Append([char]92)
    }
    [void]$builder.Append('"')
    return $builder.ToString()
}

function Invoke-PspktTextProcess {
    param(
        [Parameter(Mandatory = $true)][string]$FileName,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][AllowEmptyString()][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory,
        [hashtable]$Environment,
        [int]$TimeoutMilliseconds = $script:PspktGitTimeoutMilliseconds
    )
    $formattedArguments = New-Object 'System.Collections.Generic.List[string]'
    foreach ($argument in $Arguments) {
        [void]$formattedArguments.Add((Format-PspktWindowsArgument -Value $argument))
    }
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $FileName
    $startInfo.Arguments = [string]::Join(' ', $formattedArguments)
    $startInfo.WorkingDirectory = $WorkingDirectory
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    if ($null -ne $Environment) {
        $startInfo.EnvironmentVariables.Clear()
        foreach ($key in $Environment.Keys) {
            $startInfo.EnvironmentVariables[$key] = [string]$Environment[$key]
        }
    }
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    $started = $false
    $job = $null
    try {
        $helperType = $script:PspktNativeHelperType
        if ($null -eq $helperType) {
            Throw-PspktParity 'process containment helper is not loaded'
        }
        $job = $helperType::CreateProcessJob()
        [void]$process.Start()
        $started = $true
        try {
            $job.AssignProcess($process.Handle)
        }
        catch [System.ComponentModel.Win32Exception] {
            if ($_.Exception.NativeErrorCode -ne 5 -or -not $process.HasExited) {
                throw
            }
            if ($null -ne $job) {
                $job.Dispose()
                $job = $null
            }
        }
        $stdoutTask = $helperType::ReadStreamCappedAsync($process.StandardOutput.BaseStream, $script:PspktProcessOutputCap)
        $stderrTask = $helperType::ReadStreamCappedAsync($process.StandardError.BaseStream, $script:PspktProcessOutputCap)
        $waitClock = [System.Diagnostics.Stopwatch]::StartNew()
        while (-not $process.WaitForExit(50)) {
            if ($stdoutTask.IsFaulted -or $stderrTask.IsFaulted) {
                if ($null -ne $job) {
                    $job.Dispose()
                    $job = $null
                }
                [void]$process.WaitForExit(10000)
                [void]$stdoutTask.GetAwaiter().GetResult()
                [void]$stderrTask.GetAwaiter().GetResult()
            }
            if ($waitClock.ElapsedMilliseconds -ge $TimeoutMilliseconds) {
                if ($null -ne $job) {
                    $job.Dispose()
                    $job = $null
                }
                if (-not $process.WaitForExit(10000)) {
                    Throw-PspktParity ('process did not exit after termination: {0}' -f $FileName)
                }
                Throw-PspktParity ('process timed out: {0}' -f $FileName)
            }
        }
        $waitClock.Stop()
        if ($null -ne $job) {
            $job.Dispose()
            $job = $null
        }
        [byte[]]$stdoutBytes = $stdoutTask.GetAwaiter().GetResult()
        [byte[]]$stderrBytes = $stderrTask.GetAwaiter().GetResult()
        $utf8 = [System.Text.UTF8Encoding]::new($false, $true)
        $stdout = $utf8.GetString($stdoutBytes)
        $stderr = $utf8.GetString($stderrBytes)
        return [pscustomobject]@{
            ExitCode = $process.ExitCode
            Stdout   = $stdout
            Stderr   = $stderr
        }
    }
    finally {
        if ($null -ne $job) {
            $job.Dispose()
        }
        if ($started) {
            try {
                if (-not $process.HasExited) {
                    $process.Kill()
                    [void]$process.WaitForExit(10000)
                }
            }
            catch [System.InvalidOperationException] {
                if (-not $process.HasExited) {
                    throw
                }
            }
        }
        $process.Dispose()
    }
}

function Get-PspktGitExecutablePath {
    if ($null -ne $script:PspktGitExecutableAuthority) {
        Assert-PspktGitExecutableAuthority
        return $script:PspktGitExecutableAuthority.Path
    }
    $programFiles = $null
    if ([System.Environment]::Is64BitOperatingSystem) {
        $registryBase = $null
        $registryKey = $null
        try {
            $registryBase = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
                [Microsoft.Win32.RegistryHive]::LocalMachine,
                [Microsoft.Win32.RegistryView]::Registry64)
            $registryKey = $registryBase.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion', $false)
            if ($null -ne $registryKey) {
                $programFiles = [string]$registryKey.GetValue('ProgramFilesDir', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            }
        }
        finally {
            if ($null -ne $registryKey) {
                $registryKey.Dispose()
            }
            if ($null -ne $registryBase) {
                $registryBase.Dispose()
            }
        }
    }
    if ([string]::IsNullOrEmpty($programFiles)) {
        $programFiles = [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::ProgramFiles)
    }
    if ([string]::IsNullOrEmpty($programFiles) -or -not [System.IO.Path]::IsPathRooted($programFiles)) {
        Throw-PspktParity 'Program Files authority could not be resolved'
    }
    $gitRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($programFiles, 'Git'))
    $gitMingwRoot = [System.IO.Path]::Combine($gitRoot, 'mingw64')
    $gitBinRoot = [System.IO.Path]::Combine($gitMingwRoot, 'bin')
    $gitPath = [System.IO.Path]::Combine($gitBinRoot, 'git.exe')
    foreach ($directoryPath in @($programFiles, $gitRoot, $gitMingwRoot, $gitBinRoot)) {
        if (-not [System.IO.Directory]::Exists($directoryPath)) {
            Throw-PspktParity ('Git authority directory missing: {0}' -f $directoryPath)
        }
        if (([System.IO.File]::GetAttributes($directoryPath) -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            Throw-PspktParity ('Git authority directory is a reparse point: {0}' -f $directoryPath)
        }
    }
    if (-not [System.IO.File]::Exists($gitPath)) {
        Throw-PspktParity ('Git authority executable missing: {0}' -f $gitPath)
    }
    if (([System.IO.File]::GetAttributes($gitPath) -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        Throw-PspktParity ('Git authority executable is a reparse point: {0}' -f $gitPath)
    }
    $stream = [System.IO.File]::Open($gitPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
    try {
        if ($stream.Length -lt 1 -or $stream.Length -gt 33554432) {
            Throw-PspktParity ('Git authority executable length is invalid: {0}' -f $stream.Length)
        }
        $bytes = New-Object byte[] ([int]$stream.Length)
        $offset = 0
        while ($offset -lt $bytes.Length) {
            $read = $stream.Read($bytes, $offset, $bytes.Length - $offset)
            if ($read -le 0) {
                Throw-PspktParity 'Git authority executable short read'
            }
            $offset += $read
        }
        $script:PspktGitExecutableAuthority = [pscustomobject]@{
            Path   = $gitPath
            Stream = $stream
            Length = $bytes.Length
            Sha256 = Get-PspktSha256HexLocal -Bytes $bytes
        }
        $stream = $null
    }
    finally {
        if ($null -ne $stream) {
            $stream.Dispose()
        }
    }
    return $script:PspktGitExecutableAuthority.Path
}

function Assert-PspktGitExecutableAuthority {
    if ($null -eq $script:PspktGitExecutableAuthority) {
        Throw-PspktParity 'Git executable authority is not open'
    }
    $authority = $script:PspktGitExecutableAuthority
    if ($authority.Stream.Length -ne $authority.Length) {
        Throw-PspktParity 'Git authority executable length changed'
    }
    $authority.Stream.Position = 0
    $bytes = New-Object byte[] ([int]$authority.Length)
    $offset = 0
    while ($offset -lt $bytes.Length) {
        $read = $authority.Stream.Read($bytes, $offset, $bytes.Length - $offset)
        if ($read -le 0) {
            Throw-PspktParity 'Git authority executable short re-read'
        }
        $offset += $read
    }
    if ((Get-PspktSha256HexLocal -Bytes $bytes) -cne $authority.Sha256) {
        Throw-PspktParity 'Git authority executable digest changed'
    }
}

function Close-PspktGitExecutableAuthority {
    if ($null -ne $script:PspktGitExecutableAuthority) {
        $script:PspktGitExecutableAuthority.Stream.Dispose()
        $script:PspktGitExecutableAuthority = $null
    }
}

function Open-PspktExecutableAuthority {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $fullPath = [System.IO.Path]::GetFullPath($Path)
    if (-not [System.IO.File]::Exists($fullPath)) {
        Throw-PspktParity ('{0} executable missing: {1}' -f $Label, $fullPath)
    }
    if (([System.IO.File]::GetAttributes($fullPath) -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        Throw-PspktParity ('{0} executable is a reparse point: {1}' -f $Label, $fullPath)
    }
    $stream = [System.IO.File]::Open($fullPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
    try {
        if ($stream.Length -lt 1 -or $stream.Length -gt 33554432) {
            Throw-PspktParity ('{0} executable length is invalid: {1}' -f $Label, $stream.Length)
        }
        $bytes = New-Object byte[] ([int]$stream.Length)
        $offset = 0
        while ($offset -lt $bytes.Length) {
            $read = $stream.Read($bytes, $offset, $bytes.Length - $offset)
            if ($read -le 0) {
                Throw-PspktParity ('{0} executable short read' -f $Label)
            }
            $offset += $read
        }
        $authority = [pscustomobject]@{
            Path = $fullPath
            Label = $Label
            Stream = $stream
            Length = $bytes.Length
            Sha256 = Get-PspktSha256HexLocal -Bytes $bytes
        }
        $stream = $null
        return $authority
    }
    finally {
        if ($null -ne $stream) {
            $stream.Dispose()
        }
    }
}

function Assert-PspktExecutableAuthority {
    param([Parameter(Mandatory = $true)]$Authority)
    if ($Authority.Stream.Length -ne $Authority.Length) {
        Throw-PspktParity ('{0} executable length changed' -f $Authority.Label)
    }
    $Authority.Stream.Position = 0
    $bytes = New-Object byte[] ([int]$Authority.Length)
    $offset = 0
    while ($offset -lt $bytes.Length) {
        $read = $Authority.Stream.Read($bytes, $offset, $bytes.Length - $offset)
        if ($read -le 0) {
            Throw-PspktParity ('{0} executable short re-read' -f $Authority.Label)
        }
        $offset += $read
    }
    if ((Get-PspktSha256HexLocal -Bytes $bytes) -cne $Authority.Sha256) {
        Throw-PspktParity ('{0} executable digest changed' -f $Authority.Label)
    }
}

function New-PspktGitEnvironment {
    param(
        [Parameter(Mandatory = $true)][string]$GitExecutablePath,
        [Parameter(Mandatory = $true)][string]$HomeDirectory,
        [string]$IndexFile,
        [string]$ObjectDirectory,
        [string]$AlternateObjectDirectories,
        [switch]$SafeLineEndings
    )
    $table = @{}
    $systemRoot = [System.Environment]::GetEnvironmentVariable('SystemRoot')
    if ([string]::IsNullOrEmpty($systemRoot)) {
        $systemRoot = [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::Windows)
    }
    $gitFolder = [System.IO.Path]::GetDirectoryName($GitExecutablePath)
    $pathValue = $gitFolder + [System.IO.Path]::PathSeparator + [System.IO.Path]::Combine($systemRoot, 'System32')
    $table['SystemRoot'] = $systemRoot
    $table['windir'] = $systemRoot
    $table['PATH'] = $pathValue
    $table['PATHEXT'] = '.COM;.EXE;.BAT;.CMD'
    $table['TEMP'] = $HomeDirectory
    $table['TMP'] = $HomeDirectory
    $table['HOME'] = $HomeDirectory
    $table['GIT_CONFIG_NOSYSTEM'] = '1'
    $table['GIT_CONFIG_GLOBAL'] = [System.IO.Path]::Combine($HomeDirectory, '.gitconfig')
    $table['GIT_TERMINAL_PROMPT'] = '0'
    $table['GIT_OPTIONAL_LOCKS'] = '0'
    $table['LC_ALL'] = 'C'
    $table['LANG'] = 'C'
    if (-not [string]::IsNullOrEmpty($IndexFile)) {
        $table['GIT_INDEX_FILE'] = $IndexFile
    }
    if (-not [string]::IsNullOrEmpty($ObjectDirectory)) {
        $table['GIT_OBJECT_DIRECTORY'] = $ObjectDirectory
    }
    if (-not [string]::IsNullOrEmpty($AlternateObjectDirectories)) {
        $table['GIT_ALTERNATE_OBJECT_DIRECTORIES'] = $AlternateObjectDirectories
    }
    if ($SafeLineEndings) {
        $table['GIT_CONFIG_COUNT'] = '4'
        $table['GIT_CONFIG_KEY_0'] = 'core.autocrlf'
        $table['GIT_CONFIG_VALUE_0'] = 'true'
        $table['GIT_CONFIG_KEY_1'] = 'core.safecrlf'
        $table['GIT_CONFIG_VALUE_1'] = 'true'
        $table['GIT_CONFIG_KEY_2'] = 'core.hooksPath'
        $table['GIT_CONFIG_VALUE_2'] = 'NUL'
        $table['GIT_CONFIG_KEY_3'] = 'core.attributesFile'
        $table['GIT_CONFIG_VALUE_3'] = 'NUL'
    }
    return $table
}

function Invoke-PspktBoundGit {
    param(
        [Parameter(Mandatory = $true)][string]$GitExecutablePath,
        [Parameter(Mandatory = $true)][string]$GitDir,
        [Parameter(Mandatory = $true)][string]$WorkTree,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory,
        [Parameter(Mandatory = $true)][hashtable]$Environment,
        [Parameter(Mandatory = $true)][string[]]$CommandArgs,
        [switch]$RawStdout,
        [int]$ExactStdoutBytes = -1,
        [switch]$AllowStderr
    )
    Assert-PspktGitExecutableAuthority
    $arguments = New-Object 'System.Collections.Generic.List[string]'
    [void]$arguments.Add((Format-PspktWindowsArgument -Value '--no-replace-objects'))
    [void]$arguments.Add((Format-PspktWindowsArgument -Value ('--git-dir={0}' -f $GitDir)))
    [void]$arguments.Add((Format-PspktWindowsArgument -Value ('--work-tree={0}' -f $WorkTree)))
    foreach ($commandArg in $CommandArgs) {
        [void]$arguments.Add((Format-PspktWindowsArgument -Value $commandArg))
    }
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $GitExecutablePath
    $startInfo.Arguments = [string]::Join(' ', $arguments)
    $startInfo.WorkingDirectory = $WorkingDirectory
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.RedirectStandardInput = $true
    $startInfo.StandardOutputEncoding = [System.Text.UTF8Encoding]::new($false)
    $startInfo.StandardErrorEncoding = [System.Text.UTF8Encoding]::new($false)
    $startInfo.EnvironmentVariables.Clear()
    foreach ($key in $Environment.Keys) {
        $startInfo.EnvironmentVariables[$key] = [string]$Environment[$key]
    }
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    $started = $false
    $job = $null
    try {
        $helperType = $script:PspktNativeHelperType
        if ($null -eq $helperType) {
            Throw-PspktParity 'process containment helper is not loaded'
        }
        $job = $helperType::CreateProcessJob()
        [void]$process.Start()
        $started = $true
        try {
            $job.AssignProcess($process.Handle)
        }
        catch [System.ComponentModel.Win32Exception] {
            if ($_.Exception.NativeErrorCode -ne 5 -or -not $process.HasExited) {
                throw
            }
            $job.Dispose()
            $job = $null
        }
        $process.StandardInput.Close()
        $stdoutTask = $helperType::ReadStreamCappedAsync($process.StandardOutput.BaseStream, $script:PspktProcessOutputCap)
        $stderrTask = $helperType::ReadStreamCappedAsync($process.StandardError.BaseStream, $script:PspktProcessOutputCap)
        $waitClock = [System.Diagnostics.Stopwatch]::StartNew()
        while (-not $process.WaitForExit(50)) {
            if ($stdoutTask.IsFaulted -or $stderrTask.IsFaulted) {
                if ($null -ne $job) {
                    $job.Dispose()
                    $job = $null
                }
                [void]$process.WaitForExit(10000)
                [void]$stdoutTask.GetAwaiter().GetResult()
                [void]$stderrTask.GetAwaiter().GetResult()
            }
            if ($waitClock.ElapsedMilliseconds -ge $script:PspktGitTimeoutMilliseconds) {
                if ($null -ne $job) {
                    $job.Dispose()
                    $job = $null
                }
                if (-not $process.WaitForExit(10000)) {
                    Throw-PspktParity 'git process did not exit after termination'
                }
                Throw-PspktParity 'git process timed out'
            }
        }
        $waitClock.Stop()
        if ($null -ne $job) {
            $job.Dispose()
            $job = $null
        }
        [byte[]]$outputBytes = $stdoutTask.GetAwaiter().GetResult()
        [byte[]]$stderrBytes = $stderrTask.GetAwaiter().GetResult()
        $stderr = [System.Text.UTF8Encoding]::new($false, $true).GetString($stderrBytes)
        if ($RawStdout -and $ExactStdoutBytes -ge 0 -and $outputBytes.Length -ne $ExactStdoutBytes) {
            Throw-PspktParity ('git blob length {0} does not equal expected length {1}' -f $outputBytes.Length, $ExactStdoutBytes)
        }
        if ($process.ExitCode -ne 0) {
            Throw-PspktParity ('git exited {0}: {1}' -f $process.ExitCode, $stderr)
        }
        if (-not $AllowStderr -and -not [string]::IsNullOrEmpty($stderr)) {
            Throw-PspktParity ('git wrote stderr: {0}' -f $stderr)
        }
        Assert-PspktGitExecutableAuthority
        return ,$outputBytes
    }
    finally {
        if ($null -ne $job) {
            $job.Dispose()
        }
        if ($started) {
            try {
                if (-not $process.HasExited) {
                    $process.Kill()
                    [void]$process.WaitForExit(10000)
                }
            }
            catch [System.InvalidOperationException] {
                if (-not $process.HasExited) {
                    throw
                }
            }
        }
        $process.Dispose()
    }
}

function ConvertTo-PspktUtf8Text {
    param([AllowNull()][byte[]]$Bytes)
    if ($null -eq $Bytes) {
        $Bytes = New-Object byte[] 0
    }
    if ($Bytes.Length -ge 3 -and $Bytes[0] -eq 0xEF -and $Bytes[1] -eq 0xBB -and $Bytes[2] -eq 0xBF) {
        Throw-PspktParity 'UTF-8 BOM is forbidden'
    }
    return [System.Text.UTF8Encoding]::new($false, $true).GetString($Bytes)
}

function Get-PspktNormalizedRepoPath {
    param([Parameter(Mandatory = $true)][string]$Path)
    $full = Get-PspktBclFullPath -Path $Path
    $full = $full.Replace('/', '\').TrimEnd('\')
    return $full
}

function Get-PspktResolvedGitDirectory {
    param([Parameter(Mandatory = $true)][string]$RepositoryRoot)
    $dotGitPath = [System.IO.Path]::Combine($RepositoryRoot, '.git')
    if ([System.IO.Directory]::Exists($dotGitPath)) {
        if (([System.IO.File]::GetAttributes($dotGitPath) -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            Throw-PspktParity ('repository git directory is a reparse point: {0}' -f $dotGitPath)
        }
        return [System.IO.Path]::GetFullPath($dotGitPath)
    }
    if (-not [System.IO.File]::Exists($dotGitPath)) {
        Throw-PspktParity ('repository git metadata missing: {0}' -f $dotGitPath)
    }
    $attributes = [System.IO.File]::GetAttributes($dotGitPath)
    if (($attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
        ($attributes -band [System.IO.FileAttributes]::Directory) -ne 0) {
        Throw-PspktParity ('repository git metadata file is unsafe: {0}' -f $dotGitPath)
    }
    $bytes = [System.IO.File]::ReadAllBytes($dotGitPath)
    if ($bytes.Length -lt 9 -or $bytes.Length -gt 4096) {
        Throw-PspktParity ('repository git metadata file length is invalid: {0}' -f $bytes.Length)
    }
    $text = [System.Text.UTF8Encoding]::new($false, $true).GetString($bytes).Trim()
    if (-not $text.StartsWith('gitdir: ', [System.StringComparison]::Ordinal) -or
        $text.IndexOf("`n") -ge 0 -or $text.IndexOf("`r") -ge 0) {
        Throw-PspktParity 'repository git metadata file is malformed'
    }
    $gitDirectoryText = $text.Substring(8)
    if ([string]::IsNullOrEmpty($gitDirectoryText)) {
        Throw-PspktParity 'repository git metadata file has an empty target'
    }
    if ([System.IO.Path]::IsPathRooted($gitDirectoryText)) {
        $gitDirectory = [System.IO.Path]::GetFullPath($gitDirectoryText)
    }
    else {
        $gitDirectory = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($RepositoryRoot, $gitDirectoryText))
    }
    if (-not [System.IO.Directory]::Exists($gitDirectory) -or
        ([System.IO.File]::GetAttributes($gitDirectory) -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        Throw-PspktParity ('resolved git directory is missing or unsafe: {0}' -f $gitDirectory)
    }
    $backlinkPath = [System.IO.Path]::Combine($gitDirectory, 'gitdir')
    if (-not [System.IO.File]::Exists($backlinkPath)) {
        Throw-PspktParity ('linked worktree Git backlink is missing: {0}' -f $backlinkPath)
    }
    $backlinkBytes = [System.IO.File]::ReadAllBytes($backlinkPath)
    if ($backlinkBytes.Length -lt 1 -or $backlinkBytes.Length -gt 4096) {
        Throw-PspktParity 'linked worktree Git backlink length is invalid'
    }
    $backlinkText = [System.Text.UTF8Encoding]::new($false, $true).GetString($backlinkBytes).Trim()
    if ([System.IO.Path]::IsPathRooted($backlinkText)) {
        $backlink = [System.IO.Path]::GetFullPath($backlinkText)
    }
    else {
        $backlink = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($gitDirectory, $backlinkText))
    }
    if (-not $backlink.Equals($dotGitPath, [System.StringComparison]::OrdinalIgnoreCase)) {
        Throw-PspktParity ('linked worktree Git backlink mismatch: {0}' -f $backlink)
    }
    return $gitDirectory
}

function Get-PspktCommonGitObjectDirectory {
    param([Parameter(Mandatory = $true)][string]$CommonGitDirectory)
    $mainObjectDirectory = [System.IO.Path]::Combine($CommonGitDirectory, 'objects')
    if (-not [System.IO.Directory]::Exists($mainObjectDirectory) -or
        ([System.IO.File]::GetAttributes($mainObjectDirectory) -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        Throw-PspktParity ('common Git object directory is missing or unsafe: {0}' -f $mainObjectDirectory)
    }
    $alternatesPath = [System.IO.Path]::Combine($mainObjectDirectory, 'info', 'alternates')
    if ([System.IO.File]::Exists($alternatesPath) -and (Get-Item -LiteralPath $alternatesPath).Length -gt 0) {
        Throw-PspktParity 'common Git object alternates are not allowed'
    }
    return $mainObjectDirectory
}

function Test-PspktReadmeFossilText {
    param([Parameter(Mandatory = $true)][string]$Text)
    $normalized = [regex]::Replace($Text.ToLowerInvariant(), '\s+', ' ')
    $sentences = @($normalized -split '[.;]')
    $clauses = @($normalized -split '[.;]|\b(but|however|although|yet)\b')
    foreach ($clauseValue in $clauses) {
        $clause = $clauseValue.Trim()
        if (-not $clause.Contains('convertto-json')) {
            continue
        }
        $negated = [regex]::IsMatch(
            $clause,
            '\b(does not (use|depend on|require|need|call|invoke|leverage|utilize|consume|wrap)|do not (use|depend on|require|need|call|invoke|leverage|utilize|consume|wrap)|no longer (uses?|depends? on|requires?|needs?|calls?|invokes?|leverages?|utilizes?|consumes?|wraps?)|instead of|rather than|without|not|avoids?|unlike|unrelated to|nothing to do with|separate from)\b[^.]{0,120}\bconvertto-json\b') -or
            [regex]::IsMatch(
                $clause,
                '\bconvertto-json\b[^.]{0,120}\b((is|are)\s+(currently\s+)?not(?!\s+only\b)\s+(currently\s+)?(used|the\s+(serializer|writer|source|basis|backend)|based|backed)|not used|no longer used|avoids?|is avoided|are avoided|instead)\b')
        $historical = [regex]::IsMatch(
            $clause,
            '\b(previously|formerly|historically|earlier|prior|once|used to|replaced|replacing|migrated from|migrating from|relied on)\b') -or
            [regex]::IsMatch(
                $clause,
                '\b(was|were)\s+(generated|serialized|using|written|emitted|produced)\b')
        $generationContext = [regex]::IsMatch(
            $clause,
            '\b(generator|generation|vectors?|fixtures?|writer|outputs?|files?)\b')
        $currentUseAction = '(use|uses|using|is used|are used|generates?|is generated|are generated|serializes?|is serialized|are serialized|writes?|is written|are written|emits?|is emitted|are emitted|produces?|is produced|are produced|relies?|rely|come|comes|powers?|drives?|based|backed|source|depends?|dependent|dependency|requires?|needs?|calls?|invokes?|leverages?|utilizes?|consumes?|wraps?|built on|reliant|coupled)'
        $presentAction = [regex]::IsMatch(
            $clause,
            ('\b{0}\b' -f $currentUseAction))
        $explicitCurrentUse = [regex]::IsMatch(
            $clause,
            ('\b(still|current|currently|continues?|now|remain|remains)\b[^.]{{0,80}}\b{0}\b[^.]{{0,80}}\bconvertto-json\b' -f $currentUseAction)) -or
            [regex]::IsMatch(
                $clause,
                ('\b(still|current|currently|continues?|now|remain|remains)\b[^.]{{0,80}}\bconvertto-json\b[^.]{{0,80}}\b{0}\b' -f $currentUseAction)) -or
            [regex]::IsMatch(
                $clause,
                ('\bconvertto-json\b[^.]{{0,80}}\b(still|current|currently|continues?|now|remain|remains)\b[^.]{{0,80}}\b{0}\b' -f $currentUseAction))
        $currentNounClaim = [regex]::IsMatch(
            $clause,
            '\bcurrent\s+(serializer|writer|backend|basis)\b[^.]{0,80}\b(is|remains?|uses?)\b[^.]{0,80}\bconvertto-json\b') -or
            [regex]::IsMatch(
                $clause,
                '\bconvertto-json\b[^.]{0,80}\b(remains?|is)\b[^.]{0,80}\bcurrent\s+(serializer|writer|backend|basis)\b')
        $replacementStatement = $historical -and $clause.Contains('get-pspktcanonicaljsonbytes')
        if (($explicitCurrentUse -or $currentNounClaim -or ($generationContext -and $presentAction -and -not $historical)) -and
            -not $negated -and -not $replacementStatement) {
            Throw-PspktParity 'committed certification README still claims ConvertTo-Json generation'
        }
    }
    $deferredState = '(deferred|pending|unresolved|unfinished|incomplete|not\s+(yet\s+)?(fixed|implemented|complete|resolved)(\s+yet)?)'
    foreach ($clauseValue in $sentences) {
        $clause = $clauseValue.Trim()
        if (-not $clause.Contains('parity') -or -not [regex]::IsMatch($clause, ('\b{0}\b' -f $deferredState))) {
            continue
        }
        $historicalParity = [regex]::IsMatch(
            $clause,
            '\b(previously|formerly|historically|historical|earlier|prior|once|was|were|used to)\b')
        $currentDeferredParity = [regex]::IsMatch(
            $clause,
            ('\bparity\b[^.;]{{0,120}}\b(is|remains?|continues?\s+to\s+be)\s+(still\s+|currently\s+|now\s+)?{0}\b' -f $deferredState)) -or
            [regex]::IsMatch(
                $clause,
                ('\bparity\b[^.;]{{0,120}}\b(still|currently|now)\s+{0}\b' -f $deferredState)) -or
            [regex]::IsMatch(
                $clause,
                ('\bparity\b[^.;]{{0,120}}\b{0}\s+(still|currently|now)\b' -f $deferredState))
        if ($currentDeferredParity -or -not $historicalParity) {
            Throw-PspktParity 'committed certification README still claims deferred host-classifier parity'
        }
    }
    if ($normalized.Contains('new-pspkthostclassifierfixtures.ps1') -and
        -not $normalized.Contains('get-pspktcanonicaljsonbytes')) {
        Throw-PspktParity 'committed certification README does not name the canonical host-classifier writer'
    }
}

function Test-PspktCommittedReadme {
    param(
        [Parameter(Mandatory = $true)][string]$GitExecutablePath,
        [Parameter(Mandatory = $true)][string]$GitDir,
        [Parameter(Mandatory = $true)][string]$WorkTree,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory,
        [Parameter(Mandatory = $true)][hashtable]$Environment,
        [Parameter(Mandatory = $true)][string]$CommitId
    )
    $readmeBytes = Invoke-PspktBoundGit -GitExecutablePath $GitExecutablePath -GitDir $GitDir `
        -WorkTree $WorkTree -WorkingDirectory $WorkingDirectory -Environment $Environment `
        -CommandArgs @('ls-tree', $CommitId, '--', 'certification/README.md')
    $readmeText = ConvertTo-PspktUtf8Text -Bytes $readmeBytes
    if ([string]::IsNullOrEmpty($readmeText.Trim())) {
        return $false
    }
    $rows = @($readmeText -split "`n" | Where-Object { -not [string]::IsNullOrEmpty($_) })
    if ($rows.Count -ne 1) {
        Throw-PspktParity 'git ls-tree README returned extra output'
    }
    $row = $rows[0].TrimEnd("`r")
    $parts = $row.Split([char[]]@(' ', "`t"), 4)
    if ($parts.Count -lt 4) {
        Throw-PspktParity ('malformed ls-tree README row: {0}' -f $row)
    }
    $mode = $parts[0]
    $objectType = $parts[1]
    $blobId = $parts[2]
    $pathPart = $parts[3]
    if ($pathPart -cne 'certification/README.md') {
        Throw-PspktParity ('ls-tree README path mismatch: {0}' -f $pathPart)
    }
    if ($objectType -cne 'blob' -or ($mode -cne '100644' -and $mode -cne '100755')) {
        Throw-PspktParity ('README is not a regular blob (mode={0} type={1})' -f $mode, $objectType)
    }
    if ($blobId -cnotmatch '^[0-9a-f]{40}$') {
        Throw-PspktParity ('README blob ID is malformed: {0}' -f $blobId)
    }
    $sizeText = (ConvertTo-PspktUtf8Text -Bytes (
            Invoke-PspktBoundGit -GitExecutablePath $GitExecutablePath -GitDir $GitDir `
                -WorkTree $WorkTree -WorkingDirectory $WorkingDirectory -Environment $Environment `
                -CommandArgs @('cat-file', '-s', $blobId))).Trim()
    $blobSize = 0
    if (-not [int]::TryParse(
            $sizeText,
            [System.Globalization.NumberStyles]::None,
            [System.Globalization.CultureInfo]::InvariantCulture,
            [ref]$blobSize)) {
        Throw-PspktParity ('README blob size is malformed: {0}' -f $sizeText)
    }
    if ($blobSize -lt 0 -or $blobSize -gt $script:PspktReadmeSizeCap) {
        Throw-PspktParity ('README blob exceeds size cap ({0})' -f $blobSize)
    }
    $blob = Invoke-PspktBoundGit -GitExecutablePath $GitExecutablePath -GitDir $GitDir `
        -WorkTree $WorkTree -WorkingDirectory $WorkingDirectory -Environment $Environment `
        -CommandArgs @('cat-file', 'blob', $blobId) -RawStdout -ExactStdoutBytes $blobSize
    $content = ConvertTo-PspktUtf8Text -Bytes $blob
    Test-PspktReadmeFossilText -Text $content
    return $true
}

function Assert-PspktScopedGitAttributes {
    param(
        [Parameter(Mandatory = $true)][string]$GitExecutablePath,
        [Parameter(Mandatory = $true)][string]$GitDir,
        [Parameter(Mandatory = $true)][string]$WorkTree,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory,
        [Parameter(Mandatory = $true)][hashtable]$Environment,
        [switch]$Cached
    )
    $attributePrefix = @('check-attr')
    if ($Cached) {
        $attributePrefix += '--cached'
    }
    foreach ($textPath in $script:PspktTextAttributePaths) {
        $commandArguments = $attributePrefix + @('text', 'eol', 'filter', 'ident', 'working-tree-encoding', '--', $textPath)
        $attrBytes = Invoke-PspktBoundGit -GitExecutablePath $GitExecutablePath -GitDir $GitDir `
            -WorkTree $WorkTree -WorkingDirectory $WorkingDirectory -Environment $Environment `
            -CommandArgs $commandArguments
        $attrText = ConvertTo-PspktUtf8Text -Bytes $attrBytes
        if ($attrText -cnotmatch ([regex]::Escape($textPath) + ': text: set') -or
            $attrText -cnotmatch ([regex]::Escape($textPath) + ': eol: lf')) {
            Throw-PspktParity ('Git text attributes do not match for {0}' -f $textPath)
        }
        foreach ($unsetName in @('filter', 'ident', 'working-tree-encoding')) {
            if ($attrText -cnotmatch ([regex]::Escape($textPath) + ': ' + $unsetName + ': unset')) {
                Throw-PspktParity ('check-attr {0} was not unset for {1}' -f $unsetName, $textPath)
            }
        }
    }
    foreach ($binaryPath in $script:PspktBinaryVectorRepoPaths) {
        $commandArguments = $attributePrefix + @('text', 'eol', 'filter', 'ident', 'working-tree-encoding', '--', $binaryPath)
        $attrBytes = Invoke-PspktBoundGit -GitExecutablePath $GitExecutablePath -GitDir $GitDir `
            -WorkTree $WorkTree -WorkingDirectory $WorkingDirectory -Environment $Environment `
            -CommandArgs $commandArguments
        $attrText = ConvertTo-PspktUtf8Text -Bytes $attrBytes
        foreach ($unsetName in @('text', 'eol', 'filter', 'ident', 'working-tree-encoding')) {
            if ($attrText -cnotmatch ([regex]::Escape($binaryPath) + ': ' + $unsetName + ': unset')) {
                Throw-PspktParity ('check-attr {0} was not unset for {1}' -f $unsetName, $binaryPath)
            }
        }
    }
}

function Invoke-PspktGitAuthorityProof {
    param(
        [Parameter(Mandatory = $true)][string]$RepositoryRoot,
        [Parameter(Mandatory = $true)][string]$ScratchHome
    )
    $repoRoot = Get-PspktNormalizedRepoPath -Path $RepositoryRoot
    $gitDir = Get-PspktResolvedGitDirectory -RepositoryRoot $repoRoot
    $gitExe = Get-PspktGitExecutablePath
    if (-not [System.IO.Directory]::Exists($ScratchHome)) {
        [void][System.IO.Directory]::CreateDirectory($ScratchHome)
    }
    $configPath = [System.IO.Path]::Combine($ScratchHome, '.gitconfig')
    $configText = "[user]`n`tname = pspkt-cert`n`temail = pspkt-cert@example.invalid`n[commit]`n`tgpgsign = false`n"
    [System.IO.File]::WriteAllBytes($configPath, [System.Text.UTF8Encoding]::new($false).GetBytes($configText))
    $environment = New-PspktGitEnvironment -GitExecutablePath $gitExe -HomeDirectory $ScratchHome -SafeLineEndings
    $toplevelBytes = Invoke-PspktBoundGit -GitExecutablePath $gitExe -GitDir $gitDir -WorkTree $repoRoot -WorkingDirectory $repoRoot -Environment $environment -CommandArgs @('rev-parse', '--show-toplevel')
    $toplevelText = (ConvertTo-PspktUtf8Text -Bytes $toplevelBytes).Trim()
    $toplevelNormalized = Get-PspktNormalizedRepoPath -Path $toplevelText
    if (-not $toplevelNormalized.Equals($repoRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        Throw-PspktParity ('git toplevel mismatch: {0} vs {1}' -f $toplevelNormalized, $repoRoot)
    }
    $commonGitDirectoryText = (ConvertTo-PspktUtf8Text -Bytes (
            Invoke-PspktBoundGit -GitExecutablePath $gitExe -GitDir $gitDir -WorkTree $repoRoot `
                -WorkingDirectory $repoRoot -Environment $environment `
                -CommandArgs @('rev-parse', '--path-format=absolute', '--git-common-dir'))).Trim()
    $commonGitDirectory = Get-PspktNormalizedRepoPath -Path $commonGitDirectoryText
    if (-not [System.IO.Directory]::Exists($commonGitDirectory) -or
        ([System.IO.File]::GetAttributes($commonGitDirectory) -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        Throw-PspktParity ('common Git directory is missing or unsafe: {0}' -f $commonGitDirectory)
    }
    $mainObjectDirectory = Get-PspktCommonGitObjectDirectory -CommonGitDirectory $commonGitDirectory

    $headBytes = Invoke-PspktBoundGit -GitExecutablePath $gitExe -GitDir $gitDir -WorkTree $repoRoot -WorkingDirectory $repoRoot -Environment $environment -CommandArgs @('rev-parse', 'HEAD^{commit}')
    $headCommit = (ConvertTo-PspktUtf8Text -Bytes $headBytes).Trim()
    if ($headCommit -cnotmatch '^[0-9a-f]{40}$') {
        Throw-PspktParity ('HEAD commit is not a 40-character object ID: {0}' -f $headCommit)
    }

    $readmePresent = Test-PspktCommittedReadme -GitExecutablePath $gitExe -GitDir $gitDir `
        -WorkTree $repoRoot -WorkingDirectory $repoRoot -Environment $environment -CommitId $headCommit
    if (-not $readmePresent) {
        Write-Host ($script:PspktParityPrefix + 'README fossil check: not-applicable (absent from pinned commit)')
    }
    else {
        Write-Host ($script:PspktParityPrefix + 'README fossil check: pass')
    }

    $mainIndexPath = [System.IO.Path]::Combine($gitDir, 'index')
    $mainIndexHash = $null
    if ([System.IO.File]::Exists($mainIndexPath)) {
        $mainIndexHash = Get-PspktSha256HexLocal -Bytes ([System.IO.File]::ReadAllBytes($mainIndexPath))
    }

    $tempIndex = [System.IO.Path]::Combine($ScratchHome, 'temp-index')
    $copiedIndex = [System.IO.Path]::Combine($ScratchHome, 'copied-index')
    $objectDirectory = [System.IO.Path]::Combine($ScratchHome, 'objects')
    [void][System.IO.Directory]::CreateDirectory($objectDirectory)
    $proofGitDirectory = [System.IO.Path]::Combine($ScratchHome, 'proof.git')
    $proofInit = Invoke-PspktTextProcess -FileName $gitExe `
        -Arguments @('--no-replace-objects', 'init', '--bare', '--quiet', '--', $proofGitDirectory) `
        -WorkingDirectory $ScratchHome -Environment $environment
    Assert-PspktGitExecutableAuthority
    if ($proofInit.ExitCode -ne 0 -or -not [string]::IsNullOrEmpty($proofInit.Stderr)) {
        Throw-PspktParity ('private Git metadata initialization failed: {0}' -f $proofInit.Stderr)
    }
    $indexEnvironment = New-PspktGitEnvironment -GitExecutablePath $gitExe -HomeDirectory $ScratchHome `
        -IndexFile $tempIndex -ObjectDirectory $objectDirectory -AlternateObjectDirectories $mainObjectDirectory `
        -SafeLineEndings
    Assert-PspktScopedGitAttributes -GitExecutablePath $gitExe -GitDir $proofGitDirectory -WorkTree $repoRoot `
        -WorkingDirectory $repoRoot -Environment $environment
    [void](Invoke-PspktBoundGit -GitExecutablePath $gitExe -GitDir $proofGitDirectory -WorkTree $repoRoot -WorkingDirectory $repoRoot -Environment $indexEnvironment -CommandArgs @('read-tree', $headCommit))
    [void](Invoke-PspktBoundGit -GitExecutablePath $gitExe -GitDir $proofGitDirectory -WorkTree $repoRoot -WorkingDirectory $repoRoot -Environment $indexEnvironment -CommandArgs @('add', '--', 'certification/.gitattributes', 'tests/.gitattributes'))
    $remainingPaths = @()
    foreach ($slicePath in $script:PspktSliceRepoPaths) {
        if ($slicePath -cne 'certification/.gitattributes' -and $slicePath -cne 'tests/.gitattributes') {
            $remainingPaths += ,$slicePath
        }
    }
    $addArgs = @('add', '--') + $remainingPaths
    [void](Invoke-PspktBoundGit -GitExecutablePath $gitExe -GitDir $proofGitDirectory -WorkTree $repoRoot -WorkingDirectory $repoRoot -Environment $indexEnvironment -CommandArgs $addArgs)

    Assert-PspktScopedGitAttributes -GitExecutablePath $gitExe -GitDir $proofGitDirectory -WorkTree $repoRoot `
        -WorkingDirectory $repoRoot -Environment $indexEnvironment -Cached

    $treeBytes = Invoke-PspktBoundGit -GitExecutablePath $gitExe -GitDir $proofGitDirectory -WorkTree $repoRoot -WorkingDirectory $repoRoot -Environment $indexEnvironment -CommandArgs @('write-tree')
    $treeId = (ConvertTo-PspktUtf8Text -Bytes $treeBytes).Trim()
    [System.IO.File]::Copy($tempIndex, $copiedIndex, $true)
    $copyEnvironment = New-PspktGitEnvironment -GitExecutablePath $gitExe -HomeDirectory $ScratchHome `
        -IndexFile $copiedIndex -ObjectDirectory $objectDirectory -AlternateObjectDirectories $mainObjectDirectory `
        -SafeLineEndings
    $copyTreeBytes = Invoke-PspktBoundGit -GitExecutablePath $gitExe -GitDir $proofGitDirectory -WorkTree $repoRoot -WorkingDirectory $repoRoot -Environment $copyEnvironment -CommandArgs @('write-tree')
    $copyTreeId = (ConvertTo-PspktUtf8Text -Bytes $copyTreeBytes).Trim()
    if ($treeId -cne $copyTreeId) {
        Throw-PspktParity 'copied-index write-tree mismatch'
    }

    $prefixRoot = [System.IO.Path]::Combine($ScratchHome, 'check out prefix')
    if ([System.IO.Directory]::Exists($prefixRoot)) {
        Remove-PspktOwnedDirectoryTree -Path $prefixRoot
    }
    [void][System.IO.Directory]::CreateDirectory($prefixRoot)
    $prefix = $prefixRoot.Replace('\', '/') + '/'
    $checkoutArgs = @('checkout-index', ('--prefix={0}' -f $prefix), '--') + $script:PspktSliceRepoPaths
    [void](Invoke-PspktBoundGit -GitExecutablePath $gitExe -GitDir $proofGitDirectory -WorkTree $repoRoot -WorkingDirectory $repoRoot -Environment $indexEnvironment -CommandArgs $checkoutArgs)

    foreach ($binaryPath in $script:PspktBinaryVectorRepoPaths) {
        $lsBytes = Invoke-PspktBoundGit -GitExecutablePath $gitExe -GitDir $proofGitDirectory -WorkTree $repoRoot -WorkingDirectory $repoRoot -Environment $indexEnvironment -CommandArgs @('ls-tree', $treeId, '--', $binaryPath)
        $lsText = (ConvertTo-PspktUtf8Text -Bytes $lsBytes).Trim()
        $lsParts = $lsText.Split([char[]]@(' ', "`t"), 4)
        if ($lsParts.Count -lt 4 -or $lsParts[1] -cne 'blob' -or
            ($lsParts[0] -cne '100644' -and $lsParts[0] -cne '100755')) {
            Throw-PspktParity ('temporary-index blob missing for {0}' -f $binaryPath)
        }
        $indexOid = $lsParts[2]
        $hashBytes = Invoke-PspktBoundGit -GitExecutablePath $gitExe -GitDir $proofGitDirectory -WorkTree $repoRoot -WorkingDirectory $repoRoot -Environment $environment -CommandArgs @('hash-object', '--no-filters', '--', $binaryPath)
        $hashOid = (ConvertTo-PspktUtf8Text -Bytes $hashBytes).Trim()
        if ($indexOid -cne $hashOid) {
            Throw-PspktParity ('hash-object --no-filters mismatch for {0}' -f $binaryPath)
        }
        $sourceFull = [System.IO.Path]::Combine($repoRoot, ($binaryPath -replace '/', [string][System.IO.Path]::DirectorySeparatorChar))
        $sourceAttributes = [System.IO.File]::GetAttributes($sourceFull)
        if (($sourceAttributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
            ($sourceAttributes -band [System.IO.FileAttributes]::Directory) -ne 0) {
            Throw-PspktParity ('Git proof source is not an ordinary file: {0}' -f $binaryPath)
        }
        $sourceBytes = [System.IO.File]::ReadAllBytes($sourceFull)
        $sizeText = (ConvertTo-PspktUtf8Text -Bytes (Invoke-PspktBoundGit -GitExecutablePath $gitExe -GitDir $proofGitDirectory -WorkTree $repoRoot -WorkingDirectory $repoRoot -Environment $indexEnvironment -CommandArgs @('cat-file', '-s', $indexOid))).Trim()
        if ($sizeText -cne ([string]$sourceBytes.Length)) {
            Throw-PspktParity ('blob size mismatch for {0}' -f $binaryPath)
        }
        $checkedFull = [System.IO.Path]::Combine($prefixRoot, ($binaryPath -replace '/', [string][System.IO.Path]::DirectorySeparatorChar))
        $checkedAttributes = [System.IO.File]::GetAttributes($checkedFull)
        if (($checkedAttributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
            ($checkedAttributes -band [System.IO.FileAttributes]::Directory) -ne 0) {
            Throw-PspktParity ('checkout-index produced a non-ordinary file: {0}' -f $binaryPath)
        }
        $checkedBytes = [System.IO.File]::ReadAllBytes($checkedFull)
        if (-not (Test-PspktBytesEqual -Left $sourceBytes -Right $checkedBytes)) {
            Throw-PspktParity ('checkout-index raw byte mismatch for {0}' -f $binaryPath)
        }
    }

    foreach ($textPath in $script:PspktTextAttributePaths) {
        $lsBytes = Invoke-PspktBoundGit -GitExecutablePath $gitExe -GitDir $proofGitDirectory -WorkTree $repoRoot -WorkingDirectory $repoRoot -Environment $indexEnvironment -CommandArgs @('ls-tree', $treeId, '--', $textPath)
        $lsText = (ConvertTo-PspktUtf8Text -Bytes $lsBytes).Trim()
        $lsParts = $lsText.Split([char[]]@(' ', "`t"), 4)
        if ($lsParts.Count -lt 4 -or $lsParts[1] -cne 'blob' -or
            ($lsParts[0] -cne '100644' -and $lsParts[0] -cne '100755')) {
            Throw-PspktParity ('temporary-index blob missing for {0}' -f $textPath)
        }
        $indexOid = $lsParts[2]
        $hashBytes = Invoke-PspktBoundGit -GitExecutablePath $gitExe -GitDir $proofGitDirectory -WorkTree $repoRoot -WorkingDirectory $repoRoot -Environment $environment -CommandArgs @('hash-object', ('--path={0}' -f $textPath), '--', $textPath)
        $hashOid = (ConvertTo-PspktUtf8Text -Bytes $hashBytes).Trim()
        if ($indexOid -cne $hashOid) {
            Throw-PspktParity ('hash-object --path mismatch for {0}' -f $textPath)
        }
        $sourceFull = [System.IO.Path]::Combine($repoRoot, ($textPath -replace '/', [string][System.IO.Path]::DirectorySeparatorChar))
        $sourceAttributes = [System.IO.File]::GetAttributes($sourceFull)
        if (($sourceAttributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
            ($sourceAttributes -band [System.IO.FileAttributes]::Directory) -ne 0) {
            Throw-PspktParity ('Git proof source is not an ordinary file: {0}' -f $textPath)
        }
        $sourceLf = ConvertTo-PspktLfBytes -Bytes ([System.IO.File]::ReadAllBytes($sourceFull))
        $checkedFull = [System.IO.Path]::Combine($prefixRoot, ($textPath -replace '/', [string][System.IO.Path]::DirectorySeparatorChar))
        $checkedAttributes = [System.IO.File]::GetAttributes($checkedFull)
        if (($checkedAttributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
            ($checkedAttributes -band [System.IO.FileAttributes]::Directory) -ne 0) {
            Throw-PspktParity ('checkout-index produced a non-ordinary file: {0}' -f $textPath)
        }
        $checkedBytes = [System.IO.File]::ReadAllBytes($checkedFull)
        if (-not (Test-PspktBytesEqual -Left $sourceLf -Right $checkedBytes)) {
            Throw-PspktParity ('checkout-index LF mismatch for {0}' -f $textPath)
        }
    }

    $afterMainHash = $null
    if ([System.IO.File]::Exists($mainIndexPath)) {
        $afterMainHash = Get-PspktSha256HexLocal -Bytes ([System.IO.File]::ReadAllBytes($mainIndexPath))
    }
    if ([string]$mainIndexHash -cne [string]$afterMainHash) {
        Throw-PspktParity 'main index bytes changed'
    }
    $afterCopyTree = (ConvertTo-PspktUtf8Text -Bytes (Invoke-PspktBoundGit -GitExecutablePath $gitExe -GitDir $proofGitDirectory -WorkTree $repoRoot -WorkingDirectory $repoRoot -Environment $copyEnvironment -CommandArgs @('write-tree'))).Trim()
    if ($copyTreeId -cne $afterCopyTree) {
        Throw-PspktParity 'copied-index tree changed'
    }
    Write-Host ($script:PspktParityPrefix + 'git attribute and checkout proof: pass')
}

function Invoke-PspktGitSelfTests {
    param([Parameter(Mandatory = $true)][string]$ScratchRoot)
    $scratch = Get-PspktBclFullPath -Path $ScratchRoot
    if (-not [System.IO.Directory]::Exists($scratch)) {
        [void][System.IO.Directory]::CreateDirectory($scratch)
    }
    $gitExe = Get-PspktGitExecutablePath
    $homeDir = [System.IO.Path]::Combine($scratch, 'git-home')
    if (-not [System.IO.Directory]::Exists($homeDir)) {
        [void][System.IO.Directory]::CreateDirectory($homeDir)
    }
    $configText = "[user]`n`tname = pspkt-cert`n`temail = pspkt-cert@example.invalid`n[commit]`n`tgpgsign = false`n"
    [System.IO.File]::WriteAllBytes(([System.IO.Path]::Combine($homeDir, '.gitconfig')), [System.Text.UTF8Encoding]::new($false).GetBytes($configText))
    $environment = New-PspktGitEnvironment -GitExecutablePath $gitExe -HomeDirectory $homeDir
    $selfRepoHeads = @{}

    foreach ($acceptedReadmeText in @(
            'Previously the vectors were serialized with ConvertTo-Json. They now use Get-PspktCanonicalJsonBytes.',
            'The files were formerly generated with ConvertTo-Json; current output uses Get-PspktCanonicalJsonBytes.',
            'Historically the generator was using ConvertTo-Json. It now uses Get-PspktCanonicalJsonBytes.',
            'The generator no longer uses ConvertTo-Json and emits canonical bytes.',
            'Host-classifier fixtures are emitted by Get-PspktCanonicalJsonBytes, not ConvertTo-Json.',
            'This generator does not use ConvertTo-Json.',
            'An earlier draft of this generator relied on ConvertTo-Json for output.',
            'ConvertTo-Json produces different bytes across hosts, which is why this project avoids it.',
            'Current output uses Get-PspktCanonicalJsonBytes after replacing ConvertTo-Json.',
            'ConvertTo-Json is not currently used by the generator.',
            'The generator instead uses Get-PspktCanonicalJsonBytes rather than ConvertTo-Json.',
            'ConvertTo-Json is currently not the serializer used for fixtures.',
            'Canonical bytes replaced the ConvertTo-Json approach it once used.',
            'The current documentation contrasts Get-PspktCanonicalJsonBytes with ConvertTo-Json.',
            'The generator once used ConvertTo-Json and is currently stable.',
            'Current migration notes explain that ConvertTo-Json once serialized these files.',
            'Current docs explain that ConvertTo-Json once generated these vectors.',
            'The current writer tests compare canonical output with ConvertTo-Json.',
            'The logging writer and output backend are unrelated to ConvertTo-Json usage elsewhere.',
            'The generator no longer depends on ConvertTo-Json.',
            'The generator no longer requires ConvertTo-Json.',
            'The generator no longer needs ConvertTo-Json.',
            'The generator no longer calls ConvertTo-Json.',
            'The generator no longer invokes ConvertTo-Json.',
            'PS5/PS7 parity was previously deferred but is now fixed.',
            'This section explains why cross-host parity was once unresolved but is now fixed.',
            'Historical notes describe PS5/PS7 byte parity as previously incomplete.'
        )) {
        Test-PspktReadmeFossilText -Text $acceptedReadmeText
    }
    foreach ($rejectedReadmeText in @(
            'The generator uses ConvertTo-Json.',
            'The vectors are generated with ConvertTo-Json.',
            'The generator serializes fixtures via ConvertTo-Json.',
            'The generator emits fixtures via ConvertTo-Json.',
            'The writer still serializes fixtures via ConvertTo-Json.',
            'Previously files used another writer; the current generator uses ConvertTo-Json.',
            'ConvertTo-Json currently powers fixture generation.',
            'Vectors come from ConvertTo-Json.',
            'Fixtures rely on ConvertTo-Json.',
            'ConvertTo-Json is used for fixture generation.',
            'They now use ConvertTo-Json.',
            'ConvertTo-Json remains the fixture source.',
            'The generator remains ConvertTo-Json based.',
            'The current serializer is ConvertTo-Json.',
            'The current writer for fixtures is ConvertTo-Json.',
            'ConvertTo-Json remains the current backend.',
            'This generator remains dependent on ConvertTo-Json.',
            'This generator depends on ConvertTo-Json.',
            'This generator requires ConvertTo-Json.',
            'This generator needs ConvertTo-Json.',
            'This generator calls ConvertTo-Json.',
            'This generator invokes ConvertTo-Json.',
            'This generator leverages ConvertTo-Json.',
            'This generator utilizes ConvertTo-Json.',
            'This generator consumes ConvertTo-Json.',
            'This generator wraps ConvertTo-Json.',
            'This generator is built on ConvertTo-Json.',
            'This generator remains reliant on ConvertTo-Json.',
            'This generator remains coupled to ConvertTo-Json.',
            'Previously another writer was used, but the generator uses ConvertTo-Json now.',
            'PS5/PS7 parity remains deferred.',
            'Host-classifier byte parity is still pending.',
            'Cross-host parity is not yet fixed.',
            'PS5/PS7 parity was once fixed but is now pending.',
            'Previously documented host-classifier parity remains deferred.',
            'PS5/PS7 parity was previously fixed, but pending now.'
        )) {
        $rejected = $false
        try {
            Test-PspktReadmeFossilText -Text $rejectedReadmeText
        }
        catch {
            $rejected = $true
            if ([string]$_.Exception.Message -notmatch 'ConvertTo-Json|deferred host-classifier parity') {
                throw
            }
        }
        if (-not $rejected) {
            Throw-PspktParity ('self-test stale README phrase was accepted: {0}' -f $rejectedReadmeText)
        }
    }

    $apiMismatchSource = @"
using System;
using System.IO;
using System.Threading.Tasks;
namespace Pspkt.Certification
{
    public sealed class HostClassifierVectorNativeApiMismatchV1 : IDisposable
    {
        private HostClassifierVectorNativeApiMismatchV1() { }
        public sealed class ProcessJobV1 : IDisposable
        {
            private ProcessJobV1() { }
            public void AssignProcess(IntPtr processHandle) { }
            public void Dispose() { }
        }
        public static string BuildMarker { get { return "pspkt-host-classifier-vector-native-5"; } }
        public static string TypeVersion { get { return "1"; } }
        public bool IsReparsePoint { get { return false; } }
        public uint VolumeSerialNumber { get { return 0; } }
        public ulong FileIndex { get { return 0; } }
        public uint NumberOfLinks { get { return 1; } }
        public int Length { get { return 0; } }
        public static ProcessJobV1 CreateProcessJob() { return null; }
        public static HostClassifierVectorNativeApiMismatchV1 OpenDirectory(string path) { return null; }
        public static HostClassifierVectorNativeApiMismatchV1 OpenFile(string path) { return null; }
        public static Task<byte[]> ReadStreamCappedAsync(Stream stream, int maximumBytes) { return null; }
        public byte[] ReadExact() { return new byte[0]; }
        public byte[] ReplaceExact(byte[] bytes) { return bytes; }
        public void Dispose() { }
    }
}
"@
    Add-Type -TypeDefinition $apiMismatchSource -Language CSharp
    $apiMismatchFailed = $false
    try {
        Assert-PspktNativePublicSurface -HelperType ([Pspkt.Certification.HostClassifierVectorNativeApiMismatchV1])
    }
    catch {
        $apiMismatchFailed = $true
        if ([string]$_.Exception.Message -notmatch 'public API mismatch') {
            throw
        }
    }
    if (-not $apiMismatchFailed) {
        Throw-PspktParity 'self-test malformed native API was accepted'
    }
    function Initialize-PspktSelfRepo {
        param([Parameter(Mandatory = $true)][string]$RepoPath)
        if ([System.IO.Directory]::Exists($RepoPath)) {
            Remove-PspktOwnedDirectoryTree -Path $RepoPath
        }
        [void][System.IO.Directory]::CreateDirectory($RepoPath)
        $initResult = Invoke-PspktTextProcess -FileName $gitExe `
            -Arguments @('--no-replace-objects', 'init', '--', $RepoPath) `
            -WorkingDirectory $scratch -Environment $environment
        Assert-PspktGitExecutableAuthority
        if ($initResult.ExitCode -ne 0) {
            Throw-PspktParity ('git init failed for {0}: {1}' -f $RepoPath, $initResult.Stderr)
        }
        $selfRepoHeads[$RepoPath] = $null
        return [System.IO.Path]::Combine($RepoPath, '.git')
    }

    function Add-PspktSelfCommit {
        param(
            [Parameter(Mandatory = $true)][string]$RepoPath,
            [Parameter(Mandatory = $true)][string]$GitDir,
            [Parameter(Mandatory = $true)][string]$RelativePath,
            [Parameter(Mandatory = $true)][byte[]]$Content,
            [string]$Message = 'self-test'
        )
        $full = [System.IO.Path]::Combine($RepoPath, ($RelativePath -replace '/', [string][System.IO.Path]::DirectorySeparatorChar))
        $parent = [System.IO.Path]::GetDirectoryName($full)
        if (-not [System.IO.Directory]::Exists($parent)) {
            [void][System.IO.Directory]::CreateDirectory($parent)
        }
        [System.IO.File]::WriteAllBytes($full, $Content)
        $blobId = (ConvertTo-PspktUtf8Text -Bytes (
                Invoke-PspktBoundGit -GitExecutablePath $gitExe -GitDir $GitDir -WorkTree $RepoPath `
                    -WorkingDirectory $RepoPath -Environment $environment `
                    -CommandArgs @('hash-object', '-w', '--', $RelativePath))).Trim()
        [void](Invoke-PspktBoundGit -GitExecutablePath $gitExe -GitDir $GitDir -WorkTree $RepoPath `
                -WorkingDirectory $RepoPath -Environment $environment `
                -CommandArgs @('update-index', '--add', '--cacheinfo', ('100644,{0},{1}' -f $blobId, $RelativePath)))
        $treeId = (ConvertTo-PspktUtf8Text -Bytes (
                Invoke-PspktBoundGit -GitExecutablePath $gitExe -GitDir $GitDir -WorkTree $RepoPath `
                    -WorkingDirectory $RepoPath -Environment $environment -CommandArgs @('write-tree'))).Trim()
        $commitArgs = @('commit-tree', $treeId, '-m', $Message)
        $parentCommit = $selfRepoHeads[$RepoPath]
        if (-not [string]::IsNullOrEmpty([string]$parentCommit)) {
            $commitArgs += @('-p', [string]$parentCommit)
        }
        $commitId = (ConvertTo-PspktUtf8Text -Bytes (
                Invoke-PspktBoundGit -GitExecutablePath $gitExe -GitDir $GitDir -WorkTree $RepoPath `
                    -WorkingDirectory $RepoPath -Environment $environment -CommandArgs $commitArgs)).Trim()
        [void](Invoke-PspktBoundGit -GitExecutablePath $gitExe -GitDir $GitDir -WorkTree $RepoPath `
                -WorkingDirectory $RepoPath -Environment $environment -CommandArgs @('update-ref', 'HEAD', $commitId))
        $selfRepoHeads[$RepoPath] = $commitId
    }

    $absentRepo = [System.IO.Path]::Combine($scratch, 'git authority repo')
    $absentGit = Initialize-PspktSelfRepo -RepoPath $absentRepo
    Add-PspktSelfCommit -RepoPath $absentRepo -GitDir $absentGit -RelativePath 'other.txt' -Content ([System.Text.UTF8Encoding]::new($false).GetBytes("ok`n"))
    $absentHead = (ConvertTo-PspktUtf8Text -Bytes (Invoke-PspktBoundGit -GitExecutablePath $gitExe -GitDir $absentGit -WorkTree $absentRepo -WorkingDirectory $absentRepo -Environment $environment -CommandArgs @('rev-parse', 'HEAD^{commit}'))).Trim()
    if (Test-PspktCommittedReadme -GitExecutablePath $gitExe -GitDir $absentGit -WorkTree $absentRepo -WorkingDirectory $absentRepo -Environment $environment -CommitId $absentHead) {
        Throw-PspktParity 'self-test README absent was reported present'
    }
    $linkedWorktree = [System.IO.Path]::Combine($scratch, 'git linked worktree')
    [void](Invoke-PspktBoundGit -GitExecutablePath $gitExe -GitDir $absentGit -WorkTree $absentRepo `
            -WorkingDirectory $absentRepo -Environment $environment `
            -CommandArgs @('worktree', 'add', '--detach', $linkedWorktree, $absentHead) -AllowStderr)
    $linkedGitDirectory = Get-PspktResolvedGitDirectory -RepositoryRoot $linkedWorktree
    if (-not [System.IO.Directory]::Exists($linkedGitDirectory) -or
        $linkedGitDirectory.Equals([System.IO.Path]::Combine($linkedWorktree, '.git'), [System.StringComparison]::OrdinalIgnoreCase)) {
        Throw-PspktParity 'self-test linked worktree git directory was not resolved'
    }
    $linkedCommonDirectory = (ConvertTo-PspktUtf8Text -Bytes (
            Invoke-PspktBoundGit -GitExecutablePath $gitExe -GitDir $linkedGitDirectory -WorkTree $linkedWorktree `
                -WorkingDirectory $linkedWorktree -Environment $environment `
                -CommandArgs @('rev-parse', '--path-format=absolute', '--git-common-dir'))).Trim()
    if (-not [System.IO.Directory]::Exists($linkedCommonDirectory)) {
        Throw-PspktParity 'self-test linked worktree common Git directory was not resolved'
    }
    $linkedObjectDirectory = Get-PspktCommonGitObjectDirectory -CommonGitDirectory $linkedCommonDirectory
    $linkedCommitSize = (ConvertTo-PspktUtf8Text -Bytes (
            Invoke-PspktBoundGit -GitExecutablePath $gitExe -GitDir $linkedGitDirectory -WorkTree $linkedWorktree `
                -WorkingDirectory $linkedWorktree -Environment $environment `
                -CommandArgs @('cat-file', '-s', $absentHead))).Trim()
    if ($linkedCommitSize -cnotmatch '^[1-9][0-9]*$') {
        Throw-PspktParity 'self-test linked worktree could not read a common object'
    }
    $linkedAlternatesDirectory = [System.IO.Path]::Combine($linkedObjectDirectory, 'info')
    [void][System.IO.Directory]::CreateDirectory($linkedAlternatesDirectory)
    $linkedAlternatesPath = [System.IO.Path]::Combine($linkedAlternatesDirectory, 'alternates')
    [System.IO.File]::WriteAllText($linkedAlternatesPath, $scratch)
    $alternatesRejected = $false
    try {
        [void](Get-PspktCommonGitObjectDirectory -CommonGitDirectory $linkedCommonDirectory)
    }
    catch {
        $alternatesRejected = $true
        if ([string]$_.Exception.Message -notmatch 'alternates are not allowed') {
            throw
        }
    }
    finally {
        [System.IO.File]::Delete($linkedAlternatesPath)
    }
    if (-not $alternatesRejected) {
        Throw-PspktParity 'self-test common Git alternates were accepted'
    }

    $staleRepo = [System.IO.Path]::Combine($scratch, 'git stale readme')
    $staleGit = Initialize-PspktSelfRepo -RepoPath $staleRepo
    $staleText = "generator still uses ConvertTo-Json`r`nIts PS5/PS7 byte parity is deferred and is not fixed.`n"
    Add-PspktSelfCommit -RepoPath $staleRepo -GitDir $staleGit -RelativePath 'certification/README.md' -Content ([System.Text.UTF8Encoding]::new($false).GetBytes($staleText))
    $staleFailed = $false
    try {
        $staleHead = (ConvertTo-PspktUtf8Text -Bytes (Invoke-PspktBoundGit -GitExecutablePath $gitExe -GitDir $staleGit -WorkTree $staleRepo -WorkingDirectory $staleRepo -Environment $environment -CommandArgs @('rev-parse', 'HEAD^{commit}'))).Trim()
        [void](Test-PspktCommittedReadme -GitExecutablePath $gitExe -GitDir $staleGit -WorkTree $staleRepo -WorkingDirectory $staleRepo -Environment $environment -CommitId $staleHead)
    }
    catch {
        $staleFailed = $true
        if ([string]$_.Exception.Message -notmatch 'ConvertTo-Json') {
            throw
        }
    }
    if (-not $staleFailed) {
        Throw-PspktParity 'self-test stale README did not fail'
    }

    $fixedRepo = [System.IO.Path]::Combine($scratch, 'git corrected readme')
    $fixedGit = Initialize-PspktSelfRepo -RepoPath $fixedRepo
    $fixedText = "New-PspktHostClassifierFixtures.ps1 emits host-classifier fixtures with Get-PspktCanonicalJsonBytes under Windows PowerShell 5.1 and PowerShell 7.`nPreviously generated files used ConvertTo-Json formatting.`n"
    Add-PspktSelfCommit -RepoPath $fixedRepo -GitDir $fixedGit -RelativePath 'certification/README.md' -Content ([System.Text.UTF8Encoding]::new($false).GetBytes($fixedText))
    $fixedHead = (ConvertTo-PspktUtf8Text -Bytes (Invoke-PspktBoundGit -GitExecutablePath $gitExe -GitDir $fixedGit -WorkTree $fixedRepo -WorkingDirectory $fixedRepo -Environment $environment -CommandArgs @('rev-parse', 'HEAD^{commit}'))).Trim()
    if (-not (Test-PspktCommittedReadme -GitExecutablePath $gitExe -GitDir $fixedGit -WorkTree $fixedRepo -WorkingDirectory $fixedRepo -Environment $environment -CommitId $fixedHead)) {
        Throw-PspktParity 'self-test corrected README was reported absent'
    }

    $oversizeRepo = [System.IO.Path]::Combine($scratch, 'git oversize readme')
    $oversizeGit = Initialize-PspktSelfRepo -RepoPath $oversizeRepo
    $oversize = New-Object byte[] ($script:PspktReadmeSizeCap + 1)
    for ($fill = 0; $fill -lt $oversize.Length; $fill++) { $oversize[$fill] = 0x61 }
    Add-PspktSelfCommit -RepoPath $oversizeRepo -GitDir $oversizeGit -RelativePath 'certification/README.md' -Content $oversize
    $oversizeFailed = $false
    try {
        $overHead = (ConvertTo-PspktUtf8Text -Bytes (Invoke-PspktBoundGit -GitExecutablePath $gitExe -GitDir $oversizeGit -WorkTree $oversizeRepo -WorkingDirectory $oversizeRepo -Environment $environment -CommandArgs @('rev-parse', 'HEAD^{commit}'))).Trim()
        [void](Test-PspktCommittedReadme -GitExecutablePath $gitExe -GitDir $oversizeGit -WorkTree $oversizeRepo -WorkingDirectory $oversizeRepo -Environment $environment -CommitId $overHead)
    }
    catch {
        $oversizeFailed = $true
        if ([string]$_.Exception.Message -notmatch 'size cap') {
            throw
        }
    }
    if (-not $oversizeFailed) {
        Throw-PspktParity 'self-test oversize README did not fail'
    }

    $invalidRepo = [System.IO.Path]::Combine($scratch, 'git invalid utf8')
    $invalidGit = Initialize-PspktSelfRepo -RepoPath $invalidRepo
    Add-PspktSelfCommit -RepoPath $invalidRepo -GitDir $invalidGit -RelativePath 'certification/README.md' -Content ([byte[]](0x61, 0xFF, 0x80))
    $invalidFailed = $false
    try {
        $invalidHead = (ConvertTo-PspktUtf8Text -Bytes (Invoke-PspktBoundGit -GitExecutablePath $gitExe -GitDir $invalidGit -WorkTree $invalidRepo -WorkingDirectory $invalidRepo -Environment $environment -CommandArgs @('rev-parse', 'HEAD^{commit}'))).Trim()
        [void](Test-PspktCommittedReadme -GitExecutablePath $gitExe -GitDir $invalidGit -WorkTree $invalidRepo -WorkingDirectory $invalidRepo -Environment $environment -CommitId $invalidHead)
    }
    catch [System.Text.DecoderFallbackException] {
        $invalidFailed = $true
    }
    if (-not $invalidFailed) {
        Throw-PspktParity 'self-test invalid UTF-8 README did not fail'
    }

    $modeRepo = [System.IO.Path]::Combine($scratch, 'git nonregular')
    $modeGit = Initialize-PspktSelfRepo -RepoPath $modeRepo
    Add-PspktSelfCommit -RepoPath $modeRepo -GitDir $modeGit -RelativePath 'target.txt' -Content ([System.Text.UTF8Encoding]::new($false).GetBytes("t`n"))
    $linkDir = [System.IO.Path]::Combine($modeRepo, 'certification')
    [void][System.IO.Directory]::CreateDirectory($linkDir)
    $linkFile = [System.IO.Path]::Combine($linkDir, 'README.md')
    [System.IO.File]::WriteAllBytes($linkFile, [System.Text.UTF8Encoding]::new($false).GetBytes('target.txt'))
    $linkBlob = (ConvertTo-PspktUtf8Text -Bytes (Invoke-PspktBoundGit -GitExecutablePath $gitExe -GitDir $modeGit -WorkTree $modeRepo -WorkingDirectory $modeRepo -Environment $environment -CommandArgs @('hash-object', '-w', '--', 'certification/README.md'))).Trim()
    [void](Invoke-PspktBoundGit -GitExecutablePath $gitExe -GitDir $modeGit -WorkTree $modeRepo -WorkingDirectory $modeRepo -Environment $environment -CommandArgs @('update-index', '--add', '--cacheinfo', ('120000,{0},certification/README.md' -f $linkBlob)))
    $modeTree = (ConvertTo-PspktUtf8Text -Bytes (Invoke-PspktBoundGit -GitExecutablePath $gitExe -GitDir $modeGit -WorkTree $modeRepo -WorkingDirectory $modeRepo -Environment $environment -CommandArgs @('write-tree'))).Trim()
    $modeCommit = (ConvertTo-PspktUtf8Text -Bytes (Invoke-PspktBoundGit -GitExecutablePath $gitExe -GitDir $modeGit -WorkTree $modeRepo -WorkingDirectory $modeRepo -Environment $environment -CommandArgs @('commit-tree', $modeTree, '-p', [string]$selfRepoHeads[$modeRepo], '-m', 'symlink-readme'))).Trim()
    [void](Invoke-PspktBoundGit -GitExecutablePath $gitExe -GitDir $modeGit -WorkTree $modeRepo -WorkingDirectory $modeRepo -Environment $environment -CommandArgs @('update-ref', 'HEAD', $modeCommit))
    $selfRepoHeads[$modeRepo] = $modeCommit
    $modeHead = (ConvertTo-PspktUtf8Text -Bytes (Invoke-PspktBoundGit -GitExecutablePath $gitExe -GitDir $modeGit -WorkTree $modeRepo -WorkingDirectory $modeRepo -Environment $environment -CommandArgs @('rev-parse', 'HEAD^{commit}'))).Trim()
    $modeFailed = $false
    try {
        [void](Test-PspktCommittedReadme -GitExecutablePath $gitExe -GitDir $modeGit -WorkTree $modeRepo -WorkingDirectory $modeRepo -Environment $environment -CommitId $modeHead)
    }
    catch {
        $modeFailed = $true
        if ([string]$_.Exception.Message -notmatch 'regular blob') {
            throw
        }
    }
    if (-not $modeFailed) {
        Throw-PspktParity 'self-test non-regular README did not fail'
    }

    $replaceRepo = [System.IO.Path]::Combine($scratch, 'git replace ref')
    $replaceGit = Initialize-PspktSelfRepo -RepoPath $replaceRepo
    Add-PspktSelfCommit -RepoPath $replaceRepo -GitDir $replaceGit -RelativePath 'certification/README.md' -Content ([System.Text.UTF8Encoding]::new($false).GetBytes("original canonical bytes`n")) -Message 'original'
    $originalHead = (ConvertTo-PspktUtf8Text -Bytes (Invoke-PspktBoundGit -GitExecutablePath $gitExe -GitDir $replaceGit -WorkTree $replaceRepo -WorkingDirectory $replaceRepo -Environment $environment -CommandArgs @('rev-parse', 'HEAD^{commit}'))).Trim()
    Add-PspktSelfCommit -RepoPath $replaceRepo -GitDir $replaceGit -RelativePath 'certification/README.md' -Content ([System.Text.UTF8Encoding]::new($false).GetBytes("ConvertTo-Json redirected`n")) -Message 'redirected'
    $redirectHead = (ConvertTo-PspktUtf8Text -Bytes (Invoke-PspktBoundGit -GitExecutablePath $gitExe -GitDir $replaceGit -WorkTree $replaceRepo -WorkingDirectory $replaceRepo -Environment $environment -CommandArgs @('rev-parse', 'HEAD^{commit}'))).Trim()
    [void](Invoke-PspktBoundGit -GitExecutablePath $gitExe -GitDir $replaceGit -WorkTree $replaceRepo -WorkingDirectory $replaceRepo -Environment $environment -CommandArgs @('replace', $originalHead, $redirectHead) -AllowStderr)
    $replacedOriginal = (ConvertTo-PspktUtf8Text -Bytes (Invoke-PspktBoundGit -GitExecutablePath $gitExe -GitDir $replaceGit -WorkTree $replaceRepo -WorkingDirectory $replaceRepo -Environment $environment -CommandArgs @('rev-parse', ($originalHead + '^{commit}')))).Trim()
    if ($replacedOriginal -cne $originalHead) {
        Throw-PspktParity 'self-test replace-ref redirected pinned commit'
    }
    if (-not (Test-PspktCommittedReadme -GitExecutablePath $gitExe -GitDir $replaceGit -WorkTree $replaceRepo -WorkingDirectory $replaceRepo -Environment $environment -CommitId $originalHead)) {
        Throw-PspktParity 'self-test replace-ref README was reported absent'
    }

    $poisonHome = [System.IO.Path]::Combine($scratch, 'poison-home')
    [void][System.IO.Directory]::CreateDirectory($poisonHome)
    $previousGitDir = [System.Environment]::GetEnvironmentVariable('GIT_DIR')
    $previousWorkTree = [System.Environment]::GetEnvironmentVariable('GIT_WORK_TREE')
    $previousIndex = [System.Environment]::GetEnvironmentVariable('GIT_INDEX_FILE')
    $previousAttr = [System.Environment]::GetEnvironmentVariable('GIT_ATTR_SOURCE')
    $previousHome = [System.Environment]::GetEnvironmentVariable('HOME')
    $previousXdg = [System.Environment]::GetEnvironmentVariable('XDG_CONFIG_HOME')
    try {
        [System.Environment]::SetEnvironmentVariable('GIT_DIR', $poisonHome)
        [System.Environment]::SetEnvironmentVariable('GIT_WORK_TREE', $poisonHome)
        [System.Environment]::SetEnvironmentVariable('GIT_INDEX_FILE', [System.IO.Path]::Combine($poisonHome, 'index'))
        [System.Environment]::SetEnvironmentVariable('GIT_ATTR_SOURCE', [System.IO.Path]::Combine($poisonHome, 'attributes'))
        [System.Environment]::SetEnvironmentVariable('HOME', $poisonHome)
        [System.Environment]::SetEnvironmentVariable('XDG_CONFIG_HOME', $poisonHome)
        $poisonHead = (ConvertTo-PspktUtf8Text -Bytes (Invoke-PspktBoundGit -GitExecutablePath $gitExe -GitDir $absentGit -WorkTree $absentRepo -WorkingDirectory $absentRepo -Environment $environment -CommandArgs @('rev-parse', 'HEAD^{commit}'))).Trim()
        if ($poisonHead -cnotmatch '^[0-9a-f]{40}$') {
            Throw-PspktParity 'self-test poisoned environment redirected git'
        }
    }
    finally {
        [System.Environment]::SetEnvironmentVariable('GIT_DIR', $previousGitDir)
        [System.Environment]::SetEnvironmentVariable('GIT_WORK_TREE', $previousWorkTree)
        [System.Environment]::SetEnvironmentVariable('GIT_INDEX_FILE', $previousIndex)
        [System.Environment]::SetEnvironmentVariable('GIT_ATTR_SOURCE', $previousAttr)
        [System.Environment]::SetEnvironmentVariable('HOME', $previousHome)
        [System.Environment]::SetEnvironmentVariable('XDG_CONFIG_HOME', $previousXdg)
    }

    $echoDir = [System.IO.Path]::Combine($scratch, 'argv echo')
    [void][System.IO.Directory]::CreateDirectory($echoDir)
    $echoExe = [System.IO.Path]::Combine($echoDir, 'echoargs.exe')
    $echoCs = [System.IO.Path]::Combine($echoDir, 'echoargs.cs')
    $echoSource = @"
using System;
using System.Globalization;
using System.Text;
public static class Program
{
    public static int Main(string[] args)
    {
        Console.OutputEncoding = new UTF8Encoding(false);
        if (args.Length == 2 && string.Equals(args[0], "--emit", StringComparison.Ordinal))
        {
            int remaining;
            if (!int.TryParse(args[1], NumberStyles.None, CultureInfo.InvariantCulture, out remaining) || remaining < 0)
            {
                return 2;
            }

            string chunk = new string('x', 8192);
            while (remaining > 0)
            {
                int count = Math.Min(remaining, chunk.Length);
                Console.Out.Write(chunk.Substring(0, count));
                remaining -= count;
            }

            return 0;
        }

        for (int i = 0; i < args.Length; i++)
        {
            Console.Out.Write(args[i].Length.ToString(CultureInfo.InvariantCulture));
            Console.Out.Write('\t');
            Console.Out.WriteLine(args[i]);
        }
        return 0;
    }
}
"@
    [System.IO.File]::WriteAllBytes($echoCs, [System.Text.UTF8Encoding]::new($false).GetBytes($echoSource.Replace("`r`n", "`n")))
    $csc = [System.IO.Path]::Combine([System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory(), 'csc.exe')
    if (-not [System.IO.File]::Exists($csc)) {
        $frameworkDirectoryName = 'Framework'
        if ([System.Environment]::Is64BitProcess) {
            $frameworkDirectoryName = 'Framework64'
        }
        $csc = [System.IO.Path]::Combine(
            [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::Windows),
            'Microsoft.NET',
            $frameworkDirectoryName,
            'v4.0.30319',
            'csc.exe')
    }
    if (-not [System.IO.File]::Exists($csc)) {
        Throw-PspktParity ('csc.exe was not found for argv echo at {0}' -f $csc)
    }
    $cscAuthority = Open-PspktExecutableAuthority -Path $csc -Label 'framework csc'
    try {
        Assert-PspktExecutableAuthority -Authority $cscAuthority
        $cscResult = Invoke-PspktTextProcess -FileName $cscAuthority.Path `
            -Arguments @('/nologo', ('/out:{0}' -f $echoExe), $echoCs) `
            -WorkingDirectory $echoDir
        Assert-PspktExecutableAuthority -Authority $cscAuthority
        if ($cscResult.ExitCode -ne 0 -or -not [System.IO.File]::Exists($echoExe)) {
            Throw-PspktParity ('argv echo compile failed: {0}{1}' -f $cscResult.Stdout, $cscResult.Stderr)
        }
    }
    finally {
        $cscAuthority.Stream.Dispose()
    }
    $echoAuthority = Open-PspktExecutableAuthority -Path $echoExe -Label 'argv echo'
    try {
        $outputCapFailed = $false
        try {
            Assert-PspktExecutableAuthority -Authority $echoAuthority
            [void](Invoke-PspktTextProcess -FileName $echoAuthority.Path `
                    -Arguments @('--emit', '2000000') -WorkingDirectory $echoDir -TimeoutMilliseconds 60000)
        }
        catch {
            $outputCapFailed = $true
            if ([string]$_.Exception.ToString() -notmatch 'Process output exceeded 1048576 bytes') {
                throw
            }
        }
        if (-not $outputCapFailed) {
            Throw-PspktParity 'self-test validator output cap did not fail'
        }
        $quoteCases = @(
            @{ Name = 'empty'; Args = @('') },
            @{ Name = 'space'; Args = @('hello world') },
            @{ Name = 'quote'; Args = @('a"b') },
            @{ Name = 'slash'; Args = @('trail path\') }
        )
        foreach ($quoteCase in $quoteCases) {
            Assert-PspktExecutableAuthority -Authority $echoAuthority
            $echoResult = Invoke-PspktTextProcess -FileName $echoAuthority.Path `
                -Arguments @($quoteCase.Args) -WorkingDirectory $echoDir
            if ($echoResult.ExitCode -ne 0) {
                Throw-PspktParity ('argv echo failed for {0}: {1}' -f $quoteCase.Name, $echoResult.Stderr)
            }
            $line = ($echoResult.Stdout -split "`n")[0].TrimEnd("`r")
            $tab = $line.IndexOf([char]9)
            if ($tab -lt 0) {
                Throw-PspktParity ('argv echo malformed for {0}' -f $quoteCase.Name)
            }
            $got = $line.Substring($tab + 1)
            if ($got -cne [string]$quoteCase.Args[0]) {
                Throw-PspktParity ('argv echo mismatch for {0}' -f $quoteCase.Name)
            }
        }
        Assert-PspktExecutableAuthority -Authority $echoAuthority
    }
    finally {
        $echoAuthority.Stream.Dispose()
    }
    Write-Host ($script:PspktParityPrefix + 'git authority and argument-quoting self-tests: pass')
}

function Invoke-PspktVectorValidation {
    param(
        [Parameter(Mandatory = $true)][string]$CertificationRootValue,
        [string]$RepositoryRootValue
    )
    $owned = New-Object 'System.Collections.Generic.List[object]'
    $nativeStream = $null
    try {
        $certRoot = Get-PspktBclFullPath -Path $CertificationRootValue
        $libDir = Get-PspktBclFullPath -Path ([System.IO.Path]::Combine($certRoot, 'lib'))
        $vectorsDir = Get-PspktBclFullPath -Path ([System.IO.Path]::Combine($certRoot, 'vectors'))
        $hostClassifierDir = Get-PspktBclFullPath -Path ([System.IO.Path]::Combine($vectorsDir, 'host-classifier'))
        $resultDir = Get-PspktBclFullPath -Path ([System.IO.Path]::Combine($vectorsDir, 'certification-result'))
        $nativePath = Get-PspktBclFullPath -Path ([System.IO.Path]::Combine($libDir, 'Pspkt.Certification.HostClassifierVectorNative.cs'))
        $canonicalPath = Get-PspktBclFullPath -Path ([System.IO.Path]::Combine($libDir, 'Pspkt.Certification.CanonicalJson.ps1'))
        $classifierPath = Get-PspktBclFullPath -Path ([System.IO.Path]::Combine($libDir, 'Pspkt.Certification.HostClassifier.ps1'))

        $certAttributes = [System.IO.File]::GetAttributes($certRoot)
        if (($certAttributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            Throw-PspktParity ('reparse point rejected for ''{0}''' -f $certRoot)
        }
        Assert-PspktOrdinaryDirectory -Path $libDir -Parent $certRoot
        Assert-PspktOrdinaryDirectory -Path $vectorsDir -Parent $certRoot
        Assert-PspktOrdinaryDirectory -Path $hostClassifierDir -Parent $certRoot
        Assert-PspktOrdinaryDirectory -Path $resultDir -Parent $certRoot
        Assert-PspktOrdinaryFile -Path $nativePath -Parent $certRoot
        Assert-PspktOrdinaryFile -Path $canonicalPath -Parent $certRoot
        Assert-PspktOrdinaryFile -Path $classifierPath -Parent $certRoot

        $nativeBytes = Read-PspktNativeSourceBytes -NativePath $nativePath -Stream ([ref]$nativeStream)
        $helperType = Import-PspktNativeHelper -SourceBytes $nativeBytes -SourcePath $nativePath

        $certHandle = $helperType::OpenDirectory($certRoot)
        [void]$owned.Add($certHandle)
        if ($certHandle.IsReparsePoint) { Throw-PspktParity ('reparse point rejected for ''{0}''' -f $certRoot) }
        $vectorsHandle = $helperType::OpenDirectory($vectorsDir)
        [void]$owned.Add($vectorsHandle)
        if ($vectorsHandle.IsReparsePoint) { Throw-PspktParity ('reparse point rejected for ''{0}''' -f $vectorsDir) }
        $hostHandle = $helperType::OpenDirectory($hostClassifierDir)
        [void]$owned.Add($hostHandle)
        if ($hostHandle.IsReparsePoint) { Throw-PspktParity ('reparse point rejected for ''{0}''' -f $hostClassifierDir) }
        $resultHandle = $helperType::OpenDirectory($resultDir)
        [void]$owned.Add($resultHandle)
        if ($resultHandle.IsReparsePoint) { Throw-PspktParity ('reparse point rejected for ''{0}''' -f $resultDir) }

        $canonicalHandle = $helperType::OpenFile($canonicalPath, $false)
        [void]$owned.Add($canonicalHandle)
        if ($canonicalHandle.IsReparsePoint -or $canonicalHandle.NumberOfLinks -ne 1) {
            Throw-PspktParity 'canonical writer source identity is unsafe'
        }
        $classifierHandle = $helperType::OpenFile($classifierPath, $false)
        [void]$owned.Add($classifierHandle)
        if ($classifierHandle.IsReparsePoint -or $classifierHandle.NumberOfLinks -ne 1) {
            Throw-PspktParity 'classifier source identity is unsafe'
        }

        $canonicalScript = New-PspktPinnedSourceScriptBlock -Handle $canonicalHandle `
            -ExpectedLength $script:PspktCanonicalSourceLength -ExpectedSha256 $script:PspktCanonicalSourceSha256 `
            -Label 'canonical writer'
        $classifierScript = New-PspktPinnedSourceScriptBlock -Handle $classifierHandle `
            -ExpectedLength $script:PspktClassifierSourceLength -ExpectedSha256 $script:PspktClassifierSourceSha256 `
            -Label 'host classifier'
        . $canonicalScript
        . $classifierScript

        $inventory = @(Get-ChildItem -LiteralPath $hostClassifierDir -Force)
        if ($inventory.Count -ne 9) {
            Throw-PspktParity ('host-classifier inventory is not the exact nine ordinary JSON files (count={0})' -f $inventory.Count)
        }
        $inventoryNames = New-Object 'System.Collections.Generic.List[string]'
        foreach ($entry in $inventory) {
            if ($entry.PSIsContainer) {
                Throw-PspktParity ('host-classifier inventory is not the exact nine ordinary JSON files (directory={0})' -f $entry.Name)
            }
            $entryAttributes = $entry.Attributes
            if (($entryAttributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
                ($entryAttributes -band [System.IO.FileAttributes]::Hidden) -ne 0 -or
                ($entryAttributes -band [System.IO.FileAttributes]::System) -ne 0 -or
                -not $entry.Name.EndsWith('.json', [System.StringComparison]::Ordinal)) {
                Throw-PspktParity ('host-classifier inventory is not the exact nine ordinary JSON files ({0})' -f $entry.Name)
            }
            [void]$inventoryNames.Add($entry.Name)
        }
        foreach ($expectedName in $script:PspktHostClassifierNames) {
            $foundName = $false
            foreach ($actualName in $inventoryNames) {
                if ($actualName -ceq $expectedName) { $foundName = $true; break }
            }
            if (-not $foundName) {
                Throw-PspktParity ('host-classifier inventory is not the exact nine ordinary JSON files (missing={0})' -f $expectedName)
            }
        }

        Assert-PspktOrdinaryFile -Path ([System.IO.Path]::Combine($resultDir, 'sample-artifact.v1.json')) -Parent $certRoot
        Assert-PspktOrdinaryFile -Path ([System.IO.Path]::Combine($resultDir, 'sample-attestation.v1.json')) -Parent $certRoot

        $utf8 = [System.Text.UTF8Encoding]::new($false, $true)
        $artifactSha = $null
        foreach ($relativePath in $script:PspktExpectedRelativePaths) {
            $fullPath = [System.IO.Path]::Combine($vectorsDir, ($relativePath -replace '/', [string][System.IO.Path]::DirectorySeparatorChar))
            if (-not [System.IO.File]::Exists($fullPath)) {
                Throw-PspktParity ('missing leaf ''{0}''' -f $relativePath)
            }
            $fileHandle = $helperType::OpenFile($fullPath, $false)
            [void]$owned.Add($fileHandle)
            if ($fileHandle.IsReparsePoint) {
                Throw-PspktParity ('reparse point rejected for ''{0}''' -f $relativePath)
            }
            if ($fileHandle.NumberOfLinks -ne 1) {
                Throw-PspktParity ('hardlink rejected for ''{0}'' (nNumberOfLinks={1})' -f $relativePath, $fileHandle.NumberOfLinks)
            }
            [byte[]]$rawBytes = $fileHandle.ReadExact()
            $oracle = $script:PspktFrozenOracle[$relativePath]
            if ($rawBytes.Length -ne [int]$oracle.Length) {
                Throw-PspktParity ('frozen length mismatch for ''{0}''' -f $relativePath)
            }
            $rawSha = Get-PspktSha256Hex -Bytes $rawBytes
            if ($rawSha -cne [string]$oracle.Sha256) {
                Throw-PspktParity ('frozen hash mismatch for ''{0}''' -f $relativePath)
            }
            if ($rawBytes.Length -ge 3 -and $rawBytes[0] -eq 0xEF -and $rawBytes[1] -eq 0xBB -and $rawBytes[2] -eq 0xBF) {
                Throw-PspktParity ('BOM forbidden for ''{0}''' -f $relativePath)
            }
            $text = $utf8.GetString($rawBytes)
            $document = $text | ConvertFrom-Json
            [byte[]]$canonicalBytes = Get-PspktCanonicalJsonBytes -Value $document
            if (-not (Test-PspktBytesEqual -Left $rawBytes -Right $canonicalBytes)) {
                Throw-PspktParity ('raw bytes are not canonical for ''{0}''' -f $relativePath)
            }
            if ($relativePath.StartsWith('host-classifier/', [System.StringComparison]::Ordinal)) {
                $probe = ConvertTo-PspktLocalProbeHashtable -ProbeObject $document.probe
                $seat = Resolve-PspktHostSeat -Probe $probe
                $expected = $document.expected
                if ([string]$seat.TerminalKind -cne [string]$expected.terminalKind -or
                    [string]$seat.ShellKind -cne [string]$expected.shellKind -or
                    [string]$seat.Architecture -cne [string]$expected.architecture -or
                    [string]$seat.Status -cne [string]$expected.status -or
                    [string]$seat.Reason -cne [string]$expected.reason -or
                    -not (Test-PspktStringArrayEqual -Left $seat.HostKey -Right $expected.hostKey)) {
                    Throw-PspktParity ('classifier expectation mismatch for ''{0}''' -f $relativePath)
                }
            }
            if ($relativePath -ceq 'certification-result/sample-artifact.v1.json') {
                $artifactSha = $rawSha
            }
            if ($relativePath -ceq 'certification-result/sample-attestation.v1.json') {
                if ([string]$document.subjectDigestSha256 -cne $artifactSha) {
                    Throw-PspktParity 'artifact attestation digest mismatch'
                }
            }
        }
        Write-Host ($script:PspktParityPrefix + 'vector validation: 11 of 11 pass')

        if ([string]::IsNullOrEmpty($RepositoryRootValue)) {
            Write-Host ($script:PspktParityPrefix + 'README fossil check: not-applicable')
        }
        else {
            $gitHome = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), ('pspkt-hc-git-' + [guid]::NewGuid().ToString('N')))
            [void][System.IO.Directory]::CreateDirectory($gitHome)
            try {
                Invoke-PspktGitAuthorityProof -RepositoryRoot $RepositoryRootValue -ScratchHome $gitHome
            }
            finally {
                if ([System.IO.Directory]::Exists($gitHome)) {
                    Remove-PspktOwnedDirectoryTree -Path $gitHome
                }
            }
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
}

try {
    if ($PSCmdlet.ParameterSetName -ceq 'SelfTest') {
        $validatorPath = Get-PspktBclFullPath -Path $MyInvocation.MyCommand.Path
        $validatorDirectory = [System.IO.Path]::GetDirectoryName($validatorPath)
        $selfTestCertificationRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($validatorDirectory, '..'))
        Invoke-PspktVectorValidation -CertificationRootValue $selfTestCertificationRoot
        Invoke-PspktGitSelfTests -ScratchRoot $ScratchRoot
    }
    else {
        Invoke-PspktVectorValidation -CertificationRootValue $CertificationRoot -RepositoryRootValue $RepositoryRoot
    }
}
finally {
    Close-PspktGitExecutableAuthority
}
