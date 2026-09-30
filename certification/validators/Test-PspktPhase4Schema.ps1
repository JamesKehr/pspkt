[CmdletBinding(PositionalBinding = $false)]
param(
    [Parameter(Mandatory = $true)]
    [string]$ParserSourcePath,

    [Parameter(Mandatory = $true)]
    [string]$FixtureManifestPath,

    [Parameter(Mandatory = $true)]
    [string]$MetaSchemaPath,

    [Parameter(Mandatory = $true)]
    [string]$ResultPath
)

$gateName = [System.Environment]::GetEnvironmentVariable('PSPKT_PHASE4_GATE_EVENT')
if ([string]::IsNullOrEmpty($gateName) -or
    $gateName.Length -gt 112 -or
    $gateName -cnotmatch '^Local\\PspktPhase4[A-Za-z0-9_]{1,95}$') {
    [Console]::Error.WriteLine('Test-PspktPhase4Schema: gate authority is missing or malformed.')
    exit 2
}
$gateTimeoutText = [System.Environment]::GetEnvironmentVariable('PSPKT_PHASE4_GATE_TIMEOUT_MS')
$gateTimeoutMilliseconds = 0
if (-not [int]::TryParse(
        $gateTimeoutText,
        [System.Globalization.NumberStyles]::None,
        [System.Globalization.CultureInfo]::InvariantCulture,
        [ref]$gateTimeoutMilliseconds) -or
    $gateTimeoutMilliseconds -lt 1000 -or
    $gateTimeoutMilliseconds -gt 30000) {
    [Console]::Error.WriteLine('Test-PspktPhase4Schema: gate timeout authority is missing or malformed.')
    exit 2
}
$gateHandle = $null
try {
    $gateHandle = [System.Threading.EventWaitHandle]::OpenExisting($gateName)
}
catch {
    [Console]::Error.WriteLine('Test-PspktPhase4Schema: unable to open the gate event.')
    exit 2
}
try {
    $gateSignalled = $gateHandle.WaitOne($gateTimeoutMilliseconds)
}
finally {
    $gateHandle.Dispose()
}
if (-not $gateSignalled) {
    [Console]::Error.WriteLine('Test-PspktPhase4Schema: gate wait timed out.')
    exit 5
}

$PspktExitComplete = 0
$PspktExitUsage = 2
$PspktExitCompile = 3
$PspktExitFatal = 4
$PspktExitSealedAuthorityRequired = 8
$PspktHelperByteCap = 4194304
$PspktResultByteCap = 262144
$PspktExpectedCaseCount = 68
$PspktExpectedHelperVersion = 'pspkt-phase4-bounded-process-2'

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-PspktChildError {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Message)
    [Console]::Error.WriteLine('Test-PspktPhase4Schema: ' + $Message)
}

function Test-PspktTryGetPathAttributes {
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][ref]$Attributes,
        [AllowNull()][scriptblock]$AttributeReader = $null
    )

    try {
        if ($null -eq $AttributeReader) {
            $resolvedAttributes = [System.IO.File]::GetAttributes($Path)
        }
        else {
            $resolvedAttributes = & $AttributeReader $Path
        }
    }
    catch {
        $pathException = $_.Exception
        while ($pathException -is [System.Management.Automation.MethodInvocationException] -and
            $null -ne $pathException.InnerException) {
            $pathException = $pathException.InnerException
        }
        if ($pathException -is [System.IO.FileNotFoundException] -or
            $pathException -is [System.IO.DirectoryNotFoundException]) {
            $Attributes.Value = [System.IO.FileAttributes]0
            return $false
        }
        throw
    }

    $Attributes.Value = [System.IO.FileAttributes]$resolvedAttributes
    return $true
}

function Assert-PspktCanonicalPath {
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]
        [ValidateSet('File', 'Directory', 'MissingLeaf')]
        [string]$Kind
    )

    if ([string]::IsNullOrEmpty($Path) -or
        $Path.IndexOfAny([System.IO.Path]::GetInvalidPathChars()) -ge 0 -or
        -not [System.IO.Path]::IsPathRooted($Path)) {
        throw ('path "{0}" is not absolute.' -f $Path)
    }
    $fullPath = [System.IO.Path]::GetFullPath($Path)
    if ($Path -cne $fullPath) {
        throw ('path "{0}" is not canonical.' -f $Path)
    }

    $pathRoot = [System.IO.Path]::GetPathRoot($fullPath)
    if ([string]::IsNullOrEmpty($pathRoot)) {
        throw ('path "{0}" has no rooted volume.' -f $fullPath)
    }
    $currentPath = $pathRoot
    $rootAttributes = [System.IO.FileAttributes]0
    if (Test-PspktTryGetPathAttributes -Path $currentPath -Attributes ([ref]$rootAttributes)) {
        if (($rootAttributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw ('path root "{0}" is a reparse point.' -f $currentPath)
        }
    }
    $relativePath = $fullPath.Substring($pathRoot.Length)
    $pathSeparators = [char[]]@([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)
    $pathComponents = @($relativePath.Split($pathSeparators, [System.StringSplitOptions]::RemoveEmptyEntries))
    for ($pathComponentIndex = 0; $pathComponentIndex -lt $pathComponents.Count; $pathComponentIndex++) {
        $pathComponent = $pathComponents[$pathComponentIndex]
        $currentPath = [System.IO.Path]::Combine($currentPath, $pathComponent)
        if ($Kind -ceq 'MissingLeaf' -and $pathComponentIndex -eq ($pathComponents.Count - 1)) {
            continue
        }
        $attributes = [System.IO.FileAttributes]0
        if (Test-PspktTryGetPathAttributes -Path $currentPath -Attributes ([ref]$attributes)) {
            if (($attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw ('path component "{0}" is a reparse point.' -f $currentPath)
            }
        }
    }

    if ($Kind -ceq 'File' -and -not [System.IO.File]::Exists($fullPath)) {
        throw ('required file "{0}" does not exist.' -f $fullPath)
    }
    if ($Kind -ceq 'Directory' -and -not [System.IO.Directory]::Exists($fullPath)) {
        throw ('required directory "{0}" does not exist.' -f $fullPath)
    }
    if ($Kind -ceq 'MissingLeaf') {
        $leafAttributes = [System.IO.FileAttributes]0
        if (Test-PspktTryGetPathAttributes -Path $fullPath -Attributes ([ref]$leafAttributes)) {
            throw ('required output leaf "{0}" already exists.' -f $fullPath)
        }
    }
    return $fullPath
}

function Assert-PspktOrdinalContainedPath {
    param(
        [Parameter(Mandatory = $true)][string]$FullPath,
        [Parameter(Mandatory = $true)][string]$RootPath
    )

    $separator = [System.IO.Path]::DirectorySeparatorChar
    $rootPrefix = $RootPath.TrimEnd($separator) + $separator
    if (-not $FullPath.StartsWith($rootPrefix, [System.StringComparison]::Ordinal)) {
        throw ('path "{0}" is outside exact root "{1}".' -f $FullPath, $RootPath)
    }
}

function Assert-PspktExactSnapshotPath {
    param(
        [Parameter(Mandatory = $true)][string]$ActualPath,
        [Parameter(Mandatory = $true)][string]$SnapshotRoot,
        [Parameter(Mandatory = $true)][string]$RelativePath
    )

    $expectedPath = [System.IO.Path]::GetFullPath(
        [System.IO.Path]::Combine($SnapshotRoot, $RelativePath))
    if (-not [string]::Equals($ActualPath, $expectedPath, [System.StringComparison]::Ordinal)) {
        throw ('path "{0}" is not exact snapshot source "{1}".' -f $ActualPath, $expectedPath)
    }
    Assert-PspktOrdinalContainedPath -FullPath $ActualPath -RootPath $SnapshotRoot
}

function Open-PspktRetainedFile {
    [OutputType([System.IO.FileStream])]
    param([Parameter(Mandatory = $true)][string]$FullPath)

    [void](Assert-PspktCanonicalPath -Path $FullPath -Kind File)
    return [System.IO.FileStream]::new(
        $FullPath,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::Read)
}

function Read-PspktRetainedBytes {
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory = $true)][System.IO.FileStream]$Stream,
        [Parameter(Mandatory = $true)][long]$ByteCap,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $length = $Stream.Length
    if ($length -lt 1 -or $length -gt $ByteCap) {
        throw ('{0} size {1} is outside 1..{2} bytes.' -f $Label, $length, $ByteCap)
    }
    $count = [int]$length
    $bytes = [byte[]]::new($count)
    $Stream.Position = 0
    $offset = 0
    while ($offset -lt $count) {
        $read = $Stream.Read($bytes, $offset, $count - $offset)
        if ($read -le 0) {
            throw ('{0} was truncated during retained read.' -f $Label)
        }
        $offset += $read
    }
    if ($Stream.ReadByte() -ne -1) {
        throw ('{0} grew during retained read.' -f $Label)
    }
    return , $bytes
}

function Get-PspktChildSha256Hex {
    [OutputType([string])]
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)

    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        $digestBytes = $sha256.ComputeHash($Bytes)
    }
    finally {
        $sha256.Dispose()
    }
    $digestBuilder = [System.Text.StringBuilder]::new(64)
    foreach ($digestByte in $digestBytes) {
        [void]$digestBuilder.Append(('{0:x2}' -f [int]$digestByte))
    }
    return $digestBuilder.ToString()
}

function Assert-PspktResultField {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if ($Value.IndexOf([char]0x09) -ge 0 -or
        $Value.IndexOf([char]0x0A) -ge 0 -or
        $Value.IndexOf([char]0x0D) -ge 0) {
        throw ('result field "{0}" contains a record delimiter.' -f $Label)
    }
}

function Write-PspktSealedSchemaResult {
    param(
        [Parameter(Mandatory = $true)][string]$OutputPath,
        [Parameter(Mandatory = $true)][string]$Nonce,
        [Parameter(Mandatory = $true)][string]$HelperVersion,
        [Parameter(Mandatory = $true)][object[]]$CaseResults
    )

    $tab = [string][char]0x09
    $lineFeed = [string][char]0x0A
    $textBuilder = [System.Text.StringBuilder]::new()
    [void]$textBuilder.Append('pspkt-phase4-schema-result-v2')
    [void]$textBuilder.Append($tab)
    [void]$textBuilder.Append($Nonce)
    [void]$textBuilder.Append($tab)
    [void]$textBuilder.Append($HelperVersion)
    [void]$textBuilder.Append($lineFeed)

    foreach ($caseResult in $CaseResults) {
        $fields = [string[]]@(
            'case',
            $caseResult.Ordinal.ToString([System.Globalization.CultureInfo]::InvariantCulture),
            $caseResult.Name,
            $caseResult.Path,
            $caseResult.Stage,
            $caseResult.ExpectedOutcome,
            $caseResult.ExpectedReason,
            $caseResult.ByteLength.ToString([System.Globalization.CultureInfo]::InvariantCulture),
            $caseResult.Sha256,
            $caseResult.ActualOutcome,
            $caseResult.ActualReason
        )
        if ($fields.Length -ne 11) {
            throw ('case {0} result row does not contain exactly 11 fields.' -f $caseResult.Ordinal)
        }
        for ($fieldIndex = 0; $fieldIndex -lt $fields.Length; $fieldIndex++) {
            Assert-PspktResultField -Value $fields[$fieldIndex] -Label ('case {0} field {1}' -f $caseResult.Ordinal, $fieldIndex)
        }
        [void]$textBuilder.Append(($fields -join $tab))
        [void]$textBuilder.Append($lineFeed)
    }

    [void]$textBuilder.Append('summary')
    [void]$textBuilder.Append($tab)
    [void]$textBuilder.Append($PspktExpectedCaseCount.ToString([System.Globalization.CultureInfo]::InvariantCulture))
    [void]$textBuilder.Append($tab)
    [void]$textBuilder.Append('pass')
    [void]$textBuilder.Append($lineFeed)

    $resultBytes = [System.Text.UTF8Encoding]::new($false, $true).GetBytes($textBuilder.ToString())
    if ($resultBytes.Length -gt $PspktResultByteCap) {
        throw ('sealed schema result is {0} bytes, exceeding the {1}-byte cap.' -f $resultBytes.Length, $PspktResultByteCap)
    }

    [void](Assert-PspktCanonicalPath -Path $OutputPath -Kind MissingLeaf)
    $outputStream = [System.IO.FileStream]::new(
        $OutputPath,
        [System.IO.FileMode]::CreateNew,
        [System.IO.FileAccess]::Write,
        [System.IO.FileShare]::None)
    try {
        $outputStream.Write($resultBytes, 0, $resultBytes.Length)
        $outputStream.Flush($true)
    }
    finally {
        $outputStream.Dispose()
    }
}

$sealedResultPath = [System.Environment]::GetEnvironmentVariable('PSPKT_PHASE4_SCHEMA_RESULT_PATH')
$sealedResultNonce = [System.Environment]::GetEnvironmentVariable('PSPKT_PHASE4_SCHEMA_RESULT_NONCE')
if ([string]::IsNullOrEmpty($sealedResultPath) -or [string]::IsNullOrEmpty($sealedResultNonce)) {
    Write-PspktChildError 'sealed schema result authority is required.'
    exit $PspktExitSealedAuthorityRequired
}

$expectedAuthorityNames = [string[]]@(
    'PSPKT_PHASE4_GATE_EVENT',
    'PSPKT_PHASE4_SNAPSHOT_ROOT',
    'PSPKT_PHASE4_REPOSITORY_ROOT',
    'PSPKT_PHASE4_HELPER_PATH',
    'PSPKT_PHASE4_HELPER_SHA256',
    'PSPKT_PHASE4_HELPER_VERSION',
    'PSPKT_PHASE4_SCHEMA_RESULT_PATH',
    'PSPKT_PHASE4_SCHEMA_RESULT_NONCE',
    'PSPKT_PHASE4_GATE_TIMEOUT_MS',
    'PSPKT_PHASE4_WATCHDOG_TIMEOUT_MS'
)
$expectedAuthoritySet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
foreach ($expectedAuthorityName in $expectedAuthorityNames) {
    [void]$expectedAuthoritySet.Add($expectedAuthorityName)
}
$presentAuthoritySet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
foreach ($environmentNameValue in [System.Environment]::GetEnvironmentVariables().GetEnumerator()) {
    $environmentName = [string]$environmentNameValue.Key
    if ($environmentName.StartsWith('PSPKT_PHASE4_', [System.StringComparison]::OrdinalIgnoreCase)) {
        if (-not $expectedAuthoritySet.Contains($environmentName)) {
            Write-PspktChildError ('unexpected reserved authority name "{0}".' -f $environmentName)
            exit $PspktExitFatal
        }
        if (-not $presentAuthoritySet.Add($environmentName)) {
            Write-PspktChildError ('duplicate reserved authority name "{0}".' -f $environmentName)
            exit $PspktExitFatal
        }
    }
}
foreach ($expectedAuthorityName in $expectedAuthorityNames) {
    if (-not $presentAuthoritySet.Contains($expectedAuthorityName)) {
        Write-PspktChildError ('required reserved authority name "{0}" is missing.' -f $expectedAuthorityName)
        exit $PspktExitFatal
    }
}

$snapshotRoot = [System.Environment]::GetEnvironmentVariable('PSPKT_PHASE4_SNAPSHOT_ROOT')
$repositoryRoot = [System.Environment]::GetEnvironmentVariable('PSPKT_PHASE4_REPOSITORY_ROOT')
$helperPath = [System.Environment]::GetEnvironmentVariable('PSPKT_PHASE4_HELPER_PATH')
$helperSha256 = [System.Environment]::GetEnvironmentVariable('PSPKT_PHASE4_HELPER_SHA256')
$helperVersion = [System.Environment]::GetEnvironmentVariable('PSPKT_PHASE4_HELPER_VERSION')
$watchdogTimeoutText = [System.Environment]::GetEnvironmentVariable('PSPKT_PHASE4_WATCHDOG_TIMEOUT_MS')
$watchdogTimeoutMilliseconds = 0
$parsedNonce = [guid]::Empty
$helperStream = $null
$helperAssembly = $null
$watchdogType = $null
$watchdogCompleteMethod = $null
$watchdogDisposeMethod = $null

try {
    if ([string]::IsNullOrEmpty($snapshotRoot) -or
        [string]::IsNullOrEmpty($repositoryRoot) -or
        [string]::IsNullOrEmpty($helperPath) -or
        [string]::IsNullOrEmpty($helperSha256) -or
        [string]::IsNullOrEmpty($helperVersion)) {
        throw 'one or more required schema child authority values are empty.'
    }
    if ($helperSha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw 'helper digest authority is not lowercase 64-hex.'
    }
    if ($helperVersion -cne $PspktExpectedHelperVersion) {
        throw 'helper version authority does not match the required version.'
    }
    if ($sealedResultNonce -cnotmatch '^[0-9a-f]{32}$' -or
        -not [guid]::TryParseExact($sealedResultNonce, 'N', [ref]$parsedNonce) -or
        $parsedNonce.ToString('N') -cne $sealedResultNonce) {
        throw 'sealed schema result nonce is not a lowercase GUID-N value.'
    }
    if (-not [int]::TryParse(
            $watchdogTimeoutText,
            [System.Globalization.NumberStyles]::None,
            [System.Globalization.CultureInfo]::InvariantCulture,
            [ref]$watchdogTimeoutMilliseconds) -or
        $watchdogTimeoutMilliseconds -lt 5000 -or
        $watchdogTimeoutMilliseconds -gt 180000) {
        throw 'watchdog timeout authority is outside 5000..180000 milliseconds.'
    }

    $snapshotRoot = Assert-PspktCanonicalPath -Path $snapshotRoot -Kind Directory
    $repositoryRoot = Assert-PspktCanonicalPath -Path $repositoryRoot -Kind Directory
    $helperPath = Assert-PspktCanonicalPath -Path $helperPath -Kind File
    $sealedResultPath = Assert-PspktCanonicalPath -Path $sealedResultPath -Kind MissingLeaf
    $resultRoot = [System.IO.Path]::GetDirectoryName($sealedResultPath)
    [void](Assert-PspktCanonicalPath -Path $resultRoot -Kind Directory)
    Assert-PspktOrdinalContainedPath -FullPath $sealedResultPath -RootPath $resultRoot

    $argumentResultPath = Assert-PspktCanonicalPath -Path $ResultPath -Kind MissingLeaf
    if (-not [string]::Equals($argumentResultPath, $sealedResultPath, [System.StringComparison]::Ordinal)) {
        throw 'ResultPath does not ordinal-match sealed result authority.'
    }

    $ParserSourcePath = Assert-PspktCanonicalPath -Path $ParserSourcePath -Kind File
    $FixtureManifestPath = Assert-PspktCanonicalPath -Path $FixtureManifestPath -Kind File
    $MetaSchemaPath = Assert-PspktCanonicalPath -Path $MetaSchemaPath -Kind File
    Assert-PspktExactSnapshotPath -ActualPath $ParserSourcePath -SnapshotRoot $snapshotRoot -RelativePath 'certification\lib\Pspkt.Certification.SchemaBootstrap.cs'
    Assert-PspktExactSnapshotPath -ActualPath $FixtureManifestPath -SnapshotRoot $snapshotRoot -RelativePath 'certification\vectors\phase4-schema\fixture-manifest.v1.json'
    Assert-PspktExactSnapshotPath -ActualPath $MetaSchemaPath -SnapshotRoot $snapshotRoot -RelativePath 'certification\schema\protocol-schema-meta.v1.json'

    $canonicalJsonPath = [System.IO.Path]::GetFullPath(
        [System.IO.Path]::Combine($snapshotRoot, 'certification\lib\Pspkt.Certification.CanonicalJson.ps1'))
    $fixtureContractPath = [System.IO.Path]::GetFullPath(
        [System.IO.Path]::Combine($snapshotRoot, 'certification\lib\Pspkt.Certification.SchemaFixtureContract.ps1'))
    [void](Assert-PspktCanonicalPath -Path $canonicalJsonPath -Kind File)
    [void](Assert-PspktCanonicalPath -Path $fixtureContractPath -Kind File)
    Assert-PspktExactSnapshotPath -ActualPath $canonicalJsonPath -SnapshotRoot $snapshotRoot -RelativePath 'certification\lib\Pspkt.Certification.CanonicalJson.ps1'
    Assert-PspktExactSnapshotPath -ActualPath $fixtureContractPath -SnapshotRoot $snapshotRoot -RelativePath 'certification\lib\Pspkt.Certification.SchemaFixtureContract.ps1'

    $helperStream = Open-PspktRetainedFile -FullPath $helperPath
    $helperBytes = Read-PspktRetainedBytes -Stream $helperStream -ByteCap $PspktHelperByteCap -Label 'helper assembly'
    $actualHelperSha256 = Get-PspktChildSha256Hex -Bytes $helperBytes
    if ($actualHelperSha256 -cne $helperSha256) {
        throw 'helper assembly digest does not match the pinned authority.'
    }
    $helperAssembly = [System.Reflection.Assembly]::Load($helperBytes)
    if (-not [string]::IsNullOrEmpty($helperAssembly.Location)) {
        throw 'helper assembly was not loaded from bytes.'
    }

    $hostType = $helperAssembly.GetType('Pspkt.Certification.BoundedProcessHost', $false)
    $watchdogType = $helperAssembly.GetType('Pspkt.Certification.SchemaChildWatchdog', $false)
    if ($null -eq $hostType -or $null -eq $watchdogType) {
        throw 'helper assembly does not expose required schema child types.'
    }
    $versionField = $hostType.GetField('Version', [System.Reflection.BindingFlags]'Public, Static')
    $watchdogExitCodeField = $watchdogType.GetField('WatchdogExitCode', [System.Reflection.BindingFlags]'Public, Static')
    if ($null -eq $versionField -or
        -not $versionField.IsLiteral -or
        $versionField.FieldType -ne [string] -or
        ([string]$versionField.GetRawConstantValue()) -cne $helperVersion) {
        throw 'helper assembly version constant does not match authority.'
    }
    if ($null -eq $watchdogExitCodeField -or
        -not $watchdogExitCodeField.IsLiteral -or
        ([int]$watchdogExitCodeField.GetRawConstantValue()) -ne 6) {
        throw 'schema child watchdog exit code does not equal 6.'
    }
    $watchdogCompleteMethod = $watchdogType.GetMethod('Complete', [type[]]@())
    $watchdogDisposeMethod = $watchdogType.GetMethod('DisposeBounded', [type[]]@([int]))
    if ($null -eq $watchdogCompleteMethod -or
        $watchdogCompleteMethod.ReturnType -ne [bool] -or
        $null -eq $watchdogDisposeMethod -or
        $watchdogDisposeMethod.ReturnType -ne [bool]) {
        throw 'schema child watchdog method surface does not match.'
    }
}
catch {
    if ($null -ne $helperStream) {
        $helperStream.Dispose()
    }
    Write-PspktChildError ('sealed authority validation failed: {0}' -f $_.Exception.Message)
    exit $PspktExitFatal
}

$retainedStreams = [System.Collections.Generic.List[System.IO.FileStream]]::new()
$retainedPaths = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
[void]$retainedStreams.Add($helperStream)
[void]$retainedPaths.Add($helperPath)
$watchdog = [System.Activator]::CreateInstance(
    $watchdogType,
    [object[]]@([int]$watchdogTimeoutMilliseconds))

function Add-PspktRetainedSource {
    param([Parameter(Mandatory = $true)][string]$FullPath)

    if ($retainedPaths.Add($FullPath)) {
        $sourceStream = Open-PspktRetainedFile -FullPath $FullPath
        [void]$retainedStreams.Add($sourceStream)
    }
}

function Invoke-PspktSchemaChildBody {
    [OutputType([int])]
    param()

    $certificationRoot = [System.IO.Path]::GetFullPath(
        [System.IO.Path]::Combine($snapshotRoot, 'certification'))
    [void](Assert-PspktCanonicalPath -Path $certificationRoot -Kind Directory)
    Assert-PspktOrdinalContainedPath -FullPath $certificationRoot -RootPath $snapshotRoot

    Add-PspktRetainedSource -FullPath $canonicalJsonPath
    Add-PspktRetainedSource -FullPath $fixtureContractPath
    Add-PspktRetainedSource -FullPath $ParserSourcePath
    Add-PspktRetainedSource -FullPath $FixtureManifestPath
    Add-PspktRetainedSource -FullPath $MetaSchemaPath

    . $canonicalJsonPath
    . $fixtureContractPath

    $contract = Get-PspktPhase4Contract
    if ([int]$contract.ExpectedCaseCount -ne $PspktExpectedCaseCount) {
        throw ('shared ExpectedCaseCount is {0}, expected literal {1}.' -f $contract.ExpectedCaseCount, $PspktExpectedCaseCount)
    }

    $manifestBytes = Assert-PspktPhase4CanonicalFile `
        -FullPath $FixtureManifestPath `
        -ByteCap $contract.ManifestByteCap `
        -Label 'fixture manifest'
    $manifestText = [System.Text.UTF8Encoding]::new($false, $true).GetString($manifestBytes)
    $manifest = $manifestText | ConvertFrom-Json
    Assert-PspktPhase4ManifestShape -Manifest $manifest
    $cases = @(Get-PspktPhase4NormalizedCases -Manifest $manifest)
    if ($cases.Count -ne $PspktExpectedCaseCount) {
        throw ('normalized case count is {0}, expected {1}.' -f $cases.Count, $PspktExpectedCaseCount)
    }
    [void](Assert-PspktPhase4CorpusFileSet `
            -Cases $cases `
            -RepositoryRoot $snapshotRoot `
            -CertRoot $certificationRoot)

    $metaBytes = Assert-PspktPhase4CanonicalFile `
        -FullPath $MetaSchemaPath `
        -ByteCap $contract.MetaByteCap `
        -Label 'committed protocol schema meta'

    foreach ($case in $cases) {
        $caseFullPath = Resolve-PspktPhase4FullPath `
            -RepoPath $case.Path `
            -RepositoryRoot $snapshotRoot `
            -CertRoot $certificationRoot
        Assert-PspktOrdinalContainedPath -FullPath $caseFullPath -RootPath $snapshotRoot
        Add-PspktRetainedSource -FullPath $caseFullPath
    }

    try {
        Add-Type -Path $ParserSourcePath -ErrorAction Stop
    }
    catch {
        Write-PspktChildError ('parser compilation failed: {0}' -f $_.Exception.Message)
        return $PspktExitCompile
    }

    $reasonCodes = @([Pspkt.Certification.SchemaBootstrap]::ReasonCodes())
    Assert-PspktPhase4ReasonSetExact -Actual $reasonCodes
    $caseResults = [System.Collections.Generic.List[object]]::new()
    $allActualResultsMatch = $true

    foreach ($case in $cases) {
        $fixtureBytes = Get-PspktPhase4FixtureBytes `
            -Case $case `
            -RepositoryRoot $snapshotRoot `
            -CertRoot $certificationRoot
        if ($case.Stage -ceq 'schema-against-meta') {
            $evaluation = [Pspkt.Certification.SchemaBootstrap]::Evaluate(
                $case.Stage,
                $fixtureBytes,
                $metaBytes)
        }
        else {
            $evaluation = [Pspkt.Certification.SchemaBootstrap]::Evaluate(
                $case.Stage,
                $fixtureBytes,
                $null)
        }
        if ($null -eq $evaluation) {
            throw ('case {0} returned no evaluation result.' -f $case.Ordinal)
        }
        if ([bool]$evaluation.Accepted) {
            $actualOutcome = 'accepted'
        }
        else {
            $actualOutcome = 'rejected'
        }
        $actualReason = [string]$evaluation.Reason
        if ($contract.Outcomes -cnotcontains $actualOutcome -or
            $contract.ReasonCodes -cnotcontains $actualReason) {
            throw ('case {0} returned an outcome or reason outside the closed contract.' -f $case.Ordinal)
        }
        if ($actualOutcome -cne $case.ExpectedOutcome -or
            $actualReason -cne $case.ExpectedReason) {
            $allActualResultsMatch = $false
        }
        [void]$caseResults.Add([pscustomobject]@{
                Ordinal         = [int]$case.Ordinal
                Name            = [string]$case.Name
                Path            = [string]$case.Path
                Stage           = [string]$case.Stage
                ExpectedOutcome = [string]$case.ExpectedOutcome
                ExpectedReason  = [string]$case.ExpectedReason
                ByteLength      = [long]$case.ByteLength
                Sha256          = [string]$case.Sha256
                ActualOutcome   = $actualOutcome
                ActualReason    = $actualReason
            })
    }

    if ($caseResults.Count -ne $PspktExpectedCaseCount -or
        -not $allActualResultsMatch) {
        throw 'actual schema outcomes do not exactly match all 68 manifest expectations.'
    }

    Write-PspktSealedSchemaResult `
        -OutputPath $sealedResultPath `
        -Nonce $sealedResultNonce `
        -HelperVersion $helperVersion `
        -CaseResults $caseResults.ToArray()
    return $PspktExitComplete
}

$childExitCode = $PspktExitFatal
try {
    $childExitCode = Invoke-PspktSchemaChildBody
}
catch {
    Write-PspktChildError ('harness failed: {0}' -f $_.Exception.Message)
    $childExitCode = $PspktExitFatal
}
finally {
    $cleanupFailed = $false
    foreach ($retainedStream in $retainedStreams) {
        try {
            $retainedStream.Dispose()
        }
        catch {
            Write-PspktChildError ('retained source cleanup failed: {0}' -f $_.Exception.Message)
            $cleanupFailed = $true
        }
    }

    $completeWon = $false
    try {
        $completeWon = [bool]$watchdogCompleteMethod.Invoke($watchdog, @())
    }
    catch {
        Write-PspktChildError ('watchdog completion failed: {0}' -f $_.Exception.Message)
        $cleanupFailed = $true
    }

    $disposeQuiesced = $false
    try {
        $disposeQuiesced = [bool]$watchdogDisposeMethod.Invoke(
            $watchdog,
            [object[]]@([int]2000))
    }
    catch {
        Write-PspktChildError ('watchdog disposal failed: {0}' -f $_.Exception.Message)
        $cleanupFailed = $true
    }

    if ($cleanupFailed -or -not $completeWon -or -not $disposeQuiesced) {
        $childExitCode = $PspktExitFatal
    }
}

exit $childExitCode
