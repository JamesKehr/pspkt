Set-StrictMode -Version Latest

function Get-PspktPhase4Contract {
    [OutputType([hashtable])]
    param()

    $reasonCodes = @(
        'ok',
        'invalid-utf8',
        'bom-forbidden',
        'nul-forbidden',
        'comment-forbidden',
        'duplicate-key',
        'trailing-comma',
        'trailing-data',
        'float-forbidden',
        'exponent-forbidden',
        'negative-integer',
        'leading-zero-integer',
        'integer-overflow',
        'invalid-escape',
        'unpaired-surrogate',
        'replacement-character-forbidden',
        'file-limit',
        'depth-limit',
        'property-limit',
        'array-limit',
        'string-limit',
        'allocation-budget',
        'unknown-property',
        'missing-property',
        'duplicate-identifier',
        'unknown-primitive',
        'undefined-reference',
        'type-cycle',
        'duplicate-type-id',
        'duplicate-field-id',
        'field-order',
        'invalid-cardinality',
        'bound-overflow',
        'non-ascii-symbol',
        'meta-authority-mismatch',
        'invalid-field-condition'
    )

    $reservedStems = [System.Collections.Generic.List[string]]::new()
    foreach ($fixed in @('CON', 'PRN', 'AUX', 'NUL', 'CLOCK$')) {
        $reservedStems.Add($fixed)
    }
    for ($ordinal = 1; $ordinal -le 9; $ordinal++) {
        $reservedStems.Add('COM' + $ordinal.ToString([System.Globalization.CultureInfo]::InvariantCulture))
        $reservedStems.Add('LPT' + $ordinal.ToString([System.Globalization.CultureInfo]::InvariantCulture))
    }

    return @{
        ExpectedCaseCount          = 68
        ExpectedDirectoryFileCount = 68
        ExpectedAcceptedCaseCount  = 16
        ExpectedReasonCount        = 36
        ManifestByteCap            = 65536
        MetaByteCap                = 1048576
        FixtureByteCap             = 1048577
        MetaRepoPath               = 'certification/schema/protocol-schema-meta.v1.json'
        DirRepoPrefix              = 'certification/vectors/phase4-schema/'
        ManifestRepoPath           = 'certification/vectors/phase4-schema/fixture-manifest.v1.json'
        ManifestKind               = 'phase4-schema-fixtures'
        Stages                     = @('json', 'bootstrap-meta', 'schema-against-meta')
        Outcomes                   = @('accepted', 'rejected')
        ManifestKeys               = @('schemaVersion', 'kind', 'description', 'metaSchema', 'cases')
        CaseKeys                   = @('ordinal', 'name', 'path', 'stage', 'expectedOutcome', 'expectedReason', 'byteLength', 'sha256')
        ReasonCodes                = $reasonCodes
        ReservedDeviceStems        = $reservedStems.ToArray()
    }
}

function Test-PspktPhase4Sha256Hex {
    [OutputType([bool])]
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value)
    return ($Value -cmatch '^[0-9a-f]{64}$')
}

function Assert-PspktPhase4ReasonSetExact {
    param([Parameter(Mandatory = $true)][string[]]$Actual)
    $contract = Get-PspktPhase4Contract
    if ($Actual.Count -ne $contract.ReasonCodes.Count) {
        throw ('phase4-contract: reason-code list has {0} entries, expected {1}.' -f $Actual.Count, $contract.ReasonCodes.Count)
    }
    $actualSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($reason in $Actual) {
        if (-not $actualSet.Add($reason)) {
            throw ('phase4-contract: reason-code list repeats "{0}".' -f $reason)
        }
    }
    foreach ($reason in $contract.ReasonCodes) {
        if (-not $actualSet.Contains($reason)) {
            throw ('phase4-contract: reason-code list omits "{0}".' -f $reason)
        }
    }
}

function Test-PspktPhase4IsIntegral {
    [OutputType([bool])]
    param([Parameter(Mandatory = $true)][AllowNull()]$Value)
    if ($null -eq $Value) { return $false }
    if ($Value -is [bool]) { return $false }
    return ($Value -is [byte] -or $Value -is [sbyte] -or `
            $Value -is [int16] -or $Value -is [uint16] -or `
            $Value -is [int32] -or $Value -is [uint32] -or `
            $Value -is [int64] -or $Value -is [uint64] -or `
            $Value -is [System.Numerics.BigInteger])
}

function Get-PspktPhase4TypeName {
    [OutputType([string])]
    param([Parameter(Mandatory = $true)][AllowNull()]$Value)
    if ($null -eq $Value) { return '<null>' }
    return $Value.GetType().FullName
}

function Test-PspktPhase4PathSegment {
    [OutputType([bool])]
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Segment)

    if ([string]::IsNullOrEmpty($Segment)) { return $false }
    if ($Segment -ceq '.' -or $Segment -ceq '..') { return $false }
    if ($Segment -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]*$') { return $false }
    if ($Segment.EndsWith('.') -or $Segment.EndsWith(' ')) { return $false }
    if (-not $Segment.IsNormalized([System.Text.NormalizationForm]::FormC)) { return $false }

    $dotIndex = $Segment.IndexOf('.')
    if ($dotIndex -ge 0) {
        $stem = $Segment.Substring(0, $dotIndex)
    }
    else {
        $stem = $Segment
    }
    $contract = Get-PspktPhase4Contract
    foreach ($reserved in $contract.ReservedDeviceStems) {
        if ([string]::Equals($stem, $reserved, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $false
        }
    }
    return $true
}

function Test-PspktPhase4RepoPath {
    [OutputType([bool])]
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Path)

    if ([string]::IsNullOrEmpty($Path)) { return $false }
    foreach ($character in $Path.ToCharArray()) {
        $code = [int][char]$character
        if ($code -le 0x1F -or $code -eq 0x7F) { return $false }
    }
    if ($Path.Contains('\')) { return $false }
    if ($Path.Contains(':')) { return $false }
    if ($Path.StartsWith('/')) { return $false }
    if ($Path.EndsWith('/')) { return $false }
    if ($Path.Contains('//')) { return $false }
    if (-not $Path.IsNormalized([System.Text.NormalizationForm]::FormC)) { return $false }

    $contract = Get-PspktPhase4Contract
    $isMeta = ($Path -ceq $contract.MetaRepoPath)
    $isPhase4 = $Path.StartsWith($contract.DirRepoPrefix, [System.StringComparison]::Ordinal)
    if (-not ($isMeta -or $isPhase4)) { return $false }

    foreach ($segment in $Path.Split([char]'/')) {
        if (-not (Test-PspktPhase4PathSegment -Segment $segment)) { return $false }
    }
    return $true
}

function Resolve-PspktPhase4FullPath {
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)][string]$RepoPath,
        [Parameter(Mandatory = $true)][string]$RepositoryRoot,
        [Parameter(Mandatory = $true)][string]$CertRoot
    )

    if (-not (Test-PspktPhase4RepoPath -Path $RepoPath)) {
        throw ('phase4-contract: path "{0}" fails the repository-path grammar.' -f $RepoPath)
    }

    $relativeWindows = $RepoPath -replace '/', '\'
    $full = [System.IO.Path]::GetFullPath((Join-Path $RepositoryRoot $relativeWindows))
    return (Assert-PspktPhase4ContainedNoReparse -FullPath $full -CertRoot $CertRoot)
}

function Assert-PspktPhase4ContainedNoReparse {
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)][string]$FullPath,
        [Parameter(Mandatory = $true)][string]$CertRoot
    )
    $full = [System.IO.Path]::GetFullPath($FullPath)
    $certFull = [System.IO.Path]::GetFullPath($CertRoot)
    $separator = [System.IO.Path]::DirectorySeparatorChar
    $containmentRoot = $certFull.TrimEnd($separator) + $separator
    if (-not $full.StartsWith($containmentRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw ('phase4-contract: path "{0}" resolves outside the certification root.' -f $FullPath)
    }

    $reparse = [System.IO.FileAttributes]::ReparsePoint
    $current = $certFull.TrimEnd($separator)
    if (Test-Path -LiteralPath $current) {
        if (([System.IO.File]::GetAttributes($current) -band $reparse) -eq $reparse) {
            throw ('phase4-contract: certification root "{0}" is a reparse point.' -f $current)
        }
    }
    $remainder = $full.Substring($containmentRoot.Length)
    foreach ($component in $remainder.Split($separator)) {
        $current = $current + $separator + $component
        if (Test-Path -LiteralPath $current) {
            if (([System.IO.File]::GetAttributes($current) -band $reparse) -eq $reparse) {
                throw ('phase4-contract: path component "{0}" is a reparse point.' -f $current)
            }
        }
    }
    return $full
}

function Get-PspktPhase4CapForRepoPath {
    [OutputType([long])]
    param([Parameter(Mandatory = $true)][string]$RepoPath)
    $contract = Get-PspktPhase4Contract
    if ($RepoPath -ceq $contract.MetaRepoPath) {
        return [long]$contract.MetaByteCap
    }
    if ($RepoPath -ceq $contract.ManifestRepoPath) {
        return [long]$contract.ManifestByteCap
    }
    return [long]$contract.FixtureByteCap
}

function Read-PspktPhase4BoundedBytes {
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory = $true)][string]$FullPath,
        [Parameter(Mandatory = $true)][long]$ByteCap
    )
    $stream = [System.IO.FileStream]::new(
        $FullPath,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::Read)
    try {
        $length = $stream.Length
        if ($length -gt $ByteCap) {
            throw ('phase4-contract: file "{0}" is {1} bytes, exceeding the {2}-byte cap.' -f $FullPath, $length, $ByteCap)
        }
        $count = [int]$length
        $buffer = [byte[]]::new($count)
        $offset = 0
        while ($offset -lt $count) {
            $read = $stream.Read($buffer, $offset, $count - $offset)
            if ($read -le 0) {
                throw ('phase4-contract: file "{0}" was truncated during read (expected {1}, read {2}).' -f $FullPath, $count, $offset)
            }
            $offset += $read
        }
        if ($stream.ReadByte() -ne -1) {
            throw ('phase4-contract: file "{0}" grew during read past its declared {1} bytes.' -f $FullPath, $count)
        }
        return , $buffer
    }
    finally {
        $stream.Dispose()
    }
}

function Assert-PspktPhase4ManifestShape {
    param([Parameter(Mandatory = $true)]$Manifest)
    $contract = Get-PspktPhase4Contract

    if ($null -eq $Manifest -or -not ($Manifest -is [psobject])) {
        throw 'phase4-contract: manifest is not a JSON object.'
    }
    $topKeys = @($Manifest.PSObject.Properties.Name)
    Assert-PspktPhase4KeySetExact -Actual $topKeys -Expected $contract.ManifestKeys -Label 'manifest'

    if (-not (Test-PspktPhase4IsIntegral -Value $Manifest.schemaVersion)) {
        throw ('phase4-contract: manifest schemaVersion must be an integer (got type {0}).' -f (Get-PspktPhase4TypeName -Value $Manifest.schemaVersion))
    }
    if ([System.Numerics.BigInteger]$Manifest.schemaVersion -ne [System.Numerics.BigInteger]1) {
        throw ('phase4-contract: manifest schemaVersion must be 1 (got "{0}").' -f $Manifest.schemaVersion)
    }
    foreach ($stringField in @('kind', 'description', 'metaSchema')) {
        if (-not ($Manifest.$stringField -is [string])) {
            throw ('phase4-contract: manifest {0} must be a non-null string.' -f $stringField)
        }
    }
    if ($Manifest.kind -cne $contract.ManifestKind) {
        throw ('phase4-contract: manifest kind must be "{0}".' -f $contract.ManifestKind)
    }
    if ($Manifest.metaSchema -cne $contract.MetaRepoPath) {
        throw ('phase4-contract: manifest metaSchema must be "{0}".' -f $contract.MetaRepoPath)
    }
    if (-not ($Manifest.cases -is [System.Collections.IEnumerable]) -or ($Manifest.cases -is [string])) {
        throw 'phase4-contract: manifest cases must be a JSON array.'
    }

    foreach ($case in @($Manifest.cases)) {
        $caseKeys = @($case.PSObject.Properties.Name)
        Assert-PspktPhase4KeySetExact -Actual $caseKeys -Expected $contract.CaseKeys -Label ('case[{0}]' -f $case.ordinal)
    }
}

function Assert-PspktPhase4KeySetExact {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$Actual,
        [Parameter(Mandatory = $true)][string[]]$Expected,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $actualSorted = @($Actual | Sort-Object)
    $expectedSorted = @($Expected | Sort-Object)
    if ($actualSorted.Count -ne $expectedSorted.Count) {
        throw ('phase4-contract: {0} has {1} keys, expected {2}.' -f $Label, $actualSorted.Count, $expectedSorted.Count)
    }
    for ($index = 0; $index -lt $expectedSorted.Count; $index++) {
        if ($actualSorted[$index] -cne $expectedSorted[$index]) {
            throw ('phase4-contract: {0} key set does not match the closed schema (unexpected "{1}").' -f $Label, $actualSorted[$index])
        }
    }
}

function Get-PspktPhase4NormalizedCases {
    [OutputType([object[]])]
    param([Parameter(Mandatory = $true)]$Manifest)

    $contract = Get-PspktPhase4Contract
    $cases = @($Manifest.cases)
    if ($cases.Count -ne $contract.ExpectedCaseCount) {
        throw ('phase4-contract: manifest declares {0} cases, expected exactly {1}.' -f $cases.Count, $contract.ExpectedCaseCount)
    }

    $seenNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    $seenPaths = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    $observedStages = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    $observedReasons = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    $externalMetaCases = 0
    $acceptedCount = 0
    $normalized = [System.Collections.Generic.List[object]]::new()

    for ($index = 0; $index -lt $cases.Count; $index++) {
        $case = $cases[$index]
        if (-not (Test-PspktPhase4IsIntegral -Value $case.ordinal)) {
            throw ('phase4-contract: case at position {0} ordinal must be an integer.' -f $index)
        }
        $ordinal = [int]$case.ordinal
        if ($ordinal -ne $index) {
            throw ('phase4-contract: case at position {0} declares ordinal {1}.' -f $index, $ordinal)
        }
        foreach ($requiredString in @('name', 'path', 'stage', 'expectedOutcome', 'expectedReason', 'sha256')) {
            if (-not ($case.$requiredString -is [string])) {
                throw ('phase4-contract: case {0} field "{1}" must be a non-null string.' -f $ordinal, $requiredString)
            }
        }
        $name = [string]$case.name
        if ($name -cnotmatch '^[A-Za-z][A-Za-z0-9]*$') {
            throw ('phase4-contract: case {0} name "{1}" is not an ASCII identifier.' -f $ordinal, $name)
        }
        if (-not $seenNames.Add($name)) {
            throw ('phase4-contract: case {0} repeats name "{1}".' -f $ordinal, $name)
        }
        $stage = [string]$case.stage
        if ($contract.Stages -cnotcontains $stage) {
            throw ('phase4-contract: case {0} declares unknown stage "{1}".' -f $ordinal, $stage)
        }
        [void]$observedStages.Add($stage)
        $outcome = [string]$case.expectedOutcome
        if ($contract.Outcomes -cnotcontains $outcome) {
            throw ('phase4-contract: case {0} declares unknown outcome "{1}".' -f $ordinal, $outcome)
        }
        $reason = [string]$case.expectedReason
        if ($contract.ReasonCodes -cnotcontains $reason) {
            throw ('phase4-contract: case {0} declares unknown reason "{1}".' -f $ordinal, $reason)
        }
        [void]$observedReasons.Add($reason)
        $acceptedIsOk = (($outcome -ceq 'accepted') -eq ($reason -ceq 'ok'))
        if (-not $acceptedIsOk) {
            throw ('phase4-contract: case {0} outcome/reason are inconsistent.' -f $ordinal)
        }
        if ($outcome -ceq 'accepted') {
            $acceptedCount++
        }
        $repoPath = [string]$case.path
        if (-not (Test-PspktPhase4RepoPath -Path $repoPath)) {
            throw ('phase4-contract: case {0} path "{1}" fails the repository-path grammar.' -f $ordinal, $repoPath)
        }
        if (-not $seenPaths.Add($repoPath)) {
            throw ('phase4-contract: case {0} repeats path "{1}".' -f $ordinal, $repoPath)
        }
        if ($repoPath -ceq $contract.MetaRepoPath) {
            $externalMetaCases++
        }
        elseif (-not $repoPath.StartsWith($contract.DirRepoPrefix, [System.StringComparison]::Ordinal)) {
            throw ('phase4-contract: case {0} path "{1}" is neither the committed meta nor a phase4 fixture.' -f $ordinal, $repoPath)
        }
        if (-not (Test-PspktPhase4IsIntegral -Value $case.byteLength)) {
            throw ('phase4-contract: case {0} byteLength must be an integer.' -f $ordinal)
        }
        $byteLength = [long]$case.byteLength
        if ($byteLength -lt 0) {
            throw ('phase4-contract: case {0} byteLength is negative.' -f $ordinal)
        }
        $sha256 = [string]$case.sha256
        if (-not (Test-PspktPhase4Sha256Hex -Value $sha256)) {
            throw ('phase4-contract: case {0} sha256 "{1}" is not a lowercase 64-hex digest.' -f $ordinal, $sha256)
        }
        $normalized.Add([pscustomobject]@{
                Ordinal         = $ordinal
                Name            = $name
                Path            = $repoPath
                Stage           = $stage
                ExpectedOutcome = $outcome
                ExpectedReason  = $reason
                ByteLength      = $byteLength
                Sha256          = $sha256
            })
    }

    if ($acceptedCount -ne $contract.ExpectedAcceptedCaseCount) {
        throw ('phase4-contract: corpus has {0} accepted cases, expected {1}.' -f $acceptedCount, $contract.ExpectedAcceptedCaseCount)
    }
    if ($externalMetaCases -ne 1) {
        throw ('phase4-contract: corpus references the committed meta {0} times, expected exactly once.' -f $externalMetaCases)
    }
    foreach ($stage in $contract.Stages) {
        if (-not $observedStages.Contains($stage)) {
            throw ('phase4-contract: corpus never exercises stage "{0}".' -f $stage)
        }
    }
    if ($observedReasons.Count -ne $contract.ExpectedReasonCount) {
        throw ('phase4-contract: corpus exercises {0} distinct reasons, expected exactly {1}.' -f $observedReasons.Count, $contract.ExpectedReasonCount)
    }
    foreach ($reason in $contract.ReasonCodes) {
        if (-not $observedReasons.Contains($reason)) {
            throw ('phase4-contract: reason "{0}" is never exercised by the corpus.' -f $reason)
        }
    }
    return $normalized.ToArray()
}

function Get-PspktPhase4FixtureBytes {
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory = $true)]$Case,
        [Parameter(Mandatory = $true)][string]$RepositoryRoot,
        [Parameter(Mandatory = $true)][string]$CertRoot
    )
    $repoPath = [string]$Case.Path
    $full = Resolve-PspktPhase4FullPath -RepoPath $repoPath -RepositoryRoot $RepositoryRoot -CertRoot $CertRoot
    $cap = Get-PspktPhase4CapForRepoPath -RepoPath $repoPath
    $bytes = Read-PspktPhase4BoundedBytes -FullPath $full -ByteCap $cap
    if ([long]$bytes.Length -ne [long]$Case.ByteLength) {
        throw ('phase4-contract: case {0} fixture "{1}" length {2} does not match manifest byteLength {3}.' -f $Case.Ordinal, $repoPath, $bytes.Length, $Case.ByteLength)
    }
    $actualSha = Get-PspktSha256Hex -Bytes $bytes
    if ($actualSha -cne [string]$Case.Sha256) {
        throw ('phase4-contract: case {0} fixture "{1}" sha256 {2} does not match manifest sha256 {3}.' -f $Case.Ordinal, $repoPath, $actualSha, $Case.Sha256)
    }
    return , $bytes
}

function Assert-PspktPhase4CanonicalFile {
    param(
        [Parameter(Mandatory = $true)][string]$FullPath,
        [Parameter(Mandatory = $true)][long]$ByteCap,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $bytes = Read-PspktPhase4BoundedBytes -FullPath $FullPath -ByteCap $ByteCap
    $text = [System.Text.UTF8Encoding]::new($false, $true).GetString($bytes)
    $document = $text | ConvertFrom-Json
    $canonical = Get-PspktCanonicalJsonBytes -Value $document
    if ((Get-PspktSha256Hex -Bytes $bytes) -cne (Get-PspktSha256Hex -Bytes $canonical)) {
        throw ('phase4-contract: {0} is not canonical JSON.' -f $Label)
    }
    return , $bytes
}

function Get-PspktPhase4DirectoryFiles {
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory = $true)][string]$RepositoryRoot,
        [Parameter(Mandatory = $true)][string]$CertRoot
    )
    $contract = Get-PspktPhase4Contract
    $dirRepoWindows = ($contract.DirRepoPrefix.TrimEnd('/')) -replace '/', '\'
    $dirFull = [System.IO.Path]::GetFullPath((Join-Path $RepositoryRoot $dirRepoWindows))
    Assert-PspktPhase4ContainedNoReparse -FullPath $dirFull -CertRoot $CertRoot | Out-Null
    if (-not (Test-Path -LiteralPath $dirFull -PathType Container)) {
        throw ('phase4-contract: fixture directory "{0}" does not exist.' -f $dirFull)
    }

    $reparse = [System.IO.FileAttributes]::ReparsePoint
    $directory = [System.IO.FileAttributes]::Directory
    $rootInfo = [System.IO.DirectoryInfo]::new($dirFull)
    if (($rootInfo.Attributes -band $reparse) -eq $reparse) {
        throw ('phase4-contract: fixture directory "{0}" is a reparse point.' -f $dirFull)
    }
    $results = [System.Collections.Generic.List[string]]::new()
    $pending = [System.Collections.Generic.Stack[string]]::new()
    $pending.Push($dirFull)
    while ($pending.Count -gt 0) {
        $currentDir = $pending.Pop()
        foreach ($entry in ([System.IO.DirectoryInfo]::new($currentDir)).GetFileSystemInfos()) {
            $isReparse = (($entry.Attributes -band $reparse) -eq $reparse)
            if (($entry.Attributes -band $directory) -eq $directory) {
                if ($isReparse) {
                    throw ('phase4-contract: fixture subdirectory "{0}" is a reparse point.' -f $entry.FullName)
                }
                $pending.Push($entry.FullName)
            }
            else {
                if ($isReparse) {
                    throw ('phase4-contract: fixture "{0}" is a reparse point.' -f $entry.FullName)
                }
                $results.Add($entry.FullName)
            }
        }
    }
    return @($results.ToArray() | Sort-Object)
}

function Assert-PspktPhase4DirectoryFileCount {
    param(
        [Parameter(Mandatory = $true)][string]$RepositoryRoot,
        [Parameter(Mandatory = $true)][string]$CertRoot
    )
    $contract = Get-PspktPhase4Contract
    $files = @(Get-PspktPhase4DirectoryFiles -RepositoryRoot $RepositoryRoot -CertRoot $CertRoot)
    if ($files.Count -ne $contract.ExpectedDirectoryFileCount) {
        throw ('phase4-contract: fixture directory holds {0} files, expected exactly {1}.' -f $files.Count, $contract.ExpectedDirectoryFileCount)
    }
    return $files
}

function Assert-PspktPhase4CorpusFileSet {
    param(
        [Parameter(Mandatory = $true)][object[]]$Cases,
        [Parameter(Mandatory = $true)][string]$RepositoryRoot,
        [Parameter(Mandatory = $true)][string]$CertRoot
    )
    $contract = Get-PspktPhase4Contract
    $actualFiles = @(Assert-PspktPhase4DirectoryFileCount -RepositoryRoot $RepositoryRoot -CertRoot $CertRoot)
    $expectedPaths = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    [void]$expectedPaths.Add($contract.ManifestRepoPath)
    foreach ($case in $Cases) {
        if ($case.Path -cne $contract.MetaRepoPath) {
            [void]$expectedPaths.Add([string]$case.Path)
        }
    }
    if ($expectedPaths.Count -ne $contract.ExpectedDirectoryFileCount) {
        throw ('phase4-contract: manifest names {0} fixture-directory paths, expected {1}.' -f $expectedPaths.Count, $contract.ExpectedDirectoryFileCount)
    }

    $actualPaths = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($fullPath in $actualFiles) {
        $repoPath = $fullPath.Substring($RepositoryRoot.Length).TrimStart([char]'\', [char]'/').Replace('\', '/')
        [void]$actualPaths.Add($repoPath)
    }
    foreach ($expectedPath in $expectedPaths) {
        if (-not $actualPaths.Contains($expectedPath)) {
            throw ('phase4-contract: expected fixture-directory path "{0}" is missing.' -f $expectedPath)
        }
    }
    foreach ($actualPath in $actualPaths) {
        if (-not $expectedPaths.Contains($actualPath)) {
            throw ('phase4-contract: unexpected fixture-directory path "{0}" is present.' -f $actualPath)
        }
    }
    return $actualFiles
}
