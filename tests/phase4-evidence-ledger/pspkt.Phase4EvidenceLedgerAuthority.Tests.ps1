Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Describe 'Phase 4 evidence ledger authority' -Tag 'Precheck' {
    BeforeAll {
        $script:repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
        $script:sliceRoot = Join-Path $script:repositoryRoot 'certification\evidence-ledger'
        $script:contractPath = Join-Path $script:sliceRoot 'lib\Pspkt.Certification.EvidenceLedgerContract.ps1'
        $script:evidenceTestNames = @(
            'pins the acyclic source graph inventory and exact output set',
            'projects forward dependencies in protocol source order without reverse dependents',
            'emits the exact evidence declarations kind mapping domains and envelope',
            'requires local evidence receipt and proof structural equivalence',
            'projects complete authorization and operation ledger closures with exact kind mappings',
            'preserves copied field ids and conditional pair identities',
            'sizes every schema production and primitive with independent numeric fixtures',
            'pins evidence authorization and operation payload and envelope maxima',
            'rejects signing ledger record lists above 4096',
            'keeps authorization and operation record list purposes separate',
            'pins inclusion proof structure domains bounds and maximum bytes',
            'pins burn deferral and rehabilitation shapes across both schemas',
            'rejects BigInteger sizing values above UInt32',
            'attributes hash canonical meta and semantic mutation failures to exact gates',
            'rejects verifier references to the evidence ledger authority',
            'atomically replaces each output and preserves prior bytes on injected failure',
            'emits identical canonical JSON bytes with the lowercase control escape dialect',
            'pins the complete deferred binary consumer contract',
            'runs protocol and evidence ledger suites together without recursive combined runs')

        $script:combinedChildCode = @'
param(
    [string]$RepositoryRoot,[string]$PesterManifestPath,[string]$AllowlistPath,
    [string]$ExpectedEdition,[string]$ExpectedVersion,
    [ValidateSet('Discover','Run')][string]$Mode,
    [ValidateSet('None','Discovery','BeforeAll','SkippedOnly','EmptySelection','UnexpectedSkip','RuntimeSkip','UnexpectedExclusion','OneRequiredExcluded')][string]$ProbeCase = 'None'
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSEdition -cne $ExpectedEdition -or $PSVersionTable.PSVersion.ToString() -cne $ExpectedVersion) { throw 'Combined child host identity differs.' }
if (($ExpectedEdition -eq 'Desktop' -and $PSVersionTable.PSVersion -lt [version]'5.1') -or ($ExpectedEdition -eq 'Core' -and $PSVersionTable.PSVersion.Major -ne 7)) { throw 'Combined child host version is unsupported.' }
$manifest = Import-PowerShellDataFile -LiteralPath $PesterManifestPath
if ([version]$manifest.ModuleVersion -lt [version]'5.3.3' -or [version]$manifest.ModuleVersion -ge [version]'6.0') { throw 'Combined child Pester version is unsupported.' }
Import-Module $PesterManifestPath -ErrorAction Stop
$loaded = @(Get-Module Pester)
if ($loaded.Count -ne 1 -or $loaded[0].Version -ne [version]$manifest.ModuleVersion -or
    -not [string]::Equals([IO.Path]::GetFullPath($loaded[0].ModuleBase),[IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($PesterManifestPath)),[StringComparison]::OrdinalIgnoreCase)) {
    throw 'Combined child Pester identity differs.'
}
$allowlist = [string[]](Get-Content -LiteralPath $AllowlistPath -Raw | ConvertFrom-Json)
if ($allowlist.Count -ne 19 -or @($allowlist | Select-Object -Unique).Count -ne 19) { throw 'Evidence allowlist cardinality differs.' }
$expectedPaths = [string[]]@(
    (Join-Path $RepositoryRoot 'tests\phase4-protocol\pspkt.ProtocolCatalogEngineV2.Tests.ps1'),
    (Join-Path $RepositoryRoot 'tests\phase4-protocol\pspkt.Phase4ProtocolSchemaAuthority.Tests.ps1'),
    (Join-Path $RepositoryRoot 'tests\phase4-evidence-ledger\pspkt.Phase4EvidenceLedgerAuthority.Tests.ps1'))
$allowedSkips = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
[void]$allowedSkips.Add('Phase 4 protocol schema authority.runs the V2 and authority suites in one Pester process without recursive combined runs')
[void]$allowedSkips.Add('Phase 4 evidence ledger authority.runs protocol and evidence ledger suites together without recursive combined runs')
function Test-EvidenceCombinedResult {
    param($Result,[string[]]$ExpectedPaths,[string[]]$Names,$AllowedSkips)
    if ($null -eq $Result -or $Result.Result -ne 'Passed' -or $Result.PassedCount -le 0) { return $false }
    if ($Result.FailedCount -ne 0 -or $Result.FailedBlocksCount -ne 0 -or $Result.FailedContainersCount -ne 0) { return $false }
    if (@($Result.Containers).Count -ne 3 -or $ExpectedPaths.Count -ne 3) { return $false }
    $paths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($path in $ExpectedPaths) { [void]$paths.Add([IO.Path]::GetFullPath($path)) }
    foreach ($test in $Result.Tests) {
        if (-not $test.ScriptBlock.File -or -not $paths.Contains([IO.Path]::GetFullPath($test.ScriptBlock.File))) { return $false }
    }
    foreach ($path in $ExpectedPaths) {
        $tests = @($Result.Tests | Where-Object { [string]::Equals([IO.Path]::GetFullPath($_.ScriptBlock.File),[IO.Path]::GetFullPath($path),[StringComparison]::OrdinalIgnoreCase) })
        if ($tests.Count -eq 0) { return $false }
        if ([IO.Path]::GetFileName($path) -ceq 'pspkt.Phase4EvidenceLedgerAuthority.Tests.ps1') {
            if ($tests.Count -ne 19 -or ($tests.Name -join "`n") -cne ($Names -join "`n")) { return $false }
        }
    }
    $skipCount = 0
    foreach ($test in $Result.Tests) {
        if ($AllowedSkips.Contains($test.ExpandedPath)) {
            if (-not $test.ShouldRun -or -not $test.Skip -or $test.Result -ne 'Skipped') { return $false }
            $skipCount++
        } elseif (-not $test.ShouldRun -or -not $test.Executed -or $test.Skip -or $test.Result -ne 'Passed') {
            return $false
        }
    }
    return $skipCount -eq 2 -and $Result.SkippedCount -eq 2
}
$configuration = New-PesterConfiguration
$configuration.Run.PassThru = $true
$configuration.Output.Verbosity = 'Normal'
$configuration.Filter.Tag = @('Precheck')
if ($Mode -eq 'Discover') {
    [Environment]::SetEnvironmentVariable('PSPKT_PROTOCOL_COMBINED_CHILD',$null)
    [Environment]::SetEnvironmentVariable('PSPKT_EVIDENCE_LEDGER_COMBINED_CHILD',$null)
    $configuration.Run.Path = Join-Path $RepositoryRoot 'tests\phase4-evidence-ledger'
    $configuration.Run.SkipRun = $true
    $result = Invoke-Pester -Configuration $configuration
    if ($result.FailedCount -ne 0 -or $result.FailedBlocksCount -ne 0 -or $result.FailedContainersCount -ne 0 -or
        @($result.Containers).Count -ne 1 -or @($result.Tests).Count -ne 19 -or
        ($result.Tests.Name -join "`n") -cne ($allowlist -join "`n") -or @($result.Tests | Where-Object Executed).Count -ne 0) {
        throw 'Fresh evidence discovery failed its exact allowlist or no-execution predicate.'
    }
    "EVIDENCE_DISCOVERY_OK|edition=$ExpectedEdition|version=$ExpectedVersion|tests=19|executed=0"
    exit 0
}
$env:PSPKT_PROTOCOL_COMBINED_CHILD = '1'
$env:PSPKT_EVIDENCE_LEDGER_COMBINED_CHILD = '1'
if ($ProbeCase -ne 'None') {
    $fixtureRoot = Join-Path ([IO.Path]::GetDirectoryName($PSCommandPath)) ("probe-$ExpectedEdition-$ProbeCase")
    [void][IO.Directory]::CreateDirectory($fixtureRoot)
    $expectedPaths = [string[]]@($expectedPaths | ForEach-Object { Join-Path $fixtureRoot ([IO.Path]::GetFileName($_)) })
    $engineText = "Describe 'Protocol probe engine' -Tag 'Precheck' { It 'executes a required protocol test' { 1 | Should -Be 1 } }"
    $authorityText = 'Describe ''Phase 4 protocol schema authority'' -Tag ''Precheck'' { It ''executes a required authority test'' { 1 | Should -Be 1 }; It ''runs the V2 and authority suites in one Pester process without recursive combined runs'' -Skip:([Environment]::GetEnvironmentVariable(''PSPKT_PROTOCOL_COMBINED_CHILD'') -eq ''1'') { throw ''Recursion must not execute.'' } }'
    $lines = [Collections.Generic.List[string]]::new()
    $lines.Add("Describe 'Phase 4 evidence ledger authority' -Tag 'Precheck' {")
    for ($index=0; $index -lt 19; $index++) {
        $parameters = ''
        $body = '1 | Should -Be 1'
        if ($index -eq 18) { $parameters = ' -Skip:([Environment]::GetEnvironmentVariable(''PSPKT_EVIDENCE_LEDGER_COMBINED_CHILD'') -eq ''1'')' }
        elseif ($ProbeCase -eq 'SkippedOnly' -or ($ProbeCase -eq 'UnexpectedSkip' -and $index -eq 0)) { $parameters = ' -Skip' }
        if ($ProbeCase -eq 'OneRequiredExcluded' -and $index -eq 0) { $parameters = " -Tag 'ExcludedProbe'" }
        if ($ProbeCase -eq 'RuntimeSkip' -and $index -eq 0) { $body = "Set-ItResult -Skipped -Because 'Injected runtime skip.'" }
        $lines.Add("It '$($allowlist[$index])'$parameters { $body }")
    }
    $lines.Add('}')
    if ($ProbeCase -eq 'Discovery') { $engineText = "Describe 'unclosed discovery" }
    if ($ProbeCase -eq 'BeforeAll') { $engineText = "Describe 'Protocol probe engine' -Tag 'Precheck' { BeforeAll { throw 'Injected BeforeAll failure.' }; It 'executes a required protocol test' { 1 | Should -Be 1 } }" }
    if ($ProbeCase -eq 'SkippedOnly') {
        $engineText = $engineText.Replace("It 'executes a required protocol test'","It 'executes a required protocol test' -Skip")
        $authorityText = $authorityText.Replace("It 'executes a required authority test'","It 'executes a required authority test' -Skip")
    }
    [IO.File]::WriteAllText($expectedPaths[0],$engineText,[Text.UTF8Encoding]::new($false,$true))
    [IO.File]::WriteAllText($expectedPaths[1],$authorityText,[Text.UTF8Encoding]::new($false,$true))
    [IO.File]::WriteAllText($expectedPaths[2],($lines -join "`n"),[Text.UTF8Encoding]::new($false,$true))
    if ($ProbeCase -eq 'EmptySelection') {
        $configuration.Filter.Tag = @()
        $configuration.Filter.FullName = @('No test matches this selection')
    }
    if ($ProbeCase -eq 'UnexpectedExclusion') {
        $configuration.Filter.Tag = @()
        $configuration.Filter.FullName = @('Phase 4 evidence ledger authority.*','Phase 4 protocol schema authority.*')
    }
    if ($ProbeCase -eq 'OneRequiredExcluded') { $configuration.Filter.ExcludeTag = @('ExcludedProbe') }
}
$configuration.Run.Path = $expectedPaths
$result = Invoke-Pester -Configuration $configuration
$accepted = Test-EvidenceCombinedResult -Result $result -ExpectedPaths $expectedPaths -Names $allowlist -AllowedSkips $allowedSkips
if ($ProbeCase -ne 'None') {
    $evidenceFirst = @($result.Tests | Where-Object ExpandedPath -CEQ ('Phase 4 evidence ledger authority.' + $allowlist[0]))
    $observed = switch ($ProbeCase) {
        'Discovery' { $result.FailedContainersCount -gt 0 }
        'BeforeAll' { $result.FailedBlocksCount -gt 0 }
        'SkippedOnly' { $result.PassedCount -eq 0 -and $result.SkippedCount -gt 0 }
        'EmptySelection' { @($result.Tests | Where-Object ShouldRun).Count -eq 0 }
        'UnexpectedSkip' { $evidenceFirst.Count -eq 1 -and $evidenceFirst[0].Skip -and $evidenceFirst[0].Result -eq 'Skipped' }
        'RuntimeSkip' { $evidenceFirst.Count -eq 1 -and -not $evidenceFirst[0].Skip -and $evidenceFirst[0].Executed -and $evidenceFirst[0].Result -eq 'Skipped' }
        'UnexpectedExclusion' { @($result.Tests | Where-Object { -not $_.ShouldRun -and $_.ScriptBlock.File -eq $expectedPaths[0] }).Count -eq 1 }
        'OneRequiredExcluded' { $evidenceFirst.Count -eq 1 -and -not $evidenceFirst[0].ShouldRun }
    }
    if (-not $observed -or $accepted) { throw "Combined rejection probe did not establish its intended failure: $ProbeCase" }
    "EVIDENCE_COMBINED_REJECTED|case=$ProbeCase|edition=$ExpectedEdition|failed=$($result.FailedCount)|blocks=$($result.FailedBlocksCount)|containers=$($result.FailedContainersCount)"
    exit 1
}
if (-not $accepted) {
    $unexpected = @($result.Tests | Where-Object { (-not $_.ShouldRun -or -not $_.Executed -or $_.Result -ne 'Passed') -and -not $allowedSkips.Contains($_.ExpandedPath) } | ForEach-Object { $_.ExpandedPath + ':' + $_.Result })
    throw "Combined required-test predicate failed: passed=$($result.PassedCount), failed=$($result.FailedCount), skipped=$($result.SkippedCount), blocks=$($result.FailedBlocksCount), containers=$($result.FailedContainersCount). $($unexpected -join '; ')"
}
"EVIDENCE_COMBINED_OK|edition=$ExpectedEdition|version=$ExpectedVersion|total=$($result.TotalCount)|passed=$($result.PassedCount)|skipped=$($result.SkippedCount)|failed=0"
exit 0
'@

        function Copy-EvidenceLedgerFixture {
            param([string]$DestinationRoot)

            . $script:contractPath
            $contract = Get-PspktEvidenceLedgerContract
            foreach ($path in @($contract.Sha256ByPath.Keys) + 'certification/evidence-ledger/lib/Pspkt.Certification.EvidenceLedgerContract.ps1') {
                $destination = Join-Path $DestinationRoot $path.Replace('/','\')
                [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($destination))
                [IO.File]::WriteAllBytes($destination,[IO.File]::ReadAllBytes((Join-Path $script:repositoryRoot $path.Replace('/','\'))))
            }
            return $contract
        }

        function Update-EvidenceFixtureInputPin {
            param([string]$FixtureRoot,[string]$RelativePath,$Contract)

            $actual = (Get-FileHash -LiteralPath (Join-Path $FixtureRoot $RelativePath.Replace('/','\')) -Algorithm SHA256).Hash.ToLowerInvariant()
            $path = Join-Path $FixtureRoot 'certification\evidence-ledger\lib\Pspkt.Certification.EvidenceLedgerContract.ps1'
            $text = [IO.File]::ReadAllText($path)
            $before = "'$RelativePath' = '$($Contract.Sha256ByPath[$RelativePath])'"
            $after = "'$RelativePath' = '$actual'"
            if (-not $text.Contains($before)) { throw 'Test-local input pin was not found.' }
            [IO.File]::WriteAllText($path,$text.Replace($before,$after),[Text.UTF8Encoding]::new($false,$true))
        }

        function Invoke-EvidenceLedgerProbe {
            param([string]$Code,[string]$RepositoryRoot = $script:repositoryRoot)

            $scratch = Join-Path $TestDrive ([Guid]::NewGuid().ToString('N'))
            [void][IO.Directory]::CreateDirectory($scratch)
            $probePath = Join-Path $scratch 'probe.ps1'
            $prefix = @'
param([string]$RepositoryRoot,[string]$AssemblyRoot)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$sliceRoot = Join-Path $RepositoryRoot 'certification\evidence-ledger'
$contract = & (Join-Path $sliceRoot 'validators\Invoke-PspktPhase4EvidenceLedgerAuthorityValidators.ps1') -Worker -Mode Compile -RepositoryRoot $RepositoryRoot -AssemblyRoot $AssemblyRoot
$utf8 = [Text.UTF8Encoding]::new($false,$true)
$metaBytes = [IO.File]::ReadAllBytes((Join-Path $RepositoryRoot 'certification\schema\protocol-schema-meta.v1.json'))
$protocolBytes = [IO.File]::ReadAllBytes((Join-Path $RepositoryRoot 'certification\schema\protocol-schema.v1.json'))
$protocolInventoryBytes = [IO.File]::ReadAllBytes((Join-Path $RepositoryRoot 'certification\schema\protocol-inventory.v1.json'))
$inventoryBytes = [IO.File]::ReadAllBytes((Join-Path $sliceRoot 'schema\evidence-ledger-inventory.v1.json'))
$readmeBytes = [IO.File]::ReadAllBytes((Join-Path $sliceRoot 'README.md'))
$outputs = [Collections.Generic.Dictionary[string,byte[]]]::new([StringComparer]::Ordinal)
foreach ($path in $contract.OutputPathSet) {
    $name = [IO.Path]::GetFileName($path.Replace('/','\'))
    $outputs.Add($name,[IO.File]::ReadAllBytes((Join-Path $RepositoryRoot $path.Replace('/','\'))))
}
function ConvertTo-ProbeCanonical {
    param($Value)
    $implementation = [Pspkt.Certification.EvidenceLedger.EvidenceLedgerVerify]
    $flags = [Reflection.BindingFlags]'Static,NonPublic'
    $arguments = [object[]]::new(1)
    $arguments[0] = $utf8.GetBytes(($Value | ConvertTo-Json -Depth 40 -Compress))
    $arguments[0] = $implementation.GetMethod('Parse',$flags).Invoke($null,$arguments)
    return ,$implementation.GetMethod('Canonical',$flags).Invoke($null,$arguments)
}
function Invoke-ProbeSemantics {
    $method = [Pspkt.Certification.EvidenceLedger.EvidenceLedgerVerify].GetMethod('ValidateSemantics',[Reflection.BindingFlags]'Static,NonPublic')
    if ($null -eq $method) { throw 'The verifier semantic seam is missing.' }
    $method.Invoke($null,[object[]]@($protocolBytes,$protocolInventoryBytes,$inventoryBytes,$outputs))
}
function Invoke-ProbeValidation {
    $pins = [Collections.Generic.Dictionary[string,string]]::new([StringComparer]::Ordinal)
    $hash = [Security.Cryptography.SHA256]::Create()
    try {
        foreach ($name in $outputs.Keys) {
            $pins.Add($name,[BitConverter]::ToString($hash.ComputeHash($outputs[$name])).Replace('-','').ToLowerInvariant())
        }
        foreach ($pair in @(@('protocol-schema.v1.json',$protocolBytes),@('protocol-inventory.v1.json',$protocolInventoryBytes),
            @('protocol-schema-meta.v1.json',$metaBytes),@('evidence-ledger-inventory.v1.json',$inventoryBytes),@('README.md',$readmeBytes))) {
            $pins.Add($pair[0],[BitConverter]::ToString($hash.ComputeHash($pair[1])).Replace('-','').ToLowerInvariant())
        }
    }
    finally { $hash.Dispose() }
    [Pspkt.Certification.EvidenceLedger.EvidenceLedgerVerify]::Verify($protocolBytes,$protocolInventoryBytes,$inventoryBytes,$metaBytes,$outputs,$pins,
        [Pspkt.Certification.SchemaBootstrap].Assembly.GetName().FullName,
        [Pspkt.Certification.EvidenceLedger.EvidenceLedgerAuthority].Assembly.GetName().FullName,$readmeBytes)
}
function Assert-ProbeFailure {
    param([scriptblock]$Action,[string]$Expected)
    $caught = $null
    try { & $Action } catch { $caught = $_.Exception }
    if ($null -eq $caught) { throw "Expected failure: $Expected" }
    while ($null -ne $caught.InnerException) { $caught = $caught.InnerException }
    if ($caught.Message -cne $Expected) { throw "Expected '$Expected'; actual '$($caught.Message)'." }
}
function Assert-Probe {
    param([bool]$Condition,[string]$Message)
    if (-not $Condition) { throw $Message }
}
'@
            [IO.File]::WriteAllText($probePath, $prefix + "`n" + $Code, [Text.UTF8Encoding]::new($false, $true))
            $hostName = if ($PSVersionTable.PSEdition -eq 'Desktop') { 'powershell.exe' } else { 'pwsh.exe' }
            $priorPreference = $ErrorActionPreference
            try {
                $ErrorActionPreference = 'Continue'
                $output = & (Join-Path $PSHOME $hostName) -NoProfile -File $probePath -RepositoryRoot $RepositoryRoot -AssemblyRoot $scratch 2>&1
                $exitCode = $LASTEXITCODE
            }
            finally {
                $ErrorActionPreference = $priorPreference
            }
            if ($exitCode -ne 0) { throw ($output -join "`n") }
            return $output
        }
    }

    It 'pins the acyclic source graph inventory and exact output set' {
        Test-Path -LiteralPath $script:contractPath -PathType Leaf | Should -BeTrue
        . $script:contractPath
        $contract = Get-PspktEvidenceLedgerContract
        $contract.OutputPathSet | Should -Be @(
            'certification/evidence-ledger/schema/evidence-schema.v1.json',
            'certification/evidence-ledger/schema/signing-ledger-schema.v1.json',
            'certification/evidence-ledger/schema/signing-ledger-maxima.v1.json')
        $contract.MaintainedInputPathSet | Should -Be @(
            'certification/evidence-ledger/schema/evidence-ledger-inventory.v1.json')
        $contract.Sha256ByPath.Contains('certification/evidence-ledger/lib/Pspkt.Certification.EvidenceLedgerContract.ps1') | Should -BeFalse
        $contract.Sha256ByPath.Count | Should -Be 19
        $expectedPins = @(
            'certification/lib/Pspkt.Certification.SchemaBootstrap.cs',
            'certification/schema/protocol-schema-meta.v1.json',
            'certification/schema/protocol-schema.v1.json',
            'certification/schema/protocol-inventory.v1.json',
            'certification/evidence-ledger/.gitattributes',
            'certification/evidence-ledger/lib/.gitattributes',
            'certification/evidence-ledger/schema/.gitattributes',
            'certification/evidence-ledger/validators/.gitattributes',
            'certification/evidence-ledger/vectors/.gitattributes',
            'tests/phase4-evidence-ledger/.gitattributes',
            'certification/evidence-ledger/lib/Pspkt.Certification.EvidenceLedgerAuthority.cs',
            'certification/evidence-ledger/lib/Pspkt.Certification.EvidenceLedgerVerify.cs',
            'certification/evidence-ledger/validators/Invoke-PspktPhase4EvidenceLedgerAuthorityValidators.ps1',
            'certification/evidence-ledger/vectors/New-PspktPhase4EvidenceLedgerVectors.ps1',
            'certification/evidence-ledger/README.md',
            'certification/evidence-ledger/schema/evidence-ledger-inventory.v1.json',
            'certification/evidence-ledger/schema/evidence-schema.v1.json',
            'certification/evidence-ledger/schema/signing-ledger-schema.v1.json',
            'certification/evidence-ledger/schema/signing-ledger-maxima.v1.json')
        @($contract.Sha256ByPath.Keys | Sort-Object) | Should -Be @($expectedPins | Sort-Object)
        $inventory = Get-Content -LiteralPath (Join-Path $script:sliceRoot 'schema\evidence-ledger-inventory.v1.json') -Raw | ConvertFrom-Json
        $contract.EvidenceRootOrder | Should -Be $inventory.evidenceRoots
        $contract.EvidenceAppendOrder | Should -Be $inventory.evidenceAppend.name
        $contract.LedgerAppendOrder | Should -Be $inventory.ledgerAppend.name
        $contract.DeferredEvidenceRoots | Should -Be $inventory.deferredEvidenceRoots
        $contract.MaximumSegmentRecords | Should -Be $inventory.maximumSegmentRecords
        $contract.MaximumInclusionSiblingHashes | Should -Be $inventory.maximumInclusionSiblingHashes
        $contractHash = (Get-FileHash -LiteralPath $script:contractPath -Algorithm SHA256).Hash.ToLowerInvariant()
        foreach ($path in $contract.Sha256ByPath.Keys) {
            $absolutePath = Join-Path $script:repositoryRoot $path.Replace('/', '\')
            (Get-FileHash -LiteralPath $absolutePath -Algorithm SHA256).Hash.ToLowerInvariant() | Should -BeExactly $contract.Sha256ByPath[$path]
            [IO.File]::ReadAllText($absolutePath).Contains($contractHash) | Should -BeFalse
        }
        $validatorPath = Join-Path $script:sliceRoot 'validators\Invoke-PspktPhase4EvidenceLedgerAuthorityValidators.ps1'
        $tokens = $null
        $errors = $null
        $syntax = [Management.Automation.Language.Parser]::ParseFile($validatorPath, [ref]$tokens, [ref]$errors)
        $errors.Count | Should -Be 0
        $pinGuard = $syntax.Find({
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Assert-PspktEvidenceLedgerPins'
        }, $true)
        $pinGuard | Should -Not -BeNullOrEmpty
        . ([scriptblock]::Create($pinGuard.Extent.Text))
        $fixtureRoot = Join-Path $TestDrive 'pin-graph'
        $contract = Copy-EvidenceLedgerFixture -DestinationRoot $fixtureRoot
        Assert-PspktEvidenceLedgerPins -RepositoryRoot $fixtureRoot -Contract $contract
        $hostName = if ($PSVersionTable.PSEdition -eq 'Desktop') { 'powershell.exe' } else { 'pwsh.exe' }
        $fixtureValidator = Join-Path $fixtureRoot 'certification\evidence-ledger\validators\Invoke-PspktPhase4EvidenceLedgerAuthorityValidators.ps1'
        $pinProbe = Join-Path $TestDrive 'pin-probe.ps1'
        [IO.File]::WriteAllText($pinProbe,@'
param([string]$ValidatorPath,[string]$RepositoryRoot,[string]$AssemblyRoot)
$ErrorActionPreference = 'Stop'
try {
    & $ValidatorPath -Worker -Mode Compile -RepositoryRoot $RepositoryRoot -AssemblyRoot $AssemblyRoot
}
catch {
    [Console]::WriteLine('PIN_FAILURE|' + $_.Exception.Message)
    exit 1
}
'@,[Text.UTF8Encoding]::new($false,$true))
        $bracketAssemblyRoot = Join-Path $TestDrive 'assembly[brackets]'
        [void][IO.Directory]::CreateDirectory($bracketAssemblyRoot)
        $priorPreference = $ErrorActionPreference
        try {
            $ErrorActionPreference = 'Continue'
            $bracketOutput = & (Join-Path $PSHOME $hostName) -NoProfile -File $pinProbe -ValidatorPath $validatorPath -RepositoryRoot $script:repositoryRoot -AssemblyRoot $bracketAssemblyRoot 2>&1
            $bracketExitCode = $LASTEXITCODE
        }
        finally { $ErrorActionPreference = $priorPreference }
        $bracketExitCode | Should -Be 0 -Because ($bracketOutput -join "`n")
        [IO.Directory]::GetFiles($bracketAssemblyRoot,'*.dll').Length | Should -Be 3
        foreach ($path in $contract.Sha256ByPath.Keys) {
            $destination = Join-Path $fixtureRoot $path.Replace('/', '\')
            $original = [IO.File]::ReadAllBytes($destination)
            [IO.File]::WriteAllBytes($destination, [byte[]]@($original + 10))
            { Assert-PspktEvidenceLedgerPins -RepositoryRoot $fixtureRoot -Contract $contract } |
                Should -Throw -ExpectedMessage "Pinned evidence ledger hash differs: $path"
            $assemblyRoot = Join-Path $TestDrive ([Guid]::NewGuid().ToString('N'))
            [void][IO.Directory]::CreateDirectory($assemblyRoot)
            $priorPreference = $ErrorActionPreference
            try {
                $ErrorActionPreference = 'Continue'
                $output = & (Join-Path $PSHOME $hostName) -NoProfile -File $pinProbe -ValidatorPath $fixtureValidator -RepositoryRoot $fixtureRoot -AssemblyRoot $assemblyRoot 2>&1
                $exitCode = $LASTEXITCODE
            }
            finally { $ErrorActionPreference = $priorPreference }
            $exitCode | Should -Not -Be 0
            ($output -join "`n") | Should -BeExactly "PIN_FAILURE|Pinned evidence ledger hash differs: $path"
            [IO.Directory]::GetFiles($assemblyRoot,'*.dll').Length | Should -Be 0
            [IO.File]::WriteAllBytes($destination, $original)
        }
    }

    It 'projects forward dependencies in protocol source order without reverse dependents' {
        $fixtureRoot = Join-Path $TestDrive 'projection-inputs'
        $contract = Copy-EvidenceLedgerFixture -DestinationRoot $fixtureRoot
        $source = '{"schemaId":"SyntheticProjectionV1","schemaVersion":1,"types":[{"name":"Reverse","typeId":99,"production":"Named","fields":[{"fieldId":1,"name":"root","type":"Root"}]},{"name":"Leaf","typeId":88,"production":"Named","fields":[{"fieldId":9,"name":"value","type":"U32"}]},{"name":"Mapped","typeId":77,"production":"Named","fields":[{"fieldId":3,"name":"leaf","type":"Leaf"}]},{"name":"BranchKind","typeId":66,"production":"EnumU16","members":[{"name":"Mapped","value":0}]},{"name":"ItemSet","typeId":55,"production":"Set","elementType":"BranchKind","minCount":0,"maxCount":2},{"name":"ItemList","typeId":44,"production":"List","elementType":"Leaf","minCount":0,"maxCount":3},{"name":"HopThree","typeId":35,"production":"Named","fields":[{"fieldId":5,"name":"items","type":"ItemSet"}]},{"name":"HopTwo","typeId":33,"production":"Named","fields":[{"fieldId":7,"name":"next","type":"HopThree"}]},{"name":"HopOne","typeId":22,"production":"Named","fields":[{"fieldId":2,"name":"next","type":"HopTwo"}]},{"name":"Root","typeId":11,"production":"Named","fields":[{"fieldId":4,"name":"next","type":"HopOne"},{"fieldId":8,"name":"items","type":"ItemList"}]}]}'
        [IO.File]::WriteAllText((Join-Path $fixtureRoot 'certification\schema\protocol-schema.v1.json'),$source,[Text.UTF8Encoding]::new($false,$true))
        $inventoryPath = Join-Path $fixtureRoot 'certification\schema\protocol-inventory.v1.json'
        $inventory = Get-Content -LiteralPath $inventoryPath -Raw | ConvertFrom-Json
        $inventory.unionMappings += [pscustomobject]@{union='SyntheticBranch';discriminator='BranchKind';branches=@([pscustomobject]@{semanticLabel='Mapped';value=0;emittedIdentifier='Mapped'})}
        [IO.File]::WriteAllText($inventoryPath,($inventory | ConvertTo-Json -Depth 40 -Compress),[Text.UTF8Encoding]::new($false,$true))
        Update-EvidenceFixtureInputPin -FixtureRoot $fixtureRoot -RelativePath 'certification/schema/protocol-schema.v1.json' -Contract $contract
        Update-EvidenceFixtureInputPin -FixtureRoot $fixtureRoot -RelativePath 'certification/schema/protocol-inventory.v1.json' -Contract $contract
        Invoke-EvidenceLedgerProbe -RepositoryRoot $fixtureRoot -Code @'
$sourceBytes = $protocolBytes
$gate = [Pspkt.Certification.SchemaBootstrap]::Evaluate('schema-against-meta', $sourceBytes, $metaBytes)
Assert-Probe $gate.Accepted ('Synthetic projection meta gate: ' + $gate.Reason)
$inventory = $utf8.GetString($protocolInventoryBytes) | ConvertFrom-Json
$mapping = @{}
foreach ($row in $inventory.unionMappings) { $mapping[$row.discriminator] = @($row.branches.emittedIdentifier) }
$mapping = ConvertTo-ProbeCanonical $mapping
foreach ($implementation in @([Pspkt.Certification.EvidenceLedger.EvidenceLedgerAuthority],[Pspkt.Certification.EvidenceLedger.EvidenceLedgerVerify])) {
    $result = $utf8.GetString($implementation::Project($sourceBytes, [string[]]@('Root'), $mapping)) | ConvertFrom-Json
    Assert-Probe (($result.types.name -join ',') -ceq 'Leaf,Mapped,BranchKind,ItemSet,ItemList,HopThree,HopTwo,HopOne,Root') 'Forward source-order projection differs.'
    Assert-Probe (($result.types.typeId -join ',') -ceq '1,2,3,4,5,6,7,8,9') 'Projection IDs differ.'
    Assert-Probe (($result.types[-1].fields.fieldId -join ',') -ceq '4,8') 'Copied field IDs differ.'
    Assert-Probe ($result.types[0].fields[0].fieldId -eq 9) 'Leaf field ID differs.'
    Assert-ProbeFailure { $implementation::Project($sourceBytes, [string[]]@('Root','Missing'), $mapping) } 'Projection root is missing: Missing'
}
'@
    }

    It 'emits the exact evidence declarations kind mapping domains and envelope' {
        $schema = Get-Content -LiteralPath (Join-Path $script:sliceRoot 'schema\evidence-schema.v1.json') -Raw | ConvertFrom-Json
        $schema.schemaId | Should -BeExactly 'PspktEvidenceSchemaV1'
        $schema.types.Count | Should -Be 24
        $expected = [ordered]@{
            LocalEvidenceReceiptV1 = 'evidenceId:GUID,subjectId:GUID,leaseId:GUID,bootId:GUID,protocolSchemaDigest:SHA-256,evidenceSchemaDigest:SHA-256,payloadDigest:SHA-256,observedAt:FILETIME,observerKeyId:SHA-256,signature:Rsa3072Signature'
            LocalEvidenceProofV1 = 'evidenceId:GUID,subjectId:GUID,leaseId:GUID,bootId:GUID,protocolSchemaDigest:SHA-256,evidenceSchemaDigest:SHA-256,payloadDigest:SHA-256,observedAt:FILETIME,observerKeyId:SHA-256,signature:Rsa3072Signature'
            OperationBurnReceiptV1 = 'logicalOperationId:GUID,canonicalSemanticDigest:SHA-256,terminalRecordDigest:SHA-256,burnReasonDigest:SHA-256,burnedAt:FILETIME,observerProofDigest:SHA-256,nextAttempt:U32'
            OperationBurnDeferralReceiptV1 = 'logicalOperationId:GUID,canonicalSemanticDigest:SHA-256,successorLogicalOperationId:GUID,successorRunIntentId:GUID,successorRunIntentDigest:SHA-256,deferredAt:FILETIME,deferralReasonDigest:SHA-256,nextAttempt:U32'
            OperationRehabilitationAuthorizationV1 = 'burnReceiptDigest:SHA-256,burnedLogicalOperationId:GUID,burnedSemanticDigest:SHA-256,successorLogicalOperationId:GUID,successorRunIntentId:GUID,successorRunIntentDigest:SHA-256,capacityDeadline:FILETIME,authorizedAt:FILETIME,authorityKeyId:SHA-256,authoritySignature:Rsa3072Signature'
            OperationRehabilitationReceiptV1 = 'authorizationDigest:SHA-256,successorLogicalOperationId:GUID,successorRecordDigest:SHA-256,acceptedAt:FILETIME,observerProofDigest:SHA-256'
        }
        $schema.types[16..23].name | Should -Be @(@($expected.Keys) + 'EvidenceArtifactKind' + 'EvidenceArtifactEnvelopeV1')
        $schema.types.typeId | Should -Be @(1..24)
        foreach ($name in $expected.Keys) {
            $declaration = $schema.types | Where-Object name -CEQ $name
            ($declaration.fields | ForEach-Object { $_.name + ':' + $_.type }) -join ',' | Should -BeExactly $expected[$name]
            $declaration.fields.fieldId | Should -Be @(1..$declaration.fields.Count)
        }
        $kind = $schema.types | Where-Object name -CEQ 'EvidenceArtifactKind'
        $kind.members.value | Should -Be @(0..21)
        $roots = @('WorkerSessionKeyCertificateV1','BrokerSessionKeyCertificateBodyV1','BrokerSessionKeyCertificateEnvelopeV1','WorkerProcessIsolationAdmissionReceiptV1','WorkerProcessIsolationReceiptV1','ServiceLaunchProofV1','ServiceEnrollmentInstallProofV1','WorkerProcessDaclAccessPolicyProofV1','LiveCandidateAccessProbeV1','LocalTranscriptChunkV1','LocalTranscriptRootV1','LocalTranscriptProofV1','LocalTranscriptRootAcceptedV1','BrokerServiceLaunchProofV1','CreatorPermitInstallationBodyV1','CreatorPermitInstallationV1')
        $kind.members.name | Should -Be @($roots + @($expected.Keys))
        $inventory = Get-Content -LiteralPath (Join-Path $script:sliceRoot 'schema\evidence-ledger-inventory.v1.json') -Raw | ConvertFrom-Json
        $inventory.evidenceRoots | Should -Be $roots
        foreach ($name in $kind.members.name) { $inventory.evidenceDomains.$name | Should -BeExactly "pspkt/evidence/v1/$name" }
        @($inventory.evidenceDomains.PSObject.Properties.Value | Select-Object -Unique).Count | Should -Be 22
        $envelope = $schema.types[-1]
        ($envelope.fields | ForEach-Object { $_.name + ':' + $_.type }) -join ',' |
            Should -BeExactly 'kind:EvidenceArtifactKind,artifactId:GUID,profile:U8,payload:BoundedBytes,payloadDigest:SHA-256'
        ($envelope.fields | Where-Object name -CEQ 'payload').maxBytes | Should -Be 262143
        $schema.types.name | Should -Not -Contain 'ServiceControlEventNodeProofV1'
    }

    It 'requires local evidence receipt and proof structural equivalence' {
        Invoke-EvidenceLedgerProbe @'
Invoke-ProbeSemantics
$original = $outputs['evidence-schema.v1.json']
$schema = $utf8.GetString($original) | ConvertFrom-Json
($schema.types | Where-Object name -CEQ 'LocalEvidenceProofV1').fields[0].type = 'Opaque16'
$outputs['evidence-schema.v1.json'] = ConvertTo-ProbeCanonical $schema
$gate = [Pspkt.Certification.SchemaBootstrap]::Evaluate('schema-against-meta',$outputs['evidence-schema.v1.json'],$metaBytes)
Assert-Probe $gate.Accepted 'Proof mutation must remain meta-valid.'
Assert-ProbeFailure { Invoke-ProbeSemantics } 'Local evidence receipt and proof shapes differ.'
($schema.types | Where-Object name -CEQ 'LocalEvidenceReceiptV1').fields[0].type = 'Opaque16'
$outputs['evidence-schema.v1.json'] = ConvertTo-ProbeCanonical $schema
Assert-ProbeFailure { Invoke-ProbeSemantics } 'Evidence declaration shape differs.'
$outputs['evidence-schema.v1.json'] = $original
Invoke-ProbeSemantics
'@
    }

    It 'projects complete authorization and operation ledger closures with exact kind mappings' {
        Invoke-EvidenceLedgerProbe @'
$ledger = $utf8.GetString($outputs['signing-ledger-schema.v1.json']) | ConvertFrom-Json
Assert-Probe ($ledger.types.Count -eq 60) 'Ledger must contain exactly 60 declarations.'
Assert-Probe (($ledger.types.typeId -join ',') -ceq ((1..60) -join ',')) 'Ledger local IDs differ.'
$source = $utf8.GetString($protocolBytes) | ConvertFrom-Json
$sourceInventory = $utf8.GetString($protocolInventoryBytes) | ConvertFrom-Json
$selectedNames = @($ledger.types[0..44].name)
$orderedOriginals = @($source.types | Where-Object { $selectedNames -ccontains $_.name })
Assert-Probe (($orderedOriginals.name -join ',') -ceq ($selectedNames -join ',')) 'Copied ledger source order differs.'
for ($index = 0; $index -lt 45; $index++) {
    $original = $orderedOriginals[$index]
    $copy = $ledger.types[$index]
    $original.PSObject.Properties.Remove('typeId')
    $copy.PSObject.Properties.Remove('typeId')
    Assert-Probe ([Convert]::ToBase64String((ConvertTo-ProbeCanonical $original)) -ceq [Convert]::ToBase64String((ConvertTo-ProbeCanonical $copy))) 'Copied ledger field IDs or shape differ.'
}
$appended = @('OperationBurnReceiptV1','OperationBurnDeferralReceiptV1','OperationRehabilitationAuthorizationV1','OperationRehabilitationReceiptV1','OperationSigningLedgerKind','AuthorizationSigningLedgerRecordEnvelopeV1','OperationSigningLedgerRecordEnvelopeV1','AuthorizationSigningLedgerRecordList','OperationSigningLedgerRecordList','SigningLedgerSegmentHeaderV1','AuthorizationSigningLedgerSegmentV1','OperationSigningLedgerSegmentV1','Sha256SiblingList','AuthorizationSigningLedgerInclusionProofV1','OperationSigningLedgerInclusionProofV1')
Assert-Probe (($ledger.types[45..59].name -join ',') -ceq ($appended -join ',')) 'Ledger append order differs.'
$authorization = $ledger.types | Where-Object name -CEQ 'AuthorizationLedgerKind'
$operation = $ledger.types | Where-Object name -CEQ 'OperationRecordKind'
$extended = $ledger.types | Where-Object name -CEQ 'OperationSigningLedgerKind'
Assert-Probe ($authorization.members.Count -eq 16 -and $operation.members.Count -eq 25 -and $extended.members.Count -eq 29) 'Ledger kind cardinality differs.'
foreach ($pair in @(@('AuthorizationLedgerKind','AuthorizationLedgerRecord'),@('OperationRecordKind','OperationRecord'))) {
    $kind = $ledger.types | Where-Object name -CEQ $pair[0]
    $mapping = $sourceInventory.unionMappings | Where-Object union -CEQ $pair[1]
    Assert-Probe (($kind.members.name -join ',') -ceq ($mapping.branches.emittedIdentifier -join ',')) 'Ledger mapping differs.'
    Assert-Probe (($kind.members.value -join ',') -ceq ((0..($kind.members.Count-1)) -join ',')) 'Ledger original kind values differ.'
}
Assert-Probe ($extended.members[18].name -ceq 'AbortedCompilationDefinitivelyFailedWithLaunchAuthority') 'Value eighteen identifier differs.'
Assert-Probe (($extended.members[0..24].name -join ',') -ceq ($operation.members.name -join ',')) 'Extended original kinds differ.'
Assert-Probe (($extended.members[25..28].name -join ',') -ceq ($appended[0..3] -join ',')) 'Extended new kinds differ.'
Assert-Probe (($extended.members.value -join ',') -ceq ((0..28) -join ',')) 'Extended values differ.'
$evidence = $utf8.GetString($outputs['evidence-schema.v1.json']) | ConvertFrom-Json
foreach ($name in $appended[0..3]) {
    $left = $evidence.types | Where-Object name -CEQ $name
    $right = $ledger.types | Where-Object name -CEQ $name
    $left.PSObject.Properties.Remove('typeId')
    $right.PSObject.Properties.Remove('typeId')
    Assert-Probe ([Convert]::ToBase64String((ConvertTo-ProbeCanonical $left)) -ceq [Convert]::ToBase64String((ConvertTo-ProbeCanonical $right))) 'Cross-schema operation shape differs.'
}
Assert-Probe (-not ($ledger.types.name -ccontains 'LocalEvidenceReceiptV1') -and -not ($ledger.types.name -ccontains 'LocalEvidenceProofV1')) 'Local evidence must remain evidence-only.'
Invoke-ProbeSemantics
'@
    }

    It 'preserves copied field ids and conditional pair identities' {
        Invoke-EvidenceLedgerProbe @'
$fixture = '{"schemaVersion":1,"schemaId":"ConditionalFixtureV1","types":[{"typeId":9,"name":"Conditional","production":"Named","fields":[{"fieldId":1,"name":"id","type":"GUID"},{"fieldId":40,"name":"isolated","type":"SHA-256","profile":"InteractiveSeat","status":"Forbidden"},{"fieldId":40,"name":"isolated","type":"SHA-256","profile":"NonInteractiveElevated"},{"fieldId":45,"name":"shared","type":"U16"},{"fieldId":45,"name":"shared","type":"U16","profile":"NonInteractiveElevated","status":"Forbidden"},{"fieldId":64,"name":"seat","type":"U32","profile":"InteractiveSeat"}]}]}'
$bytes = $utf8.GetBytes($fixture)
$gate = [Pspkt.Certification.SchemaBootstrap]::Evaluate('schema-against-meta',$bytes,$metaBytes)
Assert-Probe $gate.Accepted ('Conditional fixture meta: ' + $gate.Reason)
foreach ($implementation in @([Pspkt.Certification.EvidenceLedger.EvidenceLedgerAuthority],[Pspkt.Certification.EvidenceLedger.EvidenceLedgerVerify])) {
    $flags = [Reflection.BindingFlags]'Static,NonPublic'
    $arguments = [object[]]::new(1)
    $arguments[0] = $bytes
    $parsed = $implementation.GetMethod('Parse',$flags).Invoke($null,$arguments)
    $method = $implementation.GetMethod('EffectiveFields',$flags)
    Assert-Probe ($null -ne $method) 'Effective-field semantic seam is missing.'
    $interactive = $method.Invoke($null,[object[]]@($parsed['types'][0],'InteractiveSeat'))
    $noninteractive = $method.Invoke($null,[object[]]@($parsed['types'][0],'NonInteractiveElevated'))
    Assert-Probe (($interactive | ForEach-Object { $_['fieldId'] }) -join ',' -ceq '1,45,64') 'Interactive effective field IDs differ.'
    Assert-Probe (($noninteractive | ForEach-Object { $_['fieldId'] }) -join ',' -ceq '1,40') 'Noninteractive effective field IDs differ.'
    $projected = $utf8.GetString($implementation::Project($bytes,[string[]]@('Conditional'),$utf8.GetBytes('{}'))) | ConvertFrom-Json
    Assert-Probe (($projected.types[0].fields.fieldId -join ',') -ceq '1,40,40,45,45,64') 'Conditional copy lost source IDs.'
    $parsed['types'][0]['fields'][1]['name'] = 'wrong'
    Assert-ProbeFailure { $method.Invoke($null,[object[]]@($parsed['types'][0],'InteractiveSeat')) } 'Forbidden field has no required shape.'
}
$schema = $utf8.GetString($outputs['evidence-schema.v1.json']) | ConvertFrom-Json
$conditional = $schema.types | Where-Object name -CEQ 'WorkerProcessIsolationAdmissionReceiptV1'
($conditional.fields | Where-Object { $_.fieldId -eq 40 -and $_.profile -eq 'InteractiveSeat' }).name = 'wrong'
$outputs['evidence-schema.v1.json'] = ConvertTo-ProbeCanonical $schema
$gate = [Pspkt.Certification.SchemaBootstrap]::Evaluate('schema-against-meta',$outputs['evidence-schema.v1.json'],$metaBytes)
Assert-Probe (-not $gate.Accepted) 'Pair mutation must be rejected by meta.'
Assert-ProbeFailure { Invoke-ProbeSemantics } 'Forbidden field has no required shape.'
'@
    }

    It 'sizes every schema production and primitive with independent numeric fixtures' {
        Invoke-EvidenceLedgerProbe @'
$primitiveNames = @('U8','U16','U32','U64','FILETIME','QPC','GUID','Opaque16','FixedAscii8','SHA-256','Opaque32','AsciiIdentifier','BinarySid','Utf8Short','Rsa3072PublicBlob','Rsa3072Signature','LUID','I16','I32','I64','BoundedBytes','OpaqueUtf16')
$fields = @()
for ($index = 0; $index -lt $primitiveNames.Count; $index++) {
    $field = [ordered]@{fieldId=$index+1;name='field'+$index;type=$primitiveNames[$index]}
    if ($field.type -eq 'BoundedBytes') { $field.maxBytes = 7 }
    if ($field.type -eq 'OpaqueUtf16') { $field.maxCodeUnits = 9 }
    $fields += $field
}
$fixture = @{schemaVersion=1;schemaId='SizingFixtureV1';types=@(
    @{name='Matrix';typeId=1;production='Named';fields=$fields},
    @{name='Code';typeId=2;production='EnumU16';members=@(@{name='Only';value=0})},
    @{name='Names';typeId=3;production='SemanticString';encoding='AsciiEnvironmentName';grammar='None';minBytes=1;maxBytes=32767;maxUtf16CodeUnits=32767},
    @{name='TextValue';typeId=4;production='SemanticString';encoding='Utf8';grammar='None';minBytes=1;maxBytes=14;maxUtf16CodeUnits=14},
    @{name='Numbers';typeId=5;production='List';elementType='I32';minCount=0;maxCount=3},
    @{name='Unique';typeId=6;production='Set';elementType='Code';minCount=0;maxCount=2},
    @{name='Composite';typeId=7;production='Named';fields=@(@{fieldId=1;name='numbers';type='Numbers'},@{fieldId=2;name='unique';type='Unique'},@{fieldId=3;name='text';type='TextValue'})},
    @{name='Conditional';typeId=8;production='Named';fields=@(@{fieldId=1;name='always';type='U8'},@{fieldId=2;name='value';type='BoundedBytes';maxBytes=3},@{fieldId=2;name='value';type='BoundedBytes';maxBytes=3;profile='InteractiveSeat';status='Forbidden'},@{fieldId=9;name='signed';type='I64';profile='NonInteractiveElevated'})},
    @{name='MinimumList';typeId=9;production='List';elementType='U8';minCount=0;maxCount=1},
    @{name='MinimumSet';typeId=10;production='Set';elementType='U8';minCount=0;maxCount=1}
)}
$bytes = ConvertTo-ProbeCanonical $fixture
$gate = [Pspkt.Certification.SchemaBootstrap]::Evaluate('schema-against-meta',$bytes,$metaBytes)
Assert-Probe $gate.Accepted ('Sizing fixture meta: ' + $gate.Reason)
$cases = @(@('Matrix',1670,1670),@('Code',2,2),@('Names',32771,32771),@('TextValue',18,18),@('Numbers',28,28),@('Unique',16,16),@('Composite',80,80),@('Conditional',7,34),@('MinimumList',9,9),@('MinimumSet',9,9))
foreach ($implementation in @([Pspkt.Certification.EvidenceLedger.EvidenceLedgerAuthority],[Pspkt.Certification.EvidenceLedger.EvidenceLedgerVerify])) {
    foreach ($case in $cases) {
        $interactive = $implementation::Maximum($bytes,$protocolInventoryBytes,$metaBytes,$case[0],'InteractiveSeat')
        $noninteractive = $implementation::Maximum($bytes,$protocolInventoryBytes,$metaBytes,$case[0],'NonInteractiveElevated')
        Assert-Probe ($interactive.ToString() -ceq [string]$case[1]) ('Interactive formula differs: ' + $case[0])
        Assert-Probe ($noninteractive.ToString() -ceq [string]$case[2]) ('Noninteractive formula differs: ' + $case[0])
    }
    $fixture.types[2].minBytes = 0
    $invalid = ConvertTo-ProbeCanonical $fixture
    Assert-ProbeFailure { $implementation::Maximum($invalid,$protocolInventoryBytes,$metaBytes,'Names','InteractiveSeat') } 'Sizing schema meta rejected: invalid-cardinality'
    $fixture.types[2].minBytes = 1
    $fixture.types[0].fields[-2].maxBytes = [uint64]4294967296
    $invalid = ConvertTo-ProbeCanonical $fixture
    Assert-ProbeFailure { $implementation::Maximum($invalid,$protocolInventoryBytes,$metaBytes,'Matrix','InteractiveSeat') } 'Sizing schema meta rejected: integer-overflow'
    $fixture.types[0].fields[-2].maxBytes = 7
}
'@
    }

    It 'pins evidence authorization and operation payload and envelope maxima' {
        Invoke-EvidenceLedgerProbe @'
$inventory = $utf8.GetString($inventoryBytes) | ConvertFrom-Json
$evidence = $outputs['evidence-schema.v1.json']
$ledger = $outputs['signing-ledger-schema.v1.json']
$evidenceNames = [string[]]@($inventory.evidenceRoots + $inventory.evidenceAppend[0..5].name)
$framework = if ($PSVersionTable.PSEdition -eq 'Desktop') { @('System.dll','System.Core.dll','System.Xml.dll','System.Runtime.Serialization.dll','System.Numerics.dll') } else { @(Get-ChildItem -LiteralPath (Join-Path $PSHOME 'ref') -Filter '*.dll' | ForEach-Object FullName) }
$references = @($framework + [Pspkt.Certification.SchemaBootstrap].Assembly.Location)
$conditional = $utf8.GetBytes('{"schemaId":"ProfileSizeV1","schemaVersion":1,"types":[{"name":"Conditioned","typeId":1,"production":"Named","fields":[{"fieldId":1,"name":"baseValue","type":"U8"},{"fieldId":40,"name":"elevated","type":"U64","profile":"NonInteractiveElevated"}]},{"name":"Dominant","typeId":2,"production":"Named","fields":[{"fieldId":1,"name":"signature","type":"Rsa3072Signature"}]}]}')
foreach ($implementation in @([Pspkt.Certification.EvidenceLedger.EvidenceLedgerAuthority],[Pspkt.Certification.EvidenceLedger.EvidenceLedgerVerify])) {
    Assert-Probe ($implementation::PayloadMaximum($evidence,$protocolInventoryBytes,$metaBytes,$evidenceNames) -eq 262143) 'Evidence payload maximum differs.'
    Assert-Probe ($implementation::PayloadMaximum($ledger,$protocolInventoryBytes,$metaBytes,[string[]]$inventory.authorizationKinds) -eq 649) 'Authorization payload maximum differs.'
    Assert-Probe ($implementation::PayloadMaximum($ledger,$protocolInventoryBytes,$metaBytes,[string[]]$inventory.operationKinds) -eq 636) 'Operation payload maximum differs.'
    Assert-Probe ($implementation::Maximum($ledger,$protocolInventoryBytes,$metaBytes,'AuthorizationSigningLedgerRecordEnvelopeV1','InteractiveSeat') -eq 757) 'Authorization envelope maximum differs.'
    Assert-Probe ($implementation::Maximum($ledger,$protocolInventoryBytes,$metaBytes,'OperationSigningLedgerRecordEnvelopeV1','InteractiveSeat') -eq 744) 'Operation envelope maximum differs.'
    $sourcePath = Join-Path $sliceRoot ('lib\Pspkt.Certification.' + $implementation.Name + '.cs')
    $source = [IO.File]::ReadAllText($sourcePath)
    $profileMutantName = $implementation.Name + 'ProfileMutant'
    $profileSource = $source.Replace($implementation.Name,$profileMutantName).Replace('scope == "Any" || scope == profile','scope == "Any"')
    Assert-Probe ($profileSource -cne $source.Replace($implementation.Name,$profileMutantName)) 'Profile mutant did not change profile logic.'
    $assemblyPath = Join-Path $AssemblyRoot ($profileMutantName + '.dll')
    Add-Type -TypeDefinition $profileSource -ReferencedAssemblies $references -OutputAssembly $assemblyPath
    Add-Type -Path $assemblyPath
    $mutant = ('Pspkt.Certification.EvidenceLedger.' + $profileMutantName) -as [type]
    Assert-Probe ($implementation::Maximum($conditional,$protocolInventoryBytes,$metaBytes,'Conditioned','NonInteractiveElevated') -eq 21) 'Profile fixture oracle differs.'
    Assert-Probe ($mutant::Maximum($conditional,$protocolInventoryBytes,$metaBytes,'Conditioned','NonInteractiveElevated') -ne 21) 'Profile mutant survived the branch fixture.'
    Assert-Probe ($mutant::PayloadMaximum($conditional,$protocolInventoryBytes,$metaBytes,[string[]]@('Conditioned','Dominant')) -eq 390) 'Dominant aggregate must remain unchanged.'
    $operationMutantName = $implementation.Name + 'OperationMutant'
    $operationSource = $source.Replace($implementation.Name,$operationMutantName).Replace('foreach (string name in names)','foreach (string name in new string[] { "OperationUnseenV1" })')
    Assert-Probe ($operationSource -cne $source.Replace($implementation.Name,$operationMutantName)) 'Operation mutant did not omit appended kinds.'
    $assemblyPath = Join-Path $AssemblyRoot ($operationMutantName + '.dll')
    Add-Type -TypeDefinition $operationSource -ReferencedAssemblies $references -OutputAssembly $assemblyPath
    Add-Type -Path $assemblyPath
    $mutant = ('Pspkt.Certification.EvidenceLedger.' + $operationMutantName) -as [type]
    Assert-Probe ($mutant::PayloadMaximum($ledger,$protocolInventoryBytes,$metaBytes,[string[]]$inventory.operationKinds) -ne 636) 'Appended-kind omission mutant survived.'
}
$ledgerShape = $utf8.GetString($ledger) | ConvertFrom-Json
foreach ($pair in @(@('AuthorizationSigningLedgerRecordEnvelopeV1',649),@('OperationSigningLedgerRecordEnvelopeV1',636))) {
    $envelope = $ledgerShape.types | Where-Object name -CEQ $pair[0]
    Assert-Probe (($envelope.fields | Where-Object name -CEQ 'payload').maxBytes -eq $pair[1]) 'Envelope payload bound differs.'
}
'@
    }

    It 'rejects signing ledger record lists above 4096' {
        Invoke-EvidenceLedgerProbe @'
$original = $outputs['signing-ledger-schema.v1.json']
Invoke-ProbeValidation
foreach ($name in @('AuthorizationSigningLedgerRecordList','OperationSigningLedgerRecordList')) {
    $schema = $utf8.GetString($original) | ConvertFrom-Json
    ($schema.types | Where-Object name -CEQ $name).maxCount = 4097
    $outputs['signing-ledger-schema.v1.json'] = ConvertTo-ProbeCanonical $schema
    $gate = [Pspkt.Certification.SchemaBootstrap]::Evaluate('schema-against-meta',$outputs['signing-ledger-schema.v1.json'],$metaBytes)
    Assert-Probe $gate.Accepted 'The 4097 mutation must pass frozen meta.'
    Assert-ProbeFailure { Invoke-ProbeValidation } 'Signing ledger record limit exceeds 4096.'
    $outputs['signing-ledger-schema.v1.json'] = $original
    Invoke-ProbeValidation
}
'@
    }

    It 'keeps authorization and operation record list purposes separate' {
        Invoke-EvidenceLedgerProbe @'
$original = $outputs['signing-ledger-schema.v1.json']
foreach ($purpose in @('Authorization','Operation')) {
    Invoke-ProbeValidation
    $schema = $utf8.GetString($original) | ConvertFrom-Json
    $segment = $schema.types | Where-Object name -CEQ ($purpose + 'SigningLedgerSegmentV1')
    $other = if ($purpose -eq 'Authorization') { 'Operation' } else { 'Authorization' }
    ($segment.fields | Where-Object name -CEQ 'records').type = $other + 'SigningLedgerRecordList'
    $outputs['signing-ledger-schema.v1.json'] = ConvertTo-ProbeCanonical $schema
    $gate = [Pspkt.Certification.SchemaBootstrap]::Evaluate('schema-against-meta',$outputs['signing-ledger-schema.v1.json'],$metaBytes)
    Assert-Probe $gate.Accepted 'Purpose swap must remain meta-valid.'
    Assert-ProbeFailure { Invoke-ProbeValidation } 'Signing ledger record list purpose differs.'
    $outputs['signing-ledger-schema.v1.json'] = $original
}
Invoke-ProbeValidation
'@
    }

    It 'pins inclusion proof structure domains bounds and maximum bytes' {
        Invoke-EvidenceLedgerProbe @'
Invoke-ProbeValidation
$original = $outputs['signing-ledger-schema.v1.json']
$schema = $utf8.GetString($original) | ConvertFrom-Json
$inventory = $utf8.GetString($inventoryBytes) | ConvertFrom-Json
$expected = 'segmentId:GUID,recordSequence:U64,leafIndex:U32,recordDigest:SHA-256,siblingHashes:Sha256SiblingList,directionBits:U16,merkleRoot:SHA-256,segmentDigest:SHA-256,signerKeyId:SHA-256,signature:Rsa3072Signature'
foreach ($purpose in @('Authorization','Operation')) {
    $name = $purpose + 'SigningLedgerInclusionProofV1'
    $proof = $schema.types | Where-Object name -CEQ $name
    Assert-Probe ((($proof.fields | ForEach-Object { $_.name + ':' + $_.type }) -join ',') -ceq $expected) 'Proof field shape differs.'
    Assert-Probe (($proof.fields.fieldId -join ',') -ceq ((1..10) -join ',')) 'Proof field IDs differ.'
    $domainKey = $purpose.ToLowerInvariant() + ':proof'
    Assert-Probe ($inventory.ledgerDomains.$domainKey -ceq ('pspkt/signing-ledger/' + $purpose.ToLowerInvariant() + '-proof/v1')) 'Proof domain differs.'
    foreach ($implementation in @([Pspkt.Certification.EvidenceLedger.EvidenceLedgerAuthority],[Pspkt.Certification.EvidenceLedger.EvidenceLedgerVerify])) {
        Assert-Probe ($implementation::Maximum($original,$protocolInventoryBytes,$metaBytes,$name,'InteractiveSeat') -eq 1038) 'Full proof maximum differs.'
    }
}
$siblings = $schema.types | Where-Object name -CEQ 'Sha256SiblingList'
Assert-Probe ($siblings.production -ceq 'List' -and $siblings.elementType -ceq 'SHA-256' -and $siblings.minCount -eq 0 -and $siblings.maxCount -eq 12) 'Sibling list shape differs.'
$siblings.maxCount = 13
$outputs['signing-ledger-schema.v1.json'] = ConvertTo-ProbeCanonical $schema
$gate = [Pspkt.Certification.SchemaBootstrap]::Evaluate('schema-against-meta',$outputs['signing-ledger-schema.v1.json'],$metaBytes)
Assert-Probe $gate.Accepted 'Thirteen siblings must remain meta-valid.'
Assert-ProbeFailure { Invoke-ProbeValidation } 'Signing ledger sibling limit exceeds 12.'
$outputs['signing-ledger-schema.v1.json'] = $original
Invoke-ProbeValidation
'@
    }

    It 'pins burn deferral and rehabilitation shapes across both schemas' {
        Invoke-EvidenceLedgerProbe @'
$inventory = $utf8.GetString($inventoryBytes) | ConvertFrom-Json
$original = $outputs['signing-ledger-schema.v1.json']
$names = @('OperationBurnReceiptV1','OperationBurnDeferralReceiptV1','OperationRehabilitationAuthorizationV1','OperationRehabilitationReceiptV1')
$shapes = @(
    'logicalOperationId:GUID,canonicalSemanticDigest:SHA-256,terminalRecordDigest:SHA-256,burnReasonDigest:SHA-256,burnedAt:FILETIME,observerProofDigest:SHA-256,nextAttempt:U32',
    'logicalOperationId:GUID,canonicalSemanticDigest:SHA-256,successorLogicalOperationId:GUID,successorRunIntentId:GUID,successorRunIntentDigest:SHA-256,deferredAt:FILETIME,deferralReasonDigest:SHA-256,nextAttempt:U32',
    'burnReceiptDigest:SHA-256,burnedLogicalOperationId:GUID,burnedSemanticDigest:SHA-256,successorLogicalOperationId:GUID,successorRunIntentId:GUID,successorRunIntentDigest:SHA-256,capacityDeadline:FILETIME,authorizedAt:FILETIME,authorityKeyId:SHA-256,authoritySignature:Rsa3072Signature',
    'authorizationDigest:SHA-256,successorLogicalOperationId:GUID,successorRecordDigest:SHA-256,acceptedAt:FILETIME,observerProofDigest:SHA-256')
for ($index=0; $index -lt 4; $index++) {
    $name = $names[$index]
    foreach ($file in @('evidence-schema.v1.json','signing-ledger-schema.v1.json')) {
        $schema = $utf8.GetString($outputs[$file]) | ConvertFrom-Json
        $declaration = $schema.types | Where-Object name -CEQ $name
        Assert-Probe ((($declaration.fields | ForEach-Object { $_.name + ':' + $_.type }) -join ',') -ceq $shapes[$index]) 'Operation evidence shape differs.'
    }
    $ledger = $utf8.GetString($original) | ConvertFrom-Json
    $kind = $ledger.types | Where-Object name -CEQ 'OperationSigningLedgerKind'
    Assert-Probe ($kind.members[$index+25].name -ceq $name -and $kind.members[$index+25].value -eq $index+25) 'Appended operation kind differs.'
    Assert-Probe ($inventory.evidenceDomains.$name -ceq "pspkt/evidence/v1/$name") 'Operation evidence domain differs.'
    foreach ($coverage in @('payload','record')) {
        $key = 'operation:' + $name + ':' + $coverage
        Assert-Probe ($inventory.ledgerDomains.$key -ceq "pspkt/signing-ledger/v1/operation-record/$name/$coverage") 'Operation ledger domain differs.'
    }
    ($ledger.types | Where-Object name -CEQ $name).fields[0].name = 'changed'
    $outputs['signing-ledger-schema.v1.json'] = ConvertTo-ProbeCanonical $ledger
    Assert-ProbeFailure { Invoke-ProbeValidation } 'Cross-schema operation declaration differs.'
    $outputs['signing-ledger-schema.v1.json'] = $original
}
Invoke-ProbeValidation
'@
    }

    It 'rejects BigInteger sizing values above UInt32' {
        Invoke-EvidenceLedgerProbe @'
$boundary = $utf8.GetBytes('{"schemaVersion":1,"schemaId":"BoundaryV1","types":[{"typeId":1,"name":"Boundary","production":"Named","fields":[{"fieldId":1,"name":"payload","type":"BoundedBytes","maxBytes":4294967285}]}]}')
$overflow = $utf8.GetBytes($utf8.GetString($boundary).Replace('4294967285','4294967286'))
$nested = $utf8.GetBytes('{"schemaVersion":1,"schemaId":"NestedListsV1","types":[{"typeId":1,"name":"First","production":"List","elementType":"Rsa3072Signature","minCount":0,"maxCount":65535},{"typeId":2,"name":"Second","production":"List","elementType":"First","minCount":0,"maxCount":65535},{"typeId":3,"name":"Third","production":"List","elementType":"Second","minCount":0,"maxCount":65535},{"typeId":4,"name":"Fourth","production":"List","elementType":"Third","minCount":0,"maxCount":65535}]}')
foreach ($implementation in @([Pspkt.Certification.EvidenceLedger.EvidenceLedgerAuthority],[Pspkt.Certification.EvidenceLedger.EvidenceLedgerVerify])) {
    Assert-Probe ($implementation::Maximum($boundary,$protocolInventoryBytes,$metaBytes,'Boundary','InteractiveSeat').ToString() -ceq '4294967295') 'UInt32 boundary was not preserved.'
    Assert-ProbeFailure { $implementation::Maximum($overflow,$protocolInventoryBytes,$metaBytes,'Boundary','InteractiveSeat') } 'Encoded size exceeds UInt32.'
    $raw = $implementation.GetMethod('CalculateUncheckedMaximum',[Reflection.BindingFlags]'Static,NonPublic')
    $value = $raw.Invoke($null,[object[]]@($nested,$protocolInventoryBytes,'Fourth','InteractiveSeat'))
    Assert-Probe ($value.ToString() -ceq '7156902113165128499584') 'Exact nested-list BigInteger oracle differs.'
    Assert-ProbeFailure { $implementation::Maximum($nested,$protocolInventoryBytes,$metaBytes,'Fourth','InteractiveSeat') } 'Encoded size exceeds UInt32.'
    $conversion = $implementation.GetMethod('RequireUInt32',[Reflection.BindingFlags]'Static,NonPublic')
    foreach ($text in @('0','4294967295')) {
        $value = [Numerics.BigInteger]::Parse($text)
        Assert-Probe ($conversion.Invoke($null,[object[]]@($value)).ToString() -ceq $text) 'Checked UInt32 boundary differs.'
    }
    foreach ($text in @('-1','4294967296','7156902113165128499584')) {
        $value = [Numerics.BigInteger]::Parse($text)
        Assert-ProbeFailure { $conversion.Invoke($null,[object[]]@($value)) } 'Encoded size exceeds UInt32.'
    }
}
'@
    }

    It 'attributes hash canonical meta and semantic mutation failures to exact gates' {
        Invoke-EvidenceLedgerProbe @'
$original = [Collections.Generic.Dictionary[string,byte[]]]::new([StringComparer]::Ordinal)
foreach ($name in $outputs.Keys) { $original.Add($name,$outputs[$name]) }
$original.Add('protocol-schema.v1.json',$protocolBytes)
$original.Add('protocol-inventory.v1.json',$protocolInventoryBytes)
$original.Add('evidence-ledger-inventory.v1.json',$inventoryBytes)
$original.Add('protocol-schema-meta.v1.json',$metaBytes)
$original.Add('README.md',$readmeBytes)
$originalPins = [Collections.Generic.Dictionary[string,string]]::new([StringComparer]::Ordinal)
foreach ($path in $contract.Sha256ByPath.Keys) {
    $name = [IO.Path]::GetFileName($path.Replace('/','\'))
    if ($original.ContainsKey($name)) { $originalPins.Add($name,$contract.Sha256ByPath[$path]) }
}
function Invoke-LayeredGate {
    param($Files,$Pins)
    $candidateOutputs = [Collections.Generic.Dictionary[string,byte[]]]::new([StringComparer]::Ordinal)
    foreach ($name in @('evidence-schema.v1.json','signing-ledger-schema.v1.json','signing-ledger-maxima.v1.json')) { $candidateOutputs.Add($name,$Files[$name]) }
    [Pspkt.Certification.EvidenceLedger.EvidenceLedgerVerify]::Verify($Files['protocol-schema.v1.json'],$Files['protocol-inventory.v1.json'],$Files['evidence-ledger-inventory.v1.json'],$Files['protocol-schema-meta.v1.json'],$candidateOutputs,$Pins,
        [Pspkt.Certification.SchemaBootstrap].Assembly.GetName().FullName,
        [Pspkt.Certification.EvidenceLedger.EvidenceLedgerAuthority].Assembly.GetName().FullName,$Files['README.md'])
}
$cases = @(
    @{Name='frozen-inventory-acceptance';File='protocol-inventory.v1.json';Refresh=@();Mutation='none';Expected=$null},
    @{Name='stale-hash';File='evidence-schema.v1.json';Refresh=@();Mutation='whitespace';Expected='Pinned evidence ledger output hash differs: evidence-schema.v1.json'},
    @{Name='inventory-canonical';File='evidence-ledger-inventory.v1.json';Refresh=@('evidence-ledger-inventory.v1.json');Mutation='whitespace';Expected='Noncanonical input: evidence-ledger-inventory.v1.json'},
    @{Name='evidence-canonical';File='evidence-schema.v1.json';Refresh=@('evidence-schema.v1.json');Mutation='whitespace';Expected='Noncanonical output: evidence-schema.v1.json'},
    @{Name='ledger-canonical';File='signing-ledger-schema.v1.json';Refresh=@('signing-ledger-schema.v1.json');Mutation='whitespace';Expected='Noncanonical output: signing-ledger-schema.v1.json'},
    @{Name='maxima-canonical';File='signing-ledger-maxima.v1.json';Refresh=@('signing-ledger-maxima.v1.json');Mutation='whitespace';Expected='Noncanonical output: signing-ledger-maxima.v1.json'},
    @{Name='schema-meta';File='evidence-schema.v1.json';Refresh=@('evidence-schema.v1.json');Mutation='meta';Expected='Schema-against-meta failed: evidence-schema.v1.json: unknown-property'},
    @{Name='semantic';File='evidence-schema.v1.json';Refresh=@('evidence-schema.v1.json');Mutation='semantic';Expected='Local evidence receipt and proof shapes differ.'}
)
foreach ($case in $cases) {
    Invoke-LayeredGate $original $originalPins
    $files = [Collections.Generic.Dictionary[string,byte[]]]::new($original,[StringComparer]::Ordinal)
    $pins = [Collections.Generic.Dictionary[string,string]]::new($originalPins,[StringComparer]::Ordinal)
    switch ($case.Mutation) {
        'whitespace' {
            $text = $utf8.GetString($files[$case.File])
            $files[$case.File] = $utf8.GetBytes($text.Substring(0,1) + ' ' + $text.Substring(1))
        }
        'meta' {
            $schema = $utf8.GetString($files[$case.File]) | ConvertFrom-Json
            $schema.types[0] | Add-Member -NotePropertyName unexpected -NotePropertyValue 1
            $files[$case.File] = ConvertTo-ProbeCanonical $schema
        }
        'semantic' {
            $schema = $utf8.GetString($files[$case.File]) | ConvertFrom-Json
            ($schema.types | Where-Object name -CEQ 'LocalEvidenceProofV1').fields[0].type = 'Opaque16'
            $files[$case.File] = ConvertTo-ProbeCanonical $schema
        }
    }
    $hash = [Security.Cryptography.SHA256]::Create()
    try {
        foreach ($name in $case.Refresh) { $pins[$name] = [BitConverter]::ToString($hash.ComputeHash($files[$name])).Replace('-','').ToLowerInvariant() }
    }
    finally { $hash.Dispose() }
    if ($null -eq $case.Expected) {
        Assert-Probe ($pins[$case.File] -ceq 'd67cb37777eaa5fee07404894b0d1f4a20bf11d4a4c95085bc60e350805f265f') 'Frozen inventory pin changed.'
        $canonical = ConvertTo-ProbeCanonical ($utf8.GetString($files[$case.File]) | ConvertFrom-Json)
        Assert-Probe ([Convert]::ToBase64String($canonical) -cne [Convert]::ToBase64String($files[$case.File])) 'Frozen inventory must exercise noncanonical acceptance.'
        $messages = @(Invoke-LayeredGate $files $pins)
        Assert-Probe (-not (($messages -join "`n") -match 'Noncanonical|canonical.*mismatch')) 'Frozen inventory produced a canonical mismatch.'
    } else {
        Assert-ProbeFailure { Invoke-LayeredGate $files $pins } $case.Expected
    }
}
'@
    }

    It 'rejects verifier references to the evidence ledger authority' {
        Invoke-EvidenceLedgerProbe @'
$bootstrapIdentity = [Pspkt.Certification.SchemaBootstrap].Assembly.GetName().FullName
$authorityIdentity = [Pspkt.Certification.EvidenceLedger.EvidenceLedgerAuthority].Assembly.GetName().FullName
$flags = [Reflection.BindingFlags]'Static,NonPublic'
$check = [Pspkt.Certification.EvidenceLedger.EvidenceLedgerVerify].GetMethod('CheckIndependence',$flags)
Assert-Probe ($null -ne $check) 'Verifier assembly-identity gate is missing.'
$check.Invoke($null,[object[]]@($bootstrapIdentity,$authorityIdentity))
$missingIdentityArguments = [object[]]::new(2)
$missingIdentityArguments[1] = $authorityIdentity
Assert-ProbeFailure { $check.Invoke($null,$missingIdentityArguments) } 'Verifier assembly identity is missing.'
Assert-ProbeFailure { $check.Invoke($null,[object[]]@($authorityIdentity,$authorityIdentity)) } 'Verifier bootstrap and authority assembly identities are not distinct.'
$source = [IO.File]::ReadAllText((Join-Path $sliceRoot 'lib\Pspkt.Certification.EvidenceLedgerVerify.cs')).Replace('EvidenceLedgerVerify','RenamedLedgerCheck')
$opening = "public static class RenamedLedgerCheck`n    {"
$source = $source.Replace("`r`n","`n")
Assert-Probe ($source.Contains($opening)) 'Verifier mutation anchor is missing.'
$source = $source.Replace($opening,$opening + "`n        public static Type ReferencedType() { return typeof(Pspkt.Certification.EvidenceLedger.EvidenceLedgerAuthority); }")
$framework = if ($PSVersionTable.PSEdition -eq 'Desktop') { @('System.dll','System.Core.dll','System.Xml.dll','System.Runtime.Serialization.dll','System.Numerics.dll') } else { @(Get-ChildItem -LiteralPath (Join-Path $PSHOME 'ref') -Filter '*.dll' | ForEach-Object FullName) }
$assemblyPath = Join-Path $AssemblyRoot 'RenamedLedgerCheck.dll'
Add-Type -TypeDefinition $source -ReferencedAssemblies @($framework + [Pspkt.Certification.SchemaBootstrap].Assembly.Location + [Pspkt.Certification.EvidenceLedger.EvidenceLedgerAuthority].Assembly.Location) -OutputAssembly $assemblyPath
Add-Type -Path $assemblyPath
$mutant = [Pspkt.Certification.EvidenceLedger.RenamedLedgerCheck]
Assert-Probe (@($mutant.Assembly.GetReferencedAssemblies() | Where-Object FullName -CEQ $authorityIdentity).Count -eq 1) 'Mutant must actually reference the authority assembly.'
$check = $mutant.GetMethod('CheckIndependence',$flags)
Assert-ProbeFailure { $check.Invoke($null,[object[]]@($bootstrapIdentity,$authorityIdentity)) } 'Verifier dependency matches forbidden assembly identity.'
'@
    }

    It 'atomically replaces each output and preserves prior bytes on injected failure' {
        Invoke-EvidenceLedgerProbe @'
$validator = Join-Path $sliceRoot 'validators\Invoke-PspktPhase4EvidenceLedgerAuthorityValidators.ps1'
$tokens = $null
$errors = $null
$syntax = [Management.Automation.Language.Parser]::ParseFile($validator,[ref]$tokens,[ref]$errors)
$writer = $syntax.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Write-PspktEvidenceLedgerFileAtomically' },$true)
Assert-Probe ($null -ne $writer) 'Atomic replacement boundary is missing.'
. ([scriptblock]::Create($writer.Extent.Text))
$destination = Join-Path $AssemblyRoot 'atomic-output'
[void][IO.Directory]::CreateDirectory($destination)
$file = Join-Path $destination 'evidence-schema.v1.json'
$prior = $utf8.GetBytes('distinguishable prior bytes')
$candidate = $outputs['evidence-schema.v1.json']
[IO.File]::WriteAllBytes($file,$prior)
$script:boundaryReached = $false
$injection = {
    param($TemporaryPath,$DestinationPath)
    $script:boundaryReached = $true
    Assert-Probe ([IO.File]::Exists($TemporaryPath)) 'Replacement boundary lacks candidate bytes.'
    Assert-Probe ($DestinationPath -ceq $file) 'Replacement boundary targets the wrong file.'
    Assert-Probe ([Convert]::ToBase64String([IO.File]::ReadAllBytes($TemporaryPath)) -ceq [Convert]::ToBase64String($candidate)) 'Candidate bytes differ at replacement boundary.'
    throw 'Injected atomic replacement failure.'
}
Assert-ProbeFailure { Write-PspktEvidenceLedgerFileAtomically -Path $file -Bytes $candidate -BeforeReplace $injection } 'Injected atomic replacement failure.'
Assert-Probe $script:boundaryReached 'Replacement injection boundary was not reached.'
Assert-Probe ([Convert]::ToBase64String([IO.File]::ReadAllBytes($file)) -ceq [Convert]::ToBase64String($prior)) 'Failed replacement changed prior bytes.'
Assert-Probe ([IO.Directory]::GetFiles($destination,'*.tmp').Length -eq 0) 'Failed replacement left temporary files.'
Write-PspktEvidenceLedgerFileAtomically -Path $file -Bytes $candidate
Assert-Probe ([Convert]::ToBase64String([IO.File]::ReadAllBytes($file)) -ceq [Convert]::ToBase64String($candidate)) 'Successful retry differs.'
$hostName = if ($PSVersionTable.PSEdition -eq 'Desktop') { 'powershell.exe' } else { 'pwsh.exe' }
for ($iteration=0; $iteration -lt 2; $iteration++) {
    & (Join-Path $PSHOME $hostName) -NoProfile -File $validator -Mode Generate -OutputRoot $destination
    Assert-Probe ($LASTEXITCODE -eq 0) 'Repeated generation failed.'
    foreach ($path in $contract.OutputPathSet) {
        $actual = (Get-FileHash -LiteralPath (Join-Path $destination $path.Replace('/','\')) -Algorithm SHA256).Hash.ToLowerInvariant()
        Assert-Probe ($actual -ceq $contract.Sha256ByPath[$path]) 'Repeated generation output hash differs.'
    }
}
$before = @{}
foreach ($path in $contract.Sha256ByPath.Keys) {
    $absolute = Join-Path $RepositoryRoot $path.Replace('/','\')
    $before[$path] = [IO.File]::GetLastWriteTimeUtc($absolute).Ticks
}
& (Join-Path $PSHOME $hostName) -NoProfile -File $validator -Mode Validate
Assert-Probe ($LASTEXITCODE -eq 0) 'Read-only validation failed.'
foreach ($path in $contract.Sha256ByPath.Keys) {
    $absolute = Join-Path $RepositoryRoot $path.Replace('/','\')
    Assert-Probe ([IO.File]::GetLastWriteTimeUtc($absolute).Ticks -eq $before[$path]) 'Validation wrote a pinned file.'
    Assert-Probe ((Get-FileHash -LiteralPath $absolute -Algorithm SHA256).Hash.ToLowerInvariant() -ceq $contract.Sha256ByPath[$path]) 'Validation changed pinned bytes.'
}
'@
    }

    It 'emits identical canonical JSON bytes with the lowercase control escape dialect' {
        Invoke-EvidenceLedgerProbe @'
$value = [Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
$value.Add('z','quote"slash\line/forward')
$value.Add('unsigned32',[uint32]::MaxValue)
$value.Add('signed64',[long]::MaxValue)
$value.Add('maximum',[uint64]::MaxValue)
$value.Add('controls',(-join (0..31 | ForEach-Object { [char]$_ })))
$value.Add('a',0)
$value.Add('Z',7)
$expected = '{"Z":7,"a":0,"controls":"\u0000\u0001\u0002\u0003\u0004\u0005\u0006\u0007\u0008\u0009\u000a\u000b\u000c\u000d\u000e\u000f\u0010\u0011\u0012\u0013\u0014\u0015\u0016\u0017\u0018\u0019\u001a\u001b\u001c\u001d\u001e\u001f","maximum":18446744073709551615,"signed64":9223372036854775807,"unsigned32":4294967295,"z":"quote\"slash\\line/forward"}'
$arguments = [object[]]::new(1)
$arguments[0] = $value
$priorCulture = [Threading.Thread]::CurrentThread.CurrentCulture
try {
    [Threading.Thread]::CurrentThread.CurrentCulture = [Globalization.CultureInfo]::GetCultureInfo('fr-FR')
    foreach ($implementation in @([Pspkt.Certification.EvidenceLedger.EvidenceLedgerAuthority],[Pspkt.Certification.EvidenceLedger.EvidenceLedgerVerify])) {
        $bytes = $implementation.GetMethod('Canonical',[Reflection.BindingFlags]'Static,NonPublic').Invoke($null,$arguments)
        Assert-Probe ([Convert]::ToBase64String($bytes) -ceq [Convert]::ToBase64String($utf8.GetBytes($expected))) 'Canonical UTF-8 bytes or lowercase control escapes differ.'
        Assert-Probe (-not ($utf8.GetString($bytes) -match '\\[nrt/]')) 'A short control or slash escape was emitted.'
    }
}
finally { [Threading.Thread]::CurrentThread.CurrentCulture = $priorCulture }
$inventory = $utf8.GetString($inventoryBytes) | ConvertFrom-Json
Assert-Probe ($inventory.PSObject.Properties.Name -ccontains 'consumerContract') 'Deferred binary consumer contract is missing.'
Assert-Probe ($inventory.consumerContract.Count -gt 0) 'Deferred binary consumer contract is empty.'
function Get-ReferenceDigest {
    param([byte[]]$Bytes)
    $hash = [Security.Cryptography.SHA256]::Create()
    try { return ,$hash.ComputeHash($Bytes) } finally { $hash.Dispose() }
}
function ConvertTo-ReferenceHex {
    param([byte[]]$Bytes)
    return [BitConverter]::ToString($Bytes).Replace('-','').ToLowerInvariant()
}
$nodeDomain = $utf8.GetBytes("pspkt/signing-ledger/merkle-node/v1`0")
$empty = Get-ReferenceDigest $utf8.GetBytes("pspkt/signing-ledger/merkle-empty/v1`0")
Assert-Probe ((ConvertTo-ReferenceHex $empty) -ceq 'e1c5c2149f783f5b162d08ff5870dc856425628ea7d2803b756b8bb1a5f9c800') 'Empty Merkle reference vector differs.'
$first = [byte[]](1..32 | ForEach-Object { 0x11 })
$second = [byte[]](1..32 | ForEach-Object { 0x22 })
$third = [byte[]](1..32 | ForEach-Object { 0x33 })
$left = Get-ReferenceDigest ([byte[]]@($nodeDomain + $first + $second))
$right = Get-ReferenceDigest ([byte[]]@($nodeDomain + $third + $third))
$root = Get-ReferenceDigest ([byte[]]@($nodeDomain + $left + $right))
Assert-Probe ((ConvertTo-ReferenceHex $root) -ceq 'a07095d93953517870e6aa37fd7d13b6fc85fb0dc4767e159a6a3287b5b09954') 'Odd-node Merkle reference vector differs.'
$tlv = [byte[]]@(0,1,0,0,0,16,0,17,34,51,68,85,102,119,136,153,170,187,204,221,238,255)
$covered = [byte[]]@($utf8.GetBytes("pspkt/evidence/v1/LocalEvidenceReceiptV1`0") + $tlv)
Assert-Probe ((ConvertTo-ReferenceHex (Get-ReferenceDigest $covered)) -ceq '17317d80355df64dc8344fb94cbc96736f11d04897496e66b1d7135614c301fb') 'Domain-separated network-order GUID TLV reference vector differs.'
'@
    }

    It 'pins the complete deferred binary consumer contract' {
        Invoke-EvidenceLedgerProbe @'
$inventory = $utf8.GetString($inventoryBytes) | ConvertFrom-Json
$expectedSignatures = [ordered]@{
    'LocalEvidenceReceiptV1.signature'='observerKeyId'
    'LocalEvidenceProofV1.signature'='observerKeyId'
    'OperationRehabilitationAuthorizationV1.authoritySignature'='authorityKeyId'
    'AuthorizationSigningLedgerSegmentV1.signature'='header.signerKeyId'
    'OperationSigningLedgerSegmentV1.signature'='header.signerKeyId'
    'AuthorizationSigningLedgerInclusionProofV1.signature'='signerKeyId'
    'OperationSigningLedgerInclusionProofV1.signature'='signerKeyId'
}
Assert-Probe (@($inventory.signatureKeyBindings.PSObject.Properties).Count -eq 7) 'The new signature scope must contain exactly seven fields.'
foreach ($name in $expectedSignatures.Keys) { Assert-Probe ($inventory.signatureKeyBindings.$name -ceq $expectedSignatures[$name]) ('Signature key binding differs: '+$name) }
Assert-Probe ($inventory.consumerProfileBytes.Any -eq 0 -and $inventory.consumerProfileBytes.InteractiveSeat -eq 1 -and $inventory.consumerProfileBytes.NonInteractiveElevated -eq 2) 'Consumer profile mapping differs.'
$text = $inventory.consumerContract -join ' '
foreach ($fragment in @('RSASSA-PKCS1-v1_5 with SHA-256 as specified by RFC 8017','hashes the exact domain-separated covered bytes once with SHA-256','EMSA-PKCS1-v1_5 encoding for SHA-256','modulus is exactly 3072 bits','RSA-PSS, raw RSA, alternate hashes, and prehashed-input substitution are forbidden','exactly 384 octets by RFC 8017 I2OSP in most-significant-octet-first order','a representative greater than or equal to the modulus','malformed EMSA-PKCS1-v1_5 encoding','Copied protocol signature fields retain only their frozen protocol-defined shape and semantics: this slice assigns them no new algorithm, coverage, or key-binding rule.')) {
    Assert-Probe ($text.Contains($fragment)) ('Signature contract clause is missing: '+$fragment)
}
$domains = @()
$names = @($inventory.evidenceRoots + $inventory.evidenceAppend[0..5].name)
Assert-Probe (@($inventory.evidenceDomains.PSObject.Properties).Count -eq 22) 'Evidence domain count differs.'
foreach ($name in $names) {
    Assert-Probe ($inventory.evidenceDomains.$name -ceq "pspkt/evidence/v1/$name") 'Evidence domain mapping differs.'
    $domains += $inventory.evidenceDomains.$name
}
Assert-Probe (@($inventory.ledgerDomains.PSObject.Properties).Count -eq 96) 'Ledger domain count differs.'
foreach ($purpose in @('authorization','operation')) {
    $kinds = if ($purpose -eq 'authorization') { $inventory.authorizationKinds } else { $inventory.operationKinds }
    foreach ($name in $kinds) {
        foreach ($coverage in @('payload','record')) {
            $key = $purpose+':'+$name+':'+$coverage
            Assert-Probe ($inventory.ledgerDomains.$key -ceq "pspkt/signing-ledger/v1/$purpose-record/$name/$coverage") 'Payload/record domain mapping differs.'
        }
    }
    foreach ($coverage in @('segment','proof')) {
        $key=$purpose+':'+$coverage
        Assert-Probe ($inventory.ledgerDomains.$key -ceq "pspkt/signing-ledger/$purpose-$coverage/v1") 'Segment/proof domain mapping differs.'
    }
}
Assert-Probe ($inventory.ledgerDomains.'merkle:node' -ceq 'pspkt/signing-ledger/merkle-node/v1' -and $inventory.ledgerDomains.'merkle:empty' -ceq 'pspkt/signing-ledger/merkle-empty/v1') 'Merkle domains differ.'
$domains += @($inventory.ledgerDomains.PSObject.Properties.Value)
Assert-Probe (@($domains | Select-Object -Unique).Count -eq 118) 'Domains are not globally distinct.'
foreach ($domain in $domains) { Assert-Probe ($domain -cmatch '^[\x21-\x7e]+$') 'Domain is not exact non-NUL ASCII.' }
$readme = [IO.File]::ReadAllBytes((Join-Path $sliceRoot 'README.md'))
foreach ($implementation in @([Pspkt.Certification.EvidenceLedger.EvidenceLedgerAuthority],[Pspkt.Certification.EvidenceLedger.EvidenceLedgerVerify])) {
    $flags = [Reflection.BindingFlags]'Static,NonPublic'
    $method = $implementation.GetMethod('ValidateInventory',$flags)
    Assert-Probe ($null -ne $method) 'Exact consumer inventory semantic gate is missing.'
    $arguments = [object[]]::new(1)
    $arguments[0] = $inventoryBytes
    $parsed = $implementation.GetMethod('Parse',$flags).Invoke($null,$arguments)
    $arguments[0] = $parsed
    $method.Invoke($null,$arguments)
    $clauses = $parsed['consumerContract']
    for ($index=0; $index -lt $clauses.Count; $index++) {
        $original = $clauses[$index]
        $clauses[$index] = $original + ' changed'
        Assert-ProbeFailure { $method.Invoke($null,$arguments) } 'Evidence ledger inventory shape differs.'
        $clauses[$index] = $original
        $clauses.RemoveAt($index)
        Assert-ProbeFailure { $method.Invoke($null,$arguments) } 'Evidence ledger inventory shape differs.'
        $clauses.Insert($index,$original)
    }
    foreach ($name in $expectedSignatures.Keys) {
        $parsed['signatureKeyBindings'][$name] = 'wrongKeyId'
        Assert-ProbeFailure { $method.Invoke($null,$arguments) } 'Evidence ledger inventory shape differs.'
        $parsed['signatureKeyBindings'][$name] = $expectedSignatures[$name]
    }
    $evidenceSchema = $utf8.GetString($outputs['evidence-schema.v1.json']) | ConvertFrom-Json
    foreach ($copiedField in @('WorkerSessionKeyCertificateV1.workerMasterSignature','CreatorPermitInstallationV1.hostSignature','BrokerSessionKeyCertificateEnvelopeV1.masterSignature')) {
        $parts = $copiedField.Split('.')
        $copiedType = $evidenceSchema.types | Where-Object name -CEQ $parts[0]
        Assert-Probe (($copiedType.fields | Where-Object name -CEQ $parts[1]).type -ceq 'Rsa3072Signature') 'Copied protocol signature control is missing.'
        $parsed['signatureKeyBindings'].Add($copiedField,'observerKeyId')
        Assert-ProbeFailure { $method.Invoke($null,$arguments) } 'Evidence ledger inventory shape differs.'
        $parsed['signatureKeyBindings'].Remove($copiedField) | Out-Null
    }
    $method.Invoke($null,$arguments)
    $documentation = $implementation.GetMethod('ValidateDocumentation',$flags)
    $documentationArguments = [object[]]::new(2)
    $documentationArguments[0] = $parsed
    $documentationArguments[1] = $readme
    $documentation.Invoke($null,$documentationArguments)
    foreach ($clause in $clauses) {
        $documentationArguments[1] = $utf8.GetBytes($utf8.GetString($readme).Replace('- '+$clause+"`n",''))
        Assert-ProbeFailure { $documentation.Invoke($null,$documentationArguments) } 'Evidence ledger consumer documentation differs.'
    }
}
'@
    }

    It 'runs protocol and evidence ledger suites together without recursive combined runs' -Tag 'EvidenceLedgerCombined' -Skip:([Environment]::GetEnvironmentVariable('PSPKT_EVIDENCE_LEDGER_COMBINED_CHILD') -eq '1') {
        $pester = Get-Module Pester
        $pester.Version | Should -BeGreaterOrEqual ([version]'5.3.3')
        $pester.Version | Should -BeLessThan ([version]'6.0')
        $manifestPath = Join-Path $pester.ModuleBase 'Pester.psd1'
        $childPath = Join-Path $TestDrive 'evidence-combined-child.ps1'
        $allowlistPath = Join-Path $TestDrive 'evidence-allowlist.json'
        [IO.File]::WriteAllText($allowlistPath,($script:evidenceTestNames | ConvertTo-Json),[Text.UTF8Encoding]::new($false,$true))
        [IO.File]::WriteAllText($childPath,$script:combinedChildCode,[Text.UTF8Encoding]::new($false,$true))
        foreach ($hostName in @('powershell.exe','pwsh.exe')) {
            $hostPath = (Get-Command $hostName -ErrorAction Stop).Source
            $edition = if ($hostName -eq 'powershell.exe') { 'Desktop' } else { 'Core' }
            $version = (& $hostPath -NoProfile -Command '$PSVersionTable.PSVersion.ToString()').Trim()
            $LASTEXITCODE | Should -Be 0
            foreach ($mode in @('Discover','Run')) {
                $priorPreference = $ErrorActionPreference
                try {
                    $ErrorActionPreference = 'Continue'
                    $output = & $hostPath -NoProfile -File $childPath -RepositoryRoot $script:repositoryRoot -PesterManifestPath $manifestPath -AllowlistPath $allowlistPath -ExpectedEdition $edition -ExpectedVersion $version -Mode $mode 2>&1
                    $exitCode = $LASTEXITCODE
                }
                finally { $ErrorActionPreference = $priorPreference }
                if ($exitCode -ne 0) { throw ($output -join "`n") }
                ($output -join "`n") | Should -Match 'EVIDENCE_(DISCOVERY|COMBINED)_OK'
                Write-Host ($output | Where-Object { [string]$_ -match '^EVIDENCE_' })
            }
            foreach ($probe in @('Discovery','BeforeAll','SkippedOnly','EmptySelection','UnexpectedSkip','RuntimeSkip','UnexpectedExclusion','OneRequiredExcluded')) {
                $priorPreference = $ErrorActionPreference
                try {
                    $ErrorActionPreference = 'Continue'
                    $output = & $hostPath -NoProfile -File $childPath -RepositoryRoot $script:repositoryRoot -PesterManifestPath $manifestPath -AllowlistPath $allowlistPath -ExpectedEdition $edition -ExpectedVersion $version -Mode Run -ProbeCase $probe 2>&1
                    $exitCode = $LASTEXITCODE
                }
                finally { $ErrorActionPreference = $priorPreference }
                $exitCode | Should -Not -Be 0
                ($output -join "`n") | Should -Match ("EVIDENCE_COMBINED_REJECTED\|case=" + $probe + '\|')
            }
            Write-Host "EVIDENCE_PROBES_OK|edition=$edition|version=$version|rejected=8"
        }
    }
}
