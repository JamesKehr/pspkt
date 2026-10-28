Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'

function Get-PspktBrokerLifecycleBytesDigest {
    param([byte[]]$Bytes)
    $hasher=[Security.Cryptography.SHA256]::Create()
    try{return [BitConverter]::ToString($hasher.ComputeHash($Bytes)).Replace('-','').ToLowerInvariant()}
    finally{$hasher.Dispose()}
}

function New-PspktBrokerLifecyclePesterConfiguration {
    param([object]$Container)
    if($null -eq $Container){throw 'validation:pester'}
    $configuration=[PesterConfiguration]::Default
    $configuration.Run.Path=@()
    $configuration.Run.Container=@($Container)
    $configuration.Run.PassThru=$true
    $configuration.Run.Exit=$false
    $configuration.Run.Throw=$false
    $configuration.Filter.Tag=@('Precheck')
    $configuration.Filter.ExcludeTag=@()
    $configuration.Filter.FullName=@()
    $configuration.TestDrive.Enabled=$true
    $configuration.TestRegistry.Enabled=$false
    $configuration.TestResult.Enabled=$false
    $configuration.CodeCoverage.Enabled=$false
    $configuration.Output.Verbosity='None'
    return $configuration
}

function Assert-PspktBrokerLifecyclePesterConfiguration {
    param([object]$Configuration,[object]$Container)
    if($null -eq $Configuration -or $null -eq $Container -or
        $Configuration.Run.Path.Value.Count -ne 0 -or $Configuration.Run.Container.Value.Count -ne 1 -or
        -not [object]::ReferenceEquals($Configuration.Run.Container.Value[0],$Container) -or
        -not $Configuration.Run.PassThru.Value -or $Configuration.Run.Exit.Value -or $Configuration.Run.Throw.Value -or
        ($Configuration.Filter.Tag.Value -join '|') -cne 'Precheck' -or
        $Configuration.Filter.ExcludeTag.Value.Count -ne 0 -or $Configuration.Filter.FullName.Value.Count -ne 0 -or
        -not $Configuration.TestDrive.Enabled.Value -or $Configuration.TestRegistry.Enabled.Value -or
        $Configuration.TestResult.Enabled.Value -or $Configuration.CodeCoverage.Enabled.Value -or
        $Configuration.Output.Verbosity.Value -cne 'None'){
        throw 'validation:pester'
    }
}

function Assert-PspktBrokerLifecycleCasePopulation {
    param([string[]]$Actual,[string[]]$Expected)
    if($null -eq $Actual -or $null -eq $Expected -or $Actual.Length -ne 32 -or $Expected.Length -ne 32){throw 'validation:result-counts'}
    $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    for($index=0;$index -lt 32;$index++){
        $prefix=($index+1).ToString('00',[Globalization.CultureInfo]::InvariantCulture)+' '
        if($Actual[$index] -cne $Expected[$index] -or -not $Actual[$index].StartsWith($prefix,[StringComparison]::Ordinal) -or
            $Actual[$index] -cnotmatch '\A[0-9]{2} [a-z0-9-]+\z' -or -not $seen.Add($Actual[$index])){throw 'validation:result-counts'}
    }
}

function Read-PspktBrokerLifecycleSourceFile {
    param([string]$Path,[long]$MaximumLength=16777216)
    $current=[IO.Path]::GetFullPath($Path)
    while(-not [string]::IsNullOrEmpty($current)){
        if(([IO.File]::Exists($current) -or [IO.Directory]::Exists($current)) -and
            ([IO.File]::GetAttributes($current) -band [IO.FileAttributes]::ReparsePoint)){throw 'validation:source-membership'}
        $parent=[IO.Directory]::GetParent($current)
        if($null -eq $parent){break}
        $current=$parent.FullName
    }
    if(-not [IO.File]::Exists($Path)){throw 'validation:source-membership'}
    $stream=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {
        if($stream.Length -le 0 -or $stream.Length -gt $MaximumLength){throw 'validation:source-length'}
        $bytes=[byte[]]::new([int]$stream.Length)
        $offset=0
        while($offset -lt $bytes.Length){
            $read=$stream.Read($bytes,$offset,$bytes.Length-$offset)
            if($read -le 0){throw 'validation:source-length'}
            $offset+=$read
        }
        if($stream.ReadByte() -ne -1){throw 'validation:source-length'}
        return ,$bytes
    }
    finally {$stream.Dispose()}
}

function Get-PspktBrokerLifecycleSourceSnapshot {
    param([string]$RepositoryRoot,[byte[]]$ContractBytes)
    $rootPath='certification\broker-lifecycle\lib\Pspkt.Certification.BrokerLifecycleContract.ps1'
    $pins=@(Get-PspktBrokerLifecycleSourcePins)
    if($pins.Count -ne 66 -or $null -eq $ContractBytes -or $ContractBytes.Length -gt 1048576){throw 'validation:source-membership'}
    $files=@{}
    $texts=@{}
    $records=[Collections.Generic.List[object]]::new()
    $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $encoding=[Text.UTF8Encoding]::new($false,$true)
    $total=[long]0
    foreach($pin in @($pins)+@([pscustomobject]@{Role='OrchestrationRoot';Path=$rootPath;Length=$ContractBytes.Length;Sha256=$null})){
        if(-not $seen.Add($pin.Path) -or $pin.Path -cnotmatch '\A(?:[A-Za-z0-9._-]+\\)*[A-Za-z0-9._-]+\z' -or
            @($pin.Path.Split([char]92)|Where-Object {$_ -cin @('.','..','.git')}).Count -ne 0){throw 'validation:source-membership'}
        if($pin.Path -ceq $rootPath){$bytes=[byte[]]$ContractBytes}
        else{$bytes=Read-PspktBrokerLifecycleSourceFile (Join-Path $RepositoryRoot $pin.Path)}
        $total+=$bytes.Length
        if($total -gt 67108864){throw 'validation:source-length'}
        $sha=Get-PspktBrokerLifecycleBytesDigest $bytes
        if($pin.Path -cmatch '\.(cs|ps1|md|yml)$|(?:^|\\)\.gitattributes$'){
            $text=$encoding.GetString($bytes)
            if($text.Contains("`r") -or $text.StartsWith([string][char]0xfeff,[StringComparison]::Ordinal)){throw 'validation:source-line-endings'}
            $texts[$pin.Path]=$text
        }
        if($pin.Path -cne $rootPath -and ($bytes.Length -ne $pin.Length -or $sha -cne $pin.Sha256)){throw 'validation:source-pin'}
        $files[$pin.Path]=$bytes
        $records.Add([pscustomobject][ordered]@{Role=$pin.Role;Path=$pin.Path;Length=$bytes.Length;Sha256=$sha})
    }
    if($files.Count -ne 67){throw 'validation:source-membership'}
    $capsule=Join-Path $RepositoryRoot 'certification\broker-lifecycle'
    $pending=[Collections.Generic.Queue[string]]::new()
    $pending.Enqueue($capsule)
    $capsuleFiles=0
    while($pending.Count -ne 0){
        $directory=$pending.Dequeue()
        foreach($entry in [IO.Directory]::GetFileSystemEntries($directory)){
            if([IO.File]::GetAttributes($entry) -band [IO.FileAttributes]::ReparsePoint){throw 'validation:source-membership'}
            if([IO.Directory]::Exists($entry)){$pending.Enqueue($entry)}
            else{
                $relative=$entry.Substring($RepositoryRoot.TrimEnd([char]92).Length+1)
                if(-not $files.ContainsKey($relative)){throw 'validation:source-membership'}
                $capsuleFiles++
            }
        }
    }
    if($capsuleFiles -ne 53){throw 'validation:source-membership'}
    $builder=[Text.StringBuilder]::new()
    foreach($record in $records){
        [void]$builder.Append($record.Role+[char]0+$record.Path+[char]0+$record.Length.ToString([Globalization.CultureInfo]::InvariantCulture)+
            [char]0+$record.Sha256+"`n")
    }
    return @{RepositoryRoot=$RepositoryRoot;Files=$files;RetainedTexts=$texts;Records=$records.ToArray();
        ManifestSha256=(Get-PspktBrokerLifecycleBytesDigest $encoding.GetBytes($builder.ToString()));CallerScopePassed=$false}
}

function Assert-PspktBrokerLifecycleFixtures {
    param([object]$Source)
    $base='certification\broker-lifecycle\vectors\'
    $manifestBytes=$Source.Files[$base+'hand-authored\manifest.v1.json']
    $manifest=[Text.Encoding]::UTF8.GetString($manifestBytes)|ConvertFrom-Json
    if($manifest.schemaId -cne 'PspktBrokerLifecycleProtectedManifestV1' -or @($manifest.files).Count -ne 4){throw 'validation:fixture'}
    $expected=@('framing-goldens.v1.json','bootstrap-goldens.v1.json','lifecycle-traces.v1.json','contract-expectations.v1.json')
    for($index=0;$index -lt 4;$index++){
        $record=$manifest.files[$index]
        if($record.path -cne $expected[$index]){throw 'validation:fixture'}
        $bytes=$Source.Files[$base+'hand-authored\'+$record.path]
        if($bytes.Length -ne $record.bytes -or (Get-PspktBrokerLifecycleBytesDigest $bytes) -cne $record.sha256){throw 'validation:fixture'}
    }
    $generated=[Text.Encoding]::UTF8.GetString($Source.Files[$base+'generated\manifest.v1.json'])|ConvertFrom-Json
    $frames=$Source.Files[$base+'generated\frames.v1.json']
    if($generated.file.path -cne 'frames.v1.json' -or $generated.file.bytes -ne $frames.Length -or
        $generated.file.sha256 -cne (Get-PspktBrokerLifecycleBytesDigest $frames) -or @($generated.rows).Count -ne 22){throw 'validation:fixture'}
    $expectations=[Text.Encoding]::UTF8.GetString($Source.Files[$base+'hand-authored\contract-expectations.v1.json'])|ConvertFrom-Json
    if($expectations.counts.sourcePaths -ne 67 -or $expectations.counts.runtimeSources -ne 31 -or
        $expectations.counts.cases -ne 32 -or $expectations.runtimeReasons.Count -ne 60 -or
        $expectations.validatorReasons.Count -ne 26 -or $expectations.scenarios.Count -ne 9){throw 'validation:fixture'}
    $actual=@($Source.Records.Path|Sort-Object)
    if(($actual -join '|') -cne (@($expectations.sourcePaths|Sort-Object) -join '|')){throw 'validation:source-membership'}
    return $expectations
}

function Get-PspktBrokerLifecycleAuthorityPaths {
    return [ordered]@{
        ProtocolMeta='certification\schema\protocol-schema-meta.v1.json'
        ProtocolInventory='certification\schema\protocol-inventory.v1.json'
        ProtocolSchema='certification\schema\protocol-schema.v1.json'
        MessageAssociation='certification\schema\protocol-message-association.v1.json'
        GeneratedIdMap='certification\schema\generated-base-id-map.v1.json'
        BaseTailSchedule='certification\schema\mandatory-tail-schedule.v1.json'
        FramingAddendumSchema='certification\broker-lifecycle\schema\framing-addendum-schema.v1.json'
        FramingAddendum='certification\broker-lifecycle\authority\framing-addendum.v1.json'
        DesignReviewActivation='certification\broker-lifecycle\authority\design-review-activation.v1.json'
    }
}

function Get-PspktBrokerLifecycleFixturePaths {
    return [ordered]@{
        LifecyclePolicy='certification\broker-lifecycle\schema\lifecycle-policy.v1.json'
        GeneratedFrames='certification\broker-lifecycle\vectors\generated\frames.v1.json'
        GeneratedManifest='certification\broker-lifecycle\vectors\generated\manifest.v1.json'
        FramingGoldens='certification\broker-lifecycle\vectors\hand-authored\framing-goldens.v1.json'
        BootstrapGoldens='certification\broker-lifecycle\vectors\hand-authored\bootstrap-goldens.v1.json'
        LifecycleTraces='certification\broker-lifecycle\vectors\hand-authored\lifecycle-traces.v1.json'
        ContractExpectations='certification\broker-lifecycle\vectors\hand-authored\contract-expectations.v1.json'
        ProtectedManifest='certification\broker-lifecycle\vectors\hand-authored\manifest.v1.json'
    }
}

function Import-PspktBrokerLifecyclePester {
    param([string]$ManifestPath)
    try {
        $manifest=[IO.Path]::GetFullPath($ManifestPath)
        if([IO.Path]::GetFileName($manifest) -cne 'Pester.psd1'){throw 'validation:pester'}
        $root=[IO.Path]::GetDirectoryName($manifest)
        $pins=@(
            @('Pester.psd1',15678,'77a3efb7c38e41f6e8bb8697f94ab75adac29c154651a2c4fc2bbeb390843944'),
            @('Pester.psm1',675115,'fbb25db34ed21eadc5a21922ade44ca354b6e5275c59cfc3862742398b8336c1'),
            @('Pester.ps1',10867,'4dd1cfe8a9020fc2adbd5f19b08de78b831a1c481cd19950f47f81807c7c3308'),
            @('Pester.Format.ps1xml',10186,'9976fd20bced6b31e9671b14f125eaf9f17ebf106e5357eeb077fe2bbc337f35'),
            @('PesterConfiguration.Format.ps1xml',8009,'da307eb68e64f99262e483c6f4e1b0876fe86fd74b30f62636179f259ad89c3c'),
            @('bin\net452\Pester.dll',77208,'952116f0e51acd3ccdcf1f0a067b0e0181b9f5070bc878ed0cd9bb633df890b8'),
            @('bin\netstandard2.0\Pester.dll',77208,'5515a683a7801c29aec221cc6ea767f1218d66a86f809f4e01024b00ba8c57a2')
        )
        foreach($pin in $pins){
            $bytes=Read-PspktBrokerLifecycleSourceFile (Join-Path $root $pin[0])
            if($bytes.Length -ne $pin[1] -or (Get-PspktBrokerLifecycleBytesDigest $bytes) -cne $pin[2]){throw 'validation:pester'}
        }
        $loaded=@(Get-Module -Name Pester)
        if($loaded.Count -gt 1 -or ($loaded.Count -eq 1 -and ($loaded[0].Version -ne [version]'5.3.3' -or
            -not [string]::Equals($loaded[0].ModuleBase,$root,[StringComparison]::OrdinalIgnoreCase)))){throw 'validation:pester'}
        if($loaded.Count -eq 0){$loaded=@(Import-Module -Name $manifest -PassThru -ErrorAction Stop)}
        if($loaded.Count -ne 1 -or $loaded[0].Version -ne [version]'5.3.3' -or
            -not [string]::Equals($loaded[0].ModuleBase,$root,[StringComparison]::OrdinalIgnoreCase)){throw 'validation:pester'}
        return $loaded[0]
    }
    catch {throw 'validation:pester'}
}

function Remove-PspktBrokerLifecycleOwnedDirectory {
    param([string]$Path,[string]$OwnerRoot)
    if([string]::IsNullOrEmpty($OwnerRoot) -or -not [string]::Equals([IO.Path]::GetFullPath($Path),
        [IO.Path]::GetFullPath((Join-Path $OwnerRoot 'staging')),[StringComparison]::OrdinalIgnoreCase)){throw 'validation:cleanup'}
    if(-not [IO.Directory]::Exists($Path)){return}
    $directories=[Collections.Generic.List[string]]::new()
    $files=[Collections.Generic.List[string]]::new()
    $pending=[Collections.Generic.Queue[string]]::new()
    $pending.Enqueue([IO.Path]::GetFullPath($Path))
    while($pending.Count -ne 0){
        $directory=$pending.Dequeue()
        $directories.Add($directory)
        foreach($entry in [IO.Directory]::GetFileSystemEntries($directory)){
            if([IO.File]::GetAttributes($entry) -band [IO.FileAttributes]::ReparsePoint){throw 'validation:cleanup'}
            if([IO.Directory]::Exists($entry)){$pending.Enqueue($entry)}else{$files.Add($entry)}
        }
    }
    foreach($file in $files){[IO.File]::Delete($file)}
    foreach($directory in @($directories|Sort-Object Length -Descending)){[IO.Directory]::Delete($directory,$false)}
}

function Assert-PspktBrokerLifecycleOwnedArtifacts {
    param([string]$ArtifactRoot,[object[]]$Images,[object]$ExecutionState=$null)
    try {
        $expected=@('source-records.v1.json','validation-records.v1.json')+@($Images.Name)
        $actual=@([IO.Directory]::GetFileSystemEntries($ArtifactRoot))
        if($actual.Count -ne 10 -or $Images.Count -ne 8){throw 'validation:cleanup'}
        foreach($path in $actual){
            if([IO.Directory]::Exists($path) -or ([IO.File]::GetAttributes($path) -band [IO.FileAttributes]::ReparsePoint) -or
                [IO.Path]::GetFileName($path) -cnotin $expected){throw 'validation:cleanup'}
        }
        foreach($image in $Images){
            $bytes=Read-PspktBrokerLifecycleSourceFile (Join-Path $ArtifactRoot $image.Name)
            if($bytes.Length -ne $image.Length -or (Get-PspktBrokerLifecycleBytesDigest $bytes) -cne $image.Sha256){throw 'validation:cleanup'}
        }
    }
    catch {
        if($null -ne $ExecutionState){$ExecutionState.CleanupComplete=$false}
        throw 'validation:cleanup'
    }
}

function Get-PspktBrokerLifecycleCallerState {
    $location=Get-Location
    if($location.Provider.Name -cne 'FileSystem'){throw 'validation:work-root'}
    $environment=[ordered]@{}
    foreach($name in @('TEMP','TMP','PSModuleAnalysisCachePath')){$environment[$name]=[Environment]::GetEnvironmentVariable($name,'Process')}
    return [pscustomobject]@{Environment=$environment;Location=$location.ProviderPath;Directory=[Environment]::CurrentDirectory}
}

function Restore-PspktBrokerLifecycleCallerState {
    param([object]$State)
    if($null -eq $State -or ($State.Environment.Keys -join '|') -cne 'TEMP|TMP|PSModuleAnalysisCachePath'){throw 'validation:cleanup'}
    try {
        $setter=[Environment].GetMethod('SetEnvironmentVariable',[type[]]@([string],[string],[EnvironmentVariableTarget]))
        foreach($name in $State.Environment.Keys){
            $arguments=[object[]]::new(3)
            $arguments[0]=$name
            $arguments[1]=$State.Environment[$name]
            $arguments[2]=[EnvironmentVariableTarget]::Process
            [void]$setter.Invoke($null,$arguments)
        }
        Set-Location -LiteralPath $State.Location
        [Environment]::CurrentDirectory=$State.Directory
        foreach($name in $State.Environment.Keys){
            if([Environment]::GetEnvironmentVariable($name,'Process') -cne $State.Environment[$name]){throw 'validation:cleanup'}
        }
        if((Get-Location).ProviderPath -cne $State.Location -or [Environment]::CurrentDirectory -cne $State.Directory){throw 'validation:cleanup'}
    }
    catch {throw 'validation:cleanup'}
}

function Write-PspktBrokerLifecycleOwnedJson {
    param([string]$Path,[object]$Value)
    $bytes=[Text.UTF8Encoding]::new($false,$true).GetBytes((ConvertTo-Json -InputObject $Value -Depth 40 -Compress))
    $stream=[IO.File]::Open($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try {$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)} finally {$stream.Dispose()}
}

function New-PspktBrokerLifecycleExpectedResult {
    param([object]$Source,[object]$Context,[object]$Expectations,[object[]]$Mutants,[string]$CallId)
    $files=$Source.Files
    $bindings=[ordered]@{callId=$CallId;baseCommit='46dc63bb1bd537037c32edd2cb9e5151e0ad96ad';
        hostEdition=$PSVersionTable.PSEdition;hostVersion=$PSVersionTable.PSVersion.ToString();pesterVersion='5.3.3';trustCeiling='StructuralInProcessOnly';
        sourceManifestSha256=$Source.ManifestSha256;
        fixtureManifestSha256=(Get-PspktBrokerLifecycleBytesDigest $files['certification\broker-lifecycle\vectors\hand-authored\manifest.v1.json']);
        framingAddendumSchemaSha256=(Get-PspktBrokerLifecycleBytesDigest $files['certification\broker-lifecycle\schema\framing-addendum-schema.v1.json']);
        framingAddendumSha256=(Get-PspktBrokerLifecycleBytesDigest $files['certification\broker-lifecycle\authority\framing-addendum.v1.json']);
        designReviewActivationSha256=(Get-PspktBrokerLifecycleBytesDigest $files['certification\broker-lifecycle\authority\design-review-activation.v1.json']);
        lifecyclePolicySha256=(Get-PspktBrokerLifecycleBytesDigest $files['certification\broker-lifecycle\schema\lifecycle-policy.v1.json']);
        frameworkManifestSha256=$Context.FrameworkManifestSha256}
    $sourceSets=[ordered]@{}
    foreach($image in $Context.Images){$sourceSets[$image.Role]=Get-PspktBrokerLifecycleSourceSetDigest $image.Role $image.SourceBytes}
    $transforms=[ordered]@{}
    foreach($mutant in $Mutants){$transforms[$mutant.Role]=$mutant.TransformationSha256}
    return [pscustomobject]@{Bindings=[pscustomobject]$bindings;SourceSets=[pscustomobject]$sourceSets;Transformations=[pscustomobject]$transforms;
        CaseIds=$Expectations.caseIds;CompletionChecks=$Expectations.completionChecks;CleanupChecks=$Expectations.cleanupChecks}
}

function Invoke-PspktBrokerLifecycleValidation {
    [CmdletBinding(PositionalBinding=$false)]
    param([string]$RepositoryRoot,[string]$WorkRoot,[string]$PesterManifestPath,[string]$CallId,[byte[]]$ContractBytes,[object]$ExecutionState)
    $source=Get-PspktBrokerLifecycleSourceSnapshot -RepositoryRoot $RepositoryRoot -ContractBytes $ContractBytes
    . ([scriptblock]::Create($source.RetainedTexts['certification\broker-lifecycle\lib\Pspkt.Certification.BrokerLifecycleCompilation.ps1']))
    . ([scriptblock]::Create($source.RetainedTexts['certification\broker-lifecycle\lib\Pspkt.Certification.BrokerLifecycleCi.ps1']))
    $expectations=Assert-PspktBrokerLifecycleFixtures $source
    Assert-PspktBrokerLifecycleNoPreload
    if([IO.File]::Exists($WorkRoot) -or [IO.Directory]::Exists($WorkRoot)){throw 'validation:work-root'}
    [void][IO.Directory]::CreateDirectory($WorkRoot)
    $staging=Join-Path $WorkRoot 'staging'
    [void][IO.Directory]::CreateDirectory($staging)
    $callerState=Get-PspktBrokerLifecycleCallerState
    $previousLocation=$callerState.Location
    $previousDirectory=$callerState.Directory
    $previousEnvironment=$callerState.Environment
    $context=$null
    $failure=$null
    $result=$null
    $cleanup=$true
    $ExecutionState.CleanupComplete=$false
    try {
        [Environment]::SetEnvironmentVariable('TEMP',$staging,'Process')
        [Environment]::SetEnvironmentVariable('TMP',$staging,'Process')
        [Environment]::SetEnvironmentVariable('PSModuleAnalysisCachePath',(Join-Path $staging 'module-analysis'),'Process')
        Set-Location -LiteralPath $WorkRoot
        [Environment]::CurrentDirectory=$WorkRoot
        [void](Import-PspktBrokerLifecyclePester $PesterManifestPath)
        $context=New-PspktBrokerLifecycleCompilerContext -ArtifactRoot $WorkRoot -CallId $CallId
        $bootstrapPath='certification\lib\Pspkt.Certification.SchemaBootstrap.cs'
        $bootstrapSources=[ordered]@{}
        $bootstrapSources[$bootstrapPath]=$source.Files[$bootstrapPath]
        $bootstrap=New-PspktBrokerLifecycleImage $context 'Bootstrap' $bootstrapSources
        $runtimeSources=[ordered]@{}
        foreach($name in Get-PspktBrokerLifecycleRuntimeNames){
            $path='certification\broker-lifecycle\lib\'+$name
            $runtimeSources[$path]=$source.Files[$path]
        }
        $runtime=New-PspktBrokerLifecycleImage $context 'Runtime' $runtimeSources @($bootstrap)
        $mutants=@()
        foreach($role in @('M1','M2','M3','M4','M5','M6')){
            $mutation=Get-PspktBrokerLifecycleMutantSource $role $runtimeSources
            $image=New-PspktBrokerLifecycleImage $context $role $mutation.Sources @($bootstrap)
            $mutants+=,[pscustomobject]@{Role=$role;Assembly=$image.Assembly;Initialized=$false;PositiveControl='NotRun';OracleKilled=$false;OracleId='';
                OriginalSourceSetSha256=$mutation.OriginalSourceSetSha256;MutatedSourceSetSha256=$mutation.MutatedSourceSetSha256;
                TransformationSha256=$mutation.TransformationSha256}
        }
        $authority=@{}
        $authorityPaths=Get-PspktBrokerLifecycleAuthorityPaths
        $arguments=[object[]]::new(9)
        $position=0
        foreach($name in $authorityPaths.Keys){
            $authority[$name]=$source.Files[$authorityPaths[$name]]
            $arguments[$position++]=$authority[$name]
        }
        $fixtures=@{}
        $fixturePaths=Get-PspktBrokerLifecycleFixturePaths
        foreach($name in $fixturePaths.Keys){$fixtures[$name]=$source.Files[$fixturePaths[$name]]}
        $bootstrapType=$bootstrap.Assembly.GetType('Pspkt.Certification.SchemaBootstrap',$true)
        $bootstrapResult=$bootstrapType.GetMethod('Evaluate').Invoke($null,[object[]]@('bootstrap-meta',$authority.ProtocolMeta,$null))
        if(-not $bootstrapResult.Accepted){throw 'validation:authority'}
        $bootstrap.Initialized=$true
        foreach($image in @($context.Images.ToArray()|Where-Object {$_.Role -cne 'Bootstrap'})){
            Assert-PspktBrokerLifecyclePublicSurface $image.Assembly $expectations
            try{
                $type=$image.Assembly.GetType('Pspkt.Certification.BrokerLifecycle.BrokerLifecycleProtocol',$true)
                $protocol=$type.GetMethod('CreateFromCommittedAuthorities').Invoke($null,$arguments)
                $controllerType=$image.Assembly.GetType('Pspkt.Certification.BrokerLifecycle.CheckpointServiceLifecycle',$true)
                $controller=$controllerType.GetMethod('CreateInMemory').Invoke($null,[object[]]@($protocol,'Worker',$fixtures.LifecyclePolicy))
                if($controller.GetSnapshot().TrustCeiling -cne 'StructuralInProcessOnly'){throw 'validation:authority'}
                $controller.Dispose()
            }
            catch{throw 'validation:authority'}
            $image.Initialized=$true
        }
        $testPath='certification\broker-lifecycle\tests\pspkt.Phase4BrokerLifecycle.Tests.ps1'
        $testText=$source.RetainedTexts[$testPath]
        $wrapper="{`n"+$testText+"`n}"
        $factory=[scriptblock]::Create($wrapper)
        $testBlock=& $factory
        if($null -ne $testBlock.Module -or $null -ne $ExecutionContext.SessionState.Module){throw 'validation:pester'}
        $source.CallerScopePassed=$false
        $source.ContainerObservation=[pscustomobject]@{TestLength=[Text.Encoding]::UTF8.GetByteCount($testText);
            WrapperLength=[Text.Encoding]::UTF8.GetByteCount($wrapper);TestSha256=(Get-PspktBrokerLifecycleBytesDigest ([Text.Encoding]::UTF8.GetBytes($testText)));
            WrapperSha256=(Get-PspktBrokerLifecycleBytesDigest ([Text.Encoding]::UTF8.GetBytes($wrapper)))}
        $contract=@{ExpectedCaseIds=[string[]]$expectations.caseIds;SourceManifestSha256=$source.ManifestSha256;
            CompilerContext=$context;PesterManifestPath=$PesterManifestPath;InitialEnvironment=$previousEnvironment;
            InitialLocation=$previousLocation;InitialDirectory=$previousDirectory}
        $data=@{BootstrapAssembly=$bootstrap.Assembly;RuntimeAssembly=$runtime.Assembly;AuthorityBytesById=$authority;FixtureBytesById=$fixtures;
            SourceSnapshot=$source;CompilationRecords=$context.Images.ToArray();MutantBuilds=$mutants;ArtifactRoot=$WorkRoot;
            CallerScopeMarker=('pspkt-broker-lifecycle-validation:'+$CallId);InvocationContract=$contract}
        $source.ExpectedData=$data
        $container=New-PesterContainer -ScriptBlock $testBlock -Data $data
        $source.Container=$container
        $configuration=New-PspktBrokerLifecyclePesterConfiguration $container
        Assert-PspktBrokerLifecyclePesterConfiguration $configuration $container
        $captured=@(Invoke-Pester -Configuration $configuration 2>$null 3>$null 4>$null 5>$null 6>$null)
        Assert-PspktBrokerLifecyclePesterConfiguration $configuration $container
        if($captured.Count -ne 1){throw 'validation:result-cardinality'}
        $pester=$captured[0]
        if($pester.Result -cne 'Passed' -or -not $source.CallerScopePassed){throw 'validation:result-failed'}
        $actualIds=[string[]]@($pester.Tests|ForEach-Object {$_.ExpandedName})
        Assert-PspktBrokerLifecycleCasePopulation $actualIds ([string[]]$expectations.caseIds)
        foreach($test in $pester.Tests){
            if($test.ExpandedPath -cne ('Broker lifecycle structural conformance.'+$test.ExpandedName) -or
                -not $test.ShouldRun -or -not $test.Executed -or $test.Result -cne 'Passed'){throw 'validation:result-counts'}
        }
        $counts=[pscustomobject][ordered]@{compilationCount=$context.Images.Count;loadCount=$context.Images.Count;
            initializedMutantKillCount=@($mutants|Where-Object {$_.Initialized -and $_.PositiveControl -ceq 'Passed' -and $_.OracleKilled}).Count;
            containerCount=@($pester.Containers).Count;totalCount=$pester.TotalCount;selectedCount=@($pester.Tests|Where-Object {$_.ShouldRun}).Count;
            executedCount=@($pester.Tests|Where-Object {$_.Executed}).Count;passedCount=$pester.PassedCount;failedCount=$pester.FailedCount;
            skippedCount=$pester.SkippedCount;notRunCount=$pester.NotRunCount;failedBlocksCount=$pester.FailedBlocksCount;failedContainersCount=$pester.FailedContainersCount}
        $compilations=@($context.Images|ForEach-Object {[pscustomobject][ordered]@{role=$_.Role;imageName=$_.Name;imageLength=$_.Length;
            imageSha256=$_.Sha256;sourceCount=$_.SourceCount;sourceSetSha256=$_.SourceSetSha256;referenceSetSha256=$_.ReferenceSetSha256;
            language=$_.Language;compiler=$_.Compiler}})
        $loads=@($context.Images|ForEach-Object {[pscustomobject][ordered]@{role=$_.Role;imageSha256=$_.Sha256;
            context=$(if($context.Edition -ceq 'Desktop'){'LoadFrom'}else{'Default'});initialized=[bool]$_.Initialized}})
        $mutantResults=@($mutants|ForEach-Object {[pscustomobject][ordered]@{role=$_.Role;initialized=[bool]$_.Initialized;
            positiveControl=$_.PositiveControl;oracleKilled=[bool]$_.OracleKilled;oracleId=$_.OracleId;
            originalSourceSetSha256=$_.OriginalSourceSetSha256;mutatedSourceSetSha256=$_.MutatedSourceSetSha256;transformationSha256=$_.TransformationSha256}})
        $expected=New-PspktBrokerLifecycleExpectedResult $source $context $expectations $mutants $CallId
        $resultData=[ordered]@{schemaId='PspktBrokerLifecycleValidationResultV1';schemaVersion=1;outcome='ValidationSucceeded'}
        foreach($property in $expected.Bindings.PSObject.Properties){$resultData[$property.Name]=$property.Value}
        $resultData.compilationRecords=$compilations
        $resultData.loadRecords=$loads
        $resultData.mutantResults=$mutantResults
        $resultData.counts=$counts
        $resultData.caseIds=$actualIds
        $resultData.completionChecks=[string[]]$expectations.completionChecks
        $resultData.cleanupChecks=[string[]]$expectations.cleanupChecks
        $result=[pscustomobject]$resultData
        [void](Assert-PspktBrokerLifecycleResult @($result) $expected)
        $framework=@(@($context.References)+@($context.Compilers)|ForEach-Object {[pscustomobject][ordered]@{
            name=$_.Name;identity=$_.Identity;length=$_.Length;sha256=$_.Sha256;path=$_.Path}})
        Write-PspktBrokerLifecycleOwnedJson (Join-Path $WorkRoot 'source-records.v1.json') ([ordered]@{
            schemaId='PspktBrokerLifecycleSourceRecordsV1';schemaVersion=1;callId=$CallId;sourceManifestSha256=$source.ManifestSha256;
            sources=$source.Records;framework=$framework})
        Write-PspktBrokerLifecycleOwnedJson (Join-Path $WorkRoot 'validation-records.v1.json') ([ordered]@{
            schemaId='PspktBrokerLifecycleValidationRecordsV1';schemaVersion=1;callId=$CallId;container=$source.ContainerObservation;
            counts=$counts;caseIds=$actualIds;compilations=$compilations;loads=$loads;mutants=$mutantResults;trustCeiling='StructuralInProcessOnly'})
    }
    catch {
        $failure='validation:unexpected'
        if($_.Exception.Message -cin $expectations.validatorReasons){$failure=$_.Exception.Message}
    }
    finally {
        try {Close-PspktBrokerLifecycleCompilerContext $context} catch {$cleanup=$false}
        try {Remove-PspktBrokerLifecycleOwnedDirectory $staging $WorkRoot} catch {$cleanup=$false}
        try {Restore-PspktBrokerLifecycleCallerState $callerState} catch {$cleanup=$false}
        if($null -ne $context){
            foreach($reference in @($context.References)+@($context.Compilers)){if($reference.Handle.CanRead){$cleanup=$false}}
        }
        $ExecutionState.CleanupComplete=$cleanup
    }
    if(-not $cleanup){if($null -eq $failure){$failure='validation:cleanup'}}
    if($null -ne $failure){throw $failure}
    Assert-PspktBrokerLifecycleOwnedArtifacts $WorkRoot $context.Images.ToArray() $ExecutionState
    return $result
}

function Get-PspktBrokerLifecycleSourcePins {
    $rows=@'
BytePolicy|certification\broker-lifecycle\.gitattributes|287|af9e5a4ac5cb94b99b4a74cc8ae8489ce506bdf3e737e017a2baad3d82d9cda2
Documentation|certification\broker-lifecycle\README.md|14816|52b2f40b48d62e4be4a6c3f94be8fe8897c27e57865562b9de3d28ad629db54a
AuthorityInputs|certification\broker-lifecycle\authority\framing-addendum.v1.json|16264|ae2a255f0a45f9a33fe958e9c728ff535550ea09aec8fcf11398f426f56f0a0f
AuthorityInputs|certification\broker-lifecycle\authority\design-review-activation.v1.json|570|fee195e7a19a9502330b3e2691c53258130dfbb0b5c1b40eb2a5f81bfdbca24c
AuthorityInputs|certification\broker-lifecycle\schema\framing-addendum-schema.v1.json|4445|9f00101faf660e1ea3c10904a6358ae16fe1bef4577c0e05f1af9fea86357213
AuthorityInputs|certification\broker-lifecycle\schema\lifecycle-policy.v1.json|2185|011e43d50fc6c4b00576ec8c6d08fd3636228f84509966216bba1fa1d284a536
AuthorityInputs|certification\broker-lifecycle\schema\validation-receipt-schema.v1.json|6368|97776735287db2a4684b085aa0c95dd004eb29f175085dc104893ee8f199bd4d
RuntimeSources|certification\broker-lifecycle\lib\BrokerLifecycleProtocol.cs|5157|4eb804b3cf7b6a8020b1a68d9597811284c1668094542dc7d931874bc31eeb75
RuntimeSources|certification\broker-lifecycle\lib\DecodedControlFrame.cs|4728|5db35de3857699943294ca5965db7ba1ec0f13358d28f7c8ea007021987e6c0b
RuntimeSources|certification\broker-lifecycle\lib\CheckpointServiceLifecycle.cs|38258|4065214f4a8369861783a3cc3e4da2b09be0c2aa4b64942c23ea8b194521e35b
RuntimeSources|certification\broker-lifecycle\lib\BrokerLifecycleSnapshot.cs|7890|bc77631124be34505c76bcfafb119632fcc3bff5d7ccf38ee4d342c924a5a0b1
RuntimeSources|certification\broker-lifecycle\lib\ProtocolAuthoritySnapshot.cs|14463|6b5d1a83483c0528560c43db6099ed2331ce110b2971b3d8f5258a8155f64513
RuntimeSources|certification\broker-lifecycle\lib\AuthorityJsonReader.cs|10409|b01f3bbd7b31ff94a8999078672ee83e9fb1e1f7a13fa8ec9d2e9ba3023d8b54
RuntimeSources|certification\broker-lifecycle\lib\ProtocolPayloadCodec.cs|9924|2e0635431a3be0e80558ed78fbaabbe987745f81652ba3693a38e511cb9a9002
RuntimeSources|certification\broker-lifecycle\lib\TlvCursor.cs|1518|47d154ac1b5b7f979f346dd11940506594e5365c059e3b0b8fcfc830cc56e71f
RuntimeSources|certification\broker-lifecycle\lib\FrameCodec.cs|6991|3a301bddaeb82670186e7f70d5b0983f0fbb338d8c7d726e01331dad388b398c
RuntimeSources|certification\broker-lifecycle\lib\FrameSignaturePreimage.cs|2527|d8ebe119f827f76536665b0306f24192bea91a7d65e025250c44efbb7605161a
RuntimeSources|certification\broker-lifecycle\lib\TranscriptCodec.cs|19090|9f14fe8c84f86589254a8bad9795a360b65a862f6a339da61a6b008849a085e5
RuntimeSources|certification\broker-lifecycle\lib\InMemoryDuplexTransport.cs|4113|5870e38cd09d4975ee4e22b43aa47075ed63cb9fd67cc3622e77a84d05933a62
RuntimeSources|certification\broker-lifecycle\lib\DuplexTransportPair.cs|959|371cdd4ec569c513f66c5f93d3e77edb4a953cb0cc792ed82079c1dde60a66cb
RuntimeSources|certification\broker-lifecycle\lib\IBoundedDuplexTransport.cs|387|8a3b14b1d21df5888356d7b21a1d8e3b0b61f46655b1a802082401957d4a7044
RuntimeSources|certification\broker-lifecycle\lib\FrameWriteEpisode.cs|2578|5f9a5811e2a170a4555d4adf50d4c0962e59d662e609ead36642ed1b44d6ea77
RuntimeSources|certification\broker-lifecycle\lib\PendingTransportOperation.cs|9313|2179eecab24498a7023b75c3f67cce6c4c080c53642b24af7d08859d5f804e1f
RuntimeSources|certification\broker-lifecycle\lib\DispatchLease.cs|752|27b3d11381d4b4dff132099493fa052c03b8e53e8e55f45bdb676ced2c25311b
RuntimeSources|certification\broker-lifecycle\lib\RunGenerationId.cs|693|c15d602cb515ac820650b2abae996f6818f0daa0b68161797612fdcea327f8fe
RuntimeSources|certification\broker-lifecycle\lib\ServiceRole.cs|131|f0d8f525c5a045d4071268794cbbf36cf51e9092d929f7706ac6fd748185b565
RuntimeSources|certification\broker-lifecycle\lib\ServicePhase.cs|347|0eeb2dbce980550c5788c9fb0a4b4edd6dca0b6bb9da623983ac517931d36d61
RuntimeSources|certification\broker-lifecycle\lib\ConnectionPhase.cs|416|e7d6c7c56c649b5facd1745087ce5b6dba1a892b9668c757369b4c2baebc9eff
RuntimeSources|certification\broker-lifecycle\lib\BrokerHelloProgress.cs|368|f4cbbbbbcbd7b8a85bcb5681e822c7aef39d20dcd378883eabba638c4c9693f0
RuntimeSources|certification\broker-lifecycle\lib\LocalHelloProgress.cs|230|f22a9d10af443d5ff5af4939bc422b355da99f6ec29273399e3f6c946856a179
RuntimeSources|certification\broker-lifecycle\lib\ConnectionState.cs|14162|6186663a625b3aa2fd7a6eb47e650f120ede0ec420bbb5ae839e435c604a8b9b
RuntimeSources|certification\broker-lifecycle\lib\LifecyclePolicy.cs|2988|2e9f73eff5227aedc86974c10c8c275468a57a62439a641e5fde671ad82f3a9c
RuntimeSources|certification\broker-lifecycle\lib\AbsoluteDeadline.cs|562|81c20eadba471373b581ea1ef88ecf3625a14db2daed6719174f78e2a1c5f496
RuntimeSources|certification\broker-lifecycle\lib\BrokerLifecycleFailure.cs|4593|37b5d2de616db896dfaeb9934fa99dcbe695d1f4666a9c468536189786f119e3
RuntimeSources|certification\broker-lifecycle\lib\DeterministicScheduler.cs|1777|57a1b7641c7c505788bfc850f5b91dc1ae1aecc23ce96920c6b05166d675f5cf
RuntimeSources|certification\broker-lifecycle\lib\TransportOperationStatus.cs|237|c89a076f54995f591369ca92ae2f3b71f6a56cae7b80e1e25cdbfa2b54392273
RuntimeSources|certification\broker-lifecycle\lib\LifecycleTestDriver.cs|10449|71ac772b0d7cc81a23e16c10bb4943c7a9f0fd7c2e45bd4bbdaacb7df6def058
RuntimeSources|certification\broker-lifecycle\lib\TransportOutcomeScript.cs|2823|463b10a859710b61e7e073ca8ab25beef62028695793b5ba4b87fe3dca0f18be
ValidationInputs|certification\broker-lifecycle\lib\Pspkt.Certification.BrokerLifecycleCompilation.ps1|27878|89901f5bce5be0384796e398863955b330cd026a78a0e5290db43d57c1c74ae3
ValidationInputs|certification\broker-lifecycle\lib\Pspkt.Certification.BrokerLifecycleCi.ps1|35321|cd18551ebcf0815f36a113916184e911c7ed14d4e03ecad42b8152b289a83fc6
ValidationInputs|certification\broker-lifecycle\validators\Invoke-PspktPhase4BrokerLifecycleValidators.ps1|4871|fc066fb6ef8e25581a98c2da6262b02dadf5d2aa462cd20db9eec6329cc85b47
ValidationInputs|certification\broker-lifecycle\tests\pspkt.Phase4BrokerLifecycle.Tests.ps1|191246|bbeab5b0633730dad9a244b60f6e403a7f8e240e0441013d7a86664408f1a477
ValidationInputs|certification\broker-lifecycle\tests\BrokerLifecycleOracle.ps1|13677|f4c4dd6f7093ffa22901e41f2191996ed032fdb25858a6e27bc158f644e9f726
ValidationInputs|certification\broker-lifecycle\vectors\New-PspktPhase4BrokerLifecycleVectors.ps1|7346|b9e14abbc8f373e6cf81a4587a31d80661e5b542a1598c921f5caaab276bc3c4
Fixtures|certification\broker-lifecycle\vectors\generated\frames.v1.json|34220|94bbc19f3531addbbeb912dae26e03e76b4ec42d5f8f01b378e72973c7764ab6
Fixtures|certification\broker-lifecycle\vectors\generated\manifest.v1.json|2472|7f763f755c2be604844f4ded651e1cededd3abbaaed559e113f0547508aa1157
Fixtures|certification\broker-lifecycle\vectors\hand-authored\framing-goldens.v1.json|28180|8f60064fe7b62ac4ec69ed62524d60633dba2a2c2e5ffde06e5ee1b0d2b05c92
Fixtures|certification\broker-lifecycle\vectors\hand-authored\bootstrap-goldens.v1.json|72739|ddadcbcd3e789f1111af5e3d4e2193ce4b10f3cfcf4c5f7ea253723f5661853f
Fixtures|certification\broker-lifecycle\vectors\hand-authored\lifecycle-traces.v1.json|3716|f30cfe58bd6ebd4b4bce42256cbe69c1ff55585bc29fb545534b7abcf3c7aab5
Fixtures|certification\broker-lifecycle\vectors\hand-authored\contract-expectations.v1.json|40149|2c104091c0d4b041c8ffa97f8cd9fa6eeec4efc87dc1c49779f327a34cce991c
Fixtures|certification\broker-lifecycle\vectors\hand-authored\manifest.v1.json|590|44d6eec7addf5f7951cebb6fd610fc1c8c19a54e836ebac117c2d9b3ce4e0f7b
ValidationInputs|certification\broker-lifecycle\probes\Invoke-PspktBrokerLifecycleFailedPreflightProbe.ps1|4215|7466039561e833691e20487346e89ecdd8551fbc547e4db20a04c4db529666fb
Workflow|.github\workflows\ci-broker-lifecycle.yml|20119|378b9a56415fc91c4d8b31962316f414362ed8d67416f5740fd43db158d53ff5
BootstrapSource|certification\lib\Pspkt.Certification.SchemaBootstrap.cs|90801|c5b9e5b9fa3fdc4c747d6f7af63185669d86372607773ad91767488ac5b1de74
ProtocolAuthority|certification\schema\protocol-schema-meta.v1.json|4533|ca08bcb5164acb4522729dc98b2a1bd5ee348a79a14cef95dd852ae1958dcc85
ProtocolAuthority|certification\schema\protocol-inventory.v1.json|46479|d67cb37777eaa5fee07404894b0d1f4a20bf11d4a4c95085bc60e350805f265f
ProtocolAuthority|certification\schema\protocol-schema.v1.json|66838|6d76911009b64e52417b3ca519d3b3166cfdf675a4d4deede5ab0dce449c9db4
ProtocolAuthority|certification\schema\generated-base-id-map.v1.json|121966|66884fb48fcd5ebc3949957c57906614ce3d0d3a6644c6808b1d1796afb45c91
ProtocolAuthority|certification\schema\protocol-message-association.v1.json|6959|031bf566279871cd79db696ff436aa6d9383f1bb26a62467c3364880a012c5af
ProtocolAuthority|certification\schema\mandatory-tail-schedule.v1.json|236456|9852528ea500edc054a0380afa03f20993ed9aaae876e54025178106b4e50312
BytePolicy|.gitattributes|1098|4fb78db0ed73b7f5c63edfe3ce6f71baf427bb80cfda9ec0d046b68907fc0f3c
BytePolicy|certification\.gitattributes|1915|d5a6013a52c5083c22a15f5287ee0e26731c8b47a26af659ca75a21fd4767f1f
BytePolicy|certification\lib\.gitattributes|357|400eb5662f50e67f0a102824637cf005e6cb3d779d9e332e336caa8d66bdcc63
ProtocolAuthority|certification\schema\.gitattributes|636|26c67d27238e780a96ec8fc22a2430f95aa488f6e975104f1e2f931763f4798d
BytePolicy|.github\.gitattributes|163|9f0f41af85b2461b61aa484029395d7c482c25d6061dbc27aea3e3a2a62d357e
BytePolicy|.github\workflows\.gitattributes|141|e9143abc8b396c78937f0b59af6dd8dd25b5099b3f2734710356c7191b0034d7
'@
    foreach($line in $rows.Split([char]10)){
        $fields=$line.TrimEnd([char]13).Split('|')
        [pscustomobject][ordered]@{Role=$fields[0];Path=$fields[1];Length=[long]$fields[2];Sha256=$fields[3]}
    }
}
