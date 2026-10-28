Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'

function Get-PspktBrokerLifecycleRuntimeNames {
    return @('BrokerLifecycleProtocol.cs','DecodedControlFrame.cs','CheckpointServiceLifecycle.cs','BrokerLifecycleSnapshot.cs',
        'ProtocolAuthoritySnapshot.cs','AuthorityJsonReader.cs','ProtocolPayloadCodec.cs','TlvCursor.cs','FrameCodec.cs',
        'FrameSignaturePreimage.cs','TranscriptCodec.cs','InMemoryDuplexTransport.cs','DuplexTransportPair.cs',
        'IBoundedDuplexTransport.cs','FrameWriteEpisode.cs','PendingTransportOperation.cs','DispatchLease.cs',
        'RunGenerationId.cs','ServiceRole.cs','ServicePhase.cs','ConnectionPhase.cs','BrokerHelloProgress.cs',
        'LocalHelloProgress.cs','ConnectionState.cs','LifecyclePolicy.cs','AbsoluteDeadline.cs','BrokerLifecycleFailure.cs',
        'DeterministicScheduler.cs','TransportOperationStatus.cs','LifecycleTestDriver.cs','TransportOutcomeScript.cs')
}

function Get-PspktBrokerLifecycleSourceSetDigest {
    param([string]$Role,[System.Collections.IDictionary]$Sources)
    $builder=[Text.StringBuilder]::new()
    foreach($name in $Sources.Keys){
        $bytes=[byte[]]$Sources[$name]
        [void]$builder.Append($Role+[char]0+$name+[char]0+$bytes.Length.ToString([Globalization.CultureInfo]::InvariantCulture)+
            [char]0+(Get-PspktBrokerLifecycleBytesDigest $bytes)+"`n")
    }
    return Get-PspktBrokerLifecycleBytesDigest ([Text.UTF8Encoding]::new($false,$true).GetBytes($builder.ToString()))
}

function Get-PspktBrokerLifecycleMutantSource {
    param([string]$Role,[System.Collections.IDictionary]$Sources)
    if($Sources.Count -ne 31 -or $Role -cnotin @('M1','M2','M3','M4','M5','M6')){throw 'validation:mutant'}
    $path='certification\broker-lifecycle\lib\CheckpointServiceLifecycle.cs'
    $after=''
    if($Role -ceq 'M1'){
        $path='certification\broker-lifecycle\lib\FrameCodec.cs'
        $before='Buffer.BlockCopy(WriteUnsigned((ulong)payload.Length, 4), 0, result, PayloadLengthOffset, 4);'
        $after='Buffer.BlockCopy(new byte[] { (byte)payload.Length, (byte)(payload.Length >> 8), (byte)(payload.Length >> 16), (byte)(payload.Length >> 24) }, 0, result, PayloadLengthOffset, 4);'
    }
    elseif($Role -ceq 'M2'){
        $path='certification\broker-lifecycle\lib\FrameSignaturePreimage.cs'
        $before='"pspkt-phase4-local-frame-v1\0"'
        $after='"pspkt-phase4-frame-v1\0"'
    }
    elseif($Role -ceq 'M3'){
        $path='certification\broker-lifecycle\lib\TranscriptCodec.cs'
        $before='byte[] record = Wrap(owner, firstThreeFrames[index]);'
        $after='byte[] record = firstThreeFrames[index].CompleteSignedFrame;'
    }
    elseif($Role -ceq 'M4'){
        $path='certification\broker-lifecycle\lib\ConnectionState.cs'
        $before=@'
            if (recordCount > LifecyclePolicy.MaximumLocalRecords)
            {
                throw BrokerLifecycleFailure.Reject("quota:record-count");
            }
'@
    }
    elseif($Role -ceq 'M5'){
        $before=@'
                if (!object.ReferenceEquals(completion.Generation, currentGeneration) ||
                    !object.ReferenceEquals(completion.Generation.OwnerIdentity, currentGeneration.OwnerIdentity) ||
                    (registeredOperation != null &&
                     !object.ReferenceEquals(completion.Operation, registeredOperation)))
                {
                    throw new System.IO.InvalidDataException("lifecycle:stale-generation");
                }
'@
    }
    else{
        $before=@'
            if (HasOutstandingOwnership())
            {
                return false;
            }
'@
    }
    $encoding=[Text.UTF8Encoding]::new($false,$true)
    $text=$encoding.GetString([byte[]]$Sources[$path])
    $before=$before.Replace("`r`n","`n")
    if($text.Contains("`r`n")){$before=$before.Replace("`n","`r`n")}
    if([regex]::Matches($text,[regex]::Escape($before)).Count -ne 1){throw 'validation:mutant'}
    $mutated=[ordered]@{}
    foreach($name in $Sources.Keys){$mutated[$name]=[byte[]]$Sources[$name].Clone()}
    $mutated[$path]=$encoding.GetBytes($text.Replace($before,$after))
    foreach($name in @('LifecycleTestDriver.cs','TransportOutcomeScript.cs','PendingTransportOperation.cs')){
        $key='certification\broker-lifecycle\lib\'+$name
        if((Get-PspktBrokerLifecycleBytesDigest $Sources[$key]) -cne (Get-PspktBrokerLifecycleBytesDigest $mutated[$key])){throw 'validation:mutant'}
    }
    return [pscustomobject]@{Role=$Role;Sources=$mutated;Path=$path;
        OriginalSourceSetSha256=(Get-PspktBrokerLifecycleSourceSetDigest 'Runtime' $Sources);
        MutatedSourceSetSha256=(Get-PspktBrokerLifecycleSourceSetDigest $Role $mutated);
        TransformationSha256=(Get-PspktBrokerLifecycleBytesDigest $encoding.GetBytes($before+[char]0+$after))}
}

function Assert-PspktBrokerLifecycleNoPreload {
    foreach($assembly in [AppDomain]::CurrentDomain.GetAssemblies()){
        if($assembly.GetName().Name.StartsWith('PspktBrokerLifecycle_',[StringComparison]::Ordinal) -or
            $null -ne $assembly.GetType('Pspkt.Certification.SchemaBootstrap',$false) -or
            $null -ne $assembly.GetType('Pspkt.Certification.SchemaCheckResult',$false) -or
            $null -ne $assembly.GetType('Pspkt.Certification.BrokerLifecycle.BrokerLifecycleProtocol',$false)){
            throw 'validation:preload'
        }
    }
}

function Assert-PspktBrokerLifecyclePublicSurface {
    param([Reflection.Assembly]$Assembly,[object]$Expectations)
    $prefix='Pspkt.Certification.BrokerLifecycle.'
    $flags=[Reflection.BindingFlags]'Public,Instance,Static,DeclaredOnly'
    $actual=@($Assembly.GetExportedTypes().FullName|Sort-Object)
    $expected=@($Expectations.publicTypes|ForEach-Object {$prefix+$_.name}|Sort-Object)
    if(($actual -join '|') -cne ($expected -join '|')){throw 'validation:public-surface'}
    foreach($definition in $Expectations.publicTypes){
        $type=$Assembly.GetType(($prefix+$definition.name),$true)
        if(-not $type.IsSealed -or $type.GetConstructors($flags).Count -ne 0 -or
            $type.GetFields($flags).Count -ne 0 -or $type.GetEvents($flags).Count -ne 0){throw 'validation:public-surface'}
        $methods=@($type.GetMethods($flags)|Where-Object {-not $_.IsSpecialName})
        $properties=@($type.GetProperties($flags))
        if($methods.Count -ne @($definition.methods).Count -or $properties.Count -ne @($definition.properties).Count){throw 'validation:public-surface'}
        foreach($expectedMethod in $definition.methods){
            $matches=@($methods|Where-Object {$_.Name -ceq $expectedMethod.name})
            if($matches.Count -ne 1){throw 'validation:public-surface'}
            $method=$matches[0]
            if($method.IsStatic -ne $expectedMethod.static -or $method.ReturnType.FullName -cne $expectedMethod.returnType -or $method.IsGenericMethod){throw 'validation:public-surface'}
            $parameters=$method.GetParameters()
            if($parameters.Length -ne @($expectedMethod.parameters).Count){throw 'validation:public-surface'}
            for($index=0;$index -lt $parameters.Length;$index++){
                if($parameters[$index].Name -cne $expectedMethod.parameters[$index].name -or
                    $parameters[$index].ParameterType.FullName -cne $expectedMethod.parameters[$index].type -or
                    $parameters[$index].IsOptional -or $parameters[$index].IsOut){throw 'validation:public-surface'}
            }
        }
        foreach($expectedProperty in $definition.properties){
            $matches=@($properties|Where-Object {$_.Name -ceq $expectedProperty.name})
            if($matches.Count -ne 1 -or $matches[0].PropertyType.FullName -cne $expectedProperty.type -or
                $null -ne $matches[0].GetSetMethod($true) -or -not $matches[0].GetGetMethod($true).IsPublic){throw 'validation:public-surface'}
        }
    }
    $top=@($Assembly.GetTypes()|Where-Object {-not $_.IsNested -and $_.IsNotPublic -and -not $_.Name.StartsWith('<',[StringComparison]::Ordinal)})
    if((@($top.Name|Sort-Object) -join '|') -cne (@($Expectations.internalTopLevelTypes|Sort-Object) -join '|')){throw 'validation:public-surface'}
    $nested=@($Assembly.GetTypes()|Where-Object {($_.IsNestedAssembly -or $_.IsNestedPublic) -and
        -not $_.FullName.StartsWith('<',[StringComparison]::Ordinal)})
    if((@($nested.FullName|Sort-Object) -join '|') -cne (@($Expectations.nestedInternalTypes|ForEach-Object {$prefix+$_}|Sort-Object) -join '|')){throw 'validation:public-surface'}
    foreach($entry in $Expectations.enums.PSObject.Properties){
        $type=$Assembly.GetType(($prefix+$entry.Name),$true)
        if(-not $type.IsEnum -or [Enum]::GetUnderlyingType($type) -ne [int]){throw 'validation:public-surface'}
        $names=[Enum]::GetNames($type)
        if(($names -join '|') -cne (@($entry.Value.name) -join '|')){throw 'validation:public-surface'}
        foreach($value in $entry.Value){if([int][Enum]::Parse($type,$value.name) -ne $value.value){throw 'validation:public-surface'}}
    }
    $nonpublic=[Reflection.BindingFlags]'NonPublic,Public,Static,Instance,DeclaredOnly'
    foreach($entry in @(@('TransportOutcomeScript','scriptMethods','scriptGetters'),@('LifecycleTestDriver','driverMethods','driverGetters'))){
        $type=$Assembly.GetType(($prefix+$entry[0]),$true)
        if($type.IsPublic -or -not $type.IsSealed){throw 'validation:public-surface'}
        $methods=@($type.GetMethods($nonpublic)|Where-Object {($_.IsAssembly -or $_.IsPublic) -and -not $_.IsSpecialName})
        if(@($methods|Where-Object {$_.IsPublic}).Count -ne 0 -or
            (@($methods.Name|Sort-Object) -join '|') -cne (@($Expectations.seam.($entry[1])|Sort-Object) -join '|')){throw 'validation:public-surface'}
        $properties=@($type.GetProperties($nonpublic)|Where-Object {$_.GetGetMethod($true).IsAssembly -or $_.GetGetMethod($true).IsPublic})
        if((@($properties.Name|Sort-Object) -join '|') -cne (@($Expectations.seam.($entry[2])|Sort-Object) -join '|')){throw 'validation:public-surface'}
        foreach($property in $properties){if($null -ne $property.GetSetMethod($true) -or $property.GetGetMethod($true).IsPublic){throw 'validation:public-surface'}}
        $constructors=$type.GetConstructors($nonpublic)
        if($constructors.Count -ne 1 -or -not $constructors[0].IsPrivate -or $constructors[0].GetParameters().Length -ne 2){throw 'validation:public-surface'}
    }
    foreach($definition in @($Expectations.seam.methods)+@($Expectations.seam.pureSignatures)+@($Expectations.seam.supportMethods)){
        $type=$Assembly.GetType($definition.type,$true)
        $members=@($type.GetMethods($nonpublic)|Where-Object {$_.Name -ceq $definition.name})
        if($members.Count -ne 1){throw 'validation:public-surface'}
        $method=$members[0]
        if(-not $method.IsAssembly -or $method.IsStatic -ne $definition.static -or
            $method.ReturnType.FullName -cne $definition.returnType -or
            (@($method.GetParameters()|ForEach-Object {$_.ParameterType.FullName}) -join '|') -cne (@($definition.parameters) -join '|')){
            throw 'validation:public-surface'
        }
        foreach($parameter in $method.GetParameters()){if($parameter.IsOptional -or $parameter.IsOut){throw 'validation:public-surface'}}
    }
    foreach($definition in @($Expectations.seam.properties)+@($Expectations.seam.supportProperties)){
        $type=$Assembly.GetType($definition.type,$true)
        $property=$type.GetProperty($definition.name,$nonpublic)
        if($null -eq $property -or $property.PropertyType.FullName -cne $definition.typeName -or
            $null -ne $property.GetSetMethod($true) -or -not $property.GetGetMethod($true).IsAssembly){throw 'validation:public-surface'}
    }
    foreach($definition in $Expectations.seam.constructors){
        $type=$Assembly.GetType($definition.type,$true)
        $constructors=$type.GetConstructors($nonpublic)
        if($constructors.Count -ne 1 -or
            (@($constructors[0].GetParameters()|ForEach-Object {$_.ParameterType.FullName}) -join '|') -cne (@($definition.parameters) -join '|') -or
            ($definition.access -ceq 'Private' -and -not $constructors[0].IsPrivate) -or
            ($definition.access -ceq 'Assembly' -and -not $constructors[0].IsAssembly)){throw 'validation:public-surface'}
    }
}

function Read-PspktBrokerLifecycleToolImage {
    param([string]$Path,[string]$Name,[string]$Token)
    $stream=$null
    try {
        $path=[IO.Path]::GetFullPath($Path)
        if([IO.Path]::GetFileName($path) -cne $Name -or -not [IO.File]::Exists($path) -or
            ([IO.File]::GetAttributes($path) -band [IO.FileAttributes]::ReparsePoint)){throw 'validation:reference'}
        $stream=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        if($stream.Length -le 0 -or $stream.Length -gt [int]::MaxValue){throw 'validation:reference'}
        $bytes=[byte[]]::new([int]$stream.Length)
        $offset=0
        while($offset -lt $bytes.Length){
            $read=$stream.Read($bytes,$offset,$bytes.Length-$offset)
            if($read -le 0){throw 'validation:reference'}
            $offset+=$read
        }
        if($stream.ReadByte() -ne -1){throw 'validation:reference'}
        $identity=[Reflection.AssemblyName]::GetAssemblyName($path)
        $actual=[BitConverter]::ToString($identity.GetPublicKeyToken()).Replace('-','').ToLowerInvariant()
        if(($identity.Name+'.dll') -cne $Name -or $actual -cne $Token -or -not [string]::IsNullOrEmpty($identity.CultureName)){throw 'validation:reference'}
        return [pscustomobject]@{Name=$Name;Path=$path;Identity=$identity.FullName;Bytes=$bytes;Length=$bytes.Length;
            Sha256=(Get-PspktBrokerLifecycleBytesDigest $bytes);Handle=$stream}
    }
    catch {
        if($null -ne $stream){$stream.Dispose()}
        throw 'validation:reference'
    }
}

function Get-PspktBrokerLifecycleReferenceDigest {
    param([object[]]$References)
    $builder=[Text.StringBuilder]::new()
    foreach($reference in $References){
        [void]$builder.Append($reference.Name+[char]0+$reference.Identity+[char]0+
            $reference.Length.ToString([Globalization.CultureInfo]::InvariantCulture)+[char]0+$reference.Sha256+"`n")
    }
    return Get-PspktBrokerLifecycleBytesDigest ([Text.UTF8Encoding]::new($false,$true).GetBytes($builder.ToString()))
}

function New-PspktBrokerLifecycleCompilerContext {
    param([string]$ArtifactRoot,[string]$CallId)
    if($CallId -cnotmatch '\A[0-9a-f]{32}\z'){throw 'validation:compilation'}
    $references=[Collections.Generic.List[object]]::new()
    $compilers=[Collections.Generic.List[object]]::new()
    try {
        if($PSVersionTable.PSEdition -ceq 'Desktop'){
            $referenceRoot=[Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory()
            $names=@('mscorlib.dll','System.dll','System.Core.dll','System.Xml.dll','System.Xml.Linq.dll','System.Runtime.Serialization.dll','System.Numerics.dll')
        }
        elseif($PSVersionTable.PSEdition -ceq 'Core'){
            $major=[Environment]::Version.Major
            if($major -notin @(3,5,6) -and $major -lt 7){throw 'validation:reference'}
            $referenceRoot=Join-Path $PSHOME 'ref'
            $names=@('mscorlib.dll','System.Runtime.dll','System.Collections.dll','System.Linq.dll','System.IO.dll','System.Runtime.Numerics.dll',
                'System.Runtime.Serialization.Json.dll','System.Runtime.Serialization.Primitives.dll','System.Runtime.Serialization.Xml.dll',
                'System.Xml.ReaderWriter.dll','System.Xml.XDocument.dll','System.Text.Encoding.Extensions.dll','System.Threading.dll',
                'System.Security.Cryptography.Algorithms.dll','System.Security.Cryptography.Primitives.dll')
            if($major -ge 7){$names+='System.Security.Cryptography.dll'}
        }
        else{throw 'validation:reference'}
        foreach($name in $names){
            $token='b03f5f7f11d50a3a'
            if($PSVersionTable.PSEdition -ceq 'Desktop' -or $name -ceq 'mscorlib.dll'){$token='b77a5c561934e089'}
            $references.Add((Read-PspktBrokerLifecycleToolImage (Join-Path $referenceRoot $name) $name $token))
        }
        $analysis=$null
        $csharp=$null
        $providerType=$null
        if($PSVersionTable.PSEdition -ceq 'Core'){
            foreach($name in @('Microsoft.CodeAnalysis.dll','Microsoft.CodeAnalysis.CSharp.dll')){
                $compilers.Add((Read-PspktBrokerLifecycleToolImage (Join-Path $PSHOME $name) $name '31bf3856ad364e35'))
            }
            $analysis=[System.Runtime.Loader.AssemblyLoadContext]::Default.LoadFromAssemblyPath($compilers[0].Path)
            $csharp=[System.Runtime.Loader.AssemblyLoadContext]::Default.LoadFromAssemblyPath($compilers[1].Path)
            if($analysis.FullName -cne $compilers[0].Identity -or $csharp.FullName -cne $compilers[1].Identity -or
                -not [string]::Equals($analysis.Location,$compilers[0].Path,[StringComparison]::OrdinalIgnoreCase) -or
                -not [string]::Equals($csharp.Location,$compilers[1].Path,[StringComparison]::OrdinalIgnoreCase)){throw 'validation:reference'}
        }
        else {
            $system=@($references|Where-Object {$_.Name -ceq 'System.dll'})[0]
            $systemAssembly=[Reflection.Assembly]::LoadFrom($system.Path)
            if($systemAssembly.FullName -cne $system.Identity){throw 'validation:reference'}
            $providerType=$systemAssembly.GetType('Microsoft.CSharp.CSharpCodeProvider',$true)
        }
        return [pscustomobject]@{ArtifactRoot=$ArtifactRoot;CallId=$CallId;Edition=$PSVersionTable.PSEdition;References=$references.ToArray();
            Compilers=$compilers.ToArray();Analysis=$analysis;CSharp=$csharp;ProviderType=$providerType;
            Images=[Collections.Generic.List[object]]::new();FrameworkManifestSha256=(Get-PspktBrokerLifecycleReferenceDigest (@($references.ToArray())+@($compilers.ToArray())))}
    }
    catch {
        foreach($record in @($references.ToArray())+@($compilers.ToArray())){$record.Handle.Dispose()}
        throw 'validation:reference'
    }
}

function New-PspktBrokerLifecycleImage {
    param([object]$Context,[string]$Role,[System.Collections.IDictionary]$Sources,[object[]]$Dependencies=@())
    $roles=@('Bootstrap','Runtime','M1','M2','M3','M4','M5','M6')
    $sourceCount=31
    $dependencyCount=1
    if($Role -ceq 'Bootstrap'){$sourceCount=1;$dependencyCount=0}
    if($Context.Images.Count -ge 8 -or $Role -cne $roles[$Context.Images.Count] -or
        $Sources.Count -ne $sourceCount -or $Dependencies.Count -ne $dependencyCount){throw 'validation:compilation'}
    $encoding=[Text.UTF8Encoding]::new($false,$true)
    $names=[string[]]@($Sources.Keys)
    $texts=[string[]]@($names|ForEach-Object {$encoding.GetString([byte[]]$Sources[$_])})
    $simpleName='PspktBrokerLifecycle_'+$Context.CallId+'_'+$Role
    $destination=Join-Path $Context.ArtifactRoot ($simpleName+'.dll')
    $references=@($Context.References)+@($Dependencies)
    try {
        if($Context.Edition -ceq 'Desktop'){
            foreach($reference in $Context.References){
                if([Reflection.AssemblyName]::GetAssemblyName($reference.Path).FullName -cne $reference.Identity -or
                    (Get-PspktBrokerLifecycleBytesDigest ([IO.File]::ReadAllBytes($reference.Path))) -cne $reference.Sha256){throw 'validation:reference'}
            }
            $stage=Join-Path $Context.ArtifactRoot ('compiler-'+$Role)
            if([IO.Directory]::Exists($stage) -or [IO.File]::Exists($stage)){throw 'validation:compilation'}
            [void][IO.Directory]::CreateDirectory($stage)
            $provider=$null
            $parameters=$null
            try {
                $provider=[Activator]::CreateInstance($Context.ProviderType)
                $parameters=[CodeDom.Compiler.CompilerParameters]::new()
                $parameters.GenerateExecutable=$false
                $parameters.GenerateInMemory=$false
                $parameters.IncludeDebugInformation=$false
                $parameters.CompilerOptions='/langversion:5 /optimize+'
                $parameters.OutputAssembly=Join-Path $stage ($simpleName+'.dll')
                $parameters.TempFiles=[CodeDom.Compiler.TempFileCollection]::new($stage,$false)
                foreach($reference in $references){[void]$parameters.ReferencedAssemblies.Add($reference.Path)}
                $emission=$provider.CompileAssemblyFromSource($parameters,$texts)
                if(@($emission.Errors|Where-Object {-not $_.IsWarning}).Count -ne 0){throw 'validation:compilation'}
                $imageBytes=[IO.File]::ReadAllBytes($parameters.OutputAssembly)
            }
            finally {
                if($null -ne $parameters){$parameters.TempFiles.Delete()}
                if($null -ne $provider){$provider.Dispose()}
                foreach($entry in [IO.Directory]::GetFileSystemEntries($stage)){
                    if([IO.Directory]::Exists($entry) -or ([IO.File]::GetAttributes($entry) -band [IO.FileAttributes]::ReparsePoint)){throw 'validation:cleanup'}
                    [IO.File]::Delete($entry)
                }
                [IO.Directory]::Delete($stage,$false)
            }
        }
        else {
            $analysis=$Context.Analysis
            $csharp=$Context.CSharp
            $constructor=@($csharp.GetType('Microsoft.CodeAnalysis.CSharp.CSharpParseOptions').GetConstructors()|Where-Object {$_.GetParameters().Length -eq 4})[0]
            $parseOptions=$constructor.Invoke([object[]]@(
                [Enum]::Parse($csharp.GetType('Microsoft.CodeAnalysis.CSharp.LanguageVersion'),'CSharp5'),
                [Enum]::Parse($analysis.GetType('Microsoft.CodeAnalysis.DocumentationMode'),'None'),
                [Enum]::Parse($analysis.GetType('Microsoft.CodeAnalysis.SourceCodeKind'),'Regular'),$null))
            $parse=@($csharp.GetType('Microsoft.CodeAnalysis.CSharp.CSharpSyntaxTree').GetMethods()|Where-Object {
                $_.Name -ceq 'ParseText' -and $_.GetParameters().Length -eq 5 -and $_.GetParameters()[0].ParameterType -eq [string]})[0]
            $trees=[Array]::CreateInstance($analysis.GetType('Microsoft.CodeAnalysis.SyntaxTree'),$texts.Length)
            for($index=0;$index -lt $texts.Length;$index++){
                $trees.SetValue($parse.Invoke($null,[object[]]@($texts[$index],$parseOptions,$names[$index],$encoding,[Threading.CancellationToken]::None)),$index)
            }
            $fromImage=@($analysis.GetType('Microsoft.CodeAnalysis.MetadataReference').GetMethods()|Where-Object {
                $_.Name -ceq 'CreateFromImage' -and $_.GetParameters().Length -eq 4 -and $_.GetParameters()[0].ParameterType.Name -ceq 'IEnumerable`1'})[0]
            $properties=[Activator]::CreateInstance($analysis.GetType('Microsoft.CodeAnalysis.MetadataReferenceProperties'))
            $metadata=[Array]::CreateInstance($analysis.GetType('Microsoft.CodeAnalysis.MetadataReference'),$references.Count)
            for($index=0;$index -lt $references.Count;$index++){
                $arguments=[object[]]::new(4)
                $arguments[0]=[byte[]]$references[$index].Bytes
                $arguments[1]=$properties
                $arguments[3]=[string]$references[$index].Path
                $metadata.SetValue($fromImage.Invoke($null,$arguments),$index)
            }
            $optionsType=$csharp.GetType('Microsoft.CodeAnalysis.CSharp.CSharpCompilationOptions')
            $constructor=@($optionsType.GetConstructors()|Where-Object {@($_.GetParameters()|Where-Object {-not $_.IsOptional}).Count -eq 1})[0]
            $parameters=$constructor.GetParameters()
            $arguments=[object[]]::new($parameters.Length)
            for($index=0;$index -lt $parameters.Length;$index++){$arguments[$index]=$parameters[$index].DefaultValue}
            $arguments[0]=[Enum]::Parse($analysis.GetType('Microsoft.CodeAnalysis.OutputKind'),'DynamicallyLinkedLibrary')
            $options=$constructor.Invoke($arguments)
            $options=$options.WithOptimizationLevel([Enum]::Parse($analysis.GetType('Microsoft.CodeAnalysis.OptimizationLevel'),'Release'))
            $compiler=$csharp.GetType('Microsoft.CodeAnalysis.CSharp.CSharpCompilation')
            $create=@($compiler.GetMethods()|Where-Object {$_.Name -ceq 'Create' -and $_.IsStatic -and $_.GetParameters().Length -eq 4})[0]
            $compilation=$create.Invoke($null,[object[]]@($simpleName,$trees,$metadata,$options))
            $emit=@($compiler.GetMethods()|Where-Object {$_.Name -ceq 'Emit' -and $_.GetParameters().Length -eq 7})[0]
            $stream=[IO.MemoryStream]::new()
            try {
                $arguments=[object[]]::new(7)
                $arguments[0]=$stream
                $arguments[6]=[Threading.CancellationToken]::None
                $emission=$emit.Invoke($compilation,$arguments)
                if(-not $emission.Success){throw 'validation:compilation'}
                $imageBytes=$stream.ToArray()
            }
            finally {$stream.Dispose()}
        }
        if($imageBytes.Length -le 0 -or $imageBytes.Length -gt 16777216){throw 'validation:compilation'}
        $output=[IO.File]::Open($destination,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        try {$output.Write($imageBytes,0,$imageBytes.Length);$output.Flush($true)} finally {$output.Dispose()}
        $identity=[Reflection.AssemblyName]::GetAssemblyName($destination).FullName
        if($identity -cne ($simpleName+', Version=0.0.0.0, Culture=neutral, PublicKeyToken=null')){throw 'validation:assembly-custody'}
        if($Context.Edition -ceq 'Desktop'){$assembly=[Reflection.Assembly]::LoadFrom($destination)}
        else{$assembly=[System.Runtime.Loader.AssemblyLoadContext]::Default.LoadFromAssemblyPath($destination)}
        if($assembly.FullName -cne $identity -or -not [string]::Equals($assembly.Location,$destination,[StringComparison]::OrdinalIgnoreCase)){throw 'validation:assembly-custody'}
        if($Context.Edition -ceq 'Core' -and -not [object]::ReferenceEquals(
            [System.Runtime.Loader.AssemblyLoadContext]::GetLoadContext($assembly),[System.Runtime.Loader.AssemblyLoadContext]::Default)){throw 'validation:assembly-custody'}
        $allowed=@($references.Identity)
        $emitted=@($assembly.GetReferencedAssemblies())
        foreach($reference in $emitted){if($reference.FullName -cnotin $allowed){throw 'validation:reference'}}
        foreach($dependency in $Dependencies){if(@($emitted|Where-Object {$_.FullName -ceq $dependency.Identity}).Count -ne 1){throw 'validation:reference'}}
        $image=[pscustomobject]@{Role=$Role;Name=($simpleName+'.dll');Path=$destination;Identity=$identity;Bytes=$imageBytes;
            Length=$imageBytes.Length;Sha256=(Get-PspktBrokerLifecycleBytesDigest $imageBytes);Assembly=$assembly;SourceCount=$Sources.Count;
            SourceSetSha256=(Get-PspktBrokerLifecycleSourceSetDigest $Role $Sources);
            ReferenceSetSha256=(Get-PspktBrokerLifecycleReferenceDigest $references);References=$references;SourceBytes=$Sources;
            Language='CSharp5';Compiler=$(if($Context.Edition -ceq 'Desktop'){'CodeDom'}else{'Roslyn'});Initialized=$false}
        $Context.Images.Add($image)
        return $image
    }
    catch {
        $reason=$_.Exception.Message
        if($reason -cin @('validation:compilation','validation:reference','validation:assembly-custody','validation:cleanup')){throw $reason}
        throw 'validation:compilation'
    }
}

function Close-PspktBrokerLifecycleCompilerContext {
    param([object]$Context)
    if($null -ne $Context){
        foreach($record in @($Context.References)+@($Context.Compilers)){$record.Handle.Dispose()}
    }
}
