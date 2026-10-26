Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'

function Get-PspktSignatureReferenceRuntimeNames {
    return @('EvidenceSetChecker.cs','EvidenceKeyBindingSnapshot.cs','EvidenceSetAssessment.cs','EvidenceArtifactVerification.cs',
        'EvidenceReferenceResolution.cs','EvidenceAuthoritySnapshot.cs','EvidenceCanonicalJsonReader.cs','EvidenceJsonValue.cs',
        'EvidenceKeyBindingReader.cs','EvidenceKeyBinding.cs','CanonicalRsaPublicKey.cs','EvidenceSignatureVerifier.cs',
        'EvidenceReferenceResolver.cs','EvidenceResolvedReference.cs','EvidencePayloadProjection.cs','EvidenceClaimSet.cs','EvidenceFailure.cs')
}

function Get-PspktSignatureReferenceStructuralNames {
    return @('EvidenceArtifactEnvelopeCodec.cs','DecodedEvidenceArtifactEnvelope.cs','EvidenceSchemaSnapshot.cs',
        'EvidenceAuthorityJsonReader.cs','EvidencePayloadCodec.cs','EvidenceTlvCursor.cs','EvidenceSignatureContract.cs')
}

function Get-PspktSignatureReferenceSourceSetHash {
    param([string[]]$Names,[string[]]$Texts)
    if($Names.Count -ne $Texts.Count) { throw 'validation:source-membership' }
    $encoding=[Text.UTF8Encoding]::new($false,$true)
    $manifest=[Text.StringBuilder]::new()
    for($index=0;$index -lt $Names.Count;$index++) {
        $bytes=$encoding.GetBytes($Texts[$index])
        [void]$manifest.Append($Names[$index]+[char]0+$bytes.Length.ToString([Globalization.CultureInfo]::InvariantCulture)+[char]0+
            (Get-PspktSignatureReferenceBytesDigest -Bytes $bytes)+"`n")
    }
    return (Get-PspktSignatureReferenceBytesDigest -Bytes $encoding.GetBytes($manifest.ToString()))
}

function Get-PspktSignatureReferenceReferenceSetHash {
    param([object[]]$References)
    $manifest=[Text.StringBuilder]::new()
    foreach($reference in $References) {
        [void]$manifest.Append($reference.Name+[char]0+$reference.Identity+[char]0+
            $reference.Length.ToString([Globalization.CultureInfo]::InvariantCulture)+[char]0+$reference.Sha256+"`n")
    }
    return (Get-PspktSignatureReferenceBytesDigest -Bytes ([Text.UTF8Encoding]::new($false,$true).GetBytes($manifest.ToString())))
}

function Read-PspktSignatureReferenceToolImage {
    param([string]$Path,[string]$Name,[string]$Token)
    $stream=$null
    try {
        $path=[IO.Path]::GetFullPath($Path)
        if([IO.Path]::GetFileName($path) -cne $Name -or -not [IO.File]::Exists($path) -or
            ([IO.File]::GetAttributes($path) -band [IO.FileAttributes]::ReparsePoint)) { throw 'validation:reference' }
        $stream=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        if($stream.Length -le 0 -or $stream.Length -gt [int]::MaxValue) { throw 'validation:reference' }
        $bytes=[byte[]]::new([int]$stream.Length);$offset=0
        while($offset -lt $bytes.Length) {
            $read=$stream.Read($bytes,$offset,$bytes.Length-$offset)
            if($read -le 0) { throw 'validation:reference' }
            $offset+=$read
        }
        $identity=[Reflection.AssemblyName]::GetAssemblyName($path)
        $actualToken=[BitConverter]::ToString($identity.GetPublicKeyToken()).Replace('-','').ToLowerInvariant()
        if(($identity.Name+'.dll') -cne $Name -or $actualToken -cne $Token -or
            -not [string]::IsNullOrEmpty($identity.CultureName)) { throw 'validation:reference' }
        return [pscustomobject]@{Name=$Name;Path=$path;Identity=$identity.FullName;Length=$bytes.Length;
            Sha256=(Get-PspktSignatureReferenceBytesDigest -Bytes $bytes);Bytes=$bytes;Handle=$stream}
    }
    catch {
        if($null -ne $stream) { $stream.Dispose() }
        throw 'validation:reference'
    }
}

function Assert-PspktSignatureReferenceNoPreload {
    foreach($assembly in [AppDomain]::CurrentDomain.GetAssemblies()) {
        if($assembly.GetName().Name.StartsWith('PspktEvidenceSignatureReference_',[StringComparison]::Ordinal) -or
            $null -ne $assembly.GetType('Pspkt.Certification.SchemaBootstrap',$false) -or
            $null -ne $assembly.GetType('Pspkt.Certification.EvidenceRuntime.EvidenceArtifactEnvelopeCodec',$false) -or
            $null -ne $assembly.GetType('Pspkt.Certification.EvidenceSignatureReference.EvidenceSetChecker',$false)) {
            throw 'validation:preload'
        }
    }
}

function New-PspktSignatureReferenceCompilerContext {
    [CmdletBinding(PositionalBinding=$false)]
    param([Parameter(Mandatory=$true)][string]$ArtifactRoot,[Parameter(Mandatory=$true)][string]$CallId)
    if($CallId -cnotmatch '\A[0-9a-f]{32}\z') { throw 'validation:contract' }
    $references=[Collections.Generic.List[object]]::new()
    $compilers=[Collections.Generic.List[object]]::new()
    $analysis=$null;$csharp=$null;$providerType=$null
    try {
        if($PSVersionTable.PSEdition -ceq 'Desktop') {
            $frameworkRoot=[Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory()
            $names=@('mscorlib.dll','System.dll','System.Core.dll','System.Xml.dll','System.Xml.Linq.dll','System.Runtime.Serialization.dll','System.Numerics.dll')
        }
        elseif($PSVersionTable.PSEdition -ceq 'Core') {
            $major=[Environment]::Version.Major
            if($major -notin @(3,5,6) -and $major -lt 7) { throw 'validation:reference' }
            $frameworkRoot=Join-Path $PSHOME 'ref'
            $names=@('mscorlib.dll','System.Runtime.dll','System.Collections.dll','System.Linq.dll','System.IO.dll','System.Runtime.Numerics.dll',
                'System.Runtime.Serialization.Json.dll','System.Runtime.Serialization.Primitives.dll','System.Runtime.Serialization.Xml.dll',
                'System.Xml.ReaderWriter.dll','System.Xml.XDocument.dll','System.Text.Encoding.Extensions.dll',
                'System.Security.Cryptography.Algorithms.dll','System.Security.Cryptography.Primitives.dll')
            if($major -ge 7) { $names+='System.Security.Cryptography.dll' }
        }
        else { throw 'validation:reference' }
        foreach($name in $names) {
            $token='b03f5f7f11d50a3a'
            if($PSVersionTable.PSEdition -ceq 'Desktop' -or $name -ceq 'mscorlib.dll') { $token='b77a5c561934e089' }
            $references.Add((Read-PspktSignatureReferenceToolImage -Path (Join-Path $frameworkRoot $name) -Name $name -Token $token))
        }
        if($PSVersionTable.PSEdition -ceq 'Desktop') {
            $system=@($references | Where-Object {$_.Name -ceq 'System.dll'})[0]
            $systemAssembly=[Reflection.Assembly]::LoadFrom($system.Path)
            if($systemAssembly.FullName -cne $system.Identity) { throw 'validation:reference' }
            $providerType=$systemAssembly.GetType('Microsoft.CSharp.CSharpCodeProvider',$true)
        }
        else {
            foreach($name in @('Microsoft.CodeAnalysis.dll','Microsoft.CodeAnalysis.CSharp.dll')) {
                $compilers.Add((Read-PspktSignatureReferenceToolImage -Path (Join-Path $PSHOME $name) -Name $name -Token '31bf3856ad364e35'))
            }
            $analysis=[System.Runtime.Loader.AssemblyLoadContext]::Default.LoadFromAssemblyPath($compilers[0].Path)
            $csharp=[System.Runtime.Loader.AssemblyLoadContext]::Default.LoadFromAssemblyPath($compilers[1].Path)
            if($analysis.FullName -cne $compilers[0].Identity -or $csharp.FullName -cne $compilers[1].Identity -or
                -not [string]::Equals($analysis.Location,$compilers[0].Path,[StringComparison]::OrdinalIgnoreCase) -or
                -not [string]::Equals($csharp.Location,$compilers[1].Path,[StringComparison]::OrdinalIgnoreCase)) { throw 'validation:reference' }
        }
        $imageRoot=Join-Path $ArtifactRoot 'images'
        if([IO.Directory]::Exists($imageRoot) -or [IO.File]::Exists($imageRoot)) { throw 'validation:work-root' }
        [void][IO.Directory]::CreateDirectory($imageRoot)
        return [pscustomobject]@{Edition=$PSVersionTable.PSEdition;CallId=$CallId;ArtifactRoot=$ArtifactRoot;ImageRoot=$imageRoot;
            References=$references.ToArray();Compilers=$compilers.ToArray();Analysis=$analysis;CSharp=$csharp;ProviderType=$providerType;
            Images=[Collections.Generic.List[object]]::new();FrameworkManifestSha256=(Get-PspktSignatureReferenceReferenceSetHash $references.ToArray())}
    }
    catch {
        foreach($reference in @($references.ToArray())+@($compilers.ToArray())) { $reference.Handle.Dispose() }
        throw 'validation:reference'
    }
}

function Assert-PspktSignatureReferenceAssemblyCustody {
    param([object]$Context,[object]$Image,[object[]]$Dependencies)
    $simpleName='PspktEvidenceSignatureReference_'+$Context.CallId+'_'+$Image.Role
    $identity=$simpleName+', Version=0.0.0.0, Culture=neutral, PublicKeyToken=null'
    if($Image.Identity -cne $identity -or $Image.Assembly.FullName -cne $identity -or
        -not [string]::Equals($Image.Assembly.Location,$Image.Path,[StringComparison]::OrdinalIgnoreCase) -or
        $Image.Name -cne ($simpleName+'.dll')) { throw 'validation:assembly-custody' }
    if($Context.Edition -ceq 'Core' -and -not [object]::ReferenceEquals(
        [System.Runtime.Loader.AssemblyLoadContext]::GetLoadContext($Image.Assembly),[System.Runtime.Loader.AssemblyLoadContext]::Default)) {
        throw 'validation:assembly-custody'
    }
    $fileBytes=[IO.File]::ReadAllBytes($Image.Path)
    if($fileBytes.Length -ne $Image.Length -or (Get-PspktSignatureReferenceBytesDigest -Bytes $fileBytes) -cne $Image.Sha256 -or
        [Reflection.AssemblyName]::GetAssemblyName($Image.Path).FullName -cne $identity) { throw 'validation:assembly-custody' }
    $matches=@([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object {$_.FullName -ceq $identity})
    if($matches.Count -ne 1 -or -not [object]::ReferenceEquals($matches[0],$Image.Assembly)) { throw 'validation:assembly-custody' }
    $allowed=@($Context.References.Identity)+@($Dependencies | ForEach-Object {$_.Identity})
    $emitted=@($Image.Assembly.GetReferencedAssemblies())
    foreach($reference in $emitted) {
        if($reference.FullName -cnotin $allowed) { throw 'validation:reference' }
    }
    foreach($dependency in $Dependencies) {
        if(@($emitted | Where-Object {$_.FullName -ceq $dependency.Identity}).Count -ne 1) { throw 'validation:reference' }
    }
    $expected=@()
    if($Image.Role -ceq 'Bootstrap') { $expected=@('Pspkt.Certification.SchemaBootstrap','Pspkt.Certification.SchemaCheckResult') }
    elseif($Image.Role -ceq 'Structural') { $expected=@('Pspkt.Certification.EvidenceRuntime.DecodedEvidenceArtifactEnvelope','Pspkt.Certification.EvidenceRuntime.EvidenceArtifactEnvelopeCodec') }
    else {
        $expected=@('EvidenceArtifactVerification','EvidenceKeyBindingSnapshot','EvidenceReferenceResolution','EvidenceSetAssessment','EvidenceSetChecker') |
            ForEach-Object {'Pspkt.Certification.EvidenceSignatureReference.'+$_}
    }
    $actual=@($Image.Assembly.GetExportedTypes().FullName | Sort-Object)
    if(($actual -join '|') -cne (($expected | Sort-Object) -join '|')) { throw 'validation:public-surface' }
}

function New-PspktSignatureReferenceAssemblyImage {
    [CmdletBinding(PositionalBinding=$false)]
    param([Parameter(Mandatory=$true)][object]$Context,[Parameter(Mandatory=$true)][string]$Role,
        [Parameter(Mandatory=$true)][string[]]$Texts,[Parameter(Mandatory=$true)][string[]]$Names,[object[]]$Dependencies=@())
    $roles=@('Bootstrap','Structural','Checker','M1','M2','M3','M4','M5')
    $expectedCount=17;$expectedDependencies=2
    if($Role -ceq 'Bootstrap') { $expectedCount=1;$expectedDependencies=0 }
    elseif($Role -ceq 'Structural') { $expectedCount=7;$expectedDependencies=1 }
    if($Context.Images.Count -ge 8 -or $Role -cne $roles[$Context.Images.Count] -or $Texts.Count -ne $expectedCount -or
        $Names.Count -ne $expectedCount -or $Dependencies.Count -ne $expectedDependencies) { throw 'validation:compilation' }
    $encoding=[Text.UTF8Encoding]::new($false,$true)
    $simpleName='PspktEvidenceSignatureReference_'+$Context.CallId+'_'+$Role
    $path=Join-Path $Context.ImageRoot ($simpleName+'.dll')
    $references=@($Context.References)+@($Dependencies)
    try {
        if($Context.Edition -ceq 'Desktop') {
            foreach($reference in $Context.References) {
                if([Reflection.AssemblyName]::GetAssemblyName($reference.Path).FullName -cne $reference.Identity -or
                    (Get-PspktSignatureReferenceBytesDigest -Bytes ([IO.File]::ReadAllBytes($reference.Path))) -cne $reference.Sha256) {
                    throw 'validation:reference'
                }
            }
            $stage=Join-Path $Context.ArtifactRoot ('compiler-'+$Role)
            if([IO.Directory]::Exists($stage) -or [IO.File]::Exists($stage)) { throw 'validation:compilation' }
            [void][IO.Directory]::CreateDirectory($stage)
            $stageImage=Join-Path $stage ($simpleName+'.dll')
            $provider=$null;$parameters=$null;$stageFailure=$null
            try {
                $provider=[Activator]::CreateInstance($Context.ProviderType)
                $parameters=[CodeDom.Compiler.CompilerParameters]::new()
                $parameters.GenerateExecutable=$false
                $parameters.GenerateInMemory=$false
                $parameters.IncludeDebugInformation=$false
                $parameters.CompilerOptions='/langversion:5 /optimize+'
                $parameters.OutputAssembly=$stageImage
                $parameters.TempFiles=[CodeDom.Compiler.TempFileCollection]::new($stage,$false)
                foreach($reference in $references) { [void]$parameters.ReferencedAssemblies.Add($reference.Path) }
                $result=$provider.CompileAssemblyFromSource($parameters,[string[]]$Texts)
                if(@($result.Errors | Where-Object {-not $_.IsWarning}).Count -ne 0) { throw 'validation:compilation' }
                $imageBytes=[IO.File]::ReadAllBytes($stageImage)
            }
            catch { $stageFailure='validation:compilation' }
            finally {
                try { if($null -ne $parameters) { $parameters.TempFiles.Delete() } } catch { if($null -eq $stageFailure){$stageFailure='validation:cleanup'} }
                try { if($null -ne $provider) { $provider.Dispose() } } catch { if($null -eq $stageFailure){$stageFailure='validation:cleanup'} }
                try {
                    foreach($entry in [IO.Directory]::GetFileSystemEntries($stage)) {
                        if([IO.Directory]::Exists($entry) -or ([IO.File]::GetAttributes($entry) -band [IO.FileAttributes]::ReparsePoint)) { throw 'validation:cleanup' }
                        [IO.File]::Delete($entry)
                    }
                    [IO.Directory]::Delete($stage,$false)
                }
                catch { if($null -eq $stageFailure){$stageFailure='validation:cleanup'} }
            }
            if($null -ne $stageFailure) { throw $stageFailure }
        }
        else {
            $analysis=$Context.Analysis;$csharp=$Context.CSharp
            $parseType=$csharp.GetType('Microsoft.CodeAnalysis.CSharp.CSharpParseOptions',$true)
            $parseConstructor=@($parseType.GetConstructors() | Where-Object {$_.GetParameters().Length -eq 4})[0]
            $parseOptions=$parseConstructor.Invoke([object[]]@(
                [Enum]::Parse($csharp.GetType('Microsoft.CodeAnalysis.CSharp.LanguageVersion'),'CSharp5'),
                [Enum]::Parse($analysis.GetType('Microsoft.CodeAnalysis.DocumentationMode'),'None'),
                [Enum]::Parse($analysis.GetType('Microsoft.CodeAnalysis.SourceCodeKind'),'Regular'),$null))
            $parseMethod=@($csharp.GetType('Microsoft.CodeAnalysis.CSharp.CSharpSyntaxTree').GetMethods() |
                Where-Object {$_.Name -ceq 'ParseText' -and $_.GetParameters().Length -eq 5 -and $_.GetParameters()[0].ParameterType -eq [string]})[0]
            $trees=[Array]::CreateInstance($analysis.GetType('Microsoft.CodeAnalysis.SyntaxTree'),$Texts.Length)
            for($index=0;$index -lt $Texts.Length;$index++) {
                $trees.SetValue($parseMethod.Invoke($null,[object[]]@($Texts[$index],$parseOptions,$Names[$index],$encoding,[Threading.CancellationToken]::None)),$index)
            }
            $referenceMethod=@($analysis.GetType('Microsoft.CodeAnalysis.MetadataReference').GetMethods() |
                Where-Object {$_.Name -ceq 'CreateFromImage' -and $_.GetParameters().Length -eq 4 -and $_.GetParameters()[0].ParameterType.Name -ceq 'IEnumerable`1'})[0]
            $properties=[Activator]::CreateInstance($analysis.GetType('Microsoft.CodeAnalysis.MetadataReferenceProperties'))
            $metadata=[Array]::CreateInstance($analysis.GetType('Microsoft.CodeAnalysis.MetadataReference'),$references.Count)
            for($index=0;$index -lt $references.Count;$index++) {
                $arguments=[object[]]::new(4)
                $arguments[0]=[byte[]]$references[$index].Bytes;$arguments[1]=$properties;$arguments[3]=[string]$references[$index].Path
                $metadata.SetValue($referenceMethod.Invoke($null,$arguments),$index)
            }
            $optionsType=$csharp.GetType('Microsoft.CodeAnalysis.CSharp.CSharpCompilationOptions')
            $constructor=@($optionsType.GetConstructors() | Where-Object {@($_.GetParameters() | Where-Object {-not $_.IsOptional}).Count -eq 1})[0]
            $parameters=$constructor.GetParameters();$arguments=[object[]]::new($parameters.Length)
            for($index=0;$index -lt $parameters.Length;$index++) { $arguments[$index]=$parameters[$index].DefaultValue }
            $arguments[0]=[Enum]::Parse($analysis.GetType('Microsoft.CodeAnalysis.OutputKind'),'DynamicallyLinkedLibrary')
            $options=$constructor.Invoke($arguments)
            $options=$options.WithOptimizationLevel([Enum]::Parse($analysis.GetType('Microsoft.CodeAnalysis.OptimizationLevel'),'Release'))
            $compileType=$csharp.GetType('Microsoft.CodeAnalysis.CSharp.CSharpCompilation')
            $create=@($compileType.GetMethods() | Where-Object {$_.Name -ceq 'Create' -and $_.IsStatic -and $_.GetParameters().Length -eq 4})[0]
            $compilation=$create.Invoke($null,[object[]]@($simpleName,$trees,$metadata,$options))
            $emit=@($compileType.GetMethods() | Where-Object {$_.Name -ceq 'Emit' -and $_.GetParameters().Length -eq 7})[0]
            $stream=[IO.MemoryStream]::new()
            try {
                $arguments=[object[]]::new(7);$arguments[0]=$stream;$arguments[6]=[Threading.CancellationToken]::None
                $result=$emit.Invoke($compilation,$arguments)
                if(-not $result.Success) { throw 'validation:compilation' }
                $imageBytes=$stream.ToArray()
            }
            finally { $stream.Dispose() }
        }
        if($imageBytes.Length -le 0 -or $imageBytes.Length -gt 16777216) { throw 'validation:compilation' }
        $stream=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        try { $stream.Write($imageBytes,0,$imageBytes.Length);$stream.Flush($true) }
        finally { $stream.Dispose() }
        $identity=[Reflection.AssemblyName]::GetAssemblyName($path).FullName
        if($identity -cne ($simpleName+', Version=0.0.0.0, Culture=neutral, PublicKeyToken=null')) { throw 'validation:assembly-custody' }
        if($Context.Edition -ceq 'Desktop') { $assembly=[Reflection.Assembly]::LoadFrom($path) }
        else { $assembly=[System.Runtime.Loader.AssemblyLoadContext]::Default.LoadFromAssemblyPath($path) }
        $image=[pscustomobject]@{Role=$Role;Name=($simpleName+'.dll');Path=$path;Identity=$identity;Bytes=$imageBytes;
            Length=$imageBytes.Length;Sha256=(Get-PspktSignatureReferenceBytesDigest -Bytes $imageBytes);Assembly=$assembly;SourceCount=$Texts.Count;
            SourceSetSha256=(Get-PspktSignatureReferenceSourceSetHash $Names $Texts);
            ReferenceSetSha256=(Get-PspktSignatureReferenceReferenceSetHash $references);Initialized=$false}
        Assert-PspktSignatureReferenceAssemblyCustody -Context $Context -Image $image -Dependencies $Dependencies
        $Context.Images.Add($image)
        return $image
    }
    catch {
        $literal=$_.Exception.Message
        if($literal -cin @('validation:compilation','validation:reference','validation:assembly-custody','validation:public-surface','validation:cleanup')) {
            throw $literal
        }
        throw 'validation:compilation'
    }
}

function Get-PspktSignatureReferenceMutantSource {
    param([string]$Role,[string[]]$Texts,[string[]]$Names)
    $file='EvidenceSignatureVerifier.cs'
    $old=$null;$new=$null
    switch -CaseSensitive ($Role) {
        'M1' {
            $old='if(representative >= modulus) { throw EvidenceFailure.Reject("signature:range"); }'
            $new=''
        }
        'M2' {
            $old=@'
                byte[] signature = packets[index].GetField(10);
                BigInteger representative = ReadUnsigned(signature);
                BigInteger modulus = selected[index].PublicKey.Modulus;
                if(representative >= modulus) { throw EvidenceFailure.Reject("signature:range"); }
                BigInteger recovered = BigInteger.ModPow(representative, new BigInteger(65537), modulus);
                byte[] encodedMessage = WriteUnsigned(recovered);
                byte[] covered;
                try { covered = codec.GetDeclaredSignatureCoveredBytes(packets[index].Envelope); }
                catch(InvalidDataException) { throw EvidenceFailure.Reject("envelope:structure"); }
                byte[] digest = EvidenceFailure.Hash(covered);
                byte[] expected = new byte[SignatureBytes];
                expected[1] = 1;
                for(int position = 2; position <= 331; position++) { expected[position] = 255; }
                byte[] prefix = new byte[] { 48,49,48,13,6,9,96,134,72,1,101,3,4,2,1,5,0,4,32 };
                Buffer.BlockCopy(prefix, 0, expected, 333, prefix.Length);
                Buffer.BlockCopy(digest, 0, expected, 352, digest.Length);
                if(!Equal(encodedMessage, expected)) { throw EvidenceFailure.Reject("signature:emsa"); }
'@
            $new=@'
                byte[] signature = packets[index].GetField(10);
                BigInteger representative = ReadUnsigned(signature);
                BigInteger modulus = selected[index].PublicKey.Modulus;
                string selectedFailure = representative >= modulus ? "signature:range" : "signature:emsa";
                byte[] covered;
                try { covered = codec.GetDeclaredSignatureCoveredBytes(packets[index].Envelope); }
                catch(InvalidDataException) { throw EvidenceFailure.Reject("envelope:structure"); }
                byte[] digest = EvidenceFailure.Hash(covered);
                byte[] expected = new byte[SignatureBytes];
                expected[1] = 1;
                for(int position = 2; position <= 331; position++) { expected[position] = 255; }
                byte[] prefix = new byte[] { 48,49,48,13,6,9,96,134,72,1,101,3,4,2,1,5,0,4,32 };
                Buffer.BlockCopy(prefix, 0, expected, 333, prefix.Length);
                Buffer.BlockCopy(digest, 0, expected, 352, digest.Length);
                bool matched = false;
                foreach(EvidenceKeyBinding candidate in snapshot.Bindings)
                {
                    if(candidate.Role != selected[index].Role || snapshot.EvaluationTime < candidate.NotBefore ||
                        snapshot.EvaluationTime >= candidate.NotAfter) { continue; }
                    if(representative >= candidate.PublicKey.Modulus) { continue; }
                    byte[] candidateMessage = WriteUnsigned(BigInteger.ModPow(representative, new BigInteger(65537), candidate.PublicKey.Modulus));
                    if(Equal(candidateMessage, expected)) { matched = true; break; }
                }
                if(!matched) { throw EvidenceFailure.Reject(selectedFailure); }
'@
        }
        'M3' {
            $old=@'
                if(!string.Equals(selected[index].Role, requiredRole, StringComparison.Ordinal))
                {
                    throw EvidenceFailure.Reject("key:role");
                }
'@
            $new=''
        }
        'M4' {
            $file='EvidenceReferenceResolver.cs'
            $old='if(source.Kind != 20 && source.Kind != 21) { continue; }'
            $new='if(source.Kind != 21) { continue; }'
        }
        'M5' {
            $file='EvidenceClaimSet.cs'
            $old='Array.Exists(artifacts,'
            $new='Array.TrueForAll(artifacts,'
        }
        default { throw 'validation:mutant-transform' }
    }
    $old=$old.Replace("`r`n","`n")
    $new=$new.Replace("`r`n","`n")
    $path='certification\evidence-signature-reference\lib\'+$file
    $index=[Array]::IndexOf($Names,$path)
    if($index -lt 0 -or $Texts.Length -ne 17 -or $Names.Length -ne 17 -or
        [regex]::Matches($Texts[$index],[regex]::Escape($old)).Count -ne 1) { throw 'validation:mutant-transform' }
    $mutated=[string[]]$Texts.Clone()
    $mutated[$index]=$mutated[$index].Replace($old,$new)
    $encoding=[Text.UTF8Encoding]::new($false,$true)
    return [pscustomobject]@{Texts=$mutated;Names=[string[]]$Names.Clone();
        OriginalSourceSetSha256=(Get-PspktSignatureReferenceSourceSetHash $Names $Texts);
        MutatedSourceSetSha256=(Get-PspktSignatureReferenceSourceSetHash $Names $mutated);
        TransformationSha256=(Get-PspktSignatureReferenceBytesDigest -Bytes $encoding.GetBytes($path+[char]0+$old+[char]0+$new))}
}

function Close-PspktSignatureReferenceCompilerContext {
    param([object]$Context)
    $complete=$true
    foreach($reference in @($Context.References)+@($Context.Compilers)) {
        try { $reference.Handle.Dispose() } catch { $complete=$false }
    }
    if(-not $complete) { throw 'validation:cleanup' }
}
