param(
    [Reflection.Assembly]$BootstrapAssembly,
    [Reflection.Assembly]$StructuralAssembly,
    [Reflection.Assembly]$CheckerAssembly,
    [hashtable]$AuthorityBytesById,
    [hashtable]$FixtureBytesById,
    [object]$ManifestRecordsByRole,
    [object[]]$CompileCensus,
    [object[]]$MutantBuilds,
    [string]$ArtifactRoot,
    [string]$CallerScopeMarker
)

BeforeAll {
    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'
    if($null -ne $ExecutionContext.SessionState.Module -or -not $ManifestRecordsByRole.ContainsKey('ExpectedData')) {
        throw 'validation:pester-container'
    }
    $referenceMatches=@()
    foreach($name in @('BootstrapAssembly','StructuralAssembly','CheckerAssembly','AuthorityBytesById','FixtureBytesById',
        'ManifestRecordsByRole','CompileCensus','MutantBuilds','ArtifactRoot','CallerScopeMarker')) {
        $referenceMatches+=[object]::ReferenceEquals((Get-Variable -Name $name -ValueOnly),$ManifestRecordsByRole.ExpectedData[$name])
    }
    if(@($referenceMatches | Where-Object {-not $_}).Count -ne 0 -or
        $CallerScopeMarker -cnotmatch '\Apspkt-evidence-signature-reference-validation:[0-9a-f]{32}\z') { throw 'validation:pester-container' }
    $ManifestRecordsByRole.BeforeAllCallerScopePassed=$true
    $ManifestRecordsByRole.ContainerObservation.ReferenceMatches=$referenceMatches
    function Get-TestSourceText {
        param([string]$Path)
        $name=$Path
        $prefix=$ManifestRecordsByRole.RepositoryRoot.TrimEnd([char]92)+'\'
        if($name.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)) { $name=$name.Substring($prefix.Length) }
        if(-not $ManifestRecordsByRole.RetainedTexts.ContainsKey($name)) { throw 'validation:source-membership' }
        return [string]$ManifestRecordsByRole.RetainedTexts[$name]
    }
    function Test-TestRetainedSource {
        param([string]$Path)
        $name=$Path
        $prefix=$ManifestRecordsByRole.RepositoryRoot.TrimEnd([char]92)+'\'
        if($name.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)) { $name=$name.Substring($prefix.Length) }
        return $ManifestRecordsByRole.RetainedTexts.ContainsKey($name)
    }
    . ([scriptblock]::Create((Get-TestSourceText 'certification\evidence-signature-reference\lib\Pspkt.Certification.EvidenceSignatureReferenceContract.ps1')))
    . ([scriptblock]::Create((Get-TestSourceText 'certification\evidence-signature-reference\tests\EvidenceSignatureReferenceOracle.ps1')))
    $authorityOrder = @('Meta','ProtocolInventory','EvidenceSchema','EvidenceInventory','ProtocolSchema',
        'TrustedControl','TrustRootsSchema','SnapshotSchema','Policy')
    function Get-TestTopLevelTypeNames {
        param([string]$Source)
        $pattern='(?s)(?<Comment>//[^\r\n]*|/\*.*?\*/)|(?<Literal>@"(?:[^"]|"")*"|"(?:\\.|[^"\\])*"|''(?:\\.|[^''\\])*'')|(?<Identifier>[A-Za-z_][A-Za-z0-9_]*)|(?<Punctuation>[^\s])'
        $tokens=@([regex]::Matches($Source,$pattern) | Where-Object {
            -not $_.Groups['Comment'].Success -and -not $_.Groups['Literal'].Success
        } | ForEach-Object {$_.Value})
        $depth=0
        $names=[Collections.Generic.List[string]]::new()
        for($index=0;$index -lt $tokens.Count;$index++) {
            if($tokens[$index] -ceq '{') { $depth++ }
            elseif($tokens[$index] -ceq '}') { $depth-- }
            elseif($depth -eq 1 -and $tokens[$index] -cin @('class','struct','enum','interface')) {
                $names.Add($tokens[$index+1])
            }
        }
        return ,$names.ToArray()
    }
    function Assert-TestHashCatchScopes {
        param([hashtable]$Sources)
        $required=@('EvidenceSetChecker.cs','EvidenceKeyBindingSnapshot.cs','EvidenceSetAssessment.cs','EvidenceArtifactVerification.cs',
            'EvidenceReferenceResolution.cs','EvidenceAuthoritySnapshot.cs','EvidenceCanonicalJsonReader.cs','EvidenceJsonValue.cs',
            'EvidenceKeyBindingReader.cs','EvidenceKeyBinding.cs','CanonicalRsaPublicKey.cs','EvidenceSignatureVerifier.cs',
            'EvidenceReferenceResolver.cs','EvidenceResolvedReference.cs','EvidencePayloadProjection.cs','EvidenceClaimSet.cs','EvidenceFailure.cs')
        if($Sources.Count -ne 17) { throw 'validation:source-policy' }
        $pattern='(?s)(?<Comment>//[^\r\n]*|/\*.*?\*/)|(?<Literal>@"(?:[^"]|"")*"|"(?:\\.|[^"\\])*"|''(?:\\.|[^''\\])*'')|(?<Identifier>[A-Za-z_][A-Za-z0-9_]*)|(?<Number>[0-9]+)|(?<Punctuation>[^\s])'
        $lexer=[Text.RegularExpressions.Regex]::new($pattern,[Text.RegularExpressions.RegexOptions]::None,[TimeSpan]::FromSeconds(2))
        $constructionCount=0
        foreach($name in $required) {
            if(-not $Sources.ContainsKey($name) -or $Sources[$name] -isnot [string] -or $Sources[$name].Length -gt 1048576) {
                throw 'validation:source-policy'
            }
            $tokens=[Collections.Generic.List[string]]::new()
            foreach($match in $lexer.Matches($Sources[$name])) {
                if($match.Groups['Comment'].Success) { continue }
                if($match.Groups['Literal'].Success -and $match.Value.Contains('InvalidOperationException')) { throw 'validation:source-policy' }
                $tokens.Add($match.Value)
            }
            $pairs=@{}
            $stack=[Collections.Generic.Stack[int]]::new()
            for($index=0;$index -lt $tokens.Count;$index++) {
                if($tokens[$index] -ceq '{' -or $tokens[$index] -ceq '(') { $stack.Push($index) }
                elseif($tokens[$index] -ceq '}' -or $tokens[$index] -ceq ')') {
                    if($stack.Count -eq 0) { throw 'validation:source-policy' }
                    $opening=$stack.Pop()
                    if(($tokens[$index] -ceq '}' -and $tokens[$opening] -cne '{') -or
                        ($tokens[$index] -ceq ')' -and $tokens[$opening] -cne '(')) { throw 'validation:source-policy' }
                    $pairs[$opening]=$index
                }
            }
            if($stack.Count -ne 0) { throw 'validation:source-policy' }
            $admittedExceptions=[Collections.Generic.HashSet[int]]::new()
            $admittedCalls=[Collections.Generic.HashSet[int]]::new()
            for($index=0;$index -lt $tokens.Count;$index++) {
                if($tokens[$index] -cne 'try') { continue }
                $body=$index+1
                if($tokens[$body] -cne '{' -or -not $pairs.ContainsKey($body)) { throw 'validation:source-policy' }
                $cursor=$pairs[$body]+1
                while($cursor -lt $tokens.Count -and $tokens[$cursor] -ceq 'catch') {
                    if($tokens[$cursor+1] -cne '(') { break }
                    $parametersEnd=$pairs[$cursor+1]
                    $catchBody=$parametersEnd+1
                    if($tokens[$catchBody] -cne '{' -or -not $pairs.ContainsKey($catchBody)) { throw 'validation:source-policy' }
                    for($parameter=$cursor+2;$parameter -lt $parametersEnd;$parameter++) {
                        if($tokens[$parameter] -cne 'InvalidOperationException') { continue }
                        $bodyText=@($tokens[($body+1)..($pairs[$body]-1)]) -join ' '
                        $catchText=@($tokens[($catchBody+1)..($pairs[$catchBody]-1)]) -join ' '
                        if($bodyText -cne 'return SHA256 . Create ( ) ;' -or
                            $catchText -cne 'throw Reject ( "runtime:crypto-unavailable" ) ;' -or
                            $parametersEnd-$cursor -ne 3) { throw 'validation:source-policy' }
                        [void]$admittedExceptions.Add($parameter)
                        [void]$admittedCalls.Add($body+2)
                        $constructionCount++
                    }
                    $cursor=$pairs[$catchBody]+1
                }
            }
            for($index=0;$index -lt $tokens.Count;$index++) {
                if($tokens[$index] -ceq 'InvalidOperationException' -and -not $admittedExceptions.Contains($index)) {
                    throw 'validation:source-policy'
                }
                if($index+3 -lt $tokens.Count -and $tokens[$index] -ceq 'SHA256' -and $tokens[$index+1] -ceq '.' -and
                    $tokens[$index+2] -ceq 'Create' -and $tokens[$index+3] -ceq '(' -and -not $admittedCalls.Contains($index)) {
                    throw 'validation:source-policy'
                }
            }
        }
        if($constructionCount -ne 1) { throw 'validation:source-policy' }
    }
    function New-AuthorityArguments {
        $arguments = [object[]]::new(9)
        for($index=0;$index -lt 9;$index++) {
            $arguments[$index] = [byte[]]$AuthorityBytesById[$authorityOrder[$index]].Clone()
        }
        return ,$arguments
    }
    function Get-AdmissionFailure {
        param([Reflection.MethodInfo]$Method,[object[]]$Arguments)
        try { [void]$Method.Invoke($null,$Arguments); return 'accepted' }
        catch {
            $failure = $_.Exception
            while($null -ne $failure.InnerException) { $failure = $failure.InnerException }
            return $failure.Message
        }
    }
    function Get-CallFailure {
        param([object]$Target,[string]$Name,[object[]]$Arguments)
        try { [void]$Target.GetType().GetMethod($Name).Invoke($Target,$Arguments); return 'accepted' }
        catch {
            $failure = $_.Exception
            while($null -ne $failure.InnerException) { $failure = $failure.InnerException }
            return $failure.Message
        }
    }
    function Get-TestDigest {
        param([byte[]]$Bytes)
        $algorithm = [Security.Cryptography.SHA256]::Create()
        try { return ,$algorithm.ComputeHash($Bytes) }
        finally { $algorithm.Dispose() }
    }
    function New-TestChecker {
        $type = $CheckerAssembly.GetType('Pspkt.Certification.EvidenceSignatureReference.EvidenceSetChecker',$true)
        return $type.GetMethod('CreateFromCommittedAuthorities').Invoke($null,(New-AuthorityArguments))
    }
    function New-SnapshotArguments {
        param([string]$Text,[uint64]$Time=1500)
        $bytes = [Text.UTF8Encoding]::new($false,$true).GetBytes($Text)
        $arguments = [object[]]::new(5)
        $arguments[0] = $bytes
        $arguments[1] = Get-TestDigest -Bytes $bytes
        $arguments[2] = $Time
        $arguments[3] = [Guid]'11111111-2222-4333-8444-555555555555'
        $arguments[4] = [byte[]](@(17) * 32)
        return ,$arguments
    }
    $emptySnapshot = '{"schemaId":"PspktEvidenceKeyBindingSnapshotV1","schemaVersion":1,"ledgerIdentity":"11111111-2222-4333-8444-555555555555","keys":[],"maximumSkewHundredNanoseconds":0}'
    function New-TestKeyRow {
        param([int]$Number=1)
        $blob = [byte[]]::new(512)
        $header = [byte[]]@(82,83,65,49,0,12,0,0,4,0,0,0,128,1,0,0,0,0,0,0,0,0,0,0)
        [Array]::Copy($header,0,$blob,0,24)
        $blob[25]=1
        $blob[27]=1
        $blob[28]=128
        $blob[410]=[byte][Math]::Floor($Number/256)
        $blob[411]=[byte]($Number%256)
        return [ordered]@{
            keyId=[BitConverter]::ToString((Get-TestDigest $blob)).Replace('-','').ToLowerInvariant()
            publicBlob=[BitConverter]::ToString($blob).Replace('-','').ToLowerInvariant()
            algorithm='RSA3072PKCS1SHA256'
            role='HostEvidence'
            notBefore=[uint64]1000
            notAfter=[uint64]2000
            hostInventoryPolicyDigest=('11'*32)
        }
    }
    function New-TestSnapshotText {
        param([object[]]$Rows)
        $document = [ordered]@{schemaId='PspktEvidenceKeyBindingSnapshotV1';schemaVersion=1;
            ledgerIdentity='11111111-2222-4333-8444-555555555555';keys=@($Rows);maximumSkewHundredNanoseconds=[uint64]0}
        return (ConvertTo-Json -InputObject $document -Depth 8 -Compress)
    }
    function ConvertFrom-TestHex {
        param([string]$Text)
        $bytes = [byte[]]::new($Text.Length/2)
        for($index=0;$index -lt $bytes.Length;$index++) { $bytes[$index]=[Convert]::ToByte($Text.Substring($index*2,2),16) }
        return ,$bytes
    }
    function New-FixtureBinding {
        param([object]$Checker,[string]$Id='eligible-three',[uint64]$Time=1500)
        $text = [Text.UTF8Encoding]::new($false,$true).GetString($FixtureBytesById[$Id])
        return $Checker.GetType().GetMethod('AdmitKeyBindings').Invoke($Checker,(New-SnapshotArguments $text $Time))
    }
    function New-FixtureSet {
        param([string[]]$Ids)
        $envelopes = [byte[][]]::new($Ids.Length)
        for($index=0;$index -lt $Ids.Length;$index++) { $envelopes[$index]=[byte[]]$FixtureBytesById[$Ids[$index]].Clone() }
        return ,$envelopes
    }
    function Invoke-TestCheckSet {
        param([object]$Checker,[object]$Binding,[byte[][]]$Envelopes)
        $arguments = [object[]]::new(2)
        $arguments[0] = $Envelopes
        $arguments[1] = $Binding
        return $Checker.GetType().GetMethod('CheckSet').Invoke($Checker,$arguments)
    }
}

Describe 'Evidence signature reference conformance' -Tag 'Precheck' {
    It 'authority-pins' {
        $CheckerAssembly | Should -Not -BeNullOrEmpty -Because 'the authority admission factory must exist before any input can be admitted'
        $checkerType = $CheckerAssembly.GetType('Pspkt.Certification.EvidenceSignatureReference.EvidenceSetChecker',$true)
        $factory = $checkerType.GetMethod('CreateFromCommittedAuthorities')
        $factory.Invoke($null,(New-AuthorityArguments)) | Should -Not -BeNullOrEmpty
        for($position=0;$position -lt 9;$position++) {
            $arguments = New-AuthorityArguments
            $arguments[$position][0] = $arguments[$position][0] -bxor 1
            Get-AdmissionFailure -Method $factory -Arguments $arguments | Should -BeExactly 'authority:pin'
            $arguments = New-AuthorityArguments
            $arguments[$position] = [byte[]]::new($arguments[$position].Length + 1)
            Get-AdmissionFailure -Method $factory -Arguments $arguments | Should -BeExactly 'authority:length'
        }
        $arguments = New-AuthorityArguments
        $arguments[0] = $null
        Get-AdmissionFailure -Method $factory -Arguments $arguments | Should -BeExactly 'argument:null'
        $arguments = New-AuthorityArguments
        $arguments[0] = [byte[]]::new(0)
        Get-AdmissionFailure -Method $factory -Arguments $arguments | Should -BeExactly 'argument:empty'
        $arguments = New-AuthorityArguments
        $saved = $arguments[0]
        $arguments[0] = $arguments[1]
        $arguments[1] = $saved
        Get-AdmissionFailure -Method $factory -Arguments $arguments | Should -BeExactly 'authority:length'
    }
    It 'authority-routing' {
        $references = @($CheckerAssembly.GetReferencedAssemblies().FullName)
        @($references | Where-Object { $_ -ceq $BootstrapAssembly.FullName }).Count | Should -Be 1
        @($references | Where-Object { $_ -ceq $StructuralAssembly.FullName }).Count | Should -Be 1
        $type = $CheckerAssembly.GetType('Pspkt.Certification.EvidenceSignatureReference.EvidenceSetChecker',$true)
        $checker = $type.GetMethod('CreateFromCommittedAuthorities').Invoke($null,(New-AuthorityArguments))
        $context = $type.GetField('_authorities',[Reflection.BindingFlags]'NonPublic,Instance').GetValue($checker)
        $codec = $context.GetType().GetProperty('Codec',[Reflection.BindingFlags]'NonPublic,Instance').GetValue($context,$null)
        $codec.GetType().Assembly.FullName | Should -BeExactly $StructuralAssembly.FullName
        $sourcePath = Join-Path $ManifestRecordsByRole.RepositoryRoot 'certification\evidence-signature-reference\lib\EvidenceAuthoritySnapshot.cs'
        $source = Get-TestSourceText $sourcePath
        $source | Should -Match 'Evaluate\("schema-against-meta", retained\[4\], retained\[0\]\)'
        $source | Should -Match 'Evaluate\("json", retained\[5\], null\)'
        $source | Should -Match 'Evaluate\("json", retained\[6\], null\)'
        $source | Should -Not -Match 'Evaluate\("schema-against-meta", retained\[[56]\]'
    }
    It 'frozen-dependency-closure' {
        $path = Join-Path $ManifestRecordsByRole.RepositoryRoot 'certification\evidence-signature-reference\lib\Pspkt.Certification.EvidenceSignatureReferenceContract.ps1'
        Test-TestRetainedSource $path | Should -BeTrue -Because 'the independent frozen dependency admission contract must exist'
        $snapshot = $ManifestRecordsByRole.FrozenSnapshot
        $snapshot.Records.Count | Should -Be 74
        Assert-PspktSignatureReferenceFrozenSnapshot -Snapshot $snapshot
        $invalid=[pscustomobject]@{Files=$snapshot.Files;Records=@($snapshot.Records | ForEach-Object {$_.PSObject.Copy()})}
        $invalid.Records[0].Sha256 = '0' * 64
        { Assert-PspktSignatureReferenceFrozenSnapshot -Snapshot $invalid } | Should -Throw -ExpectedMessage 'validation:source-pin'
    }
    It 'public-surface' {
        $expectedTypes = @('EvidenceSetChecker','EvidenceKeyBindingSnapshot','EvidenceSetAssessment',
            'EvidenceArtifactVerification','EvidenceReferenceResolution')
        $types = @($CheckerAssembly.GetExportedTypes())
        $types.Count | Should -Be 5
        foreach($name in $expectedTypes) {
            $type = $CheckerAssembly.GetType('Pspkt.Certification.EvidenceSignatureReference.'+$name,$true)
            $type.IsSealed | Should -BeTrue
            $type.GetConstructors().Length | Should -Be 0
            $type.GetFields().Length | Should -Be 0
            foreach($property in $type.GetProperties()) { $property.CanWrite | Should -BeFalse }
        }
        $checker = $CheckerAssembly.GetType('Pspkt.Certification.EvidenceSignatureReference.EvidenceSetChecker',$true)
        $methods = @($checker.GetMethods([Reflection.BindingFlags]'Public,Static,Instance,DeclaredOnly') | Where-Object { -not $_.IsSpecialName })
        ($methods.Name | Sort-Object) -join ',' | Should -BeExactly 'AdmitKeyBindings,CheckSet,CreateFromCommittedAuthorities'
        $checker.GetMethod('CreateFromCommittedAuthorities').GetParameters().Length | Should -Be 9
        $checker.GetMethod('AdmitKeyBindings').GetParameters()[2].ParameterType.FullName | Should -BeExactly 'System.UInt64'
        $checker.GetMethod('CheckSet').GetParameters()[0].ParameterType.FullName | Should -BeExactly 'System.Byte[][]'
        $properties = @{
            EvidenceKeyBindingSnapshot = 'EvaluationTime,HostInventoryPolicyDigest,KeyCount,LedgerIdentity,SnapshotSha256'
            EvidenceSetAssessment = 'Artifacts,KeyBindings,PolicySha256,References,UncheckedSemantics'
            EvidenceArtifactVerification = 'ArtifactId,InputIndex,Kind,PayloadDigest,Profile,UncheckedSemantics,VerifiedClaims,VerifiedKeyId'
            EvidenceReferenceResolution = 'MatchedAssertions,ReferenceDigest,SourceFieldCoveredByVerifiedSignature,SourceFieldId,SourceInputIndex,SourceKind,TargetInputIndex,TargetKind'
        }
        foreach($name in $properties.Keys) {
            $actual = @($CheckerAssembly.GetType('Pspkt.Certification.EvidenceSignatureReference.'+$name,$true).GetProperties().Name | Sort-Object)
            $actual -join ',' | Should -BeExactly $properties[$name]
        }
    }
    It 'snapshot-pin-and-owner' {
        $checker = New-TestChecker
        $arguments = New-SnapshotArguments -Text $emptySnapshot
        $snapshot = $checker.GetType().GetMethod('AdmitKeyBindings').Invoke($checker,$arguments)
        [Convert]::ToBase64String($snapshot.SnapshotSha256) | Should -BeExactly ([Convert]::ToBase64String($arguments[1]))
        $snapshot.EvaluationTime | Should -Be ([uint64]1500)
        $snapshot.LedgerIdentity | Should -Be $arguments[3]
        $arguments = New-SnapshotArguments -Text $emptySnapshot
        $arguments[1] = [byte[]]::new(32)
        Get-CallFailure -Target $checker -Name AdmitKeyBindings -Arguments $arguments | Should -BeExactly 'snapshot:pin'
        $other = New-TestChecker
        $envelopes = [byte[][]]::new(1)
        $envelopes[0] = [byte[]]@(1)
        $checkArguments = [object[]]::new(2)
        $checkArguments[0] = $envelopes
        $checkArguments[1] = $snapshot
        Get-CallFailure -Target $other -Name CheckSet -Arguments $checkArguments | Should -BeExactly 'snapshot:owner-context'
    }
    It 'snapshot-canonical-json' {
        $checker = New-TestChecker
        $cases = @(
            @((' '+$emptySnapshot),'snapshot:json'),
            @(([string][char]65279+$emptySnapshot),'snapshot:json'),
            @(($emptySnapshot+"`r"),'snapshot:json'),
            @($emptySnapshot.Replace('"schemaId"','"\u0073chemaId"'),'snapshot:json'),
            @($emptySnapshot.Replace('"schemaVersion":1,','"schemaVersion":1,"schemaVersion":1,'),'snapshot:properties'),
            @($emptySnapshot.Replace('"schemaVersion":1','"otherVersion":1'),'snapshot:properties'),
            @($emptySnapshot.Replace('"schemaVersion":1,',''),'snapshot:properties'),
            @($emptySnapshot.Replace('"schemaVersion":1','"schemaVersion":"1"'),'snapshot:properties'),
            @($emptySnapshot.Replace('"schemaId":"PspktEvidenceKeyBindingSnapshotV1","schemaVersion":1','"schemaVersion":1,"schemaId":"PspktEvidenceKeyBindingSnapshotV1"'),'snapshot:property-order')
        )
        foreach($case in $cases) {
            Get-CallFailure -Target $checker -Name AdmitKeyBindings -Arguments (New-SnapshotArguments -Text $case[0]) |
                Should -BeExactly $case[1]
        }
        $reader = $CheckerAssembly.GetType('Pspkt.Certification.EvidenceSignatureReference.EvidenceCanonicalJsonReader',$true)
        $read = $reader.GetMethod('Read',[Reflection.BindingFlags]'NonPublic,Static')
        $arguments = [object[]]::new(2)
        $arguments[0] = $AuthorityBytesById.SnapshotSchema
        $arguments[1] = 9
        $read.Invoke($null,$arguments) | Should -Not -BeNullOrEmpty
        $arguments[1] = 8
        Get-AdmissionFailure -Method $read -Arguments $arguments | Should -BeExactly 'snapshot:json-bound'
    }
    It 'snapshot-row-shape' {
        $checker = New-TestChecker
        $row = New-TestKeyRow
        $row.role = 'Other'
        Get-CallFailure -Target $checker -Name AdmitKeyBindings -Arguments (New-SnapshotArguments (New-TestSnapshotText @($row))) |
            Should -BeExactly 'snapshot:role'
        $row = New-TestKeyRow
        $row.Remove('role')
        Get-CallFailure -Target $checker -Name AdmitKeyBindings -Arguments (New-SnapshotArguments (New-TestSnapshotText @($row))) |
            Should -BeExactly 'snapshot:properties'
        $row = New-TestKeyRow
        $row['extension'] = 1
        Get-CallFailure -Target $checker -Name AdmitKeyBindings -Arguments (New-SnapshotArguments (New-TestSnapshotText @($row))) |
            Should -BeExactly 'snapshot:properties'
        $row = New-TestKeyRow
        $row.role = 1
        Get-CallFailure -Target $checker -Name AdmitKeyBindings -Arguments (New-SnapshotArguments (New-TestSnapshotText @($row))) |
            Should -BeExactly 'snapshot:properties'
        $row = New-TestKeyRow
        Get-CallFailure -Target $checker -Name AdmitKeyBindings -Arguments (New-SnapshotArguments (New-TestSnapshotText @($row))) |
            Should -BeExactly 'accepted'
    }
    It 'snapshot-count-and-size' {
        $checker = New-TestChecker
        $rows = @()
        for($index=1;$index -le 129;$index++) { $rows += New-TestKeyRow -Number $index }
        Get-CallFailure -Target $checker -Name AdmitKeyBindings -Arguments (New-SnapshotArguments (New-TestSnapshotText $rows)) |
            Should -BeExactly 'resource:key-count'
        Get-CallFailure -Target $checker -Name AdmitKeyBindings -Arguments (New-SnapshotArguments ('x'*1048577)) |
            Should -BeExactly 'resource:snapshot-bytes'
        $arguments = New-SnapshotArguments (New-TestSnapshotText @($rows[0..127]))
        $snapshot = $checker.GetType().GetMethod('AdmitKeyBindings').Invoke($checker,$arguments)
        $snapshot.KeyCount | Should -Be 128
        $source = Get-TestSourceText 'certification\evidence-signature-reference\lib\EvidenceKeyBindingReader.cs'
        $source.IndexOf('bytes.Length > MaximumSnapshotBytes') | Should -BeGreaterOrEqual 0
        $source.IndexOf('bytes.Length > MaximumSnapshotBytes') | Should -BeLessThan $source.IndexOf('(byte[])bytes.Clone()')
    }
    It 'snapshot-context-and-skew' {
        $checker = New-TestChecker
        $text = New-TestSnapshotText @((New-TestKeyRow))
        Get-CallFailure -Target $checker -Name AdmitKeyBindings -Arguments (New-SnapshotArguments $text.Replace('"maximumSkewHundredNanoseconds":0','"maximumSkewHundredNanoseconds":1')) |
            Should -BeExactly 'snapshot:skew'
        Get-CallFailure -Target $checker -Name AdmitKeyBindings -Arguments (New-SnapshotArguments $text.Replace('11111111-2222-4333-8444-555555555555','aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee')) |
            Should -BeExactly 'snapshot:ledger-context'
        $rows = @((New-TestKeyRow 1),(New-TestKeyRow 2))
        $rows[1].hostInventoryPolicyDigest = '00'*32
        Get-CallFailure -Target $checker -Name AdmitKeyBindings -Arguments (New-SnapshotArguments (New-TestSnapshotText $rows)) |
            Should -BeExactly 'snapshot:host-policy'
        Get-CallFailure -Target $checker -Name AdmitKeyBindings -Arguments (New-SnapshotArguments $text) |
            Should -BeExactly 'accepted'
    }
    It 'snapshot-rsa-envelope' {
        $checker = New-TestChecker
        foreach($mutation in @(@(511,1),@(0,0),@(5,8),@(8,3),@(27,3),@(12,127),@(16,1),@(28,0))) {
            $row = New-TestKeyRow
            $bytes = ConvertFrom-TestHex $row.publicBlob
            $bytes[[int]$mutation[0]] = [byte]$mutation[1]
            $row.publicBlob = [BitConverter]::ToString($bytes).Replace('-','').ToLowerInvariant()
            $row.keyId = [BitConverter]::ToString((Get-TestDigest $bytes)).Replace('-','').ToLowerInvariant()
            Get-CallFailure -Target $checker -Name AdmitKeyBindings -Arguments (New-SnapshotArguments (New-TestSnapshotText @($row))) |
                Should -BeExactly 'snapshot:rsa-format'
        }
        Get-CallFailure -Target $checker -Name AdmitKeyBindings -Arguments (New-SnapshotArguments (New-TestSnapshotText @((New-TestKeyRow)))) |
            Should -BeExactly 'accepted'
    }
    It 'snapshot-key-id' {
        $checker = New-TestChecker
        $row = New-TestKeyRow
        $blob = ConvertFrom-TestHex $row.publicBlob
        $row.keyId = [BitConverter]::ToString((Get-TestDigest ([byte[]]$blob[28..411]))).Replace('-','').ToLowerInvariant()
        Get-CallFailure -Target $checker -Name AdmitKeyBindings -Arguments (New-SnapshotArguments (New-TestSnapshotText @($row))) |
            Should -BeExactly 'snapshot:key-id'
        $row = New-TestKeyRow
        Get-CallFailure -Target $checker -Name AdmitKeyBindings -Arguments (New-SnapshotArguments (New-TestSnapshotText @($row,$row))) |
            Should -BeExactly 'snapshot:duplicate-key'
        Get-CallFailure -Target $checker -Name AdmitKeyBindings -Arguments (New-SnapshotArguments (New-TestSnapshotText @($row))) |
            Should -BeExactly 'accepted'
    }
    It 'snapshot-all-rows' {
        $checker = New-TestChecker
        $rows = @((New-TestKeyRow 1),(New-TestKeyRow 2),(New-TestKeyRow 3))
        $rows[1].notAfter = $rows[1].notBefore
        Get-CallFailure -Target $checker -Name AdmitKeyBindings -Arguments (New-SnapshotArguments (New-TestSnapshotText $rows)) |
            Should -BeExactly 'snapshot:interval'
        $rows[1].notBefore = [uint64]1
        $rows[1].notAfter = [uint64]2
        $rows[2].notBefore = [uint64]3000
        $rows[2].notAfter = [uint64]4000
        $arguments = New-SnapshotArguments (New-TestSnapshotText $rows)
        $snapshot = $checker.GetType().GetMethod('AdmitKeyBindings').Invoke($checker,$arguments)
        $snapshot.KeyCount | Should -Be 3
        $snapshot.EvaluationTime | Should -Be ([uint64]1500)
    }
    It 'snapshot-uint64' {
        $checker = New-TestChecker
        $row = New-TestKeyRow
        $text = New-TestSnapshotText @($row)
        Get-CallFailure -Target $checker -Name AdmitKeyBindings -Arguments (New-SnapshotArguments $text.Replace('"notBefore":1000','"notBefore":18446744073709551616')) |
            Should -BeExactly 'snapshot:integer'
        foreach($number in @('01000','-1','+1','1.5','1e3')) {
            Get-CallFailure -Target $checker -Name AdmitKeyBindings -Arguments (New-SnapshotArguments $text.Replace('"notBefore":1000',('"notBefore":'+$number))) |
                Should -BeExactly 'snapshot:integer'
        }
        $row.notBefore = [uint64]::Parse('9223372036854775807')
        $row.notAfter = [uint64]::Parse('9223372036854775809')
        $arguments = New-SnapshotArguments (New-TestSnapshotText @($row)) ([uint64]::Parse('9223372036854775808'))
        $snapshot = $checker.GetType().GetMethod('AdmitKeyBindings').Invoke($checker,$arguments)
        $snapshot.EvaluationTime | Should -Be ([uint64]::Parse('9223372036854775808'))
        $row.notBefore = [uint64]::Parse('18446744073709551614')
        $row.notAfter = [uint64]::MaxValue
        $arguments = New-SnapshotArguments (New-TestSnapshotText @($row)) ([uint64]::MaxValue)
        $snapshot = $checker.GetType().GetMethod('AdmitKeyBindings').Invoke($checker,$arguments)
        $snapshot.EvaluationTime | Should -Be ([uint64]::MaxValue)
    }
    It 'signature-kind-profile' {
        $checker = New-TestChecker
        $binding = New-FixtureBinding $checker
        $snapshotDocument = [Text.Encoding]::UTF8.GetString($FixtureBytesById['eligible-three']) | ConvertFrom-Json
        foreach($kind in @(16,17,20)) {
            foreach($profile in @(1,2)) {
                $ids = @('positive-k'+$kind+'-p'+$profile)
                if($kind -eq 20) { $ids += 'positive-k18-p1' }
                $set = New-FixtureSet $ids
                $assessment = Invoke-TestCheckSet $checker $binding $set
                $assessment.Artifacts[0].Kind | Should -Be $kind
                $assessment.Artifacts[0].Profile | Should -Be $profile
                $assessment.Artifacts[0].VerifiedClaims | Should -Contain 'signature-verified'
                $key = if($kind -eq 20) { $snapshotDocument.keys[2] } else { $snapshotDocument.keys[0] }
                Get-PspktSignatureReferenceOracleSignatureReason -Envelope $set[0] -PublicBlob (ConvertFrom-TestHex $key.publicBlob) |
                    Should -BeExactly 'ok'
                $lastSignatureByte=690
                if($kind -eq 20) { $lastSignatureByte=682 }
                $set[0][$lastSignatureByte]=$set[0][$lastSignatureByte]-bxor 1
                $set[0]=Set-PspktSignatureReferenceOracleDigest $set[0]
                Get-PspktSignatureReferenceOracleSignatureReason -Envelope $set[0] -PublicBlob (ConvertFrom-TestHex $key.publicBlob) |
                    Should -BeExactly 'signature:emsa'
                $arguments=[object[]]::new(2);$arguments[0]=$set;$arguments[1]=$binding
                $negativeId='neg-positive-signature-flip'
                if($kind -ne 16 -or $profile -ne 1) { $negativeId='neg-positive-signature-flip-k'+$kind+'-p'+$profile }
                Get-CallFailure $checker CheckSet $arguments | Should -BeExactly 'signature:emsa' -Because $negativeId
            }
        }
        $FixtureBytesById['positive-k16-p1'][307] | Should -BeGreaterOrEqual 128
        $FixtureBytesById['positive-k16-p2'][307] | Should -BeGreaterOrEqual 128
        $changed = [byte[]]$FixtureBytesById['positive-k16-p1'].Clone()
        $changed[690] = $changed[690] -bxor 1
        $set = [byte[][]]::new(1)
        $set[0] = Set-PspktSignatureReferenceOracleDigest $changed
        $arguments = [object[]]::new(2)
        $arguments[0] = $set
        $arguments[1] = $binding
        Get-CallFailure -Target $checker -Name CheckSet -Arguments $arguments | Should -BeExactly 'signature:emsa'
    }
    It 'signature-preimages' {
        $path = Join-Path $ManifestRecordsByRole.RepositoryRoot 'certification\evidence-signature-reference\vectors\hand-authored\signature-preimages.v1.json'
        Test-TestRetainedSource $path | Should -BeTrue -Because 'signature verification needs retained independently authored preimage goldens'
        $goldens = Get-TestSourceText $path | ConvertFrom-Json
        $goldens.items.Count | Should -Be 7
        foreach($golden in $goldens.items) {
            $actual = Get-PspktSignatureReferenceOracleCoveredBytes $FixtureBytesById[$golden.id]
            $actual.Length | Should -Be $golden.length
            [BitConverter]::ToString($actual).Replace('-','').ToLowerInvariant() | Should -BeExactly $golden.hex
            [BitConverter]::ToString((Get-TestDigest $actual)).Replace('-','').ToLowerInvariant() | Should -BeExactly $golden.sha256
        }
        $checker = New-TestChecker
        $binding = New-FixtureBinding $checker
        $changed = [byte[]]$FixtureBytesById['positive-k16-p1'].Clone()
        $changed[7] = 17
        $set = [byte[][]]::new(1)
        $set[0] = Set-PspktSignatureReferenceOracleDigest $changed
        $arguments = [object[]]::new(2);$arguments[0]=$set;$arguments[1]=$binding
        Get-CallFailure -Target $checker -Name CheckSet -Arguments $arguments | Should -BeExactly 'signature:emsa'
    }
    It 'signature-payload-digest' {
        Get-Command Get-PspktSignatureReferenceOraclePayloadDigest -ErrorAction SilentlyContinue |
            Should -Not -BeNullOrEmpty -Because 'Hk must be independently calculated separately from the signature preimage'
        $checker = New-TestChecker
        $binding = New-FixtureBinding $checker
        $bytes = [byte[]]$FixtureBytesById['positive-k16-p1'].Clone()
        $originalCovered = Get-PspktSignatureReferenceOracleCoveredBytes $bytes
        $originalDigest = Get-PspktSignatureReferenceOraclePayloadDigest $bytes
        [Convert]::ToBase64String($originalDigest) | Should -BeExactly ([Convert]::ToBase64String([byte[]]$bytes[697..728]))
        $bytes[690] = $bytes[690] -bxor 1
        [Convert]::ToBase64String((Get-PspktSignatureReferenceOracleCoveredBytes $bytes)) |
            Should -BeExactly ([Convert]::ToBase64String($originalCovered))
        [Convert]::ToBase64String((Get-PspktSignatureReferenceOraclePayloadDigest $bytes)) |
            Should -Not -BeExactly ([Convert]::ToBase64String($originalDigest))
        $set = [byte[][]]::new(1);$set[0]=$bytes
        $arguments = [object[]]::new(2);$arguments[0]=$set;$arguments[1]=$binding
        Get-CallFailure -Target $checker -Name CheckSet -Arguments $arguments | Should -BeExactly 'envelope:structure'
        $set[0] = Set-PspktSignatureReferenceOracleDigest $bytes
        Get-CallFailure -Target $checker -Name CheckSet -Arguments $arguments | Should -BeExactly 'signature:emsa'
        $bytes = [byte[]]$FixtureBytesById['positive-k16-p1'].Clone()
        $bytes[217] = $bytes[217] -bxor 1
        $set[0] = Set-PspktSignatureReferenceOracleDigest $bytes
        Get-CallFailure -Target $checker -Name CheckSet -Arguments $arguments | Should -BeExactly 'signature:emsa'
    }
    It 'signature-key-selection' {
        $checker = New-TestChecker
        $binding = New-FixtureBinding $checker
        $assessment = Invoke-TestCheckSet $checker $binding (New-FixtureSet @('positive-k16-p1'))
        $assessment.Artifacts[0].VerifiedClaims | Should -Contain 'signature-key-binding-checked'
        $snapshotText = [Text.Encoding]::ASCII.GetString($FixtureBytesById['eligible-three'])
        $rows = ($snapshotText | ConvertFrom-Json).keys
        $publicA = ConvertFrom-TestHex $rows[0].publicBlob
        $publicB = ConvertFrom-TestHex $rows[1].publicBlob
        Get-PspktSignatureReferenceOracleSignatureReason $FixtureBytesById['wrong-key-signed-by-b'] $publicA | Should -BeExactly 'signature:emsa'
        Get-PspktSignatureReferenceOracleSignatureReason $FixtureBytesById['wrong-key-signed-by-b'] $publicB | Should -BeExactly 'ok'
        $arguments = [object[]]::new(2)
        $arguments[0] = New-FixtureSet @('wrong-key-signed-by-b')
        $arguments[1] = $binding
        Get-CallFailure $checker CheckSet $arguments | Should -BeExactly 'signature:emsa'
        $arguments[1] = $checker.GetType().GetMethod('AdmitKeyBindings').Invoke($checker,(New-SnapshotArguments (New-TestSnapshotText @($rows[1],$rows[0]))))
        Get-CallFailure $checker CheckSet $arguments | Should -BeExactly 'signature:emsa'
        $arguments[0] = New-FixtureSet @('positive-k16-p1')
        $positive = $checker.GetType().GetMethod('CheckSet').Invoke($checker,$arguments)
        [BitConverter]::ToString($positive.Artifacts[0].VerifiedKeyId).Replace('-','').ToLowerInvariant() | Should -BeExactly $rows[0].keyId
        $changed = [byte[]]$FixtureBytesById['positive-k16-p1'].Clone()
        [Array]::Clear($changed,269,32)
        $arguments[0][0] = Set-PspktSignatureReferenceOracleDigest $changed
        Get-CallFailure $checker CheckSet $arguments | Should -BeExactly 'key:missing'
    }
    It 'signature-role' {
        $checker = New-TestChecker
        $arguments = [object[]]::new(2)
        $arguments[0] = New-FixtureSet @('positive-k16-p1')
        $arguments[1] = New-FixtureBinding $checker 'wrong-role-a'
        Get-CallFailure $checker CheckSet $arguments | Should -BeExactly 'key:role'
        $rows = ([Text.Encoding]::ASCII.GetString($FixtureBytesById['eligible-three']) | ConvertFrom-Json).keys
        $rows[2].role = 'HostEvidence'
        $arguments[0] = New-FixtureSet @('positive-k20-p1','positive-k18-p1')
        $arguments[1] = $checker.GetType().GetMethod('AdmitKeyBindings').Invoke($checker,(New-SnapshotArguments (New-TestSnapshotText $rows)))
        Get-CallFailure $checker CheckSet $arguments | Should -BeExactly 'key:role'
        $arguments[0] = New-FixtureSet @('wrong-key-signed-by-b','positive-k20-p1','positive-k18-p1')
        Get-CallFailure $checker CheckSet $arguments | Should -BeExactly 'key:role'
        $control = Invoke-TestCheckSet $checker (New-FixtureBinding $checker) (New-FixtureSet @('positive-k16-p1','positive-k20-p1','positive-k18-p1'))
        $control.Artifacts.Count | Should -Be 3
        $control.Artifacts[0].VerifiedKeyId.Length | Should -Be 32
        $control.Artifacts[1].VerifiedKeyId.Length | Should -Be 32
        $control.Artifacts[2].VerifiedKeyId.Length | Should -Be 0
    }
    It 'signature-evaluation-time' {
        $checker = New-TestChecker
        $arguments = [object[]]::new(2)
        $arguments[0] = New-FixtureSet @('positive-k16-p1')
        $arguments[1] = New-FixtureBinding $checker 'eligible-three' 2000
        Get-CallFailure $checker CheckSet $arguments | Should -BeExactly 'key:time'
        foreach($kind in @(16,17,20)) {
            $ids = @('positive-k'+$kind+'-p1')
            if($kind -eq 20) { $ids += 'positive-k18-p1' }
            $arguments[0] = New-FixtureSet $ids
            foreach($time in @([uint64]999,[uint64]2000)) {
                $arguments[1] = New-FixtureBinding $checker 'eligible-three' $time
                Get-CallFailure $checker CheckSet $arguments | Should -BeExactly 'key:time'
            }
            foreach($time in @([uint64]1000,[uint64]1999)) {
                $binding = New-FixtureBinding $checker 'eligible-three' $time
                $assessment = Invoke-TestCheckSet $checker $binding (New-FixtureSet $ids)
                $assessment.Artifacts[0].VerifiedKeyId.Length | Should -Be 32
                $assessment.KeyBindings.EvaluationTime | Should -Be $time
            }
        }
        $vectors = @(
            @('9223372036854775807','9223372036854775808','9223372036854775809'),
            @('18446744073709551614','18446744073709551614','18446744073709551615'))
        foreach($vector in $vectors) {
            $rows = ([Text.Encoding]::ASCII.GetString($FixtureBytesById['eligible-three']) | ConvertFrom-Json).keys
            $rows[0].notBefore = [uint64]::Parse($vector[0],[Globalization.CultureInfo]::InvariantCulture)
            $time = [uint64]::Parse($vector[1],[Globalization.CultureInfo]::InvariantCulture)
            $rows[0].notAfter = [uint64]::Parse($vector[2],[Globalization.CultureInfo]::InvariantCulture)
            $text = New-TestSnapshotText $rows
            $binding = $checker.GetType().GetMethod('AdmitKeyBindings').Invoke($checker,(New-SnapshotArguments $text $time))
            $assessment = Invoke-TestCheckSet $checker $binding (New-FixtureSet @('positive-k16-p1'))
            $assessment.Artifacts[0].VerifiedClaims | Should -Contain 'signature-key-binding-checked'
            Test-PspktSignatureReferenceOracleEligibility $rows[0].notBefore $time $rows[0].notAfter | Should -BeTrue
            if($vector[0] -ceq '9223372036854775807') {
                Test-PspktSignatureReferenceOracleEligibility $rows[0].notBefore $time $rows[0].notAfter -SignedCast | Should -BeFalse
            }
            $arguments[0] = New-FixtureSet @('positive-k16-p1')
            $arguments[1] = $checker.GetType().GetMethod('AdmitKeyBindings').Invoke($checker,(New-SnapshotArguments $text $rows[0].notAfter))
            Get-CallFailure $checker CheckSet $arguments | Should -BeExactly 'key:time'
        }
        [Convert]::ToBase64String([byte[]]$FixtureBytesById['positive-k16-p1'][255..262]) | Should -BeExactly 'AAAAAAAAAAA='
        [Convert]::ToBase64String([byte[]]$FixtureBytesById['positive-k20-p1'][247..254]) | Should -BeExactly 'AAAAAAAAAAA='
    }
    It 'signature-range-and-endian' {
        $source = Get-TestSourceText 'certification\evidence-signature-reference\lib\EvidenceSignatureVerifier.cs'
        $source.IndexOf('if(representative >= modulus)',[StringComparison]::Ordinal) |
            Should -BeLessThan $source.IndexOf('EvidenceFailure.Hash(covered)',[StringComparison]::Ordinal) -Because 'representative range rejection precedes owned signature hashing'
        $rows = ([Text.Encoding]::ASCII.GetString($FixtureBytesById['eligible-three']) | ConvertFrom-Json).keys
        $blob = ConvertFrom-TestHex $rows[0].publicBlob
        $modulus = Get-PspktSignatureReferenceOracleUnsigned ([byte[]]$blob[28..411])
        $controlSignature = Get-PspktSignatureReferenceOracleUnsigned ([byte[]]$FixtureBytesById['range-control-k16'][307..690])
        $rangeSignature = Get-PspktSignatureReferenceOracleUnsigned ([byte[]]$FixtureBytesById['range-plus-n-k16'][307..690])
        ($rangeSignature-$controlSignature) | Should -Be $modulus
        $reversed = [byte[]]$FixtureBytesById['signature-little-endian-k16'][307..690]
        $reversed[0] | Should -BeGreaterOrEqual 128
        $representative = Get-PspktSignatureReferenceOracleUnsigned $reversed
        $representative | Should -BeLessThan $modulus
        $recovered = [Numerics.BigInteger]::ModPow($representative,[Numerics.BigInteger]65537,$modulus)
        $recovered | Should -BeGreaterOrEqual ([Numerics.BigInteger]::Pow(2,3071))
        $type = $CheckerAssembly.GetType('Pspkt.Certification.EvidenceSignatureReference.EvidenceSignatureVerifier',$true)
        $actual = $type.GetMethod('WriteUnsigned',[Reflection.BindingFlags]'NonPublic,Static').Invoke($null,@($recovered))
        [Convert]::ToBase64String($actual) | Should -BeExactly ([Convert]::ToBase64String((ConvertTo-PspktSignatureReferenceOracleBytes $recovered 384)))
        $readArguments = [object[]]::new(1);$readArguments[0]=$reversed
        $type.GetMethod('ReadUnsigned',[Reflection.BindingFlags]'NonPublic,Static').Invoke($null,$readArguments) | Should -Be $representative
        $checker = New-TestChecker
        $binding = New-FixtureBinding $checker
        (Invoke-TestCheckSet $checker $binding (New-FixtureSet @('range-control-k16'))).Artifacts[0].VerifiedKeyId.Length | Should -Be 32
        foreach($row in @(@('range-plus-n-k16','signature:range'),@('signature-little-endian-k16','signature:emsa'))) {
            $arguments = [object[]]::new(2);$arguments[0]=New-FixtureSet @($row[0]);$arguments[1]=$binding
            Get-CallFailure $checker CheckSet $arguments | Should -BeExactly $row[1]
            Get-PspktSignatureReferenceOracleSignatureReason $FixtureBytesById[$row[0]] $blob | Should -BeExactly $row[1]
            [Convert]::ToBase64String((Get-PspktSignatureReferenceOracleCoveredBytes $FixtureBytesById[$row[0]])) |
                Should -BeExactly ([Convert]::ToBase64String((Get-PspktSignatureReferenceOracleCoveredBytes $FixtureBytesById['range-control-k16'])))
        }
    }
    It 'signature-strict-emsa' {
        $path = Join-Path $ManifestRecordsByRole.RepositoryRoot 'certification\evidence-signature-reference\vectors\hand-authored\emsa-templates.v1.json'
        Test-TestRetainedSource $path | Should -BeTrue -Because 'strict EMSA requires protected independent encoding recipes'
        $templates = Get-TestSourceText $path | ConvertFrom-Json
        $templates.width | Should -Be 384
        $templates.valid.digestInfoPrefixHex | Should -BeExactly '3031300d060960864801650304020105000420'
        $templates.valid.paddingLength | Should -Be 330
        $identifiers = @('emsa-leading-octet','emsa-padding-octet','emsa-early-separator','emsa-missing-separator',
            'emsa-der-oid','emsa-der-null-omitted','emsa-trailing-octet','emsa-wrong-digest','emsa-pss','emsa-sha1')
        ($templates.invalid.id -join '|') | Should -BeExactly ($identifiers -join '|')
        $rows = ([Text.Encoding]::ASCII.GetString($FixtureBytesById['eligible-three']) | ConvertFrom-Json).keys
        $blob = ConvertFrom-TestHex $rows[0].publicBlob
        $modulus = Get-PspktSignatureReferenceOracleUnsigned ([byte[]]$blob[28..411])
        $checker = New-TestChecker
        $binding = New-FixtureBinding $checker
        foreach($id in $identifiers) {
            $arguments = [object[]]::new(2);$arguments[0]=New-FixtureSet @($id);$arguments[1]=$binding
            Get-CallFailure $checker CheckSet $arguments | Should -BeExactly 'signature:emsa'
            Get-PspktSignatureReferenceOracleSignatureReason $FixtureBytesById[$id] $blob | Should -BeExactly 'signature:emsa'
            $representative = Get-PspktSignatureReferenceOracleUnsigned ([byte[]]$FixtureBytesById[$id][307..690])
            $representative | Should -BeLessThan $modulus
            $encoded = ConvertTo-PspktSignatureReferenceOracleBytes ([Numerics.BigInteger]::ModPow($representative,[Numerics.BigInteger]65537,$modulus)) 384
            $digest = Get-PspktSignatureReferenceOracleDigest (Get-PspktSignatureReferenceOracleCoveredBytes $FixtureBytesById[$id])
            if($id -ceq 'emsa-der-null-omitted') {
                [Convert]::ToBase64String([byte[]]$encoded[0..1]) | Should -BeExactly 'AAE='
                @($encoded[2..333] | Where-Object { $_ -ne 255 }).Count | Should -Be 0
                $encoded[334] | Should -Be 0
                [BitConverter]::ToString([byte[]]$encoded[335..351]).Replace('-','').ToLowerInvariant() |
                    Should -BeExactly '302f300b06096086480165030402010420'
                [Convert]::ToBase64String([byte[]]$encoded[352..383]) | Should -BeExactly ([Convert]::ToBase64String($digest))
            }
            elseif($id -ceq 'emsa-sha1') {
                $algorithm = [Security.Cryptography.SHA1]::Create()
                try { $sha1 = $algorithm.ComputeHash((Get-PspktSignatureReferenceOracleCoveredBytes $FixtureBytesById[$id])) }
                finally { $algorithm.Dispose() }
                [BitConverter]::ToString([byte[]]$encoded[349..363]).Replace('-','').ToLowerInvariant() | Should -BeExactly '3021300906052b0e03021a05000414'
                [Convert]::ToBase64String([byte[]]$encoded[364..383]) | Should -BeExactly ([Convert]::ToBase64String($sha1))
            }
            elseif($id -ceq 'emsa-pss') {
                Test-PspktSignatureReferenceOraclePss $encoded $digest | Should -BeTrue
            }
        }
        (Invoke-TestCheckSet $checker $binding (New-FixtureSet @('positive-k16-p1'))).Artifacts[0].VerifiedKeyId.Length | Should -Be 32
    }
    It 'signature-algorithm' {
        $checker = New-TestChecker
        $text = [Text.Encoding]::ASCII.GetString($FixtureBytesById['eligible-three'])
        $changed = $text.Replace('"algorithm":"RSA3072PKCS1SHA256"','"algorithm":"RSA3072PSSSHA256"')
        Get-CallFailure $checker AdmitKeyBindings (New-SnapshotArguments $changed) | Should -BeExactly 'snapshot:algorithm'
        $rows = ($text | ConvertFrom-Json).keys
        $rows[1].algorithm = 'RSA3072PKCS1SHA1'
        Get-CallFailure $checker AdmitKeyBindings (New-SnapshotArguments (New-TestSnapshotText $rows)) | Should -BeExactly 'snapshot:algorithm'
        $binding = New-FixtureBinding $checker
        foreach($id in @('emsa-pss','emsa-sha1')) {
            $arguments = [object[]]::new(2);$arguments[0]=New-FixtureSet @($id);$arguments[1]=$binding
            Get-CallFailure $checker CheckSet $arguments | Should -BeExactly 'signature:emsa'
        }
        (Invoke-TestCheckSet $checker $binding (New-FixtureSet @('positive-k16-p1'))).Artifacts[0].VerifiedClaims |
            Should -Contain 'signature-verified'
    }
    It 'schema-protocol-binding' {
        $checker = New-TestChecker
        $binding = New-FixtureBinding $checker
        foreach($kind in @(16,17)) {
            $arguments = [object[]]::new(2)
            $arguments[0] = New-FixtureSet @('wrong-protocol-schema-k'+$kind)
            $arguments[1] = $binding
            Get-CallFailure $checker CheckSet $arguments | Should -BeExactly 'schema:protocol-digest'
            $control = Invoke-TestCheckSet $checker $binding (New-FixtureSet @('positive-k'+$kind+'-p1'))
            $control.Artifacts[0].VerifiedClaims | Should -Contain 'protocol-schema-bytes-bound'
        }
        $AuthorityBytesById.ProtocolSchema.Length | Should -Be 66838
        [BitConverter]::ToString((Get-TestDigest $AuthorityBytesById.ProtocolSchema)).Replace('-','').ToLowerInvariant() |
            Should -BeExactly '6d76911009b64e52417b3ca519d3b3166cfdf675a4d4deede5ab0dce449c9db4'
        $rows = ([Text.Encoding]::ASCII.GetString($FixtureBytesById['eligible-three']) | ConvertFrom-Json).keys
        foreach($kind in @(16,17)) {
            Get-PspktSignatureReferenceOracleSignatureReason $FixtureBytesById['wrong-protocol-schema-k'+$kind] (ConvertFrom-TestHex $rows[0].publicBlob) |
                Should -BeExactly 'ok'
        }
    }
    It 'schema-evidence-binding' {
        $checker = New-TestChecker
        $binding = New-FixtureBinding $checker
        foreach($kind in @(16,17)) {
            $arguments = [object[]]::new(2)
            $arguments[0] = New-FixtureSet @('wrong-evidence-schema-k'+$kind)
            $arguments[1] = $binding
            Get-CallFailure $checker CheckSet $arguments | Should -BeExactly 'schema:evidence-digest'
            $control = Invoke-TestCheckSet $checker $binding (New-FixtureSet @('positive-k'+$kind+'-p1'))
            ($control.Artifacts[0].VerifiedClaims -join '|') | Should -BeExactly 'signature-verified|signature-key-binding-checked|protocol-schema-bytes-bound|evidence-schema-bytes-bound'
        }
        $AuthorityBytesById.EvidenceSchema.Length | Should -Be 22001
        [BitConverter]::ToString((Get-TestDigest $AuthorityBytesById.EvidenceSchema)).Replace('-','').ToLowerInvariant() |
            Should -BeExactly '49b07b1a401e686ce1bb05fbffb6923f6ef12a9d74deae5a06c840e2abf1fda6'
        $rows = ([Text.Encoding]::ASCII.GetString($FixtureBytesById['eligible-three']) | ConvertFrom-Json).keys
        foreach($kind in @(16,17)) {
            Get-PspktSignatureReferenceOracleSignatureReason $FixtureBytesById['wrong-evidence-schema-k'+$kind] (ConvertFrom-TestHex $rows[0].publicBlob) |
                Should -BeExactly 'ok'
        }
    }
    It 'schema-scope' {
        $checker = New-TestChecker
        $binding = New-FixtureBinding $checker
        $local = Invoke-TestCheckSet $checker $binding (New-FixtureSet @('positive-k16-p1','positive-k17-p1'))
        foreach($artifact in $local.Artifacts) {
            $artifact.UncheckedSemantics | Should -Not -Contain 'schema-bindings-unchecked'
            ($artifact.VerifiedClaims -join '|') | Should -BeExactly 'signature-verified|signature-key-binding-checked|protocol-schema-bytes-bound|evidence-schema-bytes-bound'
        }
        $authorization = Invoke-TestCheckSet $checker $binding (New-FixtureSet @('positive-k20-p1','positive-k18-p1'))
        $authorization.Artifacts[0].VerifiedClaims | Should -Not -Contain 'protocol-schema-bytes-bound'
        $authorization.Artifacts[0].VerifiedClaims | Should -Not -Contain 'evidence-schema-bytes-bound'
        $authorization.Artifacts[0].UncheckedSemantics | Should -Contain 'producer-digests-unchecked'
        Assert-PspktSignatureReferenceSchemaClaims $local.Artifacts
        Assert-PspktSignatureReferenceSchemaClaims $authorization.Artifacts
        $invalid = [pscustomobject]@{Kind=[uint16]20;VerifiedClaims=@('signature-verified','signature-key-binding-checked','protocol-schema-bytes-bound');
            UncheckedSemantics=$authorization.Artifacts[0].UncheckedSemantics}
        $reason = try { Assert-PspktSignatureReferenceSchemaClaims @($invalid); 'accepted' } catch { $_.Exception.Message }
        $reason | Should -BeExactly 'validation:residual-contract'
    }
    It 'structural-kind-coverage' {
        $frozen = $ManifestRecordsByRole.FrozenSnapshot
        $checker = New-TestChecker
        $binding = New-FixtureBinding $checker
        $executed = 0
        for($kind=0;$kind -lt 22;$kind++) {
            foreach($profile in @(1,2)) {
                if($kind -in @(16,17,18,20,21)) {
                    $ids = @('positive-k'+$kind+'-p'+$profile)
                    if($kind -eq 20) { $ids += 'positive-k18-p'+$profile }
                    if($kind -eq 21) { $ids += @(('positive-k20-p'+$profile),('positive-k18-p'+$profile)) }
                    $set = New-FixtureSet $ids
                }
                else {
                    $set = [byte[][]]::new(1)
                    $set[0] = [byte[]]$frozen.Files[('certification\evidence-runtime\vectors\generated\kind-{0:d2}-profile-{1}.bin' -f $kind,$profile)].Clone()
                }
                $result = Invoke-TestCheckSet $checker $binding $set
                $artifact = $result.Artifacts[0]
                $artifact.Kind | Should -Be $kind
                $artifact.Profile | Should -Be $profile
                $artifact.UncheckedSemantics | Should -Contain 'ledger-state-unchecked'
                $artifact.UncheckedSemantics | Should -Contain 'lifecycle-certification-unchecked'
                if($kind -in @(16,17,20)) {
                    $artifact.VerifiedKeyId.Length | Should -Be 32
                    $artifact.VerifiedClaims | Should -Contain 'signature-verified'
                }
                else {
                    $artifact.VerifiedKeyId.Length | Should -Be 0
                    $artifact.VerifiedClaims | Should -Not -Contain 'signature-verified'
                    if($kind -ne 21) { $artifact.VerifiedClaims.Count | Should -Be 0 }
                }
                if($kind -in @(0,2,15)) {
                    $artifact.UncheckedSemantics | Should -Contain 'signature-authentication-unchecked'
                    $artifact.UncheckedSemantics | Should -Contain 'signature-key-binding-unchecked'
                }
                $executed++
            }
        }
        $executed | Should -Be 44
        $set = New-FixtureSet @('positive-k16-p1')
        $set[0][6]=255;$set[0][7]=255
        $arguments = [object[]]::new(2);$arguments[0]=$set;$arguments[1]=$binding
        Get-CallFailure $checker CheckSet $arguments | Should -BeExactly 'envelope:structure'
    }
    It 'graph-conditional-edges' {
        $checker = New-TestChecker
        $binding = New-FixtureBinding $checker
        $arguments = [object[]]::new(2);$arguments[0]=New-FixtureSet @('positive-k21-p1');$arguments[1]=$binding
        Get-CallFailure $checker CheckSet $arguments | Should -BeExactly 'reference:target-missing'
        $local = Invoke-TestCheckSet $checker $binding (New-FixtureSet @('positive-k16-p1'))
        $local.References.Count | Should -Be 0
        $burn = Invoke-TestCheckSet $checker (New-FixtureBinding $checker 'zero-rows') (New-FixtureSet @('positive-k18-p1'))
        $burn.References.Count | Should -Be 0
        $burn.Artifacts[0].VerifiedKeyId.Length | Should -Be 0
        $burn.Artifacts[0].VerifiedClaims.Count | Should -Be 0
        $pair = Invoke-TestCheckSet $checker $binding (New-FixtureSet @('positive-k20-p1','positive-k18-p1'))
        $pair.References.Count | Should -Be 1
        $pair.References[0].SourceKind | Should -Be 20
        $pair.References[0].TargetKind | Should -Be 18
        $pair.References[0].SourceFieldCoveredByVerifiedSignature | Should -BeTrue
        $chain = Invoke-TestCheckSet $checker $binding (New-FixtureSet @('positive-k21-p1','positive-k18-p1','positive-k20-p1'))
        $chain.References.Count | Should -Be 2
        $chain.References[1].SourceKind | Should -Be 21
        $chain.References[1].TargetKind | Should -Be 20
        $chain.References[1].SourceFieldCoveredByVerifiedSignature | Should -BeFalse
        $chain.Artifacts[0].VerifiedKeyId.Length | Should -Be 0
        $chain.Artifacts[0].VerifiedClaims | Should -Not -Contain 'signature-verified'
    }
    It 'graph-target-category' {
        Get-Command Get-PspktSignatureReferenceOracleFields -ErrorAction SilentlyContinue |
            Should -Not -BeNullOrEmpty -Because 'reference decoys must be derived from independently decoded named field categories'
        $local = Get-PspktSignatureReferenceOracleFields $FixtureBytesById['positive-k16-p1']
        $burn = Get-PspktSignatureReferenceOracleFields $FixtureBytesById['positive-k18-p1']
        $decoys = @(
            [pscustomobject]@{Id='neg-target-inner-subject';Digest=[byte[]]$local[7]},
            [pscustomobject]@{Id='neg-target-wrong-kind';Digest=[byte[]]$FixtureBytesById['positive-k16-p1'][697..728]},
            [pscustomobject]@{Id='neg-target-ledger-record-digest';Digest=[byte[]]$burn[3]})
        $checker = New-TestChecker
        $binding = New-FixtureBinding $checker
        foreach($decoy in $decoys) {
            $set = New-FixtureSet @('positive-k21-p1','positive-k20-p1','positive-k18-p1','positive-k16-p1')
            [Array]::Copy($decoy.Digest,0,$set[0],53,32)
            $set[0] = Set-PspktSignatureReferenceOracleDigest $set[0]
            $arguments = [object[]]::new(2);$arguments[0]=$set;$arguments[1]=$binding
            Get-CallFailure $checker CheckSet $arguments | Should -BeExactly 'reference:target-missing' -Because $decoy.Id
        }
        $control = Invoke-TestCheckSet $checker $binding (New-FixtureSet @('positive-k21-p1','positive-k20-p1','positive-k18-p1','positive-k16-p1'))
        $control.References.Count | Should -Be 2
        [Convert]::ToBase64String($control.References[1].ReferenceDigest) |
            Should -BeExactly ([Convert]::ToBase64String([byte[]]$FixtureBytesById['positive-k20-p1'][689..720]))
    }
    It 'graph-missing-target' {
        $checker = New-TestChecker
        $binding = New-FixtureBinding $checker
        $arguments = [object[]]::new(2);$arguments[0]=New-FixtureSet @('positive-k20-p1');$arguments[1]=$binding
        Get-CallFailure $checker CheckSet $arguments | Should -BeExactly 'reference:target-missing'
        foreach($order in @(@(18,20,21),@(18,21,20),@(20,18,21),@(20,21,18),@(21,18,20),@(21,20,18))) {
            $ids = @($order | ForEach-Object { 'positive-k'+$_+'-p1' })
            $result = Invoke-TestCheckSet $checker $binding (New-FixtureSet $ids)
            $result.References.Count | Should -Be 2
            for($index=0;$index -lt 2;$index++) {
                $sourceKind = 20+$index
                $targetKind = if($sourceKind -eq 20) {18} else {20}
                $edge = $result.References[$index]
                $edge.SourceKind | Should -Be $sourceKind
                $edge.SourceInputIndex | Should -Be ([Array]::IndexOf($order,$sourceKind))
                $edge.TargetKind | Should -Be $targetKind
                $edge.TargetInputIndex | Should -Be ([Array]::IndexOf($order,$targetKind))
                $edge.SourceFieldId | Should -Be 1
                $result.Artifacts[$edge.SourceInputIndex].VerifiedClaims | Should -Contain 'cross-envelope-reference-resolved'
                $result.Artifacts[$edge.SourceInputIndex].UncheckedSemantics | Should -Not -Contain 'cross-envelope-references-unchecked'
            }
        }
    }
    It 'graph-cardinality' {
        $checker = New-TestChecker
        $binding = New-FixtureBinding $checker
        $ids = @('positive-k18-p1','positive-k20-p1','positive-k21-p1','fanout-authorization-2','fanout-receipt-2',
            'fanout-receipt-3','branch-burn-2','branch-authorization-2','branch-receipt-2')
        $result = Invoke-TestCheckSet $checker $binding (New-FixtureSet $ids)
        $result.Artifacts.Count | Should -Be 9
        $result.References.Count | Should -Be 7
        foreach($artifact in $result.Artifacts) {
            $artifact.UncheckedSemantics | Should -Contain 'reference-uniqueness-unchecked'
            $artifact.UncheckedSemantics | Should -Contain 'reference-timing-unchecked'
            $artifact.UncheckedSemantics | Should -Contain 'ledger-state-unchecked'
        }
        @($result.References | Where-Object { $_.TargetInputIndex -eq 0 }).Count | Should -Be 2
        @($result.References | Where-Object { $_.TargetInputIndex -eq 1 }).Count | Should -Be 2
        $orphans = Invoke-TestCheckSet $checker $binding (New-FixtureSet @('positive-k18-p1','positive-k20-p1','fanout-authorization-2','branch-burn-2'))
        $orphans.References.Count | Should -Be 2
        $orphans.Artifacts.Count | Should -Be 4
        Assert-PspktSignatureReferenceCardinalityResiduals $result.Artifacts
        $invalid = [pscustomobject]@{Kind=[uint16]18;UncheckedSemantics=@($result.Artifacts[0].UncheckedSemantics | Where-Object { $_ -cne 'reference-uniqueness-unchecked' })}
        $reason = try { Assert-PspktSignatureReferenceCardinalityResiduals @($invalid); 'accepted' } catch { $_.Exception.Message }
        $reason | Should -BeExactly 'validation:residual-contract'
    }
    It 'graph-duplicates' {
        $checker = New-TestChecker
        $binding = New-FixtureBinding $checker
        $arguments = [object[]]::new(2)
        $arguments[0] = New-FixtureSet @('positive-k16-p1','positive-k16-p1')
        $arguments[1] = $binding
        Get-CallFailure $checker CheckSet $arguments | Should -BeExactly 'envelope:duplicate-content'
        $arguments[0][1][29] = $arguments[0][1][29] -bxor 1
        $arguments[0][1][36] = 2
        Get-CallFailure $checker CheckSet $arguments | Should -BeExactly 'envelope:duplicate-content'
        $arguments[1] = New-FixtureBinding $checker 'wrong-role-a'
        Get-CallFailure $checker CheckSet $arguments | Should -BeExactly 'envelope:duplicate-content'
        $set = New-FixtureSet @('positive-k16-p1','positive-k16-p2','positive-k18-p1')
        $set[2][0] = 255
        $arguments[0]=$set;$arguments[1]=$binding
        Get-CallFailure $checker CheckSet $arguments | Should -BeExactly 'envelope:structure'
        $control = Invoke-TestCheckSet $checker (New-FixtureBinding $checker 'zero-rows') (New-FixtureSet @('positive-k18-p1','branch-burn-2'))
        $control.Artifacts.Count | Should -Be 2
    }
    It 'join-burned-operation' {
        $checker = New-TestChecker
        $binding = New-FixtureBinding $checker
        $arguments = [object[]]::new(2)
        $arguments[0] = New-FixtureSet @('wrong-burned-operation','positive-k18-p1')
        $arguments[1] = $binding
        Get-CallFailure $checker CheckSet $arguments | Should -BeExactly 'reference:burned-operation'
        $rows = ([Text.Encoding]::ASCII.GetString($FixtureBytesById['eligible-three']) | ConvertFrom-Json).keys
        Get-PspktSignatureReferenceOracleSignatureReason $FixtureBytesById['wrong-burned-operation'] (ConvertFrom-TestHex $rows[2].publicBlob) | Should -BeExactly 'ok'
        $fields = Get-PspktSignatureReferenceOracleFields $FixtureBytesById['wrong-burned-operation']
        $set = New-FixtureSet @('wrong-burned-operation','positive-k18-p1','positive-k18-p1')
        [Array]::Copy($fields[2],0,$set[2],53,16)
        $set[2] = Set-PspktSignatureReferenceOracleDigest $set[2]
        $arguments[0] = $set
        Get-CallFailure $checker CheckSet $arguments | Should -BeExactly 'reference:burned-operation'
        $arguments[0] = New-FixtureSet @('wrong-burned-operation','positive-k18-p1','positive-k21-p1')
        Get-CallFailure $checker CheckSet $arguments | Should -BeExactly 'reference:target-missing'
        $control = Invoke-TestCheckSet $checker $binding (New-FixtureSet @('positive-k20-p1','positive-k18-p1'))
        $control.References[0].MatchedAssertions | Should -Contain 'burned-logical-operation-id-equal'
    }
    It 'join-burned-semantic' {
        $checker = New-TestChecker
        $binding = New-FixtureBinding $checker
        $arguments = [object[]]::new(2)
        $arguments[0] = New-FixtureSet @('wrong-burned-semantic','positive-k18-p1')
        $arguments[1] = $binding
        Get-CallFailure $checker CheckSet $arguments | Should -BeExactly 'reference:burned-semantic'
        $rows = ([Text.Encoding]::ASCII.GetString($FixtureBytesById['eligible-three']) | ConvertFrom-Json).keys
        Get-PspktSignatureReferenceOracleSignatureReason $FixtureBytesById['wrong-burned-semantic'] (ConvertFrom-TestHex $rows[2].publicBlob) | Should -BeExactly 'ok'
        $fields = Get-PspktSignatureReferenceOracleFields $FixtureBytesById['wrong-burned-semantic']
        $set = New-FixtureSet @('wrong-burned-semantic','positive-k18-p1','positive-k18-p1')
        [Array]::Copy($fields[3],0,$set[2],75,32)
        $set[2] = Set-PspktSignatureReferenceOracleDigest $set[2]
        $arguments[0] = $set
        Get-CallFailure $checker CheckSet $arguments | Should -BeExactly 'reference:burned-semantic'
        $control = Invoke-TestCheckSet $checker $binding (New-FixtureSet @('positive-k20-p1','positive-k18-p1'))
        ($control.References[0].MatchedAssertions -join '|') | Should -BeExactly 'burned-logical-operation-id-equal|burned-semantic-digest-equal'
        $control.Artifacts[0].VerifiedClaims | Should -Contain 'linked-assertions-equal'
        $control.Artifacts[0].UncheckedSemantics | Should -Contain 'producer-digests-unchecked'
    }
    It 'join-successor-operation' {
        $checker = New-TestChecker
        $binding = New-FixtureBinding $checker
        $arguments = [object[]]::new(2)
        $arguments[0] = New-FixtureSet @('wrong-successor-operation','positive-k20-p1','positive-k18-p1')
        $arguments[1] = $binding
        Get-CallFailure $checker CheckSet $arguments | Should -BeExactly 'reference:successor-operation'
        $arguments[0] = New-FixtureSet @('wrong-successor-operation','positive-k20-p1','positive-k18-p1','branch-authorization-2','branch-burn-2')
        Get-CallFailure $checker CheckSet $arguments | Should -BeExactly 'reference:successor-operation'
        $control = Invoke-TestCheckSet $checker $binding (New-FixtureSet @('positive-k21-p1','positive-k20-p1','positive-k18-p1'))
        ($control.References[1].MatchedAssertions -join '|') | Should -BeExactly 'successor-logical-operation-id-equal'
        $control.References[1].SourceFieldCoveredByVerifiedSignature | Should -BeFalse
        ($control.Artifacts[0].VerifiedClaims -join '|') | Should -BeExactly 'cross-envelope-reference-resolved|linked-assertions-equal'
        $control.Artifacts[0].VerifiedKeyId.Length | Should -Be 0
        $control.Artifacts[2].VerifiedClaims.Count | Should -Be 0
        $control.Artifacts[2].VerifiedKeyId.Length | Should -Be 0
    }
    It 'outer-metadata' {
        $checker = New-TestChecker
        $binding = New-FixtureBinding $checker
        $set = New-FixtureSet @('positive-k16-p1','positive-k17-p1','positive-k20-p1','positive-k18-p1','positive-k21-p1')
        $before = Invoke-TestCheckSet $checker $binding $set
        for($index=0;$index -lt $set.Length;$index++) {
            $set[$index][29] = $set[$index][29] -bxor ($index+1)
            $set[$index][36] = 2
        }
        $after = Invoke-TestCheckSet $checker $binding $set
        for($index=0;$index -lt $set.Length;$index++) {
            $after.Artifacts[$index].ArtifactId | Should -Not -Be $before.Artifacts[$index].ArtifactId
            $after.Artifacts[$index].Profile | Should -Be 2
            [Convert]::ToBase64String($after.Artifacts[$index].PayloadDigest) | Should -BeExactly ([Convert]::ToBase64String($before.Artifacts[$index].PayloadDigest))
            [Convert]::ToBase64String($after.Artifacts[$index].VerifiedKeyId) | Should -BeExactly ([Convert]::ToBase64String($before.Artifacts[$index].VerifiedKeyId))
            ($after.Artifacts[$index].VerifiedClaims -join '|') | Should -BeExactly ($before.Artifacts[$index].VerifiedClaims -join '|')
            ($after.Artifacts[$index].UncheckedSemantics -join '|') | Should -BeExactly ($before.Artifacts[$index].UncheckedSemantics -join '|')
        }
        $invalid = [pscustomobject]@{Kind=[uint16]16;UncheckedSemantics=@($after.Artifacts[0].UncheckedSemantics | Where-Object { $_ -cne 'artifact-id-unbound' })}
        $reason = try { Assert-PspktSignatureReferenceOuterResiduals @($invalid); 'accepted' } catch { $_.Exception.Message }
        $reason | Should -BeExactly 'validation:residual-contract'
        Assert-PspktSignatureReferenceOuterResiduals $before.Artifacts
        Assert-PspktSignatureReferenceOuterResiduals $after.Artifacts
    }
    It 'subject-and-producer-residuals' {
        $checker = New-TestChecker
        $binding = New-FixtureBinding $checker
        $local = Invoke-TestCheckSet $checker $binding (New-FixtureSet @('positive-k16-p1','positive-k17-p1'))
        foreach($artifact in $local.Artifacts) { $artifact.UncheckedSemantics | Should -Contain 'subject-digest-unchecked' }
        $set = New-FixtureSet @('positive-k18-p1')
        [Array]::Copy([byte[]](@(170)*32),0,$set[0],113,32)
        [Array]::Copy([byte[]](@(187)*32),0,$set[0],151,32)
        $set[0] = Set-PspktSignatureReferenceOracleDigest $set[0]
        $burn = Invoke-TestCheckSet $checker (New-FixtureBinding $checker 'zero-rows') $set
        $burn.Artifacts[0].UncheckedSemantics | Should -Contain 'ledger-record-references-unchecked'
        $burn.Artifacts[0].UncheckedSemantics | Should -Contain 'producer-digests-unchecked'
        $invalid = [pscustomobject]@{Kind=[uint16]16;UncheckedSemantics=@($local.Artifacts[0].UncheckedSemantics | Where-Object { $_ -cne 'subject-digest-unchecked' })}
        $reason = try { Assert-PspktSignatureReferenceDigestResiduals @($invalid); 'accepted' } catch { $_.Exception.Message }
        $reason | Should -BeExactly 'validation:residual-contract'
        Assert-PspktSignatureReferenceDigestResiduals $local.Artifacts
        Assert-PspktSignatureReferenceDigestResiduals $burn.Artifacts
        $chain = Invoke-TestCheckSet $checker $binding (New-FixtureSet @('positive-k21-p1','positive-k20-p1','positive-k18-p1'))
        Assert-PspktSignatureReferenceDigestResiduals $chain.Artifacts
    }
    It 'key-time-and-ledger-residuals' {
        $checker = New-TestChecker
        $result = Invoke-TestCheckSet $checker (New-FixtureBinding $checker) (New-FixtureSet @('positive-k16-p1','positive-k17-p1','positive-k20-p1','positive-k18-p1','positive-k21-p1'))
        foreach($artifact in $result.Artifacts) {
            foreach($token in @('evidence-authenticity-unchecked','freshness-unchecked','ledger-state-unchecked','lifecycle-certification-unchecked')) {
                $artifact.UncheckedSemantics | Should -Contain $token
            }
            foreach($token in @('caller-pinned-key-provenance-unchecked','key-enrollment-unchecked','caller-time-eligibility-basis-unchecked')) {
                if($artifact.Kind -in @(16,17,20)) { $artifact.UncheckedSemantics | Should -Contain $token }
                else { $artifact.UncheckedSemantics | Should -Not -Contain $token }
            }
            if($artifact.Kind -in @(16,17,20)) {
                $artifact.UncheckedSemantics | Should -Not -Contain 'signature-authentication-unchecked'
                $artifact.UncheckedSemantics | Should -Not -Contain 'signature-key-binding-unchecked'
            }
        }
        $invalid = [pscustomobject]@{Kind=[uint16]20;UncheckedSemantics=@($result.Artifacts[2].UncheckedSemantics | Where-Object { $_ -cne 'caller-time-eligibility-basis-unchecked' })}
        $reason = try { Assert-PspktSignatureReferenceTrustResiduals @($invalid); 'accepted' } catch { $_.Exception.Message }
        $reason | Should -BeExactly 'validation:residual-contract'
        Assert-PspktSignatureReferenceTrustResiduals $result.Artifacts
    }
    It 'kind-token-transitions' {
        $frozen = $ManifestRecordsByRole.FrozenSnapshot
        $checker = New-TestChecker
        $binding = New-FixtureBinding $checker
        $vocabulary = @('evidence-authenticity-unchecked','artifact-id-unbound','profile-authentication-unchecked','profile-value-unbound',
            'signature-authentication-unchecked','signature-key-binding-unchecked','subject-digest-unchecked','copied-protocol-digests-unchecked',
            'cross-envelope-references-unchecked','freshness-unchecked','ledger-record-references-unchecked','schema-bindings-unchecked',
            'producer-digests-unchecked','caller-pinned-key-provenance-unchecked','key-enrollment-unchecked','caller-time-eligibility-basis-unchecked',
            'reference-uniqueness-unchecked','reference-timing-unchecked','ledger-state-unchecked','lifecycle-certification-unchecked')
        $mixed = [byte[][]]::new(2)
        $mixed[0] = $frozen.Files['certification\evidence-runtime\vectors\generated\kind-00-profile-1.bin']
        $mixed[1] = $FixtureBytesById['positive-k16-p1']
        $expectedUnion = @('ABCDEFGHJNOPST'.ToCharArray() | ForEach-Object { $vocabulary[[int]$_-65] })
        $mixedResult = Invoke-TestCheckSet $checker $binding $mixed
        ($mixedResult.UncheckedSemantics -join '|') | Should -BeExactly ($expectedUnion -join '|')
        [Array]::Reverse($mixed)
        ((Invoke-TestCheckSet $checker $binding $mixed).UncheckedSemantics -join '|') | Should -BeExactly ($expectedUnion -join '|')
        $path = Join-Path $ManifestRecordsByRole.RepositoryRoot 'certification\evidence-signature-reference\vectors\hand-authored\contract-expectations.v1.json'
        $expectations = Get-TestSourceText $path | ConvertFrom-Json
        ($expectations.tokens -join '|') | Should -BeExactly ($vocabulary -join '|')
        $expectations.kindTransitions.Count | Should -Be 22
        $arguments = New-AuthorityArguments
        $codec = $StructuralAssembly.GetType('Pspkt.Certification.EvidenceRuntime.EvidenceArtifactEnvelopeCodec',$true).
            GetMethod('CreateFromCommittedAuthorities').Invoke($null,[object[]]$arguments[0..3])
        for($kind=0;$kind -lt 22;$kind++) {
            if($kind -in @(16,17,18,20,21)) {
                $ids = @('positive-k'+$kind+'-p1')
                if($kind -eq 20) { $ids += 'positive-k18-p1' }
                if($kind -eq 21) { $ids += @('positive-k20-p1','positive-k18-p1') }
                $set = New-FixtureSet $ids
            }
            else {
                $set = [byte[][]]::new(1)
                $set[0] = $frozen.Files[('certification\evidence-runtime\vectors\generated\kind-{0:d2}-profile-1.bin' -f $kind)]
            }
            $expected = $expectations.kindTransitions[$kind]
            $expected.kind | Should -Be $kind
            $decoded = $codec.Decode($set[0])
            $beforeTokens = @($expected.structuralCodes.ToCharArray() | ForEach-Object { $vocabulary[[int]$_-65] })
            ($decoded.UncheckedSemantics -join '|') | Should -BeExactly ($beforeTokens -join '|')
            $result = Invoke-TestCheckSet $checker $binding $set
            Assert-PspktSignatureReferenceTokenTransitions -Assessment $result -Expectations $expectations
        }
        $invalidArtifact = [pscustomobject]@{Kind=[uint16]16;VerifiedClaims=$mixedResult.Artifacts[1].VerifiedClaims;
            UncheckedSemantics=@($mixedResult.Artifacts[1].UncheckedSemantics | Where-Object { $_ -cne 'evidence-authenticity-unchecked' })}
        $invalid = [pscustomobject]@{Artifacts=@($invalidArtifact);UncheckedSemantics=$invalidArtifact.UncheckedSemantics}
        $reason = try { Assert-PspktSignatureReferenceTokenTransitions -Assessment $invalid -Expectations $expectations; 'accepted' } catch { $_.Exception.Message }
        $reason | Should -BeExactly 'validation:residual-contract'
        $intersection = [pscustomobject]@{Artifacts=$mixedResult.Artifacts;UncheckedSemantics=@('ABCJST'.ToCharArray() | ForEach-Object { $vocabulary[[int]$_-65] })}
        $reason = try { Assert-PspktSignatureReferenceTokenTransitions -Assessment $intersection -Expectations $expectations; 'accepted' } catch { $_.Exception.Message }
        $reason | Should -BeExactly 'validation:residual-contract'
    }
    It 'input-bounds-and-copies' {
        $checker = New-TestChecker
        $binding = New-FixtureBinding $checker 'zero-rows'
        $arguments = [object[]]::new(2);$arguments[1]=$binding
        $arguments[0] = [byte[][]]::new(257)
        Get-CallFailure $checker CheckSet $arguments | Should -BeExactly 'resource:envelope-count'
        foreach($row in @(
            [pscustomobject]@{Set=$null;Reason='argument:null'},
            [pscustomobject]@{Set=[byte[][]]::new(0);Reason='argument:empty'},
            [pscustomobject]@{Set=[byte[][]]::new(1);Reason='argument:envelope-slot'})) {
            $arguments[0]=$row.Set
            Get-CallFailure $checker CheckSet $arguments | Should -BeExactly $row.Reason
        }
        $arguments[0]=New-FixtureSet @('positive-k18-p1');$arguments[1]=$null
        Get-CallFailure $checker CheckSet $arguments | Should -BeExactly 'argument:null'
        $arguments[1]=$binding;$arguments[0][0]=[byte[]]::new(0)
        Get-CallFailure $checker CheckSet $arguments | Should -BeExactly 'argument:empty-envelope'
        $arguments[0][0]=[byte[]]::new(262229)
        Get-CallFailure $checker CheckSet $arguments | Should -BeExactly 'resource:envelope-bytes'
        $countSet = [byte[][]]::new(256)
        for($index=0;$index -lt 256;$index++) {
            $bytes = [byte[]]$FixtureBytesById['positive-k18-p1'].Clone();$bytes[151]=[byte]$index
            $countSet[$index]=Set-PspktSignatureReferenceOracleDigest $bytes
        }
        (Invoke-TestCheckSet $checker $binding $countSet).Artifacts.Count | Should -Be 256
        $frozen = $ManifestRecordsByRole.FrozenSnapshot
        $template = $frozen.Files['certification\evidence-runtime\vectors\generated\kind-09-profile-1.bin']
        $aggregate = [byte[][]]::new(64)
        for($index=0;$index -lt 64;$index++) {
            $length = 262228
            if($index -eq 63) { $length = 16777216-63*262228 }
            $aggregate[$index] = New-PspktSignatureReferenceOracleTranscriptEnvelope $template $length $index
        }
        [long]($aggregate | ForEach-Object { $_.Length } | Measure-Object -Sum).Sum | Should -Be 16777216
        (Invoke-TestCheckSet $checker $binding $aggregate).Artifacts.Count | Should -Be 64
        $aggregate[63]=New-PspktSignatureReferenceOracleTranscriptEnvelope $template (16777217-63*262228) 63
        $arguments[0]=$aggregate
        Get-CallFailure $checker CheckSet $arguments | Should -BeExactly 'resource:aggregate-bytes'
        $source = Get-TestSourceText 'certification\evidence-signature-reference\lib\EvidenceSetChecker.cs'
        $source | Should -Match 'long totalBytes'
        $source | Should -Match 'checked\s*\{\s*totalBytes \+='
        $source.IndexOf('resource:aggregate-bytes',[StringComparison]::Ordinal) | Should -BeLessThan $source.IndexOf('DecodedStage.Create(',[StringComparison]::Ordinal)
        $authorityArguments = New-AuthorityArguments
        $checker = $CheckerAssembly.GetType('Pspkt.Certification.EvidenceSignatureReference.EvidenceSetChecker',$true).GetMethod('CreateFromCommittedAuthorities').Invoke($null,$authorityArguments)
        foreach($bytes in $authorityArguments) { $bytes[0]=$bytes[0]-bxor 255 }
        $snapshotArguments=New-SnapshotArguments ([Text.Encoding]::ASCII.GetString($FixtureBytesById['eligible-three']))
        $binding=$checker.GetType().GetMethod('AdmitKeyBindings').Invoke($checker,$snapshotArguments)
        foreach($slot in @(0,1,4)) { $snapshotArguments[$slot][0]=$snapshotArguments[$slot][0]-bxor 255 }
        $set = New-FixtureSet @('positive-k21-p1','positive-k20-p1','positive-k18-p1')
        $result = Invoke-TestCheckSet $checker $binding $set
        foreach($bytes in $set) { $bytes[0]=$bytes[0]-bxor 255 }
        $objects = @($result,$binding)+@($result.Artifacts)+@($result.References)
        foreach($value in $objects) {
            foreach($property in $value.GetType().GetProperties()) {
                if(-not $property.PropertyType.IsArray) { continue }
                $first=$property.GetValue($value,$null);$saved=$first.Clone()
                $second=$property.GetValue($value,$null)
                [object]::ReferenceEquals($first,$second) | Should -BeFalse
                if($first.Length -gt 0) {
                    if($first -is [byte[]]) { $first[0]=$first[0]-bxor 255 } else { $first[0]=$null }
                }
                $actual=$property.GetValue($value,$null)
                $actual.Length | Should -Be $saved.Length
                for($index=0;$index -lt $saved.Length;$index++) { $actual[$index] | Should -Be $saved[$index] }
            }
        }
    }
    It 'atomicity-and-diagnostics' {
        $failureType=$CheckerAssembly.GetType('Pspkt.Certification.EvidenceSignatureReference.EvidenceFailure',$true)
        $hashMethod=$failureType.GetMethod('HashAndDispose',[Reflection.BindingFlags]'Static,NonPublic')
        $hashMethod | Should -Not -BeNullOrEmpty -Because 'owned hash disposal and its failure policy must be directly observable before return'
        $algorithm=[Security.Cryptography.SHA256]::Create()
        $bytes=[Text.Encoding]::ASCII.GetBytes('owned-hash-lifecycle')
        $hashArguments=[object[]]::new(2);$hashArguments[0]=$algorithm;$hashArguments[1]=$bytes
        $hash=$hashMethod.Invoke($null,$hashArguments)
        [Convert]::ToBase64String($hash) | Should -BeExactly ([Convert]::ToBase64String((Get-TestDigest $bytes)))
        $disposed=$false
        try { [void]$algorithm.ComputeHash($bytes) } catch {
            $exception=$_.Exception
            while($null -ne $exception.InnerException) { $exception=$exception.InnerException }
            $disposed=$exception -is [ObjectDisposedException]
        }
        $disposed | Should -BeTrue
        $disposeMethod=$failureType.GetMethod('DisposeOwned',[Reflection.BindingFlags]'Static,NonPublic')
        foreach($primary in @($null,[IO.InvalidDataException]::new('signature:emsa'))) {
            $stream=[IO.MemoryStream]::new()
            $writer=[IO.StreamWriter]::new($stream,[Text.UTF8Encoding]::new($false,$true),1024,$true)
            $writer.Write([char]0xd800)
            try {
                $failure=$disposeMethod.Invoke($null,@($writer,$primary))
                if($null -eq $primary) { $failure.Message | Should -BeExactly 'runtime:cleanup' }
                else { [object]::ReferenceEquals($failure,$primary) | Should -BeTrue }
                $failure.InnerException | Should -BeNullOrEmpty
            }
            finally { $stream.Dispose() }
        }
        $normalizer=$failureType.GetMethod('Normalize',[Reflection.BindingFlags]'Static,NonPublic')
        foreach($exception in @([Exception]::new('sentinel-sensitive-path'),[IO.InvalidDataException]::new('sentinel-private-bytes'),
            [ArgumentException]::new('sentinel-parameter-name'))) {
            $failure=$normalizer.Invoke($null,@($exception))
            $failure.Message | Should -BeExactly 'runtime:unexpected'
            $failure.InnerException | Should -BeNullOrEmpty
        }
        $sources=@{}
        foreach($name in @('EvidenceSetChecker.cs','EvidenceKeyBindingSnapshot.cs','EvidenceSetAssessment.cs','EvidenceArtifactVerification.cs',
            'EvidenceReferenceResolution.cs','EvidenceAuthoritySnapshot.cs','EvidenceCanonicalJsonReader.cs','EvidenceJsonValue.cs',
            'EvidenceKeyBindingReader.cs','EvidenceKeyBinding.cs','CanonicalRsaPublicKey.cs','EvidenceSignatureVerifier.cs',
            'EvidenceReferenceResolver.cs','EvidenceResolvedReference.cs','EvidencePayloadProjection.cs','EvidenceClaimSet.cs','EvidenceFailure.cs')) {
            $sources[$name]=Get-TestSourceText ('certification\evidence-signature-reference\lib\'+$name)
        }
        Assert-TestHashCatchScopes $sources
        $badSources=@{}
        foreach($name in $sources.Keys) { $badSources[$name]=$sources[$name] }
        $badSources['EvidenceFailure.cs']=$badSources['EvidenceFailure.cs'].Replace('return SHA256.Create();','EvidenceArtifactEnvelopeCodec.CreateFromCommittedAuthorities(null,null,null,null); return SHA256.Create();')
        $reason=try { Assert-TestHashCatchScopes $badSources; 'accepted' } catch { $_.Exception.Message }
        $reason | Should -BeExactly 'validation:source-policy'
        $checker=New-TestChecker
        $binding=New-FixtureBinding $checker
        $prior=Invoke-TestCheckSet $checker $binding (New-FixtureSet @('positive-k16-p1'))
        $priorDigest=[Convert]::ToBase64String($prior.Artifacts[0].PayloadDigest)
        $unpublished=$null
        try { $unpublished=Invoke-TestCheckSet $checker $binding (New-FixtureSet @('positive-k16-p1','positive-k20-p1','positive-k18-p1','wrong-successor-operation')) }
        catch {
            $exception=$_.Exception
            while($null -ne $exception.InnerException) { $exception=$exception.InnerException }
            $exception.Message | Should -BeExactly 'reference:successor-operation'
            $exception.InnerException | Should -BeNullOrEmpty
        }
        $unpublished | Should -BeNullOrEmpty
        [Convert]::ToBase64String($prior.Artifacts[0].PayloadDigest) | Should -BeExactly $priorDigest
        (Invoke-TestCheckSet $checker $binding (New-FixtureSet @('positive-k16-p1'))).Artifacts.Count | Should -Be 1
    }
    It 'independent-fixtures' {
        $manifestPath=Join-Path $ManifestRecordsByRole.RepositoryRoot 'certification\evidence-signature-reference\vectors\hand-authored\manifest.v1.json'
        Test-TestRetainedSource $manifestPath | Should -BeTrue -Because 'independent expected artifacts require a separately pinned protected manifest'
        $snapshot=$ManifestRecordsByRole.FixtureSnapshot
        $snapshot.Fixtures.Count | Should -Be 42
        $snapshot.Files.Count | Should -Be 10
        Assert-PspktSignatureReferenceFixtureSnapshot $snapshot
        $badFiles=@{}
        foreach($name in $snapshot.Files.Keys) { $badFiles[$name]=[byte[]]$snapshot.Files[$name].Clone() }
        $badFiles['vectors\generated\public-key-a.bin'][0]=$badFiles['vectors\generated\public-key-a.bin'][0]-bxor 1
        $invalid=[pscustomobject]@{Files=$badFiles;Fixtures=$snapshot.Fixtures;Expectations=$snapshot.Expectations}
        $reason=try { Assert-PspktSignatureReferenceFixtureSnapshot $invalid; 'accepted' } catch { $_.Exception.Message }
        $reason | Should -BeExactly 'validation:fixture-pin'
        $markers=@(
            [Text.Encoding]::ASCII.GetBytes('-----BEGIN SYNTHETIC MARKER'),
            [Text.Encoding]::ASCII.GetBytes('-----END SYNTHETIC MARKER'),
            [Text.Encoding]::ASCII.GetBytes('RSA2'),
            [byte[]]@(82,83,65,50,0,12,0,0),
            [byte[]]@(82,83,65,51,0,12,0,0),
            [Text.Encoding]::ASCII.GetBytes('0x32415352'),
            [Text.Encoding]::ASCII.GetBytes('0x33415352'),
            [Text.Encoding]::ASCII.GetBytes('{"DP":"synthetic"}'),
            [Text.Encoding]::ASCII.GetBytes('{"DQ":"synthetic"}'),
            [Text.Encoding]::ASCII.GetBytes('{"InverseQ":"synthetic"}'),
            [Text.Encoding]::ASCII.GetBytes('<dp>synthetic</dp>'),
            [Text.Encoding]::ASCII.GetBytes('<dq>synthetic</dq>'),
            [Text.Encoding]::ASCII.GetBytes('<inverseq>synthetic</inverseq>'))
        foreach($marker in $markers) {
            $reason=try { Assert-PspktSignatureReferencePublicBytes $marker; 'accepted' } catch { $_.Exception.Message }
            $reason | Should -BeExactly 'validation:fixture-pin'
        }
        Assert-PspktSignatureReferencePublicBytes ([Text.Encoding]::ASCII.GetBytes('RSA3072PKCS1SHA256'))
        $generator=Get-TestSourceText 'certification\evidence-signature-reference\vectors\New-PspktPhase4EvidenceSignatureReferenceVectors.ps1'
        Assert-PspktSignatureReferenceGeneratorIsolation $generator
        $checker=New-TestChecker
        $binding=New-FixtureBinding $checker
        foreach($record in $snapshot.Expectations.fixtures) {
            if($record.id -in @('eligible-three','unused-expired','unused-future','wrong-role-a','zero-rows')) { continue }
            $set=New-FixtureSet (@($record.id)+@($record.companions))
            $arguments=[object[]]::new(2);$arguments[0]=$set;$arguments[1]=$binding
            $expected=$record.expectedReason
            if($expected -ceq 'ok') { $expected='accepted' }
            Get-CallFailure $checker CheckSet $arguments | Should -BeExactly $expected -Because $record.id
        }
    }
    It 'initialized-mutants' {
        $MutantBuilds.Count | Should -Be 5 -Because 'each semantic mutant must really compile, load, initialize and reach its control/challenge'
        $CompileCensus.Count | Should -Be 8
        $expectations=Get-TestSourceText 'certification\evidence-signature-reference\vectors\hand-authored\contract-expectations.v1.json' | ConvertFrom-Json
        for($index=0;$index -lt 5;$index++) {
            $build=$MutantBuilds[$index]
            $build.Result.role | Should -BeExactly ('M'+($index+1))
            Assert-PspktSignatureReferenceMutantResult -Result $build.Result -Expected $expectations.mutants[$index]
            Assert-PspktSignatureReferenceAssessment -Assessment $build.ControlAssessment -Envelopes $build.ControlEnvelopes -SnapshotBytes $build.ControlSnapshot -Expectations $expectations
            $build.Build.SourceCount | Should -Be 17
            $build.OriginalSourceSetSha256 | Should -BeExactly $CompileCensus[2].SourceSetSha256
            $build.Build.SourceSetSha256 | Should -Not -BeExactly $build.OriginalSourceSetSha256
            $build.ChallengeAssessment | Should -Not -BeNullOrEmpty
        }
        $invalid=[pscustomobject][ordered]@{}
        foreach($property in $MutantBuilds[0].Result.PSObject.Properties) { $invalid | Add-Member -NotePropertyName $property.Name -NotePropertyValue $property.Value }
        $invalid.controlOutcome='failed'
        $reason=try { Assert-PspktSignatureReferenceMutantResult -Result $invalid -Expected $expectations.mutants[0]; 'accepted' } catch { $_.Exception.Message }
        $reason | Should -BeExactly 'validation:mutant-control'
    }
    It 'compiler-and-load-custody' {
        $validatorPath=Join-Path $ManifestRecordsByRole.RepositoryRoot 'certification\evidence-signature-reference\validators\Invoke-PspktPhase4EvidenceSignatureReferenceValidators.ps1'
        Test-TestRetainedSource $validatorPath | Should -BeTrue -Because 'the one-shot marker must precede every standalone validation preflight'
        $tokens=$null;$errors=$null
        $validatorText=Get-TestSourceText $validatorPath
        $ast=[Management.Automation.Language.Parser]::ParseInput($validatorText,[ref]$tokens,[ref]$errors)
        $errors.Count | Should -Be 0
        ($ast.ParamBlock.Parameters.Name.VariablePath.UserPath -join '|') | Should -BeExactly 'RepositoryRoot|WorkRoot|PesterManifestPath'
        $functions=@($ast.EndBlock.Statements | Where-Object {$_ -is [Management.Automation.Language.FunctionDefinitionAst]})
        . ([scriptblock]::Create(($functions.Extent.Text -join "`n")))
        $marker='Pspkt.Certification.EvidenceSignatureReference.ValidationInvocation.Test'
        $callId=Enter-PspktSignatureReferenceInvocation -MarkerName $marker
        $callId | Should -Match '\A[0-9a-f]{32}\z'
        $reason=try { Assert-PspktSignatureReferenceInvocationRoots -RepositoryRoot $ManifestRecordsByRole.RepositoryRoot -WorkRoot $ManifestRecordsByRole.RepositoryRoot; 'accepted' } catch { $_.Exception.Message }
        $reason | Should -BeExactly 'validation:work-root'
        $spaceRoot=$ManifestRecordsByRole.RepositoryRoot+' \uncreated'
        $reason=try { Assert-PspktSignatureReferenceInvocationRoots -RepositoryRoot $ManifestRecordsByRole.RepositoryRoot -WorkRoot $spaceRoot; 'accepted' } catch { $_.Exception.Message }
        $reason | Should -BeExactly 'validation:work-root' -Because 'normalization-sensitive components must not evade source/output separation'
        $reason=try { Enter-PspktSignatureReferenceInvocation -MarkerName $marker; 'accepted' } catch { $_.Exception.Message }
        $reason | Should -BeExactly 'validation:invocation-repeat'
        . ([scriptblock]::Create((Get-TestSourceText 'certification\evidence-signature-reference\lib\Pspkt.Certification.EvidenceSignatureReferenceCompilation.ps1')))
        $context=$ManifestRecordsByRole.CompilerContext
        $runtimeNames=@(Get-PspktSignatureReferenceRuntimeNames)
        $runtimeNames.Count | Should -Be 17
        foreach($name in $runtimeNames) {
            $text=Get-TestSourceText ('certification\evidence-signature-reference\lib\'+$name)
            $declarations=Get-TestTopLevelTypeNames $text
            $declarations.Count | Should -Be 1 -Because $name
            $declarations[0] | Should -BeExactly ([IO.Path]::GetFileNameWithoutExtension($name))
        }
        @($CheckerAssembly.GetTypes() | Where-Object {
            -not $_.IsNested -and $_.Namespace -ceq 'Pspkt.Certification.EvidenceSignatureReference'
        }).Count | Should -Be 17
        ($CompileCensus.Role -join '|') | Should -BeExactly 'Bootstrap|Structural|Checker|M1|M2|M3|M4|M5'
        foreach($image in $CompileCensus) {
            $dependencies=@()
            if($image.Role -ceq 'Structural') { $dependencies=@($CompileCensus[0]) }
            elseif($image.Role -cne 'Bootstrap') { $dependencies=@($CompileCensus[0],$CompileCensus[1]) }
            Assert-PspktSignatureReferenceAssemblyCustody -Context $context -Image $image -Dependencies $dependencies
            $image.Initialized | Should -BeTrue
            $image.Name | Should -BeExactly ('PspktEvidenceSignatureReference_'+$context.CallId+'_'+$image.Role+'.dll')
        }
        $invalid=[pscustomobject]@{}
        foreach($property in $CompileCensus[2].PSObject.Properties) { $invalid | Add-Member -NotePropertyName $property.Name -NotePropertyValue $property.Value }
        $invalid.Identity='Unadmitted, Version=0.0.0.0, Culture=neutral, PublicKeyToken=null'
        $reason=try { Assert-PspktSignatureReferenceAssemblyCustody -Context $context -Image $invalid -Dependencies @($CompileCensus[0],$CompileCensus[1]); 'accepted' } catch { $_.Exception.Message }
        $reason | Should -BeExactly 'validation:assembly-custody'
    }
    It 'retained-pester-container' {
        $ManifestRecordsByRole.ContainsKey('ExpectedData') | Should -BeTrue -Because 'the retained caller-bound container must preserve all ten exact caller objects'
        $null -eq $ExecutionContext.SessionState.Module | Should -BeTrue
        foreach($name in @('BootstrapAssembly','StructuralAssembly','CheckerAssembly','AuthorityBytesById','FixtureBytesById',
            'ManifestRecordsByRole','CompileCensus','MutantBuilds','ArtifactRoot','CallerScopeMarker')) {
            [object]::ReferenceEquals((Get-Variable -Name $name -ValueOnly),$ManifestRecordsByRole.ExpectedData[$name]) | Should -BeTrue -Because $name
        }
        $CallerScopeMarker | Should -Match '\Apspkt-evidence-signature-reference-validation:[0-9a-f]{32}\z'
        $ManifestRecordsByRole.BeforeAllCallerScopePassed | Should -BeTrue
        Assert-PspktSignatureReferencePesterConfiguration $ManifestRecordsByRole.Configuration $ManifestRecordsByRole.Container
        Assert-PspktSignatureReferenceContainerObservation $ManifestRecordsByRole.ContainerObservation
        $invalid=[pscustomobject]@{}
        foreach($property in $ManifestRecordsByRole.ContainerObservation.PSObject.Properties) {
            $invalid | Add-Member -NotePropertyName $property.Name -NotePropertyValue $property.Value
        }
        $invalid.ModuleBound=$true
        $reason=try { Assert-PspktSignatureReferenceContainerObservation $invalid; 'accepted' } catch { $_.Exception.Message }
        $reason | Should -BeExactly 'validation:pester-container'
        $manifestPath=$ManifestRecordsByRole.PesterManifestPath
        Get-PspktSignatureReferencePesterManifestPath $manifestPath | Should -BeExactly ([IO.Path]::GetFullPath($manifestPath))
        $reason=try { Get-PspktSignatureReferencePesterManifestPath '.\Pester.psd1'; 'accepted' } catch { $_.Exception.Message }
        $reason | Should -BeExactly 'validation:pester-manifest'
        $module=@(Get-Module Pester)
        Assert-PspktSignatureReferenceExistingPester $module
        Assert-PspktSignatureReferenceImportedPester $module ([IO.Path]::GetDirectoryName($manifestPath))
        $wrongVersion=[pscustomobject]@{Name='Pester';Version=[version]'5.3.2';ModuleBase=[IO.Path]::GetDirectoryName($manifestPath)}
        $wrongOrigin=[pscustomobject]@{Name='Pester';Version=[version]'5.3.3';ModuleBase=$ArtifactRoot}
        $reason=try { Assert-PspktSignatureReferenceExistingPester @($wrongVersion); 'accepted' } catch { $_.Exception.Message }
        $reason | Should -BeExactly 'validation:pester-version'
        foreach($modules in @(@($wrongVersion),@($wrongOrigin),@($module[0],$module[0]))) {
            $reason=try { Assert-PspktSignatureReferenceImportedPester $modules ([IO.Path]::GetDirectoryName($manifestPath)); 'accepted' } catch { $_.Exception.Message }
            $reason | Should -BeExactly 'validation:pester-version'
        }
    }
    It 'result-boundary-rejections' {
        $path='certification\evidence-signature-reference\lib\Pspkt.Certification.EvidenceSignatureReferenceCi.ps1'
        Test-TestRetainedSource $path | Should -BeTrue -Because 'all result cardinality, shape, failure and count paths require a closed completion boundary'
        . ([scriptblock]::Create((Get-TestSourceText $path)))
        $fixture=New-PspktSignatureReferenceOracleBoundaryFixture $PSVersionTable.PSEdition $ManifestRecordsByRole.FixtureSnapshot.Expectations
        $control=@(Complete-PspktSignatureReferenceResult -Captured @($fixture.Result) -Expected $fixture.Expected)
        $control.Count | Should -Be 1
        [object]::ReferenceEquals($control[0],$fixture.Result) | Should -BeTrue
        $failure=[pscustomobject][ordered]@{schemaId='PspktEvidenceSignatureReferenceValidationResultV1';schemaVersion=1;
            outcome='ValidationFailed';callId=$fixture.Result.callId;reasonCode='validation:oracle';cleanupComplete=$true}
        $countMismatch=$fixture.Result | ConvertTo-Json -Depth 10 -Compress | ConvertFrom-Json
        $countMismatch.counts.passedCount=47
        $faults=@(
            [pscustomobject]@{Id='returned-failure';Candidates=@($failure);Reason='validation:returned-failure';Diagnostics=1},
            [pscustomobject]@{Id='malformed-result';Candidates=@([pscustomobject]@{outcome='ValidationSucceeded'});Reason='validation:result-shape';Diagnostics=0},
            [pscustomobject]@{Id='missing-result';Candidates=@();Reason='validation:result-cardinality';Diagnostics=0},
            [pscustomobject]@{Id='multiple-results';Candidates=@($fixture.Result,$fixture.Result);Reason='validation:result-cardinality';Diagnostics=0},
            [pscustomobject]@{Id='count-mismatch';Candidates=@($countMismatch);Reason='validation:result-counts';Diagnostics=0})
        foreach($fault in $faults) {
            $forwarded=[Collections.Generic.List[object]]::new()
            $reason='accepted'
            try { Complete-PspktSignatureReferenceResult -Captured $fault.Candidates -Expected $fixture.Expected | ForEach-Object {$forwarded.Add($_)} }
            catch { $reason=$_.Exception.Message }
            $reason | Should -BeExactly $fault.Reason -Because $fault.Id
            @($forwarded | Where-Object {$_.outcome -ceq 'ValidationSucceeded'}).Count | Should -Be 0
            @($forwarded | Where-Object {$_.outcome -ceq 'ValidationFailed'}).Count | Should -Be $fault.Diagnostics
        }
    }
    It 'workflow-and-attempt-binding' {
        $workflowPath='.github\workflows\ci-evidence-signature-reference.yml'
        Test-TestRetainedSource $workflowPath | Should -BeTrue -Because 'actual hosted transport and attempt binding require the committed literal-shell workflow'
        . ([scriptblock]::Create((Get-TestSourceText 'certification\evidence-signature-reference\lib\Pspkt.Certification.EvidenceSignatureReferenceCi.ps1')))
        $workflow=Get-TestSourceText $workflowPath
        $attributes=Get-TestSourceText '.github\.gitattributes'
        Assert-PspktSignatureReferenceWorkflow $workflow $attributes
        foreach($invalidText in @($workflow.Replace('shell: powershell','shell: pwsh'),$workflow.Replace(
            'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1','actions/checkout@main'),($workflow+"`r"))) {
            $reason=try { Assert-PspktSignatureReferenceWorkflow $invalidText $attributes; 'accepted' } catch { $_.Exception.Message }
            $reason | Should -BeExactly 'validation:workflow-contract'
        }
        $fixture=New-PspktSignatureReferenceOracleBoundaryFixture $PSVersionTable.PSEdition $ManifestRecordsByRole.FixtureSnapshot.Expectations
        $hostSlot='powershell_7'
        if($PSVersionTable.PSEdition -ceq 'Desktop') { $hostSlot='windows_ps51' }
        $binding=[pscustomobject]@{WorkflowRunId='123456';WorkflowRunAttempt='2';Revision=('a'*40);Slot=($hostSlot+'/checkout')}
        $receipt=New-PspktSignatureReferenceCiReceipt -Result $fixture.Result -Expected $fixture.Expected -Binding $binding
        $bytes=ConvertTo-PspktSignatureReferenceJsonBytes $receipt
        $parsed=Read-PspktSignatureReferenceCiReceipt -Bytes $bytes -Binding $binding -Expected $fixture.Expected
        $parsed.workflowRunAttempt | Should -BeExactly '2'
        foreach($field in @('workflowRunId','workflowRunAttempt','revision','slot')) {
            $invalid=$receipt | ConvertTo-Json -Depth 12 -Compress | ConvertFrom-Json
            if($field -ceq 'revision') { $invalid.$field='b'*40 }
            elseif($field -ceq 'slot') { $invalid.$field=$hostSlot+'/export' }
            else { $invalid.$field='1' }
            $reason=try { Read-PspktSignatureReferenceCiReceipt -Bytes (ConvertTo-PspktSignatureReferenceJsonBytes $invalid) -Binding $binding -Expected $fixture.Expected; 'accepted' } catch { $_.Exception.Message }
            $reason | Should -BeExactly 'validation:workflow-binding'
        }
        foreach($invalidOutcome in @($false,0,'success',$null)) {
            $reason=try { Assert-PspktSignatureReferenceRawOutcome $invalidOutcome; 'accepted' } catch { $_.Exception.Message }
            $reason | Should -BeExactly 'validation:probe'
        }
        Assert-PspktSignatureReferenceRawOutcome 'failure'
        $previousPayload=[Environment]::GetEnvironmentVariable('PSPKT_STAGE3_PAYLOAD','Process')
        $previousExtra=[Environment]::GetEnvironmentVariable('PSPKT_STAGE3_RECEIPT_EXTRA','Process')
        try {
            [Environment]::SetEnvironmentVariable('PSPKT_STAGE3_PAYLOAD',[Text.Encoding]::ASCII.GetString($bytes),'Process')
            [Environment]::SetEnvironmentVariable('PSPKT_STAGE3_RECEIPT_EXTRA',[Text.Encoding]::ASCII.GetString($bytes),'Process')
            $reason=try { Assert-PspktSignatureReferenceTransportEnvironment; 'accepted' } catch { $_.Exception.Message }
            $reason | Should -BeExactly 'validation:workflow-contract'
            [Environment]::SetEnvironmentVariable('PSPKT_STAGE3_RECEIPT_EXTRA',[NullString]::Value,'Process')
            $path=Join-Path $TestDrive 'single-receipt.json'
            Write-PspktSignatureReferenceTransport -Destination $path -MaximumBytes 16384
            [Convert]::ToBase64String([IO.File]::ReadAllBytes($path)) | Should -BeExactly ([Convert]::ToBase64String($bytes))
        }
        finally {
            if($null -eq $previousPayload) { $previousPayload=[NullString]::Value }
            if($null -eq $previousExtra) { $previousExtra=[NullString]::Value }
            [Environment]::SetEnvironmentVariable('PSPKT_STAGE3_PAYLOAD',$previousPayload,'Process')
            [Environment]::SetEnvironmentVariable('PSPKT_STAGE3_RECEIPT_EXTRA',$previousExtra,'Process')
        }
        foreach($observation in @(
            [pscustomobject]@{Length=271298;Sha256='bf450611b92dee8de7dd5e69809d5b37f86bff9f8f3b6eb3129d2fbdd889b579'},
            [pscustomobject]@{Length=271297;Sha256=('0'*64)})) {
            $reason=try { Assert-PspktSignatureReferencePesterPackage $observation.Length $observation.Sha256; 'accepted' } catch { $_.Exception.Message }
            $reason | Should -BeExactly 'validation:pester-package'
        }
        Assert-PspktSignatureReferencePesterPackage 271297 'bf450611b92dee8de7dd5e69809d5b37f86bff9f8f3b6eb3129d2fbdd889b579'
    }
    It 'receipt-size-and-census' {
        $path='certification\evidence-signature-reference\schema\evidence-signature-reference-receipt-schema.v1.json'
        Test-TestRetainedSource $path | Should -BeTrue -Because 'the compact receipt wire contract requires its closed pinned descriptor'
        . ([scriptblock]::Create((Get-TestSourceText 'certification\evidence-signature-reference\lib\Pspkt.Certification.EvidenceSignatureReferenceCi.ps1')))
        $descriptor=[Text.UTF8Encoding]::new($false,$true).GetBytes((Get-TestSourceText $path))
        Assert-PspktSignatureReferenceReceiptDescriptor $descriptor
        $oversized=[byte[]]::new(16385);$oversized[0]=255
        $reason=try { ConvertFrom-PspktSignatureReferenceCanonicalJson -Bytes $oversized; 'accepted' } catch { $_.Exception.Message }
        $reason | Should -BeExactly 'validation:receipt-size'
        $sizing=Get-PspktSignatureReferenceOracleSizingBytes $ManifestRecordsByRole.FixtureSnapshot.Expectations
        $sizing.Width.Length | Should -Be 9543
        (Get-PspktSignatureReferenceBytesDigest -Bytes $sizing.Width) | Should -BeExactly '7e7e9ce55a349d7f7a3f5d800f7d8339b0edbcf0faa667ee5a4151ad75f635d0'
        $sizing.Literal.Length | Should -Be 8976
        (Get-PspktSignatureReferenceBytesDigest -Bytes $sizing.Literal) | Should -BeExactly '2c3d9cc619e983ad8f4db19554c732bae858306d9137d5393cd535ba103f79b5'
        $sizing.Width.Length | Should -BeLessOrEqual 16384
        $fixture=New-PspktSignatureReferenceOracleBoundaryFixture $PSVersionTable.PSEdition $ManifestRecordsByRole.FixtureSnapshot.Expectations
        foreach($mutation in @('duplicate-role','duplicate-case','missing-load')) {
            $invalid=$fixture.Result | ConvertTo-Json -Depth 12 -Compress | ConvertFrom-Json
            switch($mutation) {
                'duplicate-role' { $invalid.compilationRecords[1].role='Bootstrap' }
                'duplicate-case' { $invalid.testIds[47]=$invalid.testIds[46] }
                'missing-load' { $invalid.loadRecords=@($invalid.loadRecords[0..6]) }
            }
            $reason=try { Complete-PspktSignatureReferenceResult -Captured @($invalid) -Expected $fixture.Expected; 'accepted' } catch { $_.Exception.Message }
            $reason | Should -BeExactly 'validation:result-counts'
        }
        $hostSlot='powershell_7'
        if($PSVersionTable.PSEdition -ceq 'Desktop') { $hostSlot='windows_ps51' }
        $binding=[pscustomobject]@{WorkflowRunId='123';WorkflowRunAttempt='2';Revision=('a'*40);Slot=($hostSlot+'/checkout')}
        $receipt=New-PspktSignatureReferenceCiReceipt -Result $fixture.Result -Expected $fixture.Expected -Binding $binding
        $bytes=ConvertTo-PspktSignatureReferenceJsonBytes $receipt
        $text=[Text.Encoding]::ASCII.GetString($bytes)
        foreach($variant in @(
            (' '+$text),($text+"`n"),($text.Replace('"schemaVersion":1','"schemaVersion":1,"schemaVersion":1')),
            ($text.Replace('"schemaVersion":1','"schemaVersion":01')),($text.Replace('"schemaVersion":1','"schemaVersion":1.0')),
            ($text.Replace('"schemaVersion":1','"schemaVersion":1e0')),($text.Replace('"schemaVersion":1','"schemaVersion":"1"')),
            ($text.Replace('"initialized":true','"initialized":"true"')),($text.Replace('"schemaVersion":1','"unknown":1')),
            ($text.Replace('"schemaId"','"\u0073chemaId"')))) {
            $reason=try { Read-PspktSignatureReferenceCiReceipt -Bytes ([Text.Encoding]::UTF8.GetBytes($variant)) -Binding $binding -Expected $fixture.Expected; 'accepted' } catch { $_.Exception.Message }
            $reason | Should -BeExactly 'validation:receipt-json'
        }
        $bytes.Length | Should -BeLessOrEqual 16384
        (Read-PspktSignatureReferenceCiReceipt -Bytes $bytes -Binding $binding -Expected $fixture.Expected).counts.passedCount | Should -Be 48
        $reason=try { Get-PspktSignatureReferenceReceiptExpectations ([pscustomobject]@{unknown=1}) $null; 'accepted' } catch { $_.Exception.Message }
        $reason | Should -BeExactly 'validation:receipt-json'
        $probeRows=@()
        foreach($record in @(@('returned-failure','validation:returned-failure',1),@('malformed-result','validation:result-shape',0),
            @('missing-result','validation:result-cardinality',0),@('multiple-results','validation:result-cardinality',0),@('count-mismatch','validation:result-counts',0))) {
            $probeRows+=[pscustomobject][ordered]@{caseId=$record[0];positiveControl=$true;wrapperReason=$record[1];stepReason=$record[1];
                successObjectsEmitted=0;diagnosticCount=$record[2];rawOutcome='failure'}
        }
        $group=[pscustomobject][ordered]@{schemaId='PspktEvidenceSignatureReferenceProbeGroupV1';schemaVersion=1;
            workflowRunId=$binding.WorkflowRunId;workflowRunAttempt=$binding.WorkflowRunAttempt;revision=$binding.Revision;hostSlot=$hostSlot;probes=$probeRows}
        $groupBytes=ConvertTo-PspktSignatureReferenceJsonBytes -Value $group -MaximumBytes 4096
        (Read-PspktSignatureReferenceProbeGroup -Bytes $groupBytes -HostSlot $hostSlot -Binding $binding).probes.Count | Should -Be 5
        $group.probes[0].caseId=@('returned-failure')
        $reason=try { Read-PspktSignatureReferenceProbeGroup -Bytes (ConvertTo-PspktSignatureReferenceJsonBytes -Value $group -MaximumBytes 4096) -HostSlot $hostSlot -Binding $binding; 'accepted' } catch { $_.Exception.Message }
        $reason | Should -BeExactly 'validation:probe'
    }
    It 'cleanup-and-registry' {
        $observation=[pscustomobject][ordered]@{HashesDisposed=$true;StreamsClosed=$true;CompilerStagingRemoved=$true;
            TestDriveRemoved=$false;TestRegistryAbsent=$true;EnvironmentRestored=$true;LocationsRestored=$true;
            LoadedImagesDeclared=$true;NoUnownedResidue=$true}
        $reason=try { Assert-PspktSignatureReferenceCleanupObservation $observation; 'accepted' } catch { $_.Exception.Message }
        $reason | Should -BeExactly 'validation:cleanup'
        $observation.TestDriveRemoved=$true
        Assert-PspktSignatureReferenceCleanupObservation $observation
        Assert-PspktSignatureReferenceRegistryAbsent
        $root=Join-Path $TestDrive 'declared-artifact-control'
        $images=Join-Path $root 'images'
        [void][IO.Directory]::CreateDirectory($images)
        foreach($image in $CompileCensus) { [IO.File]::WriteAllBytes((Join-Path $images $image.Name),$image.Bytes) }
        [IO.File]::WriteAllText((Join-Path $root 'source-records.v1.json'),'{}',[Text.UTF8Encoding]::new($false,$true))
        [IO.File]::WriteAllText((Join-Path $root 'validation-records.v1.json'),'{}',[Text.UTF8Encoding]::new($false,$true))
        Assert-PspktSignatureReferenceOwnedArtifacts -ArtifactRoot $root -Images $CompileCensus
        $unexpected=Join-Path $root 'unexpected.bin'
        [IO.File]::WriteAllBytes($unexpected,[byte[]]@(1))
        $reason=try { Assert-PspktSignatureReferenceOwnedArtifacts -ArtifactRoot $root -Images $CompileCensus; 'accepted' } catch { $_.Exception.Message }
        $reason | Should -BeExactly 'validation:cleanup'
        [IO.File]::Delete($unexpected)
        $owned=Join-Path $root 'testdrive'
        [void][IO.Directory]::CreateDirectory((Join-Path $owned 'nested'))
        [IO.File]::WriteAllBytes((Join-Path $owned 'nested\owned.bin'),[byte[]]@(1))
        Remove-PspktSignatureReferenceOwnedDirectory -Path $owned -AllowedRoot $owned
        [IO.Directory]::Exists($owned) | Should -BeFalse
        Assert-PspktSignatureReferenceOwnedArtifacts -ArtifactRoot $root -Images $CompileCensus
        Assert-PspktSignatureReferenceRegistryAbsent
    }
}
