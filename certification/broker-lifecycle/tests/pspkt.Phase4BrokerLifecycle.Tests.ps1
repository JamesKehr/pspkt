param(
    [Reflection.Assembly]$BootstrapAssembly,
    [Reflection.Assembly]$RuntimeAssembly,
    [hashtable]$AuthorityBytesById,
    [hashtable]$FixtureBytesById,
    [object]$SourceSnapshot,
    [object[]]$CompilationRecords,
    [object[]]$MutantBuilds,
    [string]$ArtifactRoot,
    [string]$CallerScopeMarker,
    [object]$InvocationContract
)

BeforeAll {
    Set-StrictMode -Version Latest
    $ErrorActionPreference='Stop'
    . ([scriptblock]::Create($SourceSnapshot.RetainedTexts['certification\broker-lifecycle\tests\BrokerLifecycleOracle.ps1']))
    . ([scriptblock]::Create($SourceSnapshot.RetainedTexts['certification\broker-lifecycle\lib\Pspkt.Certification.BrokerLifecycleCompilation.ps1']))
    . ([scriptblock]::Create($SourceSnapshot.RetainedTexts['certification\broker-lifecycle\lib\Pspkt.Certification.BrokerLifecycleContract.ps1']))
    . ([scriptblock]::Create($SourceSnapshot.RetainedTexts['certification\broker-lifecycle\lib\Pspkt.Certification.BrokerLifecycleCi.ps1']))
    function New-TestProtocol {
        param([Reflection.Assembly]$Assembly=$RuntimeAssembly)
        $type=$Assembly.GetType('Pspkt.Certification.BrokerLifecycle.BrokerLifecycleProtocol',$true)
        $arguments=[object[]]::new(9)
        $names=@('ProtocolMeta','ProtocolInventory','ProtocolSchema','MessageAssociation','GeneratedIdMap','BaseTailSchedule','FramingAddendumSchema','FramingAddendum','DesignReviewActivation')
        for($index=0;$index -lt $names.Count;$index++){$arguments[$index]=$AuthorityBytesById[$names[$index]]}
        return $type.GetMethod('CreateFromCommittedAuthorities').Invoke($null,$arguments)
    }
    function Convert-TestHex {
        param([string]$Text)
        $bytes=[byte[]]::new($Text.Length/2)
        for($index=0;$index -lt $bytes.Length;$index++){$bytes[$index]=[Convert]::ToByte($Text.Substring($index*2,2),16)}
        return ,$bytes
    }
    function New-TestFrameArray {
        param([object]$Protocol,[object[]]$Rows)
        $type=$Protocol.GetType().Assembly.GetType('Pspkt.Certification.BrokerLifecycle.DecodedControlFrame',$true)
        $result=[Array]::CreateInstance($type,$Rows.Count)
        for($index=0;$index -lt $Rows.Count;$index++){
            $row=$Rows[$index]
            $result.SetValue($Protocol.Decode($row.channel,$row.direction,[byte]2,(Convert-TestHex $row.frameHex)),$index)
        }
        return ,$result
    }
    function New-TestWorker {
        param([object]$Protocol)
        $type=$Protocol.GetType().Assembly.GetType('Pspkt.Certification.BrokerLifecycle.CheckpointServiceLifecycle',$true)
        return $type.GetMethod('CreateInMemory').Invoke($null,[object[]]@($Protocol,'Worker',$FixtureBytesById.LifecyclePolicy))
    }
    function New-TestBroker {
        param([object]$Protocol)
        $type=$Protocol.GetType().Assembly.GetType('Pspkt.Certification.BrokerLifecycle.CheckpointServiceLifecycle',$true)
        return $type.GetMethod('CreateInMemory').Invoke($null,[object[]]@($Protocol,'Broker',$FixtureBytesById.LifecyclePolicy))
    }
    function Open-TestBroker {
        param([object]$Controller)
        $rows=([Text.Encoding]::UTF8.GetString($FixtureBytesById.BootstrapGoldens)|ConvertFrom-Json).rows
        $broker=@($rows|Where-Object {$_.id -ceq 'BG01'})[0]
        $local=@($rows|Where-Object {$_.id -ceq 'BG04'})[0]
        $Controller.Start([UInt64]0,[UInt64]1000)
        $Controller.Pump([UInt64]0,256)
        for($index=0;$index -lt 4;$index++){
            $bytes=Convert-TestHex $broker.frames[$index].frameHex
            if($index -eq 1){$Controller.FeedPeerBytes('BrokerControl',$bytes,[UInt64]($index+1),[UInt64]1000)}
            else{$Controller.QueueFrame('BrokerControl',$bytes,[UInt64]($index+1),[UInt64]1000)}
            $Controller.Pump([UInt64]($index+1),256)
            [void]$Controller.ReadPeerBytes('BrokerControl',65536,[UInt64]($index+1))
        }
        $Controller.FeedPeerBytes('LocalIpc',(Convert-TestHex $local.frames[0].frameHex),[UInt64]5,[UInt64]1000)
        $Controller.Pump([UInt64]5,256)
        $Controller.QueueFrame('LocalIpc',(Convert-TestHex $local.frames[1].frameHex),[UInt64]6,[UInt64]1000)
        $Controller.Pump([UInt64]6,256)
        [void]$Controller.ReadPeerBytes('LocalIpc',65536,[UInt64]6)
    }
    function Pump-TestUntilFault {
        param([object]$Controller,[UInt64]$Now=7)
        for($step=0;$step -lt 256 -and $Controller.GetSnapshot().PrimaryReasonCode.Length -eq 0;$step++){$Controller.Pump($Now,1)}
        $Controller.GetSnapshot().ServicePhase | Should -BeExactly 'ControllerFaultedUnverified'
        $Controller.GetSnapshot().CleanupComplete | Should -BeFalse
    }
    function Open-TestWorker {
        param([object]$Controller)
        $bootstrap=@(([Text.Encoding]::UTF8.GetString($FixtureBytesById.BootstrapGoldens)|ConvertFrom-Json).rows|Where-Object {$_.id -ceq 'BG04'})[0]
        $Controller.Start([UInt64]0,[UInt64]1000)
        $Controller.Pump([UInt64]0,256)
        $Controller.QueueFrame('LocalIpc',(Convert-TestHex $bootstrap.frames[0].frameHex),[UInt64]1,[UInt64]1000)
        $Controller.Pump([UInt64]1,256)
        [void]$Controller.ReadPeerBytes('LocalIpc',65536,[UInt64]1)
        $Controller.FeedPeerBytes('LocalIpc',(Convert-TestHex $bootstrap.frames[1].frameHex),[UInt64]2,[UInt64]1000)
        $Controller.Pump([UInt64]2,256)
    }
    function Close-TestController {
        param([object]$Controller,[UInt64]$Now=8,[UInt64]$Deadline=1000)
        $Controller.RequestStop($Now,$Deadline)
        for($step=0;$step -lt 256 -and -not $Controller.GetSnapshot().CleanupComplete;$step++){$Controller.Pump($Now,1)}
        $Controller.GetSnapshot().CleanupComplete | Should -BeTrue
        $Controller.Dispose()
    }
    function Close-TestDrivenController {
        param([object]$Controller,[object]$Driver,[UInt64]$Now=8,[UInt64]$Deadline=1000,[string]$Channel='LocalIpc')
        $assembly=$Controller.GetType().Assembly
        $Controller.RequestStop($Now,$Deadline)
        for($step=0;$step -lt 256;$step++){
            if($null -ne $Driver -and (Invoke-PspktBrokerLifecycleTestMember $assembly 'HasPrimaryHeldCompletion' $Driver)){
                try{Invoke-PspktBrokerLifecycleTestMember $assembly 'DeliverPrimaryCompletion' $Driver ([object[]]@($Channel))}
                catch{if($_.Exception.GetBaseException().Message -cne 'lifecycle:state'){throw}}
            }
            if($Controller.GetSnapshot().CleanupComplete){break}
            try{$Controller.Pump($Now,1)}
            catch{if($_.Exception.GetBaseException().Message -cnotin @('transport:deadline','transport:indeterminate-write')){throw}}
        }
        if(-not $Controller.GetSnapshot().CleanupComplete){
            try{$Controller.Pump($Deadline,256)}
            catch{if($_.Exception.GetBaseException().Message -cnotin @('transport:deadline','transport:indeterminate-write')){throw}}
            if($null -ne $Driver -and (Invoke-PspktBrokerLifecycleTestMember $assembly 'HasPrimaryHeldCompletion' $Driver)){
                try{Invoke-PspktBrokerLifecycleTestMember $assembly 'DeliverPrimaryCompletion' $Driver ([object[]]@($Channel))}
                catch{if($_.Exception.GetBaseException().Message -cne 'lifecycle:state'){throw}}
            }
            $Controller.Pump($Deadline,256)
        }
        $Controller.GetSnapshot().CleanupComplete | Should -BeTrue
        if($null -ne $Driver){Invoke-PspktBrokerLifecycleTestMember $assembly 'DriverDispose' $Driver}
        $Controller.Dispose()
    }
    function New-TestRetirementReference {
        param([bool]$WithDriver)
        $protocol=New-TestProtocol
        $controller=New-TestWorker $protocol
        $driver=$null
        if($WithDriver){$driver=Invoke-PspktBrokerLifecycleTestMember $RuntimeAssembly 'DriverCreate' $null ([object[]]@($controller,$null))}
        $reference=[WeakReference]::new($controller)
        $controller.Dispose()
        if($null -ne $driver){Invoke-PspktBrokerLifecycleTestMember $RuntimeAssembly 'DriverDispose' $driver}
        $controller=$null
        $protocol=$null
        return [pscustomobject]@{Reference=$reference;Driver=$driver}
    }
    function Assert-TestUnchangedControllerRejection {
        param([scriptblock]$Operation,[string]$ExpectedReason,[object[]]$Controllers=@())
        $before=@($Controllers|ForEach-Object {$_.GetSnapshot()|ConvertTo-Json -Depth 5 -Compress})
        $reason=$null
        try{[void](& $Operation)}
        catch{$reason=$_.Exception.GetBaseException().Message}
        $reason | Should -BeExactly $ExpectedReason
        for($index=0;$index -lt $Controllers.Count;$index++){
            ($Controllers[$index].GetSnapshot()|ConvertTo-Json -Depth 5 -Compress) | Should -BeExactly $before[$index]
        }
    }
    function Invoke-TestForeignChallenge {
        param([Reflection.Assembly]$Assembly)
        $bootstrap=@(([Text.Encoding]::UTF8.GetString($FixtureBytesById.BootstrapGoldens)|ConvertFrom-Json).rows|Where-Object {$_.id -ceq 'BG04'})[0]
        $frame=Convert-TestHex $bootstrap.frames[0].frameHex
        $primary=New-TestWorker (New-TestProtocol $Assembly)
        $foreign=New-TestWorker (New-TestProtocol $Assembly)
        $driver=$null
        $result=$null
        try{
            foreach($controller in @($primary,$foreign)){
                $controller.Start([UInt64]0,[UInt64]1000)
                $controller.Pump([UInt64]0,256)
                $controller.QueueFrame('LocalIpc',$frame,[UInt64]1,[UInt64]1000)
                $controller.Pump([UInt64]1,1)
                $controller.GetSnapshot().RunGenerationId | Should -Be 1
            }
            $driver=Invoke-PspktBrokerLifecycleTestMember $Assembly 'DriverCreate' $null ([object[]]@($primary,$foreign))
            $primaryScript=New-PspktBrokerLifecycleOutcomeScript $Assembly ([int[]]@(4)) ([int[]]@(0))
            $foreignScript=New-PspktBrokerLifecycleOutcomeScript $Assembly ([int[]]@(4,5)) ([int[]]@(0,0))
            Invoke-PspktBrokerLifecycleTestMember $Assembly 'BindPrimaryWrite' $driver ([object[]]@('LocalIpc',$primaryScript))
            Invoke-PspktBrokerLifecycleTestMember $Assembly 'BindForeignWrite' $driver ([object[]]@('LocalIpc',$foreignScript))
            $primary.Pump([UInt64]1,1)
            $foreign.Pump([UInt64]1,1)
            (Invoke-PspktBrokerLifecycleTestMember $Assembly 'HasPrimaryHeldCompletion' $driver) | Should -BeTrue
            (Invoke-PspktBrokerLifecycleTestMember $Assembly 'HasForeignHeldCompletion' $driver) | Should -BeTrue
            $primary.ReadPeerBytes('LocalIpc',65536,[UInt64]1).Length | Should -Be 536
            $foreign.ReadPeerBytes('LocalIpc',65536,[UInt64]1).Length | Should -Be 536
            Assert-TestUnchangedControllerRejection {
                Invoke-PspktBrokerLifecycleTestMember $Assembly 'DeliverForeignCompletion' $driver ([object[]]@('LocalIpc'))
            } 'argument:context' @($primary,$foreign)
            Assert-TestUnchangedControllerRejection {
                Invoke-PspktBrokerLifecycleTestMember $Assembly 'DeliverForeignCompletionToPrimary' $driver ([object[]]@('BrokerControl'))
            } 'argument:context' @($primary,$foreign)
            (Invoke-PspktBrokerLifecycleTestMember $Assembly 'HasForeignHeldCompletion' $driver) | Should -BeTrue
            $before=$primary.GetSnapshot()|ConvertTo-Json -Depth 5 -Compress
            $reason=$null
            try{Invoke-PspktBrokerLifecycleTestMember $Assembly 'DeliverForeignCompletionToPrimary' $driver ([object[]]@('LocalIpc'))}
            catch{$reason=$_.Exception.GetBaseException().Message}
            $after=$primary.GetSnapshot()
            $ownReason=$null
            try{Invoke-PspktBrokerLifecycleTestMember $Assembly 'DeliverPrimaryCompletion' $driver ([object[]]@('LocalIpc'))}
            catch{$ownReason=$_.Exception.GetBaseException().Message}
            $duplicate=$null
            try{Invoke-PspktBrokerLifecycleTestMember $Assembly 'DeliverPrimaryCompletion' $driver ([object[]]@('LocalIpc'))}
            catch{$duplicate=$_.Exception.GetBaseException().Message}
            $duplicate | Should -BeExactly 'lifecycle:state'
            $result=[pscustomobject]@{ForeignReason=$reason;Before=$before;After=($after|ConvertTo-Json -Depth 5 -Compress);
                PrematureRecords=$after.LocalIpcWorkerToBrokerObservedRecordCount;OwnReason=$ownReason;
                FinalRecords=$primary.GetSnapshot().LocalIpcWorkerToBrokerObservedRecordCount}
        }
        finally{
            if($null -ne $driver){
                if(Invoke-PspktBrokerLifecycleTestMember $Assembly 'HasForeignHeldCompletion' $driver){
                    try{Invoke-PspktBrokerLifecycleTestMember $Assembly 'DeliverForeignCompletionToPrimary' $driver ([object[]]@('LocalIpc'))}
                    catch{if($_.Exception.GetBaseException().Message -cnotin @('lifecycle:stale-generation','lifecycle:state')){throw}}
                }
                if(Invoke-PspktBrokerLifecycleTestMember $Assembly 'HasPrimaryHeldCompletion' $driver){
                    try{Invoke-PspktBrokerLifecycleTestMember $Assembly 'DeliverPrimaryCompletion' $driver ([object[]]@('LocalIpc'))}
                    catch{if($_.Exception.GetBaseException().Message -cne 'lifecycle:state'){throw}}
                }
            }
            foreach($controller in @($primary,$foreign)){$controller.RequestStop([UInt64]2,[UInt64]100)}
            foreach($now in @([UInt64]2,[UInt64]100)){
                for($step=0;$step -lt 256;$step++){
                    $complete=$true
                    foreach($controller in @($primary,$foreign)){
                        if(-not $controller.GetSnapshot().CleanupComplete){
                            $complete=$false
                            try{$controller.Pump($now,1)}
                            catch{if($_.Exception.GetBaseException().Message -cne 'transport:deadline'){throw}}
                        }
                    }
                    if($complete){break}
                }
            }
            foreach($controller in @($primary,$foreign)){
                $controller.GetSnapshot().CleanupComplete | Should -BeTrue
                $controller.GetSnapshot().OutstandingDispatchLeases | Should -Be 0
            }
            if($null -ne $driver){Invoke-PspktBrokerLifecycleTestMember $Assembly 'DriverDispose' $driver}
            $primary.Dispose()
            $foreign.Dispose()
        }
        return $result
    }
}

Describe 'Broker lifecycle structural conformance' -Tag 'Precheck' {
    It '01 authority-byte-pins' {
        $AuthorityBytesById.Count | Should -Be 9
        $pins=[ordered]@{
            FramingAddendumSchema='9f00101faf660e1ea3c10904a6358ae16fe1bef4577c0e05f1af9fea86357213'
            FramingAddendum='ae2a255f0a45f9a33fe958e9c728ff535550ea09aec8fcf11398f426f56f0a0f'
            DesignReviewActivation='fee195e7a19a9502330b3e2691c53258130dfbb0b5c1b40eb2a5f81bfdbca24c'
        }
        foreach($name in $pins.Keys){
            $hasher=[Security.Cryptography.SHA256]::Create()
            try{$actual=[BitConverter]::ToString($hasher.ComputeHash($AuthorityBytesById[$name])).Replace('-','').ToLowerInvariant()}
            finally{$hasher.Dispose()}
            $actual | Should -BeExactly $pins[$name]
        }
        $RuntimeAssembly | Should -Not -BeNullOrEmpty
        $factoryType=$RuntimeAssembly.GetType('Pspkt.Certification.BrokerLifecycle.BrokerLifecycleProtocol',$true)
        $factory=$factoryType.GetMethod('CreateFromCommittedAuthorities')
        $orderedNames=@('ProtocolMeta','ProtocolInventory','ProtocolSchema','MessageAssociation','GeneratedIdMap','BaseTailSchedule','FramingAddendumSchema','FramingAddendum','DesignReviewActivation')
        $arguments=[object[]]::new(9)
        for($index=0;$index -lt $orderedNames.Count;$index++){$arguments[$index]=$AuthorityBytesById[$orderedNames[$index]]}
        $protocol=$factory.Invoke($null,$arguments)
        $protocol.GetType().FullName | Should -BeExactly 'Pspkt.Certification.BrokerLifecycle.BrokerLifecycleProtocol'
        for($index=0;$index -lt 8;$index++){
            $changed=[object[]]$arguments.Clone()
            $changed[$index]=[byte[]]$arguments[$index].Clone()
            $changed[$index][0]=$changed[$index][0] -bxor 1
            $reason=$null
            try{[void]$factory.Invoke($null,$changed)}
            catch{$reason=$_.Exception.GetBaseException().Message}
            $reason | Should -BeExactly 'authority:pin'
        }
        $ready=[Text.Encoding]::UTF8.GetString($arguments[8])
        $changed=[object[]]$arguments.Clone()
        $changed[8]=[Text.Encoding]::UTF8.GetBytes($ready.Replace('UnanimousDESIGN_READY','Pending'))
        $reason=$null
        try{[void]$factory.Invoke($null,$changed)}
        catch{$reason=$_.Exception.GetBaseException().Message}
        $reason | Should -BeExactly 'authority:design-review-pending'
        $changed[8]=[Text.Encoding]::UTF8.GetBytes($ready.Replace('b52563460c3f27021d038d322cf42fc6766b0706f84d006ecfdadebb737467ca',('0'*64)))
        $reason=$null
        try{[void]$factory.Invoke($null,$changed)}
        catch{$reason=$_.Exception.GetBaseException().Message}
        $reason | Should -BeExactly 'authority:design-review-binding'
        $FixtureBytesById.ContainsKey('LifecyclePolicy') | Should -BeTrue
        $controllerType=$RuntimeAssembly.GetType('Pspkt.Certification.BrokerLifecycle.CheckpointServiceLifecycle',$true)
        $createController=$controllerType.GetMethod('CreateInMemory')
        foreach($role in @('Broker','Worker')){
            $controller=$createController.Invoke($null,[object[]]@($protocol,$role,$FixtureBytesById.LifecyclePolicy))
            $controller.GetType().FullName | Should -BeExactly $controllerType.FullName
            $controller.Dispose()
        }
        $badPolicy=[byte[]]$FixtureBytesById.LifecyclePolicy.Clone()
        $badPolicy[0]=$badPolicy[0] -bxor 1
        $reason=$null
        try{[void]$createController.Invoke($null,[object[]]@($protocol,'Worker',$badPolicy))}
        catch{$reason=$_.Exception.GetBaseException().Message}
        $reason | Should -BeExactly 'authority:pin'
    }

    It '02 base-association-closure' {
        $FixtureBytesById.ContainsKey('GeneratedFrames') | Should -BeTrue
        $frames=([Text.Encoding]::UTF8.GetString($FixtureBytesById.GeneratedFrames)|ConvertFrom-Json).rows
        $frames.Count | Should -Be 22
        $expected=@(
            'BrokerControl|BrokerToHost|4353|BootstrapBrokerHello'
            'BrokerControl|HostToBroker|4354|BrokerBootstrapHostHello'
            'BrokerControl|BrokerToHost|4355|BootstrapBrokerContext'
            'BrokerControl|BrokerToHost|4356|BootstrapBrokerFinished'
            'BrokerControl|HostToBroker|4369|TokenMintAuthorizationBodyV1'
            'BrokerControl|HostToBroker|4372|Keepalive'
            'BrokerControl|BrokerToHost|4372|Keepalive'
            'BrokerControl|BrokerToHost|4373|BrokerFailure'
            'BrokerControl|HostToBroker|4373|BrokerFailure'
            'BrokerControl|BrokerToHost|4375|BrokerMintInstallSampleV1'
            'BrokerControl|HostToBroker|4376|BrokerMintDeadlineAuthorizationV1'
            'BrokerControl|BrokerToHost|4377|LocalTranscriptChunkV1'
            'BrokerControl|BrokerToHost|4378|LocalTranscriptRootV1'
            'BrokerControl|HostToBroker|4379|LocalTranscriptRootAcceptedV1'
            'LocalIpc|WorkerToBroker|4609|LocalHelloW'
            'LocalIpc|BrokerToWorker|4610|LocalHelloB'
            'LocalIpc|WorkerToBroker|4624|MintRequest'
            'LocalIpc|BrokerToWorker|4625|MintResult'
            'LocalIpc|WorkerToBroker|4626|LocalKeepalive'
            'LocalIpc|BrokerToWorker|4626|LocalKeepalive'
            'LocalIpc|WorkerToBroker|4627|LocalFailure'
            'LocalIpc|BrokerToWorker|4627|LocalFailure'
        )
        $actual=@($frames|ForEach-Object {$_.channel+'|'+$_.direction+'|'+$_.kind+'|'+$_.payloadRoot})
        ($actual -join "`n") | Should -BeExactly ($expected -join "`n")
        $protocol=New-TestProtocol
        $accepted=0
        $contexts=@('WorkerApp|WorkerToHost','WorkerApp|HostToWorker','BrokerControl|HostToBroker','BrokerControl|BrokerToHost','LocalIpc|WorkerToBroker','LocalIpc|BrokerToWorker')
        $kinds=@(0,1,2,3,4,5,6,7,4224,4353,4354,4355,4356,4368,4369,4370,4371,4372,4373,4374,4375,4376,4377,4378,4379,4609,4610,4624,4625,4626,4627,65535)
        foreach($context in $contexts){
            $parts=$context.Split('|')
            foreach($kind in $kinds){
                $positive=@($frames|Where-Object {$_.channel -ceq $parts[0] -and $_.direction -ceq $parts[1] -and $_.kind -eq $kind})
                if($positive.Count -eq 1){$bytes=Convert-TestHex $positive[0].frameHex}
                else{$bytes=Convert-TestHex $frames[0].frameHex;$bytes[6]=[byte][Math]::Floor($kind/256);$bytes[7]=[byte]($kind%256)}
                if($positive.Count -eq 1){
                    $decoded=$protocol.Decode($parts[0],$parts[1],[byte]2,$bytes)
                    $decoded.Kind | Should -Be $kind
                    $decoded.Channel | Should -BeExactly $parts[0]
                    $decoded.Direction | Should -BeExactly $parts[1]
                    $accepted++
                }
                else{
                    $reason=$null
                    try{[void]$protocol.Decode($parts[0],$parts[1],[byte]2,$bytes)}
                    catch{$reason=$_.Exception.GetBaseException().Message}
                    $wanted='frame:kind-unavailable'
                    if($parts[0] -ceq 'WorkerApp'){$wanted='frame:channel-unavailable'}
                    elseif(@($frames|Where-Object {$_.channel -ceq $parts[0] -and $_.kind -eq $kind}).Count -gt 0){$wanted='frame:direction'}
                    $reason | Should -BeExactly $wanted
                }
            }

        }
        $accepted | Should -Be 22
        foreach($frame in $frames){
            foreach($profile in @(0,1,3,255)){
                $reason=$null
                try{[void]$protocol.Decode($frame.channel,$frame.direction,[byte]$profile,(Convert-TestHex $frame.frameHex))}
                catch{$reason=$_.Exception.GetBaseException().Message}
                $reason | Should -BeExactly 'frame:profile'
            }
        }
    }

    It '03 omitted-kinds-and-tail-status' {
        $protocol=New-TestProtocol
        $frames=([Text.Encoding]::UTF8.GetString($FixtureBytesById.GeneratedFrames)|ConvertFrom-Json).rows
        foreach($kind in @(4368,4370,4371,4374)){
            $bytes=Convert-TestHex $frames[0].frameHex
            $bytes[6]=[byte][Math]::Floor($kind/256)
            $bytes[7]=[byte]($kind%256)
            foreach($direction in @('HostToBroker','BrokerToHost')){
                $reason=$null
                try{[void]$protocol.Decode('BrokerControl',$direction,[byte]2,$bytes)}
                catch{$reason=$_.Exception.GetBaseException().Message}
                $reason | Should -BeExactly 'frame:kind-unavailable'
            }
        }
        $controllerType=$RuntimeAssembly.GetType('Pspkt.Certification.BrokerLifecycle.CheckpointServiceLifecycle',$true)
        foreach($role in @('Broker','Worker')){
            $controller=$controllerType.GetMethod('CreateInMemory').Invoke($null,[object[]]@($protocol,$role,$FixtureBytesById.LifecyclePolicy))
            try{
                $snapshot=$controller.GetSnapshot()
                $snapshot.TrustCeiling | Should -BeExactly 'StructuralInProcessOnly'
                $snapshot.LocalTailAuthorityStatus | Should -BeExactly 'UnavailableForSelectedBaseSnapshot'
                if($role -ceq 'Broker'){$snapshot.BrokerTailAuthorityStatus | Should -BeExactly 'UnavailableForSelectedBaseSnapshot'}
                else{
                    $snapshot.BrokerTailAuthorityStatus | Should -BeExactly 'NotApplicableToRole'
                    $snapshot.BrokerConnectionPhase | Should -BeExactly 'TransportNotApplicableToRole'
                    $snapshot.BrokerHelloProgress | Should -BeExactly 'BrokerBootstrapNotApplicableToRole'
                    $snapshot.BrokerControlHostToBrokerObservedRecordCount | Should -Be 0
                    $snapshot.BrokerControlBrokerToHostObservedRecordCount | Should -Be 0
                }
            }
            finally{$controller.Dispose()}
        }
    }

    It '04 canonical-payload-and-primitive-abi' {
        $protocol=New-TestProtocol
        $frames=([Text.Encoding]::UTF8.GetString($FixtureBytesById.GeneratedFrames)|ConvertFrom-Json).rows
        foreach($row in $frames){
            $decoded=$protocol.Decode($row.channel,$row.direction,[byte]2,(Convert-TestHex $row.frameHex))
            $decoded.Kind | Should -Be $row.kind
        }
        foreach($specification in @(@(4353,[int[]]@(9)),@(4369,[int[]]@(7)),@(4355,[int[]]@(1,8)),@(4610,[int[]]@(8,8)))){
            $row=@($frames|Where-Object {$_.kind -eq $specification[0]})[0]
            foreach($profile in @(0,1,3,255)){
                $changed=Set-PspktBrokerLifecycleOracleFrameField (Convert-TestHex $row.frameHex) $specification[1] ([byte[]]@($profile))
                $reason=$null
                try{[void]$protocol.Decode($row.channel,$row.direction,[byte]2,$changed)}
                catch{$reason=$_.Exception.GetBaseException().Message}
                $reason | Should -BeExactly 'frame:profile'
            }
        }
        foreach($specification in @(@(4355,[int[]]@(2,3)),@(4610,[int[]]@(9,3)))){
            $row=@($frames|Where-Object {$_.kind -eq $specification[0]})[0]
            foreach($length in @(383,385)){
                $changed=Set-PspktBrokerLifecycleOracleFrameField (Convert-TestHex $row.frameHex) $specification[1] (New-PspktBrokerLifecycleOraclePattern $length 165)
                $reason=$null
                try{[void]$protocol.Decode($row.channel,$row.direction,[byte]2,$changed)}
                catch{$reason=$_.Exception.GetBaseException().Message}
                $reason | Should -BeExactly 'payload:primitive'
            }
        }
        $hello=@($frames|Where-Object {$_.kind -eq 4353})[0]
        foreach($value in @([byte[]]@(),([Text.Encoding]::ASCII.GetBytes('not valid')),(New-PspktBrokerLifecycleOraclePattern 129 65))){
            $changed=Set-PspktBrokerLifecycleOracleFrameField (Convert-TestHex $hello.frameHex) @(15) $value
            $reason=$null
            try{[void]$protocol.Decode($hello.channel,$hello.direction,[byte]2,$changed)}
            catch{$reason=$_.Exception.GetBaseException().Message}
            $reason | Should -BeExactly 'payload:primitive'
        }
        $maximumAscii=Set-PspktBrokerLifecycleOracleFrameField (Convert-TestHex $hello.frameHex) @(15) (New-PspktBrokerLifecycleOraclePattern 128 65)
        $protocol.Decode($hello.channel,$hello.direction,[byte]2,$maximumAscii).Kind | Should -Be 4353
        foreach($length in @(23,513)){
            $changed=Set-PspktBrokerLifecycleOracleFrameField (Convert-TestHex $hello.frameHex) @(1) (New-PspktBrokerLifecycleOraclePattern $length 1)
            $reason=$null
            try{[void]$protocol.Decode($hello.channel,$hello.direction,[byte]2,$changed)}
            catch{$reason=$_.Exception.GetBaseException().Message}
            $reason | Should -BeExactly 'payload:primitive'
        }
        $badSid=Set-PspktBrokerLifecycleOracleFrameField (Convert-TestHex $hello.frameHex) @(16) ([byte[]]@(2,0,0,0,0,0,0,5))
        $reason=$null
        try{[void]$protocol.Decode($hello.channel,$hello.direction,[byte]2,$badSid)}
        catch{$reason=$_.Exception.GetBaseException().Message}
        $reason | Should -BeExactly 'payload:primitive'
        $accepted=@($frames|Where-Object {$_.kind -eq 4379})[0]
        $nilChallenge=Set-PspktBrokerLifecycleOracleFrameField (Convert-TestHex $accepted.frameHex) @(4) ([byte[]]::new(16))
        $protocol.Decode($accepted.channel,$accepted.direction,[byte]2,$nilChallenge).Kind | Should -Be 4379
        $chunk=@($frames|Where-Object {$_.kind -eq 4377})[0]
        $badBounded=Set-PspktBrokerLifecycleOracleFrameField (Convert-TestHex $chunk.frameHex) @(10) ([byte[]]@(0,0,0,1))
        $reason=$null
        try{[void]$protocol.Decode($chunk.channel,$chunk.direction,[byte]2,$badBounded)}
        catch{$reason=$_.Exception.GetBaseException().Message}
        $reason | Should -BeExactly 'payload:length'
        $keepalive=@($frames|Where-Object {$_.kind -eq 4372})[0]
        $wrongTag=Convert-TestHex $keepalive.frameHex
        $wrongTag[25]=2
        $reason=$null
        try{[void]$protocol.Decode($keepalive.channel,$keepalive.direction,[byte]2,$wrongTag)}
        catch{$reason=$_.Exception.GetBaseException().Message}
        $reason | Should -BeExactly 'payload:tag'
        foreach($specification in @(@(4353,9,1),@(4373,1,2),@(4609,2,4),@(4369,3,8),@(4609,3,8),@(4375,5,8),@(4609,4,16),@(4353,2,32),@(4609,1,32))){
            $row=@($frames|Where-Object {$_.kind -eq $specification[0]})[0]
            foreach($length in @(($specification[2]-1),($specification[2]+1))){
                $changed=Set-PspktBrokerLifecycleOracleFrameField (Convert-TestHex $row.frameHex) @($specification[1]) (New-PspktBrokerLifecycleOraclePattern $length 1)
                $reason=$null
                try{[void]$protocol.Decode($row.channel,$row.direction,[byte]2,$changed)}
                catch{$reason=$_.Exception.GetBaseException().Message}
                $reason | Should -BeExactly 'payload:primitive'
            }
        }
        $root=@($frames|Where-Object {$_.kind -eq 4378})[0]
        foreach($length in @(512,513)){
            $bounded=Join-PspktBrokerLifecycleOracleBytes @((New-PspktBrokerLifecycleOracleUnsigned 4 $length),(New-PspktBrokerLifecycleOraclePattern $length 66))
            $changed=Set-PspktBrokerLifecycleOracleFrameField (Convert-TestHex $root.frameHex) @(10) $bounded
            if($length -eq 512){$protocol.Decode($root.channel,$root.direction,[byte]2,$changed).Kind | Should -Be 4378}
            else{
                $reason=$null
                try{[void]$protocol.Decode($root.channel,$root.direction,[byte]2,$changed)}
                catch{$reason=$_.Exception.GetBaseException().Message}
                $reason | Should -BeExactly 'payload:primitive'
            }
        }
        $original=Convert-TestHex $keepalive.frameHex
        $payload=[byte[]]$original[24..37]
        foreach($replacement in @([byte[]]@(),(Join-PspktBrokerLifecycleOracleBytes @($payload,$payload)),(Join-PspktBrokerLifecycleOracleBytes @($payload,[byte[]]@(165))))){
            $changed=Set-PspktBrokerLifecycleOracleFramePayload $original $replacement
            $reason=$null
            try{[void]$protocol.Decode($keepalive.channel,$keepalive.direction,[byte]2,$changed)}
            catch{$reason=$_.Exception.GetBaseException().Message}
            $wanted='payload:trailing'
            if($replacement.Length -eq 0){$wanted='payload:length'}
            $reason | Should -BeExactly $wanted
        }
    }

    It '05 payload-budget-before-allocation' {
        Invoke-PspktBrokerLifecycleInternal $RuntimeAssembly 'ValidateLogicalBudget' ([object[]]@([UInt64]1966080,[UInt64]8192,[int]4,[int]4096))
        foreach($arguments in @(
            [object[]]@([UInt64]1966081,[UInt64]8192,[int]4,[int]4096),
            [object[]]@([UInt64]0,[UInt64]8193,[int]1,[int]0),
            [object[]]@([UInt64]0,[UInt64]0,[int]5,[int]0),
            [object[]]@([UInt64]0,[UInt64]0,[int]1,[int]4097),
            [object[]]@([UInt64]::MaxValue,[UInt64]::MaxValue,[int]4,[int]4096),
            [object[]]@([UInt64]0,[UInt64]0,[int]0,[int]0),
            [object[]]@([UInt64]0,[UInt64]0,[int]1,[int]-1)
        )){
            $reason=$null
            try{Invoke-PspktBrokerLifecycleInternal $RuntimeAssembly 'ValidateLogicalBudget' $arguments}
            catch{$reason=$_.Exception.GetBaseException().Message}
            $reason | Should -BeExactly 'payload:budget'
        }
        $protocol=New-TestProtocol
        $row=@(([Text.Encoding]::UTF8.GetString($FixtureBytesById.GeneratedFrames)|ConvertFrom-Json).rows|Where-Object {$_.kind -eq 4372})[0]
        $bytes=Convert-TestHex $row.frameHex
        [Array]::Copy(([byte[]]@(255,255,255,255)),0,$bytes,26,4)
        $reason=$null
        try{[void]$protocol.Decode($row.channel,$row.direction,[byte]2,$bytes)}
        catch{$reason=$_.Exception.GetBaseException().Message}
        $reason | Should -BeExactly 'payload:length'
    }

    It '06 header-layout-and-full-frame-bound' {
        $protocol=New-TestProtocol
        $row=@(([Text.Encoding]::UTF8.GetString($FixtureBytesById.GeneratedFrames)|ConvertFrom-Json).rows|Where-Object {$_.kind -eq 4372})[0]
        foreach($change in @(@(0,81,'frame:header'),@(5,2,'frame:version'),@(9,1,'frame:flags'),@(11,1,'frame:reserved'))){
            $bytes=Convert-TestHex $row.frameHex
            $bytes[$change[0]]=[byte]$change[1]
            $reason=$null
            try{[void]$protocol.Decode($row.channel,$row.direction,[byte]2,$bytes)}
            catch{$reason=$_.Exception.GetBaseException().Message}
            $reason | Should -BeExactly $change[2]
        }
        Invoke-PspktBrokerLifecycleInternal $RuntimeAssembly 'ValidateCompleteFrameLength' ([object[]]@([UInt64]1048168,[UInt64]1048576))
        foreach($arguments in @([object[]]@([UInt64]1048169,[UInt64]1048577),[object[]]@([UInt64]::MaxValue,[UInt64]407),[object[]]@([UInt64]14,[UInt64]421))){
            $reason=$null
            try{Invoke-PspktBrokerLifecycleInternal $RuntimeAssembly 'ValidateCompleteFrameLength' $arguments}
            catch{$reason=$_.Exception.GetBaseException().Message}
            $reason | Should -BeExactly 'frame:length'
        }
        $FixtureBytesById.ContainsKey('FramingGoldens') | Should -BeTrue
        $goldens=([Text.Encoding]::UTF8.GetString($FixtureBytesById.FramingGoldens)|ConvertFrom-Json).rows
        foreach($golden in @($goldens|Where-Object {$_.id -cin @('FG01','FG02','FG03','FG04')})){
            $expected=Convert-TestHex $golden.frameHex
            $payload=[byte[]]$expected[24..37]
            $signature=[byte[]]$expected[38..421]
            $encoded=$protocol.Encode($golden.channel,$golden.direction,[byte]2,[UInt16]$golden.kind,[UInt64]1,$payload,$signature)
            [BitConverter]::ToString($encoded) | Should -BeExactly ([BitConverter]::ToString($expected))
            (Get-PspktBrokerLifecycleOracleDigest $encoded) | Should -BeExactly $golden.sha256
            $decoded=$protocol.Decode($golden.channel,$golden.direction,[byte]2,$encoded)
            $decoded.Sequence | Should -Be 1
            $decoded.PayloadLength | Should -Be 14
            $decoded.CompleteSignedFrame.Length | Should -Be 422
        }
        $oversized=Convert-TestHex $row.frameHex
        [Array]::Copy(([byte[]]@(255,255,255,255)),0,$oversized,20,4)
        $reason=$null
        try{[void]$protocol.Decode($row.channel,$row.direction,[byte]2,$oversized)}
        catch{$reason=$_.Exception.GetBaseException().Message}
        $reason | Should -BeExactly 'frame:length'
        $sequence=[Convert]::ToUInt64('0102030405060708',16)
        $example=Convert-TestHex $goldens[0].frameHex
        $encoded=$protocol.Encode('BrokerControl','HostToBroker',[byte]2,[UInt16]4372,$sequence,[byte[]]$example[24..37],[byte[]]$example[38..421])
        [BitConverter]::ToString($encoded[12..19]).Replace('-','').ToLowerInvariant() | Should -BeExactly '0102030405060708'
        $protocol.Decode('BrokerControl','HostToBroker',[byte]2,$encoded).Sequence | Should -Be $sequence
    }

    It '07 signature-preimage-channel-matrix' {
        $protocol=New-TestProtocol
        $goldens=([Text.Encoding]::UTF8.GetString($FixtureBytesById.FramingGoldens)|ConvertFrom-Json).rows
        $local=@($goldens|Where-Object {$_.id -ceq 'FG03'})[0]
        $frame=$protocol.Decode('LocalIpc','WorkerToBroker',[byte]2,(Convert-TestHex $local.frameHex))
        $localIdentifier=Convert-TestHex '2031425364754887a9bacbdcedfe0f10'
        $evidenceMeta=Convert-TestHex 'b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf'
        $evidenceSchema=Convert-TestHex 'd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef'
        $preimage=$protocol.BuildSignaturePreimage($frame,[byte]2,$localIdentifier,$evidenceMeta,$evidenceSchema)
        [Text.Encoding]::ASCII.GetString($preimage,0,27) | Should -BeExactly 'pspkt-phase4-local-frame-v1'
        $groups=@($goldens|Where-Object {$_.id -cin @('FG05','FG06')})
        $groups.Count | Should -Be 2
        $count=0
        foreach($group in $groups){
            foreach($item in $group.cases){
                $decoded=$protocol.Decode($item.channel,$item.direction,[byte]2,(Convert-TestHex $item.frameHex))
                $actual=$protocol.BuildSignaturePreimage($decoded,[byte]$item.role,(Convert-TestHex $item.channelIdentifier),$evidenceMeta,$evidenceSchema)
                $actual.Length | Should -Be $item.preimageLength
                [BitConverter]::ToString($actual).Replace('-','').ToLowerInvariant() | Should -BeExactly $item.preimageHex
                (Get-PspktBrokerLifecycleOracleDigest $actual) | Should -BeExactly $item.sha256
                $count++
            }
        }
        $count | Should -Be 5
        $workerCase=@($groups[1].cases|Where-Object {$_.kind -eq 4609})[0]
        $workerFrame=$protocol.Decode('LocalIpc','WorkerToBroker',[byte]2,(Convert-TestHex $workerCase.frameHex))
        $workerPreimage=Convert-TestHex $workerCase.preimageHex
        $swappedRole=Copy-PspktBrokerLifecycleOracleSwappedRanges $workerPreimage 28 29 1
        (Get-PspktBrokerLifecycleOracleDigest $swappedRole) | Should -BeExactly '173e0178be41c0cfbe47912354cd90b329cc19865b96687200a61f944faec9a8'
        $swappedRole[28] | Should -Be 2
        $swappedRole[29] | Should -Be 1
        $reason=$null
        try{[void]$protocol.BuildSignaturePreimage($workerFrame,[byte]$swappedRole[29],$localIdentifier,$evidenceMeta,$evidenceSchema)}
        catch{$reason=$_.Exception.GetBaseException().Message}
        $reason | Should -BeExactly 'context:role'
        $swappedEvidence=Copy-PspktBrokerLifecycleOracleSwappedRanges $workerPreimage 110 142 32
        (Get-PspktBrokerLifecycleOracleDigest $swappedEvidence) | Should -BeExactly 'b216ab8206da16ae93baf00d82227143f6088a861e86eabde1cb4f2753c45e48'
        $actual=$protocol.BuildSignaturePreimage($workerFrame,[byte]2,$localIdentifier,$evidenceSchema,$evidenceMeta)
        [BitConverter]::ToString($actual) | Should -BeExactly ([BitConverter]::ToString($swappedEvidence))
        (Get-PspktBrokerLifecycleOracleDigest $actual) | Should -BeExactly 'b216ab8206da16ae93baf00d82227143f6088a861e86eabde1cb4f2753c45e48'
        foreach($swap in @(
            @{CaseIndex=0;FirstPath=[int[]]@(10);SecondPath=[int[]]@(11);FirstOffset=469;SecondOffset=491;Width=16;
                FirstHex='5061728394a54b8a9cadbecfd0e1f203';SecondHex='4051627384954a89abbccddeef102132';
                Sha256='479a4bfdee63d26bb0b5f02506884abcb2bb28768a3445a66981bb64464a2d42'},
            @{CaseIndex=0;FirstPath=[int[]]@(2);SecondPath=[int[]]@(12);FirstOffset=228;SecondOffset=513;Width=32;
                FirstHex='87a9ecb9c81bf0a11aaf8f3a9c4697528224d4125b86ebd21e7dc23c5a0d2f5b';
                SecondHex='101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f';
                Sha256='69f1389f8b9dd319b39870ec685f064135419b8fd99740f511e2ab9b106bd0b6'},
            @{CaseIndex=1;FirstPath=[int[]]@(2);SecondPath=[int[]]@(3);FirstOffset=236;SecondOffset=274;Width=32;
                FirstHex='101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f';
                SecondHex='303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f';
                Sha256='b7a7173e7b199f669bdad3190524ca339e8a1f462e5c041d409b198f09114be7'},
            @{CaseIndex=2;FirstPath=[int[]]@(1,6);SecondPath=[int[]]@(1,7);FirstOffset=346;SecondOffset=368;Width=16;
                FirstHex='4051627384954a89abbccddeef102132';SecondHex='60718293a4b54c8badbecfd0e1f20314';
                Sha256='f2f25092c0edc4a22bdd4bc4fca103c6628c19c18918c7eedf87537869ed051a'}
        )){
            $item=$groups[0].cases[$swap.CaseIndex]
            $expected=Copy-PspktBrokerLifecycleOracleSwappedRanges (Convert-TestHex $item.preimageHex) $swap.FirstOffset $swap.SecondOffset $swap.Width
            (Get-PspktBrokerLifecycleOracleDigest $expected) | Should -BeExactly $swap.Sha256
            $changed=Set-PspktBrokerLifecycleOracleFrameField (Convert-TestHex $item.frameHex) $swap.FirstPath (Convert-TestHex $swap.SecondHex)
            $changed=Set-PspktBrokerLifecycleOracleFrameField $changed $swap.SecondPath (Convert-TestHex $swap.FirstHex)
            $decoded=$protocol.Decode($item.channel,$item.direction,[byte]2,$changed)
            $actual=$protocol.BuildSignaturePreimage($decoded,[byte]$item.role,(Convert-TestHex $item.channelIdentifier),$evidenceMeta,$evidenceSchema)
            [BitConverter]::ToString($actual) | Should -BeExactly ([BitConverter]::ToString($expected))
            (Get-PspktBrokerLifecycleOracleDigest $actual) | Should -BeExactly $swap.Sha256
        }
        $reason=$null
        try{[void]$protocol.BuildSignaturePreimage($frame,[byte]1,$localIdentifier,$evidenceMeta,$evidenceSchema)}
        catch{$reason=$_.Exception.GetBaseException().Message}
        $reason | Should -BeExactly 'context:role'
        $foreign=(New-TestProtocol).Decode('LocalIpc','WorkerToBroker',[byte]2,(Convert-TestHex $local.frameHex))
        $reason=$null
        try{[void]$protocol.BuildSignaturePreimage($foreign,[byte]2,$localIdentifier,$evidenceMeta,$evidenceSchema)}
        catch{$reason=$_.Exception.GetBaseException().Message}
        $reason | Should -BeExactly 'argument:owner'
        $context=@($groups[0].cases|Where-Object {$_.kind -eq 4355})[0]
        $changed=Set-PspktBrokerLifecycleOracleFrameField (Convert-TestHex $context.frameHex) @(1,16) ([byte[]]::new(32))
        $reason=$null
        try{[void]$protocol.Decode('BrokerControl','BrokerToHost',[byte]2,$changed)}
        catch{$reason=$_.Exception.GetBaseException().Message}
        $reason | Should -BeExactly 'context:protocol-schema'
        $hello=@($groups[0].cases|Where-Object {$_.kind -eq 4353})[0]
        $decoded=$protocol.Decode($hello.channel,$hello.direction,[byte]2,(Convert-TestHex $hello.frameHex))
        $reason=$null
        try{[void]$protocol.BuildSignaturePreimage($decoded,[byte]3,(Convert-TestHex $hello.channelIdentifier),([byte[]]::new(32)),$evidenceSchema)}
        catch{$reason=$_.Exception.GetBaseException().Message}
        $reason | Should -BeExactly 'context:evidence-schema-meta'
        $reason=$null
        try{[void]$protocol.BuildSignaturePreimage($decoded,[byte]3,$localIdentifier,$evidenceMeta,$evidenceSchema)}
        catch{$reason=$_.Exception.GetBaseException().Message}
        $reason | Should -BeExactly 'context:binding-shape'
        $protocol.GetType().GetMethod('CreateFromCommittedAuthorities').GetParameters().Length | Should -Be 9
    }

    It '08 trailer-is-structural-only' {
        $protocol=New-TestProtocol
        $row=@(([Text.Encoding]::UTF8.GetString($FixtureBytesById.GeneratedFrames)|ConvertFrom-Json).rows|Where-Object {$_.kind -eq 4626})[0]
        $original=Convert-TestHex $row.frameHex
        $payload=[byte[]]$original[24..37]
        $signature=[byte[]]::new(384)
        $encoded=$protocol.Encode($row.channel,$row.direction,[byte]2,[UInt16]4626,[UInt64]1,$payload,$signature)
        $decoded=$protocol.Decode($row.channel,$row.direction,[byte]2,$encoded)
        $tokens=@('frame-signature-unchecked','nested-signature-unchecked','signer-key-binding-unchecked',
            'evidence-schema-context-unverified','peer-identity-unchecked','service-trust-unchecked',
            'bootstrap-authentication-unchecked','message-operational-semantics-unchecked','durable-acceptance-unchecked',
            'cross-lease-replay-unchecked','mandatory-tail-completion-unchecked','keepalive-timing-unchecked','lifecycle-certification-unchecked')
        ($decoded.UncheckedSemantics -join '|') | Should -BeExactly ($tokens -join '|')
        ($protocol.UncheckedSemantics -join '|') | Should -BeExactly ($tokens -join '|')
        $changed=$decoded.UncheckedSemantics
        $changed[0]='caller-mutated'
        ($decoded.UncheckedSemantics -join '|') | Should -BeExactly ($tokens -join '|')
        $changed=$protocol.UncheckedSemantics
        $changed[0]='caller-mutated'
        ($protocol.UncheckedSemantics -join '|') | Should -BeExactly ($tokens -join '|')
        foreach($width in @(383,385)){
            $reason=$null
            try{[void]$protocol.Encode($row.channel,$row.direction,[byte]2,[UInt16]4626,[UInt64]1,$payload,([byte[]]::new($width)))}
            catch{$reason=$_.Exception.GetBaseException().Message}
            $reason | Should -BeExactly 'frame:signature-width'
        }
        $copy=$decoded.Signature
        $copy[0]=255
        $decoded.Signature[0] | Should -Be 0
        $copy=$decoded.CompleteSignedFrame
        $copy[0]=0
        $decoded.CompleteSignedFrame[0] | Should -Be 80
        $copy=$decoded.CanonicalPayload
        $copy[0]=255
        $decoded.CanonicalPayload[0] | Should -Be 0
        @($decoded.GetType().GetProperties()|Where-Object {$_.Name -cmatch 'Authenticated|VerifiedSigner|TrustedPeer'}).Count | Should -Be 0
        $controllerType=$RuntimeAssembly.GetType('Pspkt.Certification.BrokerLifecycle.CheckpointServiceLifecycle',$true)
        $controller=$controllerType.GetMethod('CreateInMemory').Invoke($null,[object[]]@($protocol,'Worker',$FixtureBytesById.LifecyclePolicy))
        try{
            $snapshot=$controller.GetSnapshot()
            $snapshot.TrustCeiling | Should -BeExactly 'StructuralInProcessOnly'
            ($snapshot.UncheckedSemantics -join '|') | Should -BeExactly ($tokens -join '|')
        }
        finally{$controller.Dispose()}
    }

    It '09 wrapped-record-layout' {
        $protocol=New-TestProtocol
        $goldens=([Text.Encoding]::UTF8.GetString($FixtureBytesById.FramingGoldens)|ConvertFrom-Json).rows
        $source=@($goldens|Where-Object {$_.id -ceq 'FG02'})[0]
        $frame=$protocol.Decode($source.channel,$source.direction,[byte]2,(Convert-TestHex $source.frameHex))
        $record=$protocol.BuildTranscriptRecord($frame)
        $record.Length | Should -Be 435
        $record[0] | Should -Be 2
        (Read-PspktBrokerLifecycleOracleUnsigned $record 1 8) | Should -Be 1
        (Read-PspktBrokerLifecycleOracleUnsigned $record 9 4) | Should -Be 422
        $wrappers=@($goldens|Where-Object {$_.id -cin @('FG07','FG08')})
        $wrappers.Count | Should -Be 2
        foreach($wrapper in $wrappers){
            $decoded=$protocol.Decode($wrapper.channel,$wrapper.direction,[byte]2,(Convert-TestHex $wrapper.frameHex))
            $actual=$protocol.BuildTranscriptRecord($decoded)
            [BitConverter]::ToString($actual).Replace('-','').ToLowerInvariant() | Should -BeExactly $wrapper.recordHex
            (Get-PspktBrokerLifecycleOracleDigest $actual) | Should -BeExactly $wrapper.sha256
            $actual[-1] | Should -Be $decoded.Signature[-1]
        }
        $foreign=(New-TestProtocol).Decode($source.channel,$source.direction,[byte]2,(Convert-TestHex $source.frameHex))
        $reason=$null
        try{[void]$protocol.BuildTranscriptRecord($foreign)}
        catch{$reason=$_.Exception.GetBaseException().Message}
        $reason | Should -BeExactly 'argument:owner'
    }

    It '10 broker-finished-wrapped-three' {
        $protocol=New-TestProtocol
        $group=@(([Text.Encoding]::UTF8.GetString($FixtureBytesById.FramingGoldens)|ConvertFrom-Json).rows|Where-Object {$_.id -ceq 'FG05'})[0]
        $frameType=$RuntimeAssembly.GetType('Pspkt.Certification.BrokerLifecycle.DecodedControlFrame',$true)
        $frames=[Array]::CreateInstance($frameType,3)
        for($index=0;$index -lt 3;$index++){
            $item=$group.cases[$index]
            $frames.SetValue($protocol.Decode($item.channel,$item.direction,[byte]2,(Convert-TestHex $item.frameHex)),$index)
        }
        $digest=$protocol.ComputeBootstrapBrokerFinishedDigest($frames)
        [BitConverter]::ToString($digest).Replace('-','').ToLowerInvariant() | Should -BeExactly '3bf8bfe6897e9ef369d1c99a055e33caab24bf518068e89ce435e7924e3cd7b9'
        $FixtureBytesById.ContainsKey('BootstrapGoldens') | Should -BeTrue
        $golden=@(([Text.Encoding]::UTF8.GetString($FixtureBytesById.BootstrapGoldens)|ConvertFrom-Json).rows|Where-Object {$_.id -ceq 'BG02'})[0]
        $parts=[Collections.Generic.List[object]]::new()
        for($index=0;$index -lt 3;$index++){
            $complete=Convert-TestHex $group.cases[$index].frameHex
            $direction=2
            if($index -eq 1){$direction=1}
            $parts.Add([byte[]]@($direction))
            $parts.Add((New-PspktBrokerLifecycleOracleUnsigned 8 0))
            $parts.Add((New-PspktBrokerLifecycleOracleUnsigned 4 $complete.Length))
            $parts.Add($complete)
        }
        $preimage=Join-PspktBrokerLifecycleOracleBytes $parts.ToArray()
        $preimage.Length | Should -Be 3155
        [BitConverter]::ToString($preimage).Replace('-','').ToLowerInvariant() | Should -BeExactly $golden.preimageHex
        (Get-PspktBrokerLifecycleOracleDigest $preimage) | Should -BeExactly $golden.sha256
        $changed=$frames.Clone()
        $changed.SetValue($frames.GetValue(0),1)
        $reason=$null
        try{[void]$protocol.ComputeBootstrapBrokerFinishedDigest($changed)}
        catch{$reason=$_.Exception.GetBaseException().Message}
        $reason | Should -BeExactly 'context:ordering'
        $reason=$null
        try{[void]$protocol.ComputeBootstrapBrokerFinishedDigest([Array]::CreateInstance($frameType,2))}
        catch{$reason=$_.Exception.GetBaseException().Message}
        $reason | Should -BeExactly 'context:binding-shape'
    }

    It '11 canonical-signed-and-bootstrap-bindings' {
        $protocol=New-TestProtocol
        $goldens=([Text.Encoding]::UTF8.GetString($FixtureBytesById.BootstrapGoldens)|ConvertFrom-Json).rows
        $broker=@($goldens|Where-Object {$_.id -ceq 'BG01'})[0]
        $frameType=$RuntimeAssembly.GetType('Pspkt.Certification.BrokerLifecycle.DecodedControlFrame',$true)
        $frames=[Array]::CreateInstance($frameType,4)
        for($index=0;$index -lt 4;$index++){
            $item=$broker.frames[$index]
            $frames.SetValue($protocol.Decode($item.channel,$item.direction,[byte]2,(Convert-TestHex $item.frameHex)),$index)
        }
        $digest=$protocol.ComputeBrokerChannelBinding($frames)
        [BitConverter]::ToString($digest).Replace('-','').ToLowerInvariant() | Should -BeExactly 'e0674bc650a4f0301373df02e70b3bb7e25186cd3c5f0134167ffa0dc4273bfa'
        $binding=@($goldens|Where-Object {$_.id -ceq 'BG03'})[0]
        (Get-PspktBrokerLifecycleOracleDigest (Convert-TestHex $binding.preimageHex)) | Should -BeExactly $binding.sha256
        $binding.preimageLength | Should -Be 3667
        $local=@($goldens|Where-Object {$_.id -ceq 'BG04'})[0]
        $workerHello=$protocol.Decode('LocalIpc','WorkerToBroker',[byte]2,(Convert-TestHex $local.frames[0].frameHex))
        $brokerHello=$protocol.Decode('LocalIpc','BrokerToWorker',[byte]2,(Convert-TestHex $local.frames[1].frameHex))
        $localIdentifier=Convert-TestHex '2031425364754887a9bacbdcedfe0f10'
        $boot=Convert-TestHex '4051627384954a89abbccddeef102132'
        foreach($variant in @(0,1,2)){
            $worker=$null;$peer=$null;$brokerPid=[UInt32]0;$workerPid=[UInt32]0;$brokerTime=[UInt64]0;$workerTime=[UInt64]0
            if($variant -gt 0){
                $worker=$workerHello
                $brokerPid=[Convert]::ToUInt32('10203040',16)
                $workerPid=[Convert]::ToUInt32('50607080',16)
                $brokerTime=[Convert]::ToUInt64('1122334455667788',16)
                $workerTime=[Convert]::ToUInt64('2233445566778899',16)
            }
            if($variant -eq 2){$peer=$brokerHello}
            $expected=@($goldens|Where-Object {$_.id -ceq ('BG0'+(5+$variant))})[0]
            $actual=$protocol.ComputeLocalChannelBinding([byte]$variant,$localIdentifier,$boot,$brokerPid,$brokerTime,$workerPid,$workerTime,$worker,$peer)
            [BitConverter]::ToString($actual).Replace('-','').ToLowerInvariant() | Should -BeExactly $expected.sha256
            (Get-PspktBrokerLifecycleOracleDigest (Convert-TestHex $expected.preimageHex)) | Should -BeExactly $expected.sha256
            $expected.pipePath | Should -BeExactly '\\.\pipe\pspkt-broker-worker-4051627384954a89abbccddeef102132'
            [Text.Encoding]::UTF8.GetByteCount($expected.pipePath) | Should -Be 61
        }
        $localPreimage=Convert-TestHex (@($goldens|Where-Object {$_.id -ceq 'BG07'})[0].preimageHex)
        $brokerPid=[Convert]::ToUInt32('10203040',16)
        $workerPid=[Convert]::ToUInt32('50607080',16)
        $brokerTime=[Convert]::ToUInt64('1122334455667788',16)
        $workerTime=[Convert]::ToUInt64('2233445566778899',16)
        foreach($swap in @(
            @{Kind='pids';FirstOffset=128;SecondOffset=140;Width=4;Sha256='d5b2e51cea7b3e8b1f0e2fa4805a308456fef99b0138c45a022c67fe37523f9b'},
            @{Kind='times';FirstOffset=132;SecondOffset=144;Width=8;Sha256='397a298c4942b75c1174b8a0c4e3bb97654b6bcf67ab625edb7ee47b34261b6f'},
            @{Kind='channel-boot';FirstOffset=33;SecondOffset=112;Width=16;Sha256='0693ec51b8530d1c276df29c3cf360a94b038835ef26cbfef40143bb018b2838'}
        )){
            $expected=Copy-PspktBrokerLifecycleOracleSwappedRanges $localPreimage $swap.FirstOffset $swap.SecondOffset $swap.Width
            $selectedChannel=$localIdentifier
            $selectedBoot=$boot
            $selectedBrokerPid=$brokerPid
            $selectedWorkerPid=$workerPid
            $selectedBrokerTime=$brokerTime
            $selectedWorkerTime=$workerTime
            if($swap.Kind -ceq 'pids'){
                $selectedBrokerPid=$workerPid
                $selectedWorkerPid=$brokerPid
            }
            elseif($swap.Kind -ceq 'times'){
                $selectedBrokerTime=$workerTime
                $selectedWorkerTime=$brokerTime
            }
            else{
                $selectedChannel=$boot
                $selectedBoot=$localIdentifier
                $pathBytes=[Text.Encoding]::ASCII.GetBytes('\\.\pipe\pspkt-broker-worker-2031425364754887a9bacbdcedfe0f10')
                $pathBytes.Length | Should -Be 61
                [Array]::Copy($pathBytes,0,$expected,51,61)
            }
            $expected.Length | Should -Be 2275
            (Get-PspktBrokerLifecycleOracleDigest $expected) | Should -BeExactly $swap.Sha256
            $actual=$protocol.ComputeLocalChannelBinding([byte]2,$selectedChannel,$selectedBoot,$selectedBrokerPid,
                $selectedBrokerTime,$selectedWorkerPid,$selectedWorkerTime,$workerHello,$brokerHello)
            [BitConverter]::ToString($actual).Replace('-','').ToLowerInvariant() | Should -BeExactly $swap.Sha256
        }
        $serviceIdentifier=Convert-TestHex '102132435465478698a9bacbdcedfe0f'
        $leaseIdentifier=Convert-TestHex '3041526374854988bacbdcedfe0f1021'
        $changedFrames=[Collections.Generic.List[object]]::new()
        foreach($item in $broker.frames){$changedFrames.Add((Convert-TestHex $item.frameHex))}
        $changedFrames[0]=Set-PspktBrokerLifecycleOracleFrameField $changedFrames[0] ([int[]]@(3)) $leaseIdentifier
        $changedFrames[1]=Set-PspktBrokerLifecycleOracleFrameField $changedFrames[1] ([int[]]@(4)) $serviceIdentifier
        $wrappedParts=[Collections.Generic.List[object]]::new()
        for($index=0;$index -lt 3;$index++){
            $direction=2
            if($index -eq 1){$direction=1}
            $wrappedParts.Add([byte[]]@($direction))
            $wrappedParts.Add((New-PspktBrokerLifecycleOracleUnsigned 8 0))
            $wrappedParts.Add((New-PspktBrokerLifecycleOracleUnsigned 4 $changedFrames[$index].Length))
            $wrappedParts.Add($changedFrames[$index])
        }
        $finishedDigest=Get-PspktBrokerLifecycleOracleDigest (Join-PspktBrokerLifecycleOracleBytes $wrappedParts.ToArray())
        $finishedDigest | Should -BeExactly '8b2ffc2eadce7a4deb615a35e9041d81a1bd8f2d19c0bd898875a9b6f8b98be6'
        $changedFrames[3]=Set-PspktBrokerLifecycleOracleFrameField $changedFrames[3] ([int[]]@(1)) (Convert-TestHex $finishedDigest)
        $expected=Join-PspktBrokerLifecycleOracleBytes @(
            [Text.Encoding]::ASCII.GetBytes("pspkt-phase4-broker-bootstrap-v1`0"),$leaseIdentifier,$serviceIdentifier,
            (Convert-TestHex '0102030405060708'),
            (Convert-TestHex '505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f'),
            $changedFrames[0],$changedFrames[1],$changedFrames[2],$changedFrames[3])
        $expected.Length | Should -Be 3667
        (Get-PspktBrokerLifecycleOracleDigest $expected) | Should -BeExactly 'a58495853937a8b2b01362cb357cd388b661f37b17b20c099c7f4765b2990909'
        $swappedFrames=[Array]::CreateInstance($frameType,4)
        for($index=0;$index -lt 4;$index++){
            $item=$broker.frames[$index]
            $swappedFrames.SetValue($protocol.Decode($item.channel,$item.direction,[byte]2,$changedFrames[$index]),$index)
        }
        [BitConverter]::ToString($protocol.ComputeBrokerChannelBinding($swappedFrames)).Replace('-','').ToLowerInvariant() |
            Should -BeExactly 'a58495853937a8b2b01362cb357cd388b661f37b17b20c099c7f4765b2990909'
        $reason=$null
        try{[void]$protocol.ComputeLocalChannelBinding([byte]0,$localIdentifier,$boot,[UInt32]0,[UInt64]0,[UInt32]0,[UInt64]0,$workerHello,$null)}
        catch{$reason=$_.Exception.GetBaseException().Message}
        $reason | Should -BeExactly 'context:binding-shape'
        $reason=$null
        try{[void]$protocol.ComputeLocalChannelBinding([byte]2,$localIdentifier,$boot,[UInt32]1,[UInt64]1,[UInt32]1,[UInt64]1,$workerHello,$null)}
        catch{$reason=$_.Exception.GetBaseException().Message}
        $reason | Should -BeExactly 'context:binding-shape'
        $changed=$frames.Clone()
        $changed.SetValue($frames.GetValue(0),3)
        $reason=$null
        try{[void]$protocol.ComputeBrokerChannelBinding($changed)}
        catch{$reason=$_.Exception.GetBaseException().Message}
        $reason | Should -BeExactly 'context:ordering'
    }

    It '12 transcript-domain-and-order' {
        $protocol=New-TestProtocol
        $empty=New-TestFrameArray $protocol @()
        $actual=$protocol.ComputeBrokerTranscriptDigest($empty)
        [BitConverter]::ToString($actual).Replace('-','').ToLowerInvariant() | Should -BeExactly '2bc971eb8bc389d7c4c314f4b7d6515ae7a9082193feb5c922510449eebb17ef'
        $localIdentifier=Convert-TestHex '2031425364754887a9bacbdcedfe0f10'
        [BitConverter]::ToString($protocol.ComputeLocalTranscriptDigest($empty,$empty,$localIdentifier)).Replace('-','').ToLowerInvariant() |
            Should -BeExactly '95754d62ff0f20bd8ee96cf932ffd19ff54a64c813da780e62edad86eef6d328'
        [BitConverter]::ToString($protocol.ComputeLocalRecordSetDigest($empty,$empty)).Replace('-','').ToLowerInvariant() |
            Should -BeExactly '65212d433fdba73ed39be4c6388b0abf02ff00cf9ae94d5cf46b24dc09f4678d'
        $goldens=([Text.Encoding]::UTF8.GetString($FixtureBytesById.BootstrapGoldens)|ConvertFrom-Json).rows
        $broker=@($goldens|Where-Object {$_.id -ceq 'BG08'})[0]
        $brokerFrames=New-TestFrameArray $protocol $broker.nonempty.frames
        [BitConverter]::ToString($protocol.ComputeBrokerTranscriptDigest($brokerFrames)).Replace('-','').ToLowerInvariant() |
            Should -BeExactly $broker.nonempty.sha256
        $local=@($goldens|Where-Object {$_.id -ceq 'BG09'})[0]
        $workerFrames=New-TestFrameArray $protocol $local.nonempty.workerToBroker
        $brokerLocalFrames=New-TestFrameArray $protocol $local.nonempty.brokerToWorker
        [BitConverter]::ToString($protocol.ComputeLocalTranscriptDigest($workerFrames,$brokerLocalFrames,$localIdentifier)).Replace('-','').ToLowerInvariant() |
            Should -BeExactly $local.nonempty.sha256
        $recordSet=@($goldens|Where-Object {$_.id -ceq 'BG10'})[0]
        [BitConverter]::ToString($protocol.ComputeLocalRecordSetDigest($workerFrames,$brokerLocalFrames)).Replace('-','').ToLowerInvariant() |
            Should -BeExactly $recordSet.nonempty.sha256
        foreach($row in @($broker,$local,$recordSet)){
            foreach($item in @($row.empty,$row.nonempty)){
                $bytes=Convert-TestHex $item.preimageHex
                $bytes.Length | Should -Be $item.preimageLength
                (Get-PspktBrokerLifecycleOracleDigest $bytes) | Should -BeExactly $item.sha256
            }
        }
        $swappedBrokerFrames=$brokerFrames.Clone()
        $changed=Set-PspktBrokerLifecycleOracleFrameField (Convert-TestHex $broker.nonempty.frames[4].frameHex) ([int[]]@(1)) (Convert-TestHex '31425364758697a8')
        $swappedBrokerFrames.SetValue($protocol.Decode('BrokerControl','BrokerToHost',[byte]2,$changed),4)
        $changed=Set-PspktBrokerLifecycleOracleFrameField (Convert-TestHex $broker.nonempty.frames[5].frameHex) ([int[]]@(1)) (Convert-TestHex '425364758697a8b9')
        $swappedBrokerFrames.SetValue($protocol.Decode('BrokerControl','HostToBroker',[byte]2,$changed),5)
        $expected=Copy-PspktBrokerLifecycleOracleSwappedRanges (Convert-TestHex $broker.nonempty.preimageHex) 3752 4187 8
        $expected.Length | Should -Be 4579
        (Get-PspktBrokerLifecycleOracleDigest $expected) | Should -BeExactly 'aa9cbeae3cf17cb0ac4ff1a660847f180eba0f61f68e219babc18d536a3a30e3'
        [BitConverter]::ToString($protocol.ComputeBrokerTranscriptDigest($swappedBrokerFrames)).Replace('-','').ToLowerInvariant() |
            Should -BeExactly 'aa9cbeae3cf17cb0ac4ff1a660847f180eba0f61f68e219babc18d536a3a30e3'
        $swappedWorkerFrames=$workerFrames.Clone()
        $swappedLocalBrokerFrames=$brokerLocalFrames.Clone()
        $changed=Set-PspktBrokerLifecycleOracleFrameField (Convert-TestHex $local.nonempty.workerToBroker[1].frameHex) ([int[]]@(1)) (Convert-TestHex '64758697a8b9cadb')
        $swappedWorkerFrames.SetValue($protocol.Decode('LocalIpc','WorkerToBroker',[byte]2,$changed),1)
        $changed=Set-PspktBrokerLifecycleOracleFrameField (Convert-TestHex $local.nonempty.brokerToWorker[1].frameHex) ([int[]]@(1)) (Convert-TestHex '5364758697a8b9ca')
        $swappedLocalBrokerFrames.SetValue($protocol.Decode('LocalIpc','BrokerToWorker',[byte]2,$changed),1)
        $expected=Copy-PspktBrokerLifecycleOracleSwappedRanges (Convert-TestHex $local.nonempty.preimageHex) 683 2688 8
        $expected.Length | Should -Be 3080
        (Get-PspktBrokerLifecycleOracleDigest $expected) | Should -BeExactly 'bc28813f3f893c98886e11fc872061c46bfca5187782dd1457b7fe224510a51c'
        [BitConverter]::ToString($protocol.ComputeLocalTranscriptDigest($swappedWorkerFrames,$swappedLocalBrokerFrames,$localIdentifier)).Replace('-','').ToLowerInvariant() |
            Should -BeExactly 'bc28813f3f893c98886e11fc872061c46bfca5187782dd1457b7fe224510a51c'
        $expected=Copy-PspktBrokerLifecycleOracleSwappedRanges (Convert-TestHex $recordSet.nonempty.preimageHex) 644 2671 8
        $expected.Length | Should -Be 3063
        (Get-PspktBrokerLifecycleOracleDigest $expected) | Should -BeExactly '4d29bc9e854f74ca915a6160495a33e7495f6f0698a1bc6b37e0e1142cc2ddb3'
        [BitConverter]::ToString($protocol.ComputeLocalRecordSetDigest($swappedWorkerFrames,$swappedLocalBrokerFrames)).Replace('-','').ToLowerInvariant() |
            Should -BeExactly '4d29bc9e854f74ca915a6160495a33e7495f6f0698a1bc6b37e0e1142cc2ddb3'
        $changed=Set-PspktBrokerLifecycleOracleFrameField (Convert-TestHex $local.nonempty.brokerToWorker[0].frameHex) ([int[]]@(8,15)) (Convert-TestHex '6d76911009b64e52417b3ca519d3b3166cfdf675a4d4deede5ab0dce449c9db4')
        $changed=Set-PspktBrokerLifecycleOracleFrameField $changed ([int[]]@(8,16)) (Convert-TestHex 'ca08bcb5164acb4522729dc98b2a1bd5ee348a79a14cef95dd852ae1958dcc85')
        $reason=$null
        try{[void]$protocol.Decode('LocalIpc','BrokerToWorker',[byte]2,$changed)}
        catch{$reason=$_.Exception.GetBaseException().Message}
        $reason | Should -BeExactly 'context:protocol-schema-meta'
        $wrong=$brokerFrames.Clone()
        $wrong.SetValue($brokerFrames.GetValue(1),0)
        $reason=$null
        try{[void]$protocol.ComputeBrokerTranscriptDigest($wrong)}
        catch{$reason=$_.Exception.GetBaseException().Message}
        $reason | Should -BeExactly 'context:ordering'
        $reason=$null
        try{[void]$protocol.ComputeLocalTranscriptDigest($workerFrames,$empty,$localIdentifier)}
        catch{$reason=$_.Exception.GetBaseException().Message}
        $reason | Should -BeExactly 'context:bootstrap-incomplete'
        $reason=$null
        try{[void]$protocol.ComputeLocalRecordSetDigest($empty,$brokerLocalFrames)}
        catch{$reason=$_.Exception.GetBaseException().Message}
        $reason | Should -BeExactly 'context:bootstrap-incomplete'
        $type=$RuntimeAssembly.GetType('Pspkt.Certification.BrokerLifecycle.DecodedControlFrame',$true)
        $oversized=[Array]::CreateInstance($type,257)
        for($index=0;$index -lt 257;$index++){$oversized.SetValue($workerFrames.GetValue(0),$index)}
        $reason=$null
        try{[void]$protocol.ComputeLocalRecordSetDigest($oversized,$brokerLocalFrames)}
        catch{$reason=$_.Exception.GetBaseException().Message}
        $reason | Should -BeExactly 'quota:record-count'
        $protocol.GetType().GetMethod('ComputeBrokerTranscriptDigest').GetParameters().Length | Should -Be 1
        $protocol.GetType().GetMethod('ComputeLocalTranscriptDigest').GetParameters().Length | Should -Be 3
    }

    It '13 fragmented-coalesced-and-truncated' {
        $RuntimeAssembly.GetType('Pspkt.Certification.BrokerLifecycle.CheckpointServiceLifecycle',$true).GetMethod('Start') | Should -Not -BeNullOrEmpty
        $source=@(([Text.Encoding]::UTF8.GetString($FixtureBytesById.FramingGoldens)|ConvertFrom-Json).rows|Where-Object {$_.id -ceq 'FG04'})[0]
        $frame=Convert-TestHex $source.frameHex
        for($split=0;$split -le $frame.Length;$split++){
            if($split%64 -eq 0){$protocol=New-TestProtocol}
            $controller=New-TestWorker $protocol
            try{
                Open-TestWorker $controller
                if($split -gt 0){
                    $controller.FeedPeerBytes('LocalIpc',[byte[]]$frame[0..($split-1)],[UInt64]3,[UInt64]1000)
                    $controller.Pump([UInt64]3,256)
                }
                if($split -lt $frame.Length){
                    $controller.GetSnapshot().LocalIpcBrokerToWorkerObservedRecordCount | Should -Be 1
                    $controller.FeedPeerBytes('LocalIpc',[byte[]]$frame[$split..($frame.Length-1)],[UInt64]4,[UInt64]1000)
                    $controller.Pump([UInt64]4,256)
                }
                $snapshot=$controller.GetSnapshot()
                $snapshot.LocalIpcBrokerToWorkerObservedRecordCount | Should -Be 2
                $snapshot.LocalIpcBrokerToWorkerLastObservedSequence | Should -Be 1
                $snapshot.LocalIpcBrokerToWorkerObservedFullSignedFrameBytes | Should -Be 2001
            }
            finally{Close-TestController $controller}
        }
        $controller=New-TestWorker (New-TestProtocol)
        try{
            Open-TestWorker $controller
            $second=[byte[]]$frame.Clone()
            [Array]::Copy((New-PspktBrokerLifecycleOracleUnsigned 8 2),0,$second,12,8)
            $controller.FeedPeerBytes('LocalIpc',(Join-PspktBrokerLifecycleOracleBytes @($frame,$second)),[UInt64]3,[UInt64]1000)
            $controller.Pump([UInt64]3,256)
            $controller.GetSnapshot().LocalIpcBrokerToWorkerObservedRecordCount | Should -Be 3
            $controller.GetSnapshot().LocalIpcBrokerToWorkerLastObservedSequence | Should -Be 2
        }
        finally{Close-TestController $controller}
        foreach($cut in @(1,23,24,100,421)){
            $controller=New-TestWorker (New-TestProtocol)
            try{
                Open-TestWorker $controller
                $controller.FeedPeerBytes('LocalIpc',[byte[]]$frame[0..($cut-1)],[UInt64]3,[UInt64]1000)
                $controller.Pump([UInt64]3,256)
                $reason=$null
                try{$controller.ObservePeerEof('LocalIpc',[UInt64]4)}
                catch{$reason=$_.Exception.GetBaseException().Message}
                $reason | Should -BeExactly 'transport:premature-eof'
                $controller.GetSnapshot().LocalIpcBrokerToWorkerObservedRecordCount | Should -Be 1
                $controller.GetSnapshot().PrimaryReasonCode | Should -BeExactly 'transport:premature-eof'
            }
            finally{Close-TestController $controller}
        }
        $controller=New-TestWorker (New-TestProtocol)
        Open-TestWorker $controller
        $controller.RequestStop([UInt64]5,[UInt64]1000)
        $controller.Pump([UInt64]5,256)
        $controller.ObservePeerEof('LocalIpc',[UInt64]6)
        $controller.GetSnapshot().CleanupComplete | Should -BeTrue
        $controller.Dispose()
    }

    It '14 bootstrap-and-application-sequences' {
        $framing=([Text.Encoding]::UTF8.GetString($FixtureBytesById.FramingGoldens)|ConvertFrom-Json).rows
        $incoming=@($framing|Where-Object {$_.id -ceq 'FG04'})[0]
        $outgoing=@($framing|Where-Object {$_.id -ceq 'FG03'})[0]
        foreach($send in @($false,$true)){
            $controller=New-TestWorker (New-TestProtocol)
            try{
                $controller.Start([UInt64]0,[UInt64]1000)
                $controller.Pump([UInt64]0,256)
                $reason=$null
                try{
                    if($send){$controller.QueueFrame('LocalIpc',(Convert-TestHex $outgoing.frameHex),[UInt64]1,[UInt64]1000)}
                    else{$controller.FeedPeerBytes('LocalIpc',(Convert-TestHex $incoming.frameHex),[UInt64]1,[UInt64]1000);$controller.Pump([UInt64]1,256)}
                }
                catch{$reason=$_.Exception.GetBaseException().Message}
                $reason | Should -BeExactly 'context:bootstrap-incomplete'
                $controller.GetSnapshot().LocalIpcWorkerToBrokerObservedRecordCount | Should -Be 0
                $controller.GetSnapshot().LocalIpcBrokerToWorkerObservedRecordCount | Should -Be 0
            }
            finally{Close-TestController $controller}
        }
        $protocol=New-TestProtocol
        $type=$RuntimeAssembly.GetType('Pspkt.Certification.BrokerLifecycle.CheckpointServiceLifecycle',$true)
        $controller=$type.GetMethod('CreateInMemory').Invoke($null,[object[]]@($protocol,'Broker',$FixtureBytesById.LifecyclePolicy))
        try{
            $bootstrap=@(([Text.Encoding]::UTF8.GetString($FixtureBytesById.BootstrapGoldens)|ConvertFrom-Json).rows|Where-Object {$_.id -ceq 'BG01'})[0]
            $controller.Start([UInt64]0,[UInt64]1000)
            $controller.Pump([UInt64]0,256)
            for($index=0;$index -lt 4;$index++){
                $bytes=Convert-TestHex $bootstrap.frames[$index].frameHex
                if($index -eq 1){$controller.FeedPeerBytes('BrokerControl',$bytes,[UInt64]($index+1),[UInt64]1000)}
                else{$controller.QueueFrame('BrokerControl',$bytes,[UInt64]($index+1),[UInt64]1000)}
                $controller.Pump([UInt64]($index+1),256)
                [void]$controller.ReadPeerBytes('BrokerControl',65536,[UInt64]($index+1))
            }
            $snapshot=$controller.GetSnapshot()
            $snapshot.BrokerHelloProgress | Should -BeExactly 'BrokerBootstrapObservedUnverified'
            $snapshot.BrokerControlBrokerToHostObservedRecordCount | Should -Be 3
            $snapshot.BrokerControlBrokerToHostLastObservedSequence | Should -Be 0
            $reason=$null
            try{$controller.QueueFrame('BrokerControl',(Convert-TestHex $bootstrap.frames[3].frameHex),[UInt64]5,[UInt64]1000)}
            catch{$reason=$_.Exception.GetBaseException().Message}
            $reason | Should -BeExactly 'context:ordering'
            $controller.GetSnapshot().BrokerControlBrokerToHostObservedRecordCount | Should -Be 3
        }
        finally{Close-TestController $controller}
        foreach($sequence in @([UInt64]0,[UInt64]2,[UInt64]::MaxValue)){
            $controller=New-TestWorker (New-TestProtocol)
            try{
                Open-TestWorker $controller
                $bytes=Convert-TestHex $incoming.frameHex
                [Array]::Copy((New-PspktBrokerLifecycleOracleUnsigned 8 $sequence),0,$bytes,12,8)
                $reason=$null
                try{$controller.FeedPeerBytes('LocalIpc',$bytes,[UInt64]3,[UInt64]1000);$controller.Pump([UInt64]3,256)}
                catch{$reason=$_.Exception.GetBaseException().Message}
                $reason | Should -BeExactly 'context:sequence'
                $controller.GetSnapshot().LocalIpcBrokerToWorkerObservedRecordCount | Should -Be 1
            }
            finally{Close-TestController $controller}
        }
        $controller=New-TestWorker (New-TestProtocol)
        try{
            Open-TestWorker $controller
            $bytes=Convert-TestHex $incoming.frameHex
            $controller.FeedPeerBytes('LocalIpc',$bytes,[UInt64]3,[UInt64]1000)
            $controller.Pump([UInt64]3,256)
            $reason=$null
            try{$controller.FeedPeerBytes('LocalIpc',$bytes,[UInt64]4,[UInt64]1000);$controller.Pump([UInt64]4,256)}
            catch{$reason=$_.Exception.GetBaseException().Message}
            $reason | Should -BeExactly 'context:sequence'
            $controller.GetSnapshot().LocalIpcBrokerToWorkerObservedRecordCount | Should -Be 2
        }
        finally{Close-TestController $controller}
        $bootstrapRows=([Text.Encoding]::UTF8.GetString($FixtureBytesById.BootstrapGoldens)|ConvertFrom-Json).rows
        $brokerBootstrap=@($bootstrapRows|Where-Object {$_.id -ceq 'BG01'})[0]
        $localBootstrap=@($bootstrapRows|Where-Object {$_.id -ceq 'BG04'})[0]
        foreach($cut in @(1,2,3)){
        foreach($send in @($true,$false)){
            $controller=New-TestBroker (New-TestProtocol)
            try{
                $controller.Start([UInt64]0,[UInt64]1000)
                $controller.Pump([UInt64]0,256)
                for($index=0;$index -lt $cut;$index++){
                    $bytes=Convert-TestHex $brokerBootstrap.frames[$index].frameHex
                    if($index -eq 1){$controller.FeedPeerBytes('BrokerControl',$bytes,[UInt64]0,[UInt64]1000)}
                    else{$controller.QueueFrame('BrokerControl',$bytes,[UInt64]0,[UInt64]1000)}
                    $controller.Pump([UInt64]0,256)
                    [void]$controller.ReadPeerBytes('BrokerControl',65536,[UInt64]0)
                }
                $before=$controller.GetSnapshot()
                $application=@($framing|Where-Object {$_.id -ceq $(if($send){'FG02'}else{'FG01'})})[0]
                $reason=$null
                try{
                    if($send){$controller.QueueFrame('BrokerControl',(Convert-TestHex $application.frameHex),[UInt64]1,[UInt64]1000)}
                    else{$controller.FeedPeerBytes('BrokerControl',(Convert-TestHex $application.frameHex),[UInt64]1,[UInt64]1000);$controller.Pump([UInt64]1,256)}
                }
                catch{$reason=$_.Exception.GetBaseException().Message}
                $reason | Should -BeExactly 'context:bootstrap-incomplete'
                $after=$controller.GetSnapshot()
                $after.BrokerControlHostToBrokerObservedRecordCount | Should -Be $before.BrokerControlHostToBrokerObservedRecordCount
                $after.BrokerControlBrokerToHostObservedRecordCount | Should -Be $before.BrokerControlBrokerToHostObservedRecordCount
            }
            finally{Close-TestController $controller}
        }
        }
        foreach($role in @('Broker','Worker')){
        foreach($send in @($true,$false)){
            if($role -ceq 'Broker'){$controller=New-TestBroker (New-TestProtocol)}else{$controller=New-TestWorker (New-TestProtocol)}
            try{
                $controller.Start([UInt64]0,[UInt64]1000)
                $controller.Pump([UInt64]0,256)
                $hello=Convert-TestHex $localBootstrap.frames[0].frameHex
                if($role -ceq 'Worker'){$controller.QueueFrame('LocalIpc',$hello,[UInt64]0,[UInt64]1000)}
                else{$controller.FeedPeerBytes('LocalIpc',$hello,[UInt64]0,[UInt64]1000)}
                $controller.Pump([UInt64]0,256)
                [void]$controller.ReadPeerBytes('LocalIpc',65536,[UInt64]0)
                $workerDirection=($role -ceq 'Worker') -eq $send
                $application=@($framing|Where-Object {$_.id -ceq $(if($workerDirection){'FG03'}else{'FG04'})})[0]
                $reason=$null
                try{
                    if($send){$controller.QueueFrame('LocalIpc',(Convert-TestHex $application.frameHex),[UInt64]1,[UInt64]1000)}
                    else{$controller.FeedPeerBytes('LocalIpc',(Convert-TestHex $application.frameHex),[UInt64]1,[UInt64]1000);$controller.Pump([UInt64]1,256)}
                }
                catch{$reason=$_.Exception.GetBaseException().Message}
                $reason | Should -BeExactly 'context:bootstrap-incomplete'
                $controller.GetSnapshot().LocalIpcWorkerToBrokerObservedRecordCount | Should -Be 1
                $controller.GetSnapshot().LocalIpcBrokerToWorkerObservedRecordCount | Should -Be 0
            }
            finally{Close-TestController $controller}
        }
        }
        foreach($fieldId in @(7,8)){
        foreach($origin in @([UInt64]0,[UInt64]2,[UInt64]::MaxValue)){
            $controller=New-TestBroker (New-TestProtocol)
            try{
                $controller.Start([UInt64]0,[UInt64]1000)
                $controller.Pump([UInt64]0,256)
                $controller.QueueFrame('BrokerControl',(Convert-TestHex $brokerBootstrap.frames[0].frameHex),[UInt64]0,[UInt64]1000)
                $controller.Pump([UInt64]0,256)
                [void]$controller.ReadPeerBytes('BrokerControl',65536,[UInt64]0)
                $invalid=Set-PspktBrokerLifecycleOracleFrameField (Convert-TestHex $brokerBootstrap.frames[1].frameHex) ([int[]]@($fieldId)) (New-PspktBrokerLifecycleOracleUnsigned 8 $origin)
                $reason=$null
                try{$controller.FeedPeerBytes('BrokerControl',$invalid,[UInt64]1,[UInt64]1000);$controller.Pump([UInt64]1,256)}
                catch{$reason=$_.Exception.GetBaseException().Message}
                $reason | Should -BeExactly 'context:sequence-origin'
                $controller.GetSnapshot().BrokerControlHostToBrokerObservedRecordCount | Should -Be 0
                $controller.GetSnapshot().BrokerControlBrokerToHostObservedRecordCount | Should -Be 1
            }
            finally{Close-TestController $controller}
        }
        }
        foreach($send in @($true,$false)){
        $controller=New-TestWorker (New-TestProtocol)
        try{
            Open-TestWorker $controller
            $application=@($framing|Where-Object {$_.id -ceq $(if($send){'FG03'}else{'FG04'})})[0]
            $hello=Convert-TestHex $localBootstrap.frames[$(if($send){0}else{1})].frameHex
            if($send){$controller.QueueFrame('LocalIpc',(Convert-TestHex $application.frameHex),[UInt64]3,[UInt64]1000)}
            else{$controller.FeedPeerBytes('LocalIpc',(Convert-TestHex $application.frameHex),[UInt64]3,[UInt64]1000)}
            $controller.Pump([UInt64]3,256)
            [void]$controller.ReadPeerBytes('LocalIpc',65536,[UInt64]3)
            $before=$controller.GetSnapshot()
            $reason=$null
            try{
                if($send){$controller.QueueFrame('LocalIpc',$hello,[UInt64]4,[UInt64]1000)}
                else{$controller.FeedPeerBytes('LocalIpc',$hello,[UInt64]4,[UInt64]1000);$controller.Pump([UInt64]4,256)}
            }
            catch{$reason=$_.Exception.GetBaseException().Message}
            $reason | Should -BeExactly 'context:ordering'
            $after=$controller.GetSnapshot()
            $after.LocalIpcWorkerToBrokerObservedRecordCount | Should -Be $before.LocalIpcWorkerToBrokerObservedRecordCount
            $after.LocalIpcBrokerToWorkerObservedRecordCount | Should -Be $before.LocalIpcBrokerToWorkerObservedRecordCount
        }
        finally{Close-TestController $controller}
        }
    }

    It '15 local-three-quota-transaction' {
        $source=$SourceSnapshot.RetainedTexts['certification\broker-lifecycle\lib\ConnectionState.cs']
        $start=$source.IndexOf('internal void Observe(DecodedControlFrame frame)',[StringComparison]::Ordinal)
        $finish=$source.IndexOf('internal void ValidateAdmission(', $start,[StringComparison]::Ordinal)
        $body=$source.Substring($start,$finish-$start)
        $guard=$body.IndexOf('ValidateLocalQuota(',[StringComparison]::Ordinal)
        $guard | Should -BeGreaterOrEqual 0
        foreach($assignment in @('ledger.LastSequence =','ledger.Records =','ledger.FullBytes =','ledger.WrapperBytes =')){
            $body.IndexOf($assignment,[StringComparison]::Ordinal) | Should -BeGreaterThan $guard
        }
        Invoke-PspktBrokerLifecycleInternal $RuntimeAssembly 'ValidateLocalQuota' ([object[]]@([UInt64]256,[UInt64]1048576,[UInt64]1051904))
        foreach($specification in @(
            @([UInt64]257,[UInt64]108454,[UInt64]111795,'quota:record-count'),
            @([UInt64]256,[UInt64]1048577,[UInt64]1051905,'quota:full-frame-bytes'),
            @([UInt64]256,[UInt64]1048576,[UInt64]1051905,'quota:wrapper-bytes'),
            @([UInt64]1,[UInt64]422,[UInt64]434,'quota:counter-consistency'),
            @([UInt64]::MaxValue,[UInt64]0,[UInt64]0,'quota:record-count')
        )){
            $reason=$null
            try{Invoke-PspktBrokerLifecycleInternal $RuntimeAssembly 'ValidateLocalQuota' ([object[]]@($specification[0],$specification[1],$specification[2]))}
            catch{$reason=$_.Exception.GetBaseException().Message}
            $reason | Should -BeExactly $specification[3]
        }
        $controllerSource=$SourceSnapshot.RetainedTexts['certification\broker-lifecycle\lib\CheckpointServiceLifecycle.cs']
        $start=$controllerSource.IndexOf('public void QueueFrame(',[StringComparison]::Ordinal)
        $finish=$controllerSource.IndexOf('public byte[] ReadPeerBytes(', $start,[StringComparison]::Ordinal)
        $queueBody=$controllerSource.Substring($start,$finish-$start)
        $reservationGuard=$queueBody.IndexOf('ValidateQuota(',[StringComparison]::Ordinal)
        $reservationGuard | Should -BeGreaterOrEqual 0
        $queueBody.IndexOf('runtime.Writes.Enqueue(',[StringComparison]::Ordinal) | Should -BeGreaterThan $reservationGuard
    }

    It '16 ordinary-cardinality-and-no-tail-promise' {
        $framing=([Text.Encoding]::UTF8.GetString($FixtureBytesById.FramingGoldens)|ConvertFrom-Json).rows
        foreach($specification in @(@('Worker','LocalIpc',$false,'FG04',64),@('Worker','LocalIpc',$true,'FG03',64),
            @('Broker','BrokerControl',$false,'FG01',256),@('Broker','BrokerControl',$true,'FG02',256))){
            $protocol=New-TestProtocol
            if($specification[0] -ceq 'Worker'){$controller=New-TestWorker $protocol}else{$controller=New-TestBroker $protocol}
            try{
                if($specification[0] -ceq 'Worker'){Open-TestWorker $controller}else{Open-TestBroker $controller}
                $row=@($framing|Where-Object {$_.id -ceq $specification[3]})[0]
                for($sequence=1;$sequence -le $specification[4];$sequence++){
                    $bytes=Convert-TestHex $row.frameHex
                    [Array]::Copy((New-PspktBrokerLifecycleOracleUnsigned 8 $sequence),0,$bytes,12,8)
                    if($specification[2]){$controller.QueueFrame($specification[1],$bytes,[UInt64]7,[UInt64]1000)}
                    else{$controller.FeedPeerBytes($specification[1],$bytes,[UInt64]7,[UInt64]1000)}
                    $controller.Pump([UInt64]7,256)
                    [void]$controller.ReadPeerBytes($specification[1],65536,[UInt64]7)
                }
                $before=$controller.GetSnapshot()
                $bytes=Convert-TestHex $row.frameHex
                [Array]::Copy((New-PspktBrokerLifecycleOracleUnsigned 8 ($specification[4]+1)),0,$bytes,12,8)
                $reason=$null
                try{
                    if($specification[2]){$controller.QueueFrame($specification[1],$bytes,[UInt64]7,[UInt64]1000)}
                    else{$controller.FeedPeerBytes($specification[1],$bytes,[UInt64]7,[UInt64]1000);$controller.Pump([UInt64]7,256)}
                }
                catch{$reason=$_.Exception.GetBaseException().Message}
                $reason | Should -BeExactly 'quota:per-kind'
                $after=$controller.GetSnapshot()
                foreach($property in @($before.GetType().GetProperties()|Where-Object {$_.Name -cmatch 'Observed|LastObserved'})){
                    $property.GetValue($after,$null) | Should -Be $property.GetValue($before,$null)
                }
                $after.LocalTailAuthorityStatus | Should -BeExactly 'UnavailableForSelectedBaseSnapshot'
                $after.UncheckedSemantics | Should -Contain 'keepalive-timing-unchecked'
            }
            finally{Close-TestController $controller}
        }
        $generated=([Text.Encoding]::UTF8.GetString($FixtureBytesById.GeneratedFrames)|ConvertFrom-Json).rows
        foreach($specification in @(@('Broker','BrokerControl','BrokerToHost',$true),@('Broker','LocalIpc','BrokerToWorker',$true),
            @('Worker','LocalIpc','WorkerToBroker',$true),@('Broker','BrokerControl','HostToBroker',$false),
            @('Broker','LocalIpc','WorkerToBroker',$false),@('Worker','LocalIpc','BrokerToWorker',$false))){
            $protocol=New-TestProtocol
            if($specification[0] -ceq 'Worker'){$controller=New-TestWorker $protocol}else{$controller=New-TestBroker $protocol}
            try{
                if($specification[0] -ceq 'Worker'){Open-TestWorker $controller}else{Open-TestBroker $controller}
                $kind=4627
                if($specification[1] -ceq 'BrokerControl'){$kind=4373}
                $row=@($generated|Where-Object {$_.kind -eq $kind -and $_.direction -ceq $specification[2]})[0]
                if($specification[3]){$controller.QueueFrame($specification[1],(Convert-TestHex $row.frameHex),[UInt64]7,[UInt64]1000)}
                else{$controller.FeedPeerBytes($specification[1],(Convert-TestHex $row.frameHex),[UInt64]7,[UInt64]1000)}
                Pump-TestUntilFault $controller
                $expected='lifecycle:peer-failure-observed'
                if($specification[3]){$expected='lifecycle:local-failure-emitted'}
                $controller.GetSnapshot().PrimaryReasonCode | Should -BeExactly $expected
                foreach($channel in $(if($specification[0] -ceq 'Broker'){@('BrokerControl','LocalIpc')}else{@('LocalIpc')})){
                    foreach($send in @($true,$false)){
                        if($channel -ceq 'BrokerControl'){$id=$(if($send){'FG02'}else{'FG01'})}
                        elseif($specification[0] -ceq 'Broker'){$id=$(if($send){'FG04'}else{'FG03'})}
                        else{$id=$(if($send){'FG03'}else{'FG04'})}
                        $traffic=@($framing|Where-Object {$_.id -ceq $id})[0]
                        $before=$controller.GetSnapshot()|ConvertTo-Json -Depth 5 -Compress
                        $reason=$null
                        try{
                            if($send){$controller.QueueFrame($channel,(Convert-TestHex $traffic.frameHex),[UInt64]7,[UInt64]1000)}
                            else{$controller.FeedPeerBytes($channel,(Convert-TestHex $traffic.frameHex),[UInt64]7,[UInt64]1000)}
                        }
                        catch{$reason=$_.Exception.GetBaseException().Message}
                        $wanted='lifecycle:state'
                        if($channel -ceq $specification[1] -and $send -eq $specification[3]){$wanted='lifecycle:traffic-after-terminal'}
                        $reason | Should -BeExactly $wanted
                        ($controller.GetSnapshot()|ConvertTo-Json -Depth 5 -Compress) | Should -BeExactly $before
                    }
                }
                $reason=$null
                try{$controller.FeedPeerBytes($specification[1],$null,[UInt64]7,[UInt64]1000)}
                catch{$reason=$_.Exception.GetBaseException().Message}
                $reason | Should -BeExactly 'argument:null'
                $reason=$null
                try{$controller.FeedPeerBytes($specification[1],([byte[]]::new(65537)),[UInt64]7,[UInt64]1000)}
                catch{$reason=$_.Exception.GetBaseException().Message}
                $reason | Should -BeExactly 'argument:range'
                $unsupportedChannel='WorkerApp'
                if($specification[0] -ceq 'Worker'){$unsupportedChannel='BrokerControl'}
                $probeBytes=Convert-TestHex (@($framing|Where-Object {$_.id -ceq 'FG03'})[0].frameHex)
                Assert-TestUnchangedControllerRejection {
                    $controller.QueueFrame($unsupportedChannel,$probeBytes,[UInt64]7,[UInt64]1000)
                } 'argument:context' @($controller)
                Assert-TestUnchangedControllerRejection {
                    $controller.FeedPeerBytes($unsupportedChannel,$probeBytes,[UInt64]7,[UInt64]1000)
                } 'argument:context' @($controller)
            }
            finally{Close-TestController $controller}
            $controller.GetSnapshot().ServicePhase | Should -BeExactly 'ControllerFaultedUnverified'
            $controller.GetSnapshot().PrimaryReasonCode | Should -BeExactly $expected
        }
        $controller=New-TestWorker (New-TestProtocol)
        try{
            Open-TestWorker $controller
            $failure=@($generated|Where-Object {$_.kind -eq 4627 -and $_.direction -ceq 'WorkerToBroker'})[0]
            $first=Convert-TestHex $failure.frameHex
            $second=[byte[]]$first.Clone()
            [Array]::Copy((New-PspktBrokerLifecycleOracleUnsigned 8 2),0,$second,12,8)
            $controller.QueueFrame('LocalIpc',$first,[UInt64]7,[UInt64]1000)
            $controller.GetSnapshot().PrimaryReasonCode | Should -BeExactly ''
            $reason=$null
            try{$controller.QueueFrame('LocalIpc',$second,[UInt64]7,[UInt64]1000)}
            catch{$reason=$_.Exception.GetBaseException().Message}
            $reason | Should -BeExactly 'quota:per-kind'
            $controller.ReadPeerBytes('LocalIpc',65536,[UInt64]7).Length | Should -Be 0
            $controller.GetSnapshot().LocalIpcWorkerToBrokerObservedRecordCount | Should -Be 1
        }
        finally{Close-TestController $controller}
        $controller=New-TestWorker (New-TestProtocol)
        try{
            Open-TestWorker $controller
            $failure=@($generated|Where-Object {$_.kind -eq 4627 -and $_.direction -ceq 'WorkerToBroker'})[0]
            $bytes=Convert-TestHex $failure.frameHex
            $follower=Convert-TestHex (@($framing|Where-Object {$_.id -ceq 'FG03'})[0].frameHex)
            [Array]::Copy((New-PspktBrokerLifecycleOracleUnsigned 8 2),0,$follower,12,8)
            $controller.QueueFrame('LocalIpc',$bytes,[UInt64]7,[UInt64]1000)
            $controller.QueueFrame('LocalIpc',$follower,[UInt64]7,[UInt64]1000)
            Pump-TestUntilFault $controller
            $controller.GetSnapshot().LocalIpcWorkerToBrokerObservedRecordCount | Should -Be 2
            [BitConverter]::ToString($controller.ReadPeerBytes('LocalIpc',65536,[UInt64]7)) | Should -BeExactly ([BitConverter]::ToString($bytes))
        }
        finally{Close-TestController $controller}
        $controller=New-TestWorker (New-TestProtocol)
        $driver=$null
        try{
            Open-TestWorker $controller
            $ordinary=@($framing|Where-Object {$_.id -ceq 'FG03'})[0]
            $controller.QueueFrame('LocalIpc',(Convert-TestHex $ordinary.frameHex),[UInt64]7,[UInt64]1000)
            $controller.Pump([UInt64]7,1)
            $driver=Invoke-PspktBrokerLifecycleTestMember $RuntimeAssembly 'DriverCreate' $null ([object[]]@($controller,$null))
            $script=New-PspktBrokerLifecycleOutcomeScript $RuntimeAssembly ([int[]]@(1)) ([int[]]@(1))
            Invoke-PspktBrokerLifecycleTestMember $RuntimeAssembly 'BindPrimaryWrite' $driver ([object[]]@('LocalIpc',$script))
            $controller.RequestStop([UInt64]7,[UInt64]1000)
            $controller.Pump([UInt64]7,1)
            $controller.Pump([UInt64]7,1)
            (Invoke-PspktBrokerLifecycleTestMember $RuntimeAssembly 'PrimaryWriteRetirementReason' $driver) | Should -BeExactly 'lifecycle:state'
            (Invoke-PspktBrokerLifecycleTestMember $RuntimeAssembly 'CopyConsumedPrimaryOutcomes' $driver).Length | Should -Be 0
            $snapshot=$controller.GetSnapshot()
            $snapshot.ServicePhase | Should -BeExactly 'ControllerQuiescing'
            $snapshot.LocalConnectionPhase | Should -BeExactly 'TransportDrainingUnverified'
            $snapshot.PrimaryReasonCode | Should -BeExactly ''
            $snapshot.CleanupComplete | Should -BeFalse
            $controller.ReadPeerBytes('LocalIpc',65536,[UInt64]7).Length | Should -Be 0
            foreach($send in @($true,$false)){
                $before=$controller.GetSnapshot()|ConvertTo-Json -Depth 5 -Compress
                $reason=$null
                try{
                    if($send){$controller.QueueFrame('LocalIpc',(Convert-TestHex $ordinary.frameHex),[UInt64]7,[UInt64]1000)}
                    else{$controller.FeedPeerBytes('LocalIpc',(Convert-TestHex (@($framing|Where-Object {$_.id -ceq 'FG04'})[0].frameHex)),[UInt64]7,[UInt64]1000)}
                }
                catch{$reason=$_.Exception.GetBaseException().Message}
                $reason | Should -BeExactly 'lifecycle:state'
                ($controller.GetSnapshot()|ConvertTo-Json -Depth 5 -Compress) | Should -BeExactly $before
            }
            Assert-TestUnchangedControllerRejection {
                $controller.QueueFrame('BrokerControl',(Convert-TestHex $ordinary.frameHex),[UInt64]7,[UInt64]1000)
            } 'argument:context' @($controller)
            Assert-TestUnchangedControllerRejection {
                $controller.FeedPeerBytes('BrokerControl',(Convert-TestHex $ordinary.frameHex),[UInt64]7,[UInt64]1000)
            } 'argument:context' @($controller)
        }
        finally{
            Close-TestDrivenController $controller $driver
        }
        $controller=New-TestBroker (New-TestProtocol)
        $driver=$null
        try{
            Open-TestBroker $controller
            $sent=@($generated|Where-Object {$_.kind -eq 4627 -and $_.direction -ceq 'BrokerToWorker'})[0]
            $received=@($generated|Where-Object {$_.kind -eq 4627 -and $_.direction -ceq 'WorkerToBroker'})[0]
            $controller.QueueFrame('LocalIpc',(Convert-TestHex $sent.frameHex),[UInt64]7,[UInt64]1000)
            $controller.Pump([UInt64]7,1)
            $driver=Invoke-PspktBrokerLifecycleTestMember $RuntimeAssembly 'DriverCreate' $null ([object[]]@($controller,$null))
            $script=New-PspktBrokerLifecycleOutcomeScript $RuntimeAssembly ([int[]]@(1,4)) ([int[]]@(3,0))
            Invoke-PspktBrokerLifecycleTestMember $RuntimeAssembly 'BindPrimaryWrite' $driver ([object[]]@('LocalIpc',$script))
            $controller.Pump([UInt64]7,1)
            $controller.ReadPeerBytes('LocalIpc',65536,[UInt64]7).Length | Should -Be 3
            $controller.GetSnapshot().LocalIpcBrokerToWorkerObservedRecordCount | Should -Be 1
            $controller.Pump([UInt64]7,1)
            (Invoke-PspktBrokerLifecycleTestMember $RuntimeAssembly 'HasPrimaryHeldCompletion' $driver) | Should -BeTrue
            $controller.GetSnapshot().PrimaryReasonCode | Should -BeExactly ''
            $controller.FeedPeerBytes('LocalIpc',(Convert-TestHex $received.frameHex),[UInt64]7,[UInt64]1000)
            Pump-TestUntilFault $controller
            $controller.GetSnapshot().PrimaryReasonCode | Should -BeExactly 'lifecycle:peer-failure-observed'
            $ordinary=@($framing|Where-Object {$_.id -ceq 'FG04'})[0]
            $reason=$null
            try{$controller.QueueFrame('LocalIpc',(Convert-TestHex $ordinary.frameHex),[UInt64]7,[UInt64]1000)}
            catch{$reason=$_.Exception.GetBaseException().Message}
            $reason | Should -BeExactly 'lifecycle:state'
            Invoke-PspktBrokerLifecycleTestMember $RuntimeAssembly 'DeliverPrimaryCompletion' $driver ([object[]]@('LocalIpc'))
            $controller.GetSnapshot().PrimaryReasonCode | Should -BeExactly 'lifecycle:peer-failure-observed'
            $controller.GetSnapshot().LocalIpcBrokerToWorkerObservedRecordCount | Should -Be 2
            $reason=$null
            try{$controller.QueueFrame('LocalIpc',(Convert-TestHex $ordinary.frameHex),[UInt64]7,[UInt64]1000)}
            catch{$reason=$_.Exception.GetBaseException().Message}
            $reason | Should -BeExactly 'lifecycle:traffic-after-terminal'
            foreach($send in @($true,$false)){
                $row=@($framing|Where-Object {$_.id -ceq $(if($send){'FG02'}else{'FG01'})})[0]
                $reason=$null
                try{
                    if($send){$controller.QueueFrame('BrokerControl',(Convert-TestHex $row.frameHex),[UInt64]7,[UInt64]1000)}
                    else{$controller.FeedPeerBytes('BrokerControl',(Convert-TestHex $row.frameHex),[UInt64]7,[UInt64]1000)}
                }
                catch{$reason=$_.Exception.GetBaseException().Message}
                $reason | Should -BeExactly 'lifecycle:state'
            }
        }
        finally{
            Close-TestDrivenController $controller $driver
        }
    }

    It '17 in-memory-capacity-and-backpressure' {
        $framing=([Text.Encoding]::UTF8.GetString($FixtureBytesById.FramingGoldens)|ConvertFrom-Json).rows
        $controller=New-TestBroker (New-TestProtocol)
        $driver=$null
        try{
            Open-TestBroker $controller
            $brokerFrame=@($framing|Where-Object {$_.id -ceq 'FG02'})[0]
            $localFrame=@($framing|Where-Object {$_.id -ceq 'FG03'})[0]
            $controller.QueueFrame('BrokerControl',(Convert-TestHex $brokerFrame.frameHex),[UInt64]7,[UInt64]1000)
            $controller.Pump([UInt64]7,1)
            $driver=Invoke-PspktBrokerLifecycleTestMember $RuntimeAssembly 'DriverCreate' $null ([object[]]@($controller,$null))
            $script=New-PspktBrokerLifecycleOutcomeScript $RuntimeAssembly ([int[]]@(4)) ([int[]]@(0))
            Invoke-PspktBrokerLifecycleTestMember $RuntimeAssembly 'BindPrimaryWrite' $driver ([object[]]@('BrokerControl',$script))
            $controller.Pump([UInt64]7,1)
            (Invoke-PspktBrokerLifecycleTestMember $RuntimeAssembly 'HasPrimaryHeldCompletion' $driver) | Should -BeTrue
            $controller.FeedPeerBytes('LocalIpc',(Convert-TestHex $localFrame.frameHex),[UInt64]7,[UInt64]1000)
            $controller.Pump([UInt64]7,256)
            $controller.GetSnapshot().LocalIpcWorkerToBrokerObservedRecordCount | Should -Be 2
            $controller.GetSnapshot().BrokerControlBrokerToHostObservedRecordCount | Should -Be 3
            (Invoke-PspktBrokerLifecycleTestMember $RuntimeAssembly 'HasPrimaryHeldCompletion' $driver) | Should -BeTrue
        }
        finally{Close-TestDrivenController $controller $driver -Channel 'BrokerControl'}
        $controller=New-TestWorker (New-TestProtocol)
        try{
            Open-TestWorker $controller
            $ordinary=@($framing|Where-Object {$_.id -ceq 'FG03'})[0]
            for($sequence=1;$sequence -le 8;$sequence++){
                $bytes=Convert-TestHex $ordinary.frameHex
                [Array]::Copy((New-PspktBrokerLifecycleOracleUnsigned 8 $sequence),0,$bytes,12,8)
                $controller.QueueFrame('LocalIpc',$bytes,[UInt64]7,[UInt64]1000)
            }
            $before=$controller.GetSnapshot()|ConvertTo-Json -Depth 5 -Compress
            $bytes=Convert-TestHex $ordinary.frameHex
            [Array]::Copy((New-PspktBrokerLifecycleOracleUnsigned 8 9),0,$bytes,12,8)
            $reason=$null
            try{$controller.QueueFrame('LocalIpc',$bytes,[UInt64]7,[UInt64]1000)}
            catch{$reason=$_.Exception.GetBaseException().Message}
            $reason | Should -BeExactly 'transport:capacity'
            ($controller.GetSnapshot()|ConvertTo-Json -Depth 5 -Compress) | Should -BeExactly $before
            $controller.ReadPeerBytes('LocalIpc',65536,[UInt64]7).Length | Should -Be 0
            $controller.GetSnapshot().ServicePhase | Should -BeExactly 'ControllerActiveUnverified'
            $controller.Pump([UInt64]7,256)
            $controller.ReadPeerBytes('LocalIpc',65536,[UInt64]7).Length | Should -Be 3376
            $controller.GetSnapshot().LocalIpcWorkerToBrokerObservedRecordCount | Should -Be 9
        }
        finally{Close-TestController $controller}
        $controller=New-TestWorker (New-TestProtocol)
        try{
            Open-TestWorker $controller
            $chunk=[byte[]]::new(65536)
            for($index=0;$index -lt 32;$index++){$controller.FeedPeerBytes('LocalIpc',$chunk,[UInt64]7,[UInt64]1000)}
            $before=$controller.GetSnapshot()|ConvertTo-Json -Depth 5 -Compress
            $reason=$null
            try{$controller.FeedPeerBytes('LocalIpc',([byte[]]@(1)),[UInt64]7,[UInt64]1000)}
            catch{$reason=$_.Exception.GetBaseException().Message}
            $reason | Should -BeExactly 'transport:capacity'
            ($controller.GetSnapshot()|ConvertTo-Json -Depth 5 -Compress) | Should -BeExactly $before
            $controller.GetSnapshot().LocalIpcBrokerToWorkerObservedRecordCount | Should -Be 1
        }
        finally{Close-TestController $controller}
        Invoke-PspktBrokerLifecycleInternal $RuntimeAssembly 'ValidateQueueCapacity' ([object[]]@([int]7,[UInt64]2096730,[int]422))
        foreach($arguments in @([object[]]@([int]8,[UInt64]0,[int]422),[object[]]@([int]0,[UInt64]2096731,[int]422),[object[]]@([int]0,[UInt64]::MaxValue,[int]422))){
            $reason=$null
            try{Invoke-PspktBrokerLifecycleInternal $RuntimeAssembly 'ValidateQueueCapacity' $arguments}
            catch{$reason=$_.Exception.GetBaseException().Message}
            $reason | Should -BeExactly 'transport:capacity'
        }
    }

    It '18 write-episode-continuation' {
        $control=New-TestRetirementReference $false
        $disposedDriver=New-TestRetirementReference $true
        [GC]::Collect()
        [GC]::Collect()
        $control.Reference.IsAlive | Should -BeFalse
        $disposedDriver.Reference.IsAlive | Should -BeFalse
        $bootstrap=@(([Text.Encoding]::UTF8.GetString($FixtureBytesById.BootstrapGoldens)|ConvertFrom-Json).rows|Where-Object {$_.id -ceq 'BG04'})[0]
        $frame=Convert-TestHex $bootstrap.frames[0].frameHex
        foreach($scripted in @($true,$false)){
            $controller=New-TestWorker (New-TestProtocol)
            $driver=$null
            try{
                $controller.Start([UInt64]0,[UInt64]1000)
                $controller.Pump([UInt64]0,256)
                $controller.QueueFrame('LocalIpc',$frame,[UInt64]1,[UInt64]1000)
                $controller.Pump([UInt64]1,1)
                $driver=Invoke-PspktBrokerLifecycleTestMember $RuntimeAssembly 'DriverCreate' $null ([object[]]@($controller,$null))
                $bad=New-PspktBrokerLifecycleOutcomeScript $RuntimeAssembly ([int[]]@(1)) ([int[]]@(536))
                $before=$controller.GetSnapshot()|ConvertTo-Json -Depth 5 -Compress
                $reason=$null
                try{Invoke-PspktBrokerLifecycleTestMember $RuntimeAssembly 'BindPrimaryWrite' $driver ([object[]]@('LocalIpc',$bad))}
                catch{$reason=$_.Exception.GetBaseException().Message}
                $reason | Should -BeExactly 'argument:range'
                ($controller.GetSnapshot()|ConvertTo-Json -Depth 5 -Compress) | Should -BeExactly $before
                if($scripted){
                    $increments=[int[]]@(1,7)
                    $script=New-PspktBrokerLifecycleOutcomeScript $RuntimeAssembly ([int[]]@(1,1)) $increments
                    $increments[0]=99
                    (Invoke-PspktBrokerLifecycleTestMember $RuntimeAssembly 'ScriptCopyByteIncrements' $script)[0] | Should -Be 1
                }
                else{$script=New-PspktBrokerLifecycleOutcomeScript $RuntimeAssembly ([int[]]@()) ([int[]]@())}
                Invoke-PspktBrokerLifecycleTestMember $RuntimeAssembly 'BindPrimaryWrite' $driver ([object[]]@('LocalIpc',$script))
                $reason=$null
                try{Invoke-PspktBrokerLifecycleTestMember $RuntimeAssembly 'DriverDispose' $driver}
                catch{$reason=$_.Exception.GetBaseException().Message}
                $reason | Should -BeExactly 'lifecycle:dispose-before-quiescence'
                $parts=[Collections.Generic.List[object]]::new()
                if($scripted){
                    foreach($length in @(1,7)){
                        $controller.Pump([UInt64]1,1)
                        $piece=$controller.ReadPeerBytes('LocalIpc',65536,[UInt64]1)
                        $piece.Length | Should -Be $length
                        $parts.Add($piece)
                        $controller.GetSnapshot().LocalIpcWorkerToBrokerObservedRecordCount | Should -Be 0
                    }
                    $reason=$null
                    try{Invoke-PspktBrokerLifecycleTestMember $RuntimeAssembly 'BindPrimaryWrite' $driver ([object[]]@('LocalIpc',$script))}
                    catch{$reason=$_.Exception.GetBaseException().Message}
                    $reason | Should -BeExactly 'lifecycle:state'
                }
                $controller.Pump([UInt64]1,1)
                $last=$controller.ReadPeerBytes('LocalIpc',65536,[UInt64]1)
                $last.Length | Should -Be $(if($scripted){528}else{536})
                $parts.Add($last)
                [BitConverter]::ToString((Join-PspktBrokerLifecycleOracleBytes $parts.ToArray())) | Should -BeExactly ([BitConverter]::ToString($frame))
                $snapshot=$controller.GetSnapshot()
                $snapshot.LocalIpcWorkerToBrokerObservedRecordCount | Should -Be 1
                $snapshot.LocalIpcWorkerToBrokerObservedFullSignedFrameBytes | Should -Be 536
                $snapshot.LocalIpcWorkerToBrokerObservedWrapperInclusiveBytes | Should -Be 549
                $consumed=Invoke-PspktBrokerLifecycleTestMember $RuntimeAssembly 'CopyConsumedPrimaryOutcomes' $driver
                $consumed.Length | Should -Be $(if($scripted){2}else{0})
            }
            finally{Close-TestDrivenController $controller $driver}
        }
    }

    It '19 uncertain-write-is-terminal' {
        $rows=([Text.Encoding]::UTF8.GetString($FixtureBytesById.FramingGoldens)|ConvertFrom-Json).rows
        $ordinary=Convert-TestHex (@($rows|Where-Object {$_.id -ceq 'FG03'})[0].frameHex)
        $incoming=Convert-TestHex (@($rows|Where-Object {$_.id -ceq 'FG04'})[0].frameHex)
        $scenarios=@(
            @{Kinds=[int[]]@(3);Increments=[int[]]@(0);Prefix=0;Hold=$false;Expiry=$false;Reason='transport:indeterminate-write'},
            @{Kinds=[int[]]@(2);Increments=[int[]]@(0);Prefix=0;Hold=$false;Expiry=$false;Reason='transport:indeterminate-write'},
            @{Kinds=[int[]]@(1,2);Increments=[int[]]@(3,0);Prefix=3;Hold=$false;Expiry=$false;Reason='transport:indeterminate-write'},
            @{Kinds=[int[]]@(1,3);Increments=[int[]]@(3,0);Prefix=3;Hold=$false;Expiry=$false;Reason='transport:indeterminate-write'},
            @{Kinds=[int[]]@(4,2);Increments=[int[]]@(0,0);Prefix=0;Hold=$true;Expiry=$false;Reason='transport:indeterminate-write'},
            @{Kinds=[int[]]@(4,3);Increments=[int[]]@(0,0);Prefix=0;Hold=$true;Expiry=$false;Reason='transport:indeterminate-write'},
            @{Kinds=[int[]]@(4);Increments=[int[]]@(0);Prefix=0;Hold=$true;Expiry=$true;Reason='transport:deadline'}
        )
        foreach($scenario in $scenarios){
            $controller=New-TestWorker (New-TestProtocol)
            $driver=$null
            try{
                Open-TestWorker $controller
                $deadline=[UInt64]1000
                if($scenario.Expiry){$deadline=[UInt64]10}
                $controller.QueueFrame('LocalIpc',$ordinary,[UInt64]7,$deadline)
                $controller.Pump([UInt64]7,1)
                $driver=Invoke-PspktBrokerLifecycleTestMember $RuntimeAssembly 'DriverCreate' $null ([object[]]@($controller,$null))
                $script=New-PspktBrokerLifecycleOutcomeScript $RuntimeAssembly $scenario.Kinds $scenario.Increments
                Invoke-PspktBrokerLifecycleTestMember $RuntimeAssembly 'BindPrimaryWrite' $driver ([object[]]@('LocalIpc',$script))
                if($scenario.Prefix -ne 0){
                    $controller.Pump([UInt64]7,1)
                    $controller.ReadPeerBytes('LocalIpc',65536,[UInt64]7).Length | Should -Be 3
                }
                if($scenario.Hold){
                    $controller.Pump([UInt64]7,1)
                    (Invoke-PspktBrokerLifecycleTestMember $RuntimeAssembly 'HasPrimaryHeldCompletion' $driver) | Should -BeTrue
                    $controller.ReadPeerBytes('LocalIpc',65536,[UInt64]7).Length | Should -Be 422
                }
                $controller.GetSnapshot().LocalIpcWorkerToBrokerObservedRecordCount | Should -Be 1
                $failureNow=[UInt64]7
                if($scenario.Expiry){$controller.Pump([UInt64]9,1);$failureNow=[UInt64]10}
                $reason=$null
                try{$controller.Pump($failureNow,1)}
                catch{$reason=$_.Exception.GetBaseException().Message}
                $reason | Should -BeExactly $scenario.Reason
                $snapshot=$controller.GetSnapshot()
                $snapshot.ServicePhase | Should -BeExactly 'ControllerFaultedUnverified'
                $snapshot.PrimaryReasonCode | Should -BeExactly $scenario.Reason
                $snapshot.LocalIpcWorkerToBrokerObservedRecordCount | Should -Be 1
                (Invoke-PspktBrokerLifecycleTestMember $RuntimeAssembly 'PrimaryWriteRetirementReason' $driver) | Should -BeExactly $scenario.Reason
                $reason=$null
                try{$controller.QueueFrame('LocalIpc',$ordinary,$failureNow,[UInt64]1000)}
                catch{$reason=$_.Exception.GetBaseException().Message}
                $reason | Should -BeExactly 'lifecycle:traffic-after-terminal'
                $reason=$null
                try{$controller.FeedPeerBytes('LocalIpc',$incoming,$failureNow,[UInt64]1000)}
                catch{$reason=$_.Exception.GetBaseException().Message}
                $reason | Should -BeExactly 'lifecycle:state'
                if($scenario.Hold){
                    $controller.GetSnapshot().CleanupComplete | Should -BeFalse
                    $reason=$null
                    try{Invoke-PspktBrokerLifecycleTestMember $RuntimeAssembly 'DeliverPrimaryCompletion' $driver ([object[]]@('LocalIpc'))}
                    catch{$reason=$_.Exception.GetBaseException().Message}
                    $reason | Should -BeExactly 'lifecycle:state'
                    (Invoke-PspktBrokerLifecycleTestMember $RuntimeAssembly 'HasPrimaryHeldCompletion' $driver) | Should -BeFalse
                }
                $controller.GetSnapshot().PrimaryReasonCode | Should -BeExactly $scenario.Reason
                $controller.GetSnapshot().LocalIpcWorkerToBrokerObservedRecordCount | Should -Be 1
                (Invoke-PspktBrokerLifecycleTestMember $RuntimeAssembly 'CopyConsumedPrimaryOutcomes' $driver).Length | Should -Be $scenario.Kinds.Length
            }
            finally{Close-TestDrivenController $controller $driver -Now ([UInt64]20)}
        }
        foreach($delayed in @($false,$true)){
            $controller=New-TestWorker (New-TestProtocol)
            $driver=$null
            try{
                Open-TestWorker $controller
                $controller.QueueFrame('LocalIpc',$ordinary,[UInt64]7,[UInt64]1000)
                $controller.Pump([UInt64]7,1)
                $driver=Invoke-PspktBrokerLifecycleTestMember $RuntimeAssembly 'DriverCreate' $null ([object[]]@($controller,$null))
                if($delayed){$script=New-PspktBrokerLifecycleOutcomeScript $RuntimeAssembly ([int[]]@(4)) ([int[]]@(0))}
                else{$script=New-PspktBrokerLifecycleOutcomeScript $RuntimeAssembly ([int[]]@()) ([int[]]@())}
                Invoke-PspktBrokerLifecycleTestMember $RuntimeAssembly 'BindPrimaryWrite' $driver ([object[]]@('LocalIpc',$script))
                $controller.Pump([UInt64]7,1)
                if($delayed){
                    $controller.GetSnapshot().LocalIpcWorkerToBrokerObservedRecordCount | Should -Be 1
                    Invoke-PspktBrokerLifecycleTestMember $RuntimeAssembly 'DeliverPrimaryCompletion' $driver ([object[]]@('LocalIpc'))
                }
                $controller.GetSnapshot().LocalIpcWorkerToBrokerObservedRecordCount | Should -Be 2
                $controller.GetSnapshot().PrimaryReasonCode | Should -BeExactly ''
                $controller.ReadPeerBytes('LocalIpc',65536,[UInt64]7).Length | Should -Be 422
            }
            finally{Close-TestDrivenController $controller $driver}
        }
    }

    It '20 limited-dispatch-and-no-trust-promotion' {
        $rows=([Text.Encoding]::UTF8.GetString($FixtureBytesById.GeneratedFrames)|ConvertFrom-Json).rows
        foreach($kind in @(4369,4375,4376,4377,4378,4379,4624,4625)){
            $controller=New-TestBroker (New-TestProtocol)
            try{
                Open-TestBroker $controller
                $row=@($rows|Where-Object {$_.kind -eq $kind})[0]
                $send=$row.direction -cin @('BrokerToHost','BrokerToWorker')
                $before=$controller.GetSnapshot()
                $reason=$null
                try{
                    if($send){$controller.QueueFrame($row.channel,(Convert-TestHex $row.frameHex),[UInt64]100,[UInt64]1000)}
                    else{$controller.FeedPeerBytes($row.channel,(Convert-TestHex $row.frameHex),[UInt64]100,[UInt64]1000);$controller.Pump([UInt64]100,256)}
                }
                catch{$reason=$_.Exception.GetBaseException().Message}
                $reason | Should -BeExactly 'lifecycle:dispatch-out-of-scope'
                $after=$controller.GetSnapshot()
                $after.PrimaryReasonCode | Should -BeExactly 'lifecycle:dispatch-out-of-scope'
                $after.TrustCeiling | Should -BeExactly 'StructuralInProcessOnly'
                $after.UncheckedSemantics.Count | Should -Be 13
                foreach($property in @($before.GetType().GetProperties()|Where-Object {$_.Name -cmatch 'Observed|LastObserved'})){
                    $property.GetValue($after,$null) | Should -Be $property.GetValue($before,$null)
                }
                $reason=$null
                try{[void]$controller.ReadPeerBytes($row.channel,1,[UInt64]99)}
                catch{$reason=$_.Exception.GetBaseException().Message}
                $reason | Should -BeExactly 'argument:range'
            }
            finally{Close-TestController $controller -Now ([UInt64]101)}
        }
        $failure=@($rows|Where-Object {$_.kind -eq 4627 -and $_.direction -ceq 'WorkerToBroker'})[0]
        foreach($expiry in @($false,$true)){
            $controller=New-TestWorker (New-TestProtocol)
            $driver=$null
            try{
                Open-TestWorker $controller
                $deadline=[UInt64]1000
                if($expiry){$deadline=[UInt64]10}
                $controller.QueueFrame('LocalIpc',(Convert-TestHex $failure.frameHex),[UInt64]7,$deadline)
                $controller.Pump([UInt64]7,1)
                $driver=Invoke-PspktBrokerLifecycleTestMember $RuntimeAssembly 'DriverCreate' $null ([object[]]@($controller,$null))
                if($expiry){$script=New-PspktBrokerLifecycleOutcomeScript $RuntimeAssembly ([int[]]@(4)) ([int[]]@(0))}
                else{$script=New-PspktBrokerLifecycleOutcomeScript $RuntimeAssembly ([int[]]@(4,2)) ([int[]]@(0,0))}
                Invoke-PspktBrokerLifecycleTestMember $RuntimeAssembly 'BindPrimaryWrite' $driver ([object[]]@('LocalIpc',$script))
                $controller.Pump([UInt64]7,1)
                $controller.GetSnapshot().PrimaryReasonCode | Should -BeExactly ''
                $reason=$null
                try{$controller.Pump($(if($expiry){[UInt64]10}else{[UInt64]7}),1)}
                catch{$reason=$_.Exception.GetBaseException().Message}
                $wanted=$(if($expiry){'transport:deadline'}else{'transport:indeterminate-write'})
                $reason | Should -BeExactly $wanted
                $controller.GetSnapshot().PrimaryReasonCode | Should -BeExactly $wanted
                $controller.GetSnapshot().LocalIpcWorkerToBrokerObservedRecordCount | Should -Be 1
                $reason=$null
                try{Invoke-PspktBrokerLifecycleTestMember $RuntimeAssembly 'DeliverPrimaryCompletion' $driver ([object[]]@('LocalIpc'))}
                catch{$reason=$_.Exception.GetBaseException().Message}
                $reason | Should -BeExactly 'lifecycle:state'
                $controller.GetSnapshot().PrimaryReasonCode | Should -BeExactly $wanted
            }
            finally{Close-TestDrivenController $controller $driver -Now ([UInt64]20)}
        }
        $controller=New-TestWorker (New-TestProtocol)
        try{
            Open-TestWorker $controller
            $row=@($rows|Where-Object {$_.kind -eq 4627 -and $_.direction -ceq 'BrokerToWorker'})[0]
            $malformed=Set-PspktBrokerLifecycleOracleFrameField (Convert-TestHex $row.frameHex) @(3) ([Text.Encoding]::ASCII.GetBytes('not valid'))
            $controller.FeedPeerBytes('LocalIpc',$malformed,[UInt64]7,[UInt64]1000)
            $reason=$null
            try{$controller.Pump([UInt64]7,256)}
            catch{$reason=$_.Exception.GetBaseException().Message}
            $reason | Should -BeExactly 'payload:primitive'
            $controller.GetSnapshot().PrimaryReasonCode | Should -BeExactly 'payload:primitive'
            $controller.GetSnapshot().LocalIpcBrokerToWorkerObservedRecordCount | Should -Be 1
        }
        finally{Close-TestController $controller}
        foreach($source in @($SourceSnapshot.RetainedTexts.Keys|Where-Object {$_.EndsWith('.cs')})){
            $SourceSnapshot.RetainedTexts[$source] | Should -Not -Match 'DllImport|System\.Diagnostics\.Process|ServiceBase|S4U|unsafe\s'
        }
    }

    It '21 broker-worker-role-lifetimes' {
        $controller=New-TestWorker (New-TestProtocol)
        try{
            $before=$controller.GetSnapshot()|ConvertTo-Json -Depth 5 -Compress
            $reason=$null
            try{$controller.ObservePeerEof('LocalIpc',[UInt64]0)}
            catch{$reason=$_.Exception.GetBaseException().Message}
            $reason | Should -BeExactly 'lifecycle:state'
            ($controller.GetSnapshot()|ConvertTo-Json -Depth 5 -Compress) | Should -BeExactly $before
        }
        finally{Close-TestController $controller}
        foreach($role in @('Broker','Worker')){
            $protocol=New-TestProtocol
            if($role -ceq 'Broker'){$controller=New-TestBroker $protocol}else{$controller=New-TestWorker $protocol}
            try{
                $created=$controller.GetSnapshot()
                $created.ServiceRole | Should -BeExactly $role
                $created.ServicePhase | Should -BeExactly 'ControllerCreated'
                $created.RunGenerationId | Should -Be 1
                $created.LocalConnectionPhase | Should -BeExactly 'TransportNotOpened'
                $controller.Start([UInt64]0,[UInt64]1000)
                $controller.Pump([UInt64]0,1)
                $first=$controller.GetSnapshot()
                $first.ServicePhase | Should -BeExactly 'ControllerStarting'
                if($role -ceq 'Broker'){
                    $first.BrokerConnectionPhase | Should -BeExactly 'TransportOpenUnverified'
                    $first.LocalConnectionPhase | Should -BeExactly 'TransportNotOpened'
                }
                else{
                    $first.BrokerConnectionPhase | Should -BeExactly 'TransportNotApplicableToRole'
                    $first.LocalConnectionPhase | Should -BeExactly 'TransportOpenUnverified'
                }
                $controller.Pump([UInt64]0,256)
                $active=$controller.GetSnapshot()
                $active.ServicePhase | Should -BeExactly 'ControllerActiveUnverified'
                $active.LocalConnectionPhase | Should -BeExactly 'TransportOpenUnverified'
                $created.ServicePhase | Should -BeExactly 'ControllerCreated'
                $reason=$null
                try{$controller.Start([UInt64]0,[UInt64]1000)}
                catch{$reason=$_.Exception.GetBaseException().Message}
                $reason | Should -BeExactly 'lifecycle:state'
                $reason=$null
                try{[void]$controller.ReadPeerBytes('WorkerApp',1,[UInt64]0)}
                catch{$reason=$_.Exception.GetBaseException().Message}
                $reason | Should -BeExactly 'argument:context'
            }
            finally{Close-TestController $controller}
            $final=$controller.GetSnapshot()
            $final.CleanupComplete | Should -BeTrue
            $final.TrustCeiling | Should -BeExactly 'StructuralInProcessOnly'
            if($role -ceq 'Broker'){
                $final.ServicePhase | Should -BeExactly 'ControllerFaultedUnverified'
                $final.PrimaryReasonCode | Should -BeExactly 'lifecycle:base-broker-terminal-unavailable'
            }
            else{
                $final.ServicePhase | Should -BeExactly 'ControllerStoppedUnverified'
                $final.PrimaryReasonCode | Should -BeExactly ''
                $final.BrokerConnectionPhase | Should -BeExactly 'TransportNotApplicableToRole'
            }
        }
        $protocol=New-TestProtocol
        for($index=1;$index -le 64;$index++){
            $controller=New-TestWorker $protocol
            $controller.GetSnapshot().RunGenerationId | Should -Be $index
            $controller.Dispose()
        }
        $reason=$null
        try{[void](New-TestWorker $protocol)}
        catch{$reason=$_.Exception.GetBaseException().Message}
        $reason | Should -BeExactly 'transport:capacity'
    }

    It '22 stop-during-every-setup-cut' {
        $controller=New-TestWorker (New-TestProtocol)
        try{
            $controller.RequestStop([UInt64]1,[UInt64]2)
            $reason=$null
            try{$controller.Pump([UInt64]2,1)}
            catch{$reason=$_.Exception.GetBaseException().Message}
            $reason | Should -BeExactly 'transport:deadline'
            $controller.GetSnapshot().ServicePhase | Should -BeExactly 'ControllerFaultedUnverified'
            $controller.GetSnapshot().LocalConnectionPhase | Should -BeExactly 'TransportNotOpened'
        }
        finally{Close-TestController $controller}
        $local=@(([Text.Encoding]::UTF8.GetString($FixtureBytesById.BootstrapGoldens)|ConvertFrom-Json).rows|Where-Object {$_.id -ceq 'BG04'})[0]
        $workerHello=Convert-TestHex $local.frames[0].frameHex
        foreach($cut in 1..12){
            $protocol=New-TestProtocol
            if($cut -eq 2){$controller=New-TestBroker $protocol}else{$controller=New-TestWorker $protocol}
            $driver=$null
            try{
                if($cut -gt 1){
                    $controller.Start([UInt64]0,[UInt64]1000)
                    if($cut -in @(2,3)){$controller.Pump([UInt64]0,1)}
                    elseif($cut -eq 4){$controller.Pump([UInt64]0,2)}
                    else{$controller.Pump([UInt64]0,256)}
                }
                if($cut -in @(5,6,7,8)){
                    $controller.QueueFrame('LocalIpc',$workerHello,[UInt64]1,[UInt64]1000)
                    if($cut -ge 6){
                        $controller.Pump([UInt64]1,1)
                        $driver=Invoke-PspktBrokerLifecycleTestMember $RuntimeAssembly 'DriverCreate' $null ([object[]]@($controller,$null))
                        if($cut -eq 8){$script=New-PspktBrokerLifecycleOutcomeScript $RuntimeAssembly ([int[]]@(4)) ([int[]]@(0))}
                        else{$script=New-PspktBrokerLifecycleOutcomeScript $RuntimeAssembly ([int[]]@(1,1)) ([int[]]@(1,7))}
                        Invoke-PspktBrokerLifecycleTestMember $RuntimeAssembly 'BindPrimaryWrite' $driver ([object[]]@('LocalIpc',$script))
                        if($cut -ge 7){$controller.Pump([UInt64]1,1)}
                    }
                }
                if($cut -ge 9){
                    $controller.RequestStop([UInt64]2,[UInt64]1000)
                    if($cut -ge 10){
                        $controller.Pump([UInt64]2,1)
                        $controller.Pump([UInt64]2,1)
                        $controller.GetSnapshot().LocalConnectionPhase | Should -BeExactly 'TransportDrainingUnverified'
                        $controller.GetSnapshot().CleanupComplete | Should -BeFalse
                    }
                    if($cut -ge 11){
                        $controller.Pump([UInt64]2,1)
                        $controller.GetSnapshot().PendingTransportOperations | Should -Be 0
                        $controller.GetSnapshot().CleanupComplete | Should -BeFalse
                    }
                    if($cut -eq 12){
                        $controller.Pump([UInt64]2,1)
                        $controller.GetSnapshot().LocalConnectionPhase | Should -BeExactly 'LocalObservationSealedUnverified'
                        $controller.GetSnapshot().OutstandingDispatchLeases | Should -Be 0
                    }
                }
                $controller.RequestStop([UInt64]2,[UInt64]1000)
                if($cut -eq 6){
                    $controller.Pump([UInt64]2,1)
                    $controller.Pump([UInt64]2,1)
                    (Invoke-PspktBrokerLifecycleTestMember $RuntimeAssembly 'PrimaryWriteRetirementReason' $driver) | Should -BeExactly 'lifecycle:state'
                    (Invoke-PspktBrokerLifecycleTestMember $RuntimeAssembly 'CopyConsumedPrimaryOutcomes' $driver).Length | Should -Be 0
                    $controller.ReadPeerBytes('LocalIpc',65536,[UInt64]2).Length | Should -Be 0
                }
            }
            finally{
                if($null -ne $driver){Close-TestDrivenController $controller $driver}
                else{Close-TestController $controller}
            }
            $snapshot=$controller.GetSnapshot()
            $snapshot.CleanupComplete | Should -BeTrue
            $snapshot.PendingTransportOperations | Should -Be 0
            $snapshot.OutstandingDispatchLeases | Should -Be 0
            if($cut -in @(5,6)){$snapshot.LocalIpcWorkerToBrokerObservedRecordCount | Should -Be 0}
            if($cut -in @(7,8)){$snapshot.LocalIpcWorkerToBrokerObservedRecordCount | Should -Be 1}
        }
    }

    It '23 repeated-and-concurrent-stop' {
        $controller=New-TestWorker (New-TestProtocol)
        try{
            Open-TestWorker $controller
            $controller.RequestStop([UInt64]10,[UInt64]100)
            $before=$controller.GetSnapshot()|ConvertTo-Json -Depth 5 -Compress
            $reason=$null
            try{$controller.Pump([UInt64]9,1)}
            catch{$reason=$_.Exception.GetBaseException().Message}
            $reason | Should -BeExactly 'argument:range'
            ($controller.GetSnapshot()|ConvertTo-Json -Depth 5 -Compress) | Should -BeExactly $before
        }
        finally{Close-TestController $controller -Now ([UInt64]20)}
        $row=@(([Text.Encoding]::UTF8.GetString($FixtureBytesById.FramingGoldens)|ConvertFrom-Json).rows|Where-Object {$_.id -ceq 'FG03'})[0]
        $ordinary=Convert-TestHex $row.frameHex
        $incoming=Convert-TestHex (@(([Text.Encoding]::UTF8.GetString($FixtureBytesById.FramingGoldens)|ConvertFrom-Json).rows|Where-Object {$_.id -ceq 'FG04'})[0].frameHex)
        foreach($scenario in @(@(100,200,$false),@(200,100,$false),@(100,100,$true))){
            $controller=New-TestWorker (New-TestProtocol)
            $driver=$null
            $pool=$null
            $ready=$null
            $go=$null
            $workers=@()
            $handles=@()
            try{
                Open-TestWorker $controller
                $controller.QueueFrame('LocalIpc',(Convert-TestHex $row.frameHex),[UInt64]3,[UInt64]500)
                $controller.Pump([UInt64]3,1)
                $driver=Invoke-PspktBrokerLifecycleTestMember $RuntimeAssembly 'DriverCreate' $null ([object[]]@($controller,$null))
                $script=New-PspktBrokerLifecycleOutcomeScript $RuntimeAssembly ([int[]]@(4)) ([int[]]@(0))
                Invoke-PspktBrokerLifecycleTestMember $RuntimeAssembly 'BindPrimaryWrite' $driver ([object[]]@('LocalIpc',$script))
                $controller.Pump([UInt64]3,1)
                $drained=$controller.ReadPeerBytes('LocalIpc',65536,[UInt64]9)
                $drained.Length | Should -Be 422
                if($scenario[2]){
                    $pool=[RunspaceFactory]::CreateRunspacePool(1,2)
                    $pool.Open()
                    $ready=[Threading.CountdownEvent]::new(2)
                    $go=[Threading.ManualResetEvent]::new($false)
                    for($index=0;$index -lt 2;$index++){
                        $worker=[powershell]::Create()
                        $worker.RunspacePool=$pool
                        [void]$worker.AddScript('param($controller,$ready,$go) [void]$ready.Signal(); if(-not $go.WaitOne(5000)){throw "validation:cleanup"}; $controller.RequestStop([UInt64]10,[UInt64]100)')
                        [void]$worker.AddArgument($controller).AddArgument($ready).AddArgument($go)
                        $workers+=,$worker
                        $handles+=,$worker.BeginInvoke()
                    }
                    $ready.Wait(5000) | Should -BeTrue
                    $go.Set() | Should -BeTrue
                    for($index=0;$index -lt 2;$index++){
                        $handles[$index].AsyncWaitHandle.WaitOne(5000) | Should -BeTrue
                        [void]$workers[$index].EndInvoke($handles[$index])
                        $workers[$index].HadErrors | Should -BeFalse
                    }
                }
                else{
                    $controller.RequestStop([UInt64]10,[UInt64]$scenario[0])
                    $controller.RequestStop([UInt64]20,[UInt64]$scenario[1])
                }
                $controller.Pump([UInt64]20,256)
                $controller.Pump([UInt64]($scenario[0]-1),1)
                $snapshot=$controller.GetSnapshot()
                $snapshot.ServicePhase | Should -BeExactly 'ControllerQuiescing'
                $snapshot.LocalConnectionPhase | Should -BeExactly 'TransportDrainingUnverified'
                $snapshot.PrimaryReasonCode | Should -BeExactly ''
                $snapshot.CleanupComplete | Should -BeFalse
                Assert-TestUnchangedControllerRejection {
                    $controller.QueueFrame('LocalIpc',$ordinary,[UInt64]($scenario[0]-1),[UInt64]500)
                } 'lifecycle:state' @($controller)
                Assert-TestUnchangedControllerRejection {
                    $controller.FeedPeerBytes('LocalIpc',$incoming,[UInt64]($scenario[0]-1),[UInt64]500)
                } 'lifecycle:state' @($controller)
                $reason=$null
                try{$controller.Pump([UInt64]$scenario[0],1)}
                catch{$reason=$_.Exception.GetBaseException().Message}
                $reason | Should -BeExactly 'transport:deadline'
                $snapshot=$controller.GetSnapshot()
                $snapshot.ServicePhase | Should -BeExactly 'ControllerFaultedUnverified'
                $snapshot.LocalConnectionPhase | Should -BeExactly 'TransportDrainingUnverified'
                $snapshot.PrimaryReasonCode | Should -BeExactly 'transport:deadline'
                $snapshot.CleanupComplete | Should -BeFalse
                (Invoke-PspktBrokerLifecycleTestMember $RuntimeAssembly 'PrimaryWriteRetirementReason' $driver) | Should -BeExactly 'transport:deadline'
                [BitConverter]::ToString($drained) | Should -BeExactly ([BitConverter]::ToString($ordinary))
                $snapshot.LocalIpcWorkerToBrokerLastObservedSequence | Should -Be 0
                $snapshot.LocalIpcWorkerToBrokerObservedRecordCount | Should -Be 1
                $snapshot.LocalIpcWorkerToBrokerObservedFullSignedFrameBytes | Should -Be 536
                $snapshot.LocalIpcWorkerToBrokerObservedWrapperInclusiveBytes | Should -Be 549
                $snapshot.LocalIpcBrokerToWorkerObservedRecordCount | Should -Be 1
                $snapshot.LocalIpcBrokerToWorkerObservedFullSignedFrameBytes | Should -Be 1579
                $snapshot.LocalIpcBrokerToWorkerObservedWrapperInclusiveBytes | Should -Be 1592
                $snapshot.GetType().GetProperty('StopDeadline') | Should -BeNullOrEmpty
                Assert-TestUnchangedControllerRejection {
                    $controller.QueueFrame('LocalIpc',$ordinary,[UInt64]$scenario[0],[UInt64]500)
                } 'lifecycle:traffic-after-terminal' @($controller)
                Assert-TestUnchangedControllerRejection {
                    $controller.FeedPeerBytes('LocalIpc',$incoming,[UInt64]$scenario[0],[UInt64]500)
                } 'lifecycle:state' @($controller)
                $reason=$null
                try{Invoke-PspktBrokerLifecycleTestMember $RuntimeAssembly 'DeliverPrimaryCompletion' $driver ([object[]]@('LocalIpc'))}
                catch{$reason=$_.Exception.GetBaseException().Message}
                $reason | Should -BeExactly 'lifecycle:state'
            }
            finally{
                if($null -ne $go){[void]$go.Set()}
                foreach($worker in $workers){$worker.Dispose()}
                foreach($handle in $handles){$handle.AsyncWaitHandle.Dispose()}
                if($null -ne $pool){$pool.Dispose()}
                if($null -ne $ready){$ready.Dispose()}
                if($null -ne $go){$go.Dispose()}
                Close-TestDrivenController $controller $driver -Now ([UInt64]300)
            }
            $controller.GetSnapshot().OutstandingDispatchLeases | Should -Be 0
            $controller.GetSnapshot().PrimaryReasonCode | Should -BeExactly 'transport:deadline'
        }
    }

    It '24 generation-and-lease-exactness' {
        $generationMutant=@($MutantBuilds|Where-Object {$_.Role -ceq 'M5'})
        $generationMutant.Count | Should -Be 1
        foreach($assembly in @($RuntimeAssembly,$generationMutant[0].Assembly)){
            $bootstrap=@(([Text.Encoding]::UTF8.GetString($FixtureBytesById.BootstrapGoldens)|ConvertFrom-Json).rows|Where-Object {$_.id -ceq 'BG04'})[0]
            $controller=New-TestWorker (New-TestProtocol $assembly)
            $driver=$null
            try{
                $controller.Start([UInt64]0,[UInt64]1000)
                $controller.Pump([UInt64]0,256)
                $controller.QueueFrame('LocalIpc',(Convert-TestHex $bootstrap.frames[0].frameHex),[UInt64]1,[UInt64]1000)
                $controller.Pump([UInt64]1,1)
                $driver=Invoke-PspktBrokerLifecycleTestMember $assembly 'DriverCreate' $null ([object[]]@($controller,$null))
                $script=New-PspktBrokerLifecycleOutcomeScript $assembly ([int[]]@(4)) ([int[]]@(0))
                Invoke-PspktBrokerLifecycleTestMember $assembly 'BindPrimaryWrite' $driver ([object[]]@('LocalIpc',$script))
                $controller.Pump([UInt64]1,1)
                Invoke-PspktBrokerLifecycleTestMember $assembly 'DeliverPrimaryCompletion' $driver ([object[]]@('LocalIpc'))
                $controller.GetSnapshot().LocalIpcWorkerToBrokerObservedRecordCount | Should -Be 1
            }
            finally{Close-TestDrivenController $controller $driver}
        }
        $baseline=Invoke-TestForeignChallenge $RuntimeAssembly
        $baseline.ForeignReason | Should -BeExactly 'lifecycle:stale-generation'
        $baseline.After | Should -BeExactly $baseline.Before
        $baseline.PrematureRecords | Should -Be 0
        $baseline.OwnReason | Should -BeNullOrEmpty
        $baseline.FinalRecords | Should -Be 1
        $mutated=Invoke-TestForeignChallenge $generationMutant[0].Assembly
        $mutated.ForeignReason | Should -BeNullOrEmpty
        $mutated.PrematureRecords | Should -Be 1
        $mutated.OwnReason | Should -BeExactly 'lifecycle:state'
        $generationMutant[0].Initialized=$true
        $generationMutant[0].PositiveControl='Passed'
        $generationMutant[0].OracleKilled=$true
        $generationMutant[0].OracleId='generation-owner'
    }

    It '25 abort-wakes-and-absolute-deadline' {
        $local=@(([Text.Encoding]::UTF8.GetString($FixtureBytesById.BootstrapGoldens)|ConvertFrom-Json).rows|Where-Object {$_.id -ceq 'BG04'})[0]
        $workerHello=Convert-TestHex $local.frames[0].frameHex
        $framing=([Text.Encoding]::UTF8.GetString($FixtureBytesById.FramingGoldens)|ConvertFrom-Json).rows
        $ordinary=Convert-TestHex (@($framing|Where-Object {$_.id -ceq 'FG03'})[0].frameHex)
        $incoming=Convert-TestHex (@($framing|Where-Object {$_.id -ceq 'FG04'})[0].frameHex)
        $controller=New-TestWorker (New-TestProtocol)
        $driver=$null
        try{
            Open-TestWorker $controller
            $controller.QueueFrame('LocalIpc',$ordinary,[UInt64]3,[UInt64]5)
            $controller.Pump([UInt64]3,1)
            $driver=Invoke-PspktBrokerLifecycleTestMember $RuntimeAssembly 'DriverCreate' $null ([object[]]@($controller,$null))
            $script=New-PspktBrokerLifecycleOutcomeScript $RuntimeAssembly ([int[]]@(1)) ([int[]]@(1))
            Invoke-PspktBrokerLifecycleTestMember $RuntimeAssembly 'BindPrimaryWrite' $driver ([object[]]@('LocalIpc',$script))
            $before=$controller.GetSnapshot()
            $before.ServicePhase | Should -BeExactly 'ControllerActiveUnverified'
            $before.LocalConnectionPhase | Should -BeExactly 'BootstrapObservedUnverified'
            $before.PrimaryReasonCode | Should -BeExactly ''
            $before.PendingTransportOperations | Should -Be 1
            (Invoke-PspktBrokerLifecycleTestMember $RuntimeAssembly 'PrimaryWriteRetirementReason' $driver) | Should -BeExactly ''
            $controller.ReadPeerBytes('LocalIpc',65536,[UInt64]4).Length | Should -Be 0
            $reason=$null
            try{$controller.Pump([UInt64]5,1)}
            catch{$reason=$_.Exception.GetBaseException().Message}
            $reason | Should -BeExactly 'transport:deadline'
            (Invoke-PspktBrokerLifecycleTestMember $RuntimeAssembly 'PrimaryWriteRetirementReason' $driver) | Should -BeExactly 'transport:deadline'
            (Invoke-PspktBrokerLifecycleTestMember $RuntimeAssembly 'CopyConsumedPrimaryOutcomes' $driver).Length | Should -Be 0
            $controller.ReadPeerBytes('LocalIpc',65536,[UInt64]5).Length | Should -Be 0
            $after=$controller.GetSnapshot()
            $after.ServicePhase | Should -BeExactly 'ControllerFaultedUnverified'
            $after.LocalConnectionPhase | Should -BeExactly 'TransportDrainingUnverified'
            $after.PrimaryReasonCode | Should -BeExactly 'transport:deadline'
            $after.CleanupComplete | Should -BeFalse
            $after.PendingTransportOperations | Should -Be 0
            $after.OutstandingDispatchLeases | Should -Be 0
            foreach($property in @($before.GetType().GetProperties()|Where-Object {$_.Name -cmatch 'Observed|LastObserved'})){
                $property.GetValue($after,$null) | Should -Be $property.GetValue($before,$null)
            }
            Assert-TestUnchangedControllerRejection {
                $controller.QueueFrame('LocalIpc',$ordinary,[UInt64]5,[UInt64]1000)
            } 'lifecycle:state' @($controller)
            Assert-TestUnchangedControllerRejection {
                $controller.FeedPeerBytes('LocalIpc',$incoming,[UInt64]5,[UInt64]1000)
            } 'lifecycle:state' @($controller)
        }
        finally{Close-TestDrivenController $controller $driver}
        $controller.GetSnapshot().PrimaryReasonCode | Should -BeExactly 'transport:deadline'
        $controller.GetSnapshot().CleanupComplete | Should -BeTrue
        $controller=New-TestBroker (New-TestProtocol)
        try{
            $controller.Start([UInt64]0,[UInt64]1000)
            $controller.Pump([UInt64]0,256)
            $controller.FeedPeerBytes('LocalIpc',[byte[]]$workerHello[0..0],[UInt64]3,[UInt64]5)
            $controller.Pump([UInt64]3,1)
            $controller.FeedPeerBytes('LocalIpc',[byte[]]$workerHello[1..1],[UInt64]4,[UInt64]1000)
            $controller.Pump([UInt64]4,1)
            $reason=$null
            try{$controller.Pump([UInt64]5,1)}
            catch{$reason=$_.Exception.GetBaseException().Message}
            $reason | Should -BeExactly 'transport:deadline'
            $controller.GetSnapshot().PrimaryReasonCode | Should -BeExactly 'transport:deadline'
            $controller.GetSnapshot().LocalIpcWorkerToBrokerObservedRecordCount | Should -Be 0
        }
        finally{Close-TestController $controller}
        $controller=New-TestWorker (New-TestProtocol)
        try{
            $controller.Start([UInt64]0,[UInt64]5)
            $reason=$null
            try{$controller.Pump([UInt64]5,1)}
            catch{$reason=$_.Exception.GetBaseException().Message}
            $reason | Should -BeExactly 'transport:deadline'
            $controller.GetSnapshot().LocalConnectionPhase | Should -BeExactly 'TransportNotOpened'
        }
        finally{Close-TestController $controller}
        $controller=New-TestWorker (New-TestProtocol)
        try{
            $controller.Start([UInt64]0,[UInt64]1000)
            $controller.Pump([UInt64]0,256)
            $controller.QueueFrame('LocalIpc',$workerHello,[UInt64]1,[UInt64]1000)
            $controller.Pump([UInt64]1,1)
            $controller.RequestStop([UInt64]2,[UInt64]1000)
            $controller.Pump([UInt64]2,1)
            $controller.Pump([UInt64]2,1)
            $snapshot=$controller.GetSnapshot()
            $snapshot.LocalIpcWorkerToBrokerAbortWakeCount | Should -Be 1
            $snapshot.LocalIpcBrokerToWorkerAbortWakeCount | Should -Be 1
            $snapshot.PendingTransportOperations | Should -Be 1
            $snapshot.CleanupComplete | Should -BeFalse
            $controller.RequestStop([UInt64]2,[UInt64]2000)
            $controller.Pump([UInt64]2,256)
            $snapshot=$controller.GetSnapshot()
            $snapshot.LocalIpcWorkerToBrokerAbortWakeCount | Should -Be 1
            $snapshot.LocalIpcBrokerToWorkerAbortWakeCount | Should -Be 1
            $snapshot.PendingTransportOperations | Should -Be 0
            $snapshot.OutstandingDispatchLeases | Should -Be 0
            $snapshot.CleanupComplete | Should -BeTrue
        }
        finally{Close-TestController $controller}
    }

    It '26 seal-eof-and-no-half-close' {
        $controller=New-TestWorker (New-TestProtocol)
        try{
            Open-TestWorker $controller
            $controller.RequestStop([UInt64]3,[UInt64]1000)
            $controller.Pump([UInt64]3,1)
            $controller.Pump([UInt64]3,1)
            $controller.GetSnapshot().LocalConnectionPhase | Should -BeExactly 'TransportDrainingUnverified'
            $controller.Pump([UInt64]3,1)
            $snapshot=$controller.GetSnapshot()
            $snapshot.LocalConnectionPhase | Should -BeExactly 'LocalObservationSealedUnverified'
            $snapshot.PendingTransportOperations | Should -Be 0
            $snapshot.OutstandingDispatchLeases | Should -Be 0
            $snapshot.CleanupComplete | Should -BeFalse
            $reason=$null
            try{$controller.ObservePeerEof('LocalIpc',[UInt64]3)}
            catch{$reason=$_.Exception.GetBaseException().Message}
            $reason | Should -BeNullOrEmpty
            $controller.GetSnapshot().PrimaryReasonCode | Should -BeExactly ''
            $controller.Pump([UInt64]3,1)
            $controller.GetSnapshot().LocalConnectionPhase | Should -BeExactly 'TransportClosedUnverified'
            $controller.GetSnapshot().ServicePhase | Should -BeExactly 'ControllerStoppedUnverified'
        }
        finally{Close-TestController $controller}
        $closureMutant=@($MutantBuilds|Where-Object {$_.Role -ceq 'M6'})
        $closureMutant.Count | Should -Be 1
        $row=@(([Text.Encoding]::UTF8.GetString($FixtureBytesById.FramingGoldens)|ConvertFrom-Json).rows|Where-Object {$_.id -ceq 'FG03'})[0]
        foreach($assembly in @($RuntimeAssembly,$closureMutant[0].Assembly)){
            $control=New-TestWorker (New-TestProtocol $assembly)
            Open-TestWorker $control
            Close-TestController $control
            $control.GetSnapshot().CleanupComplete | Should -BeTrue
            $controller=New-TestWorker (New-TestProtocol $assembly)
            $driver=$null
            try{
                Open-TestWorker $controller
                $controller.QueueFrame('LocalIpc',(Convert-TestHex $row.frameHex),[UInt64]7,[UInt64]1000)
                $controller.Pump([UInt64]7,1)
                $driver=Invoke-PspktBrokerLifecycleTestMember $assembly 'DriverCreate' $null ([object[]]@($controller,$null))
                $script=New-PspktBrokerLifecycleOutcomeScript $assembly ([int[]]@(4,2)) ([int[]]@(0,0))
                Invoke-PspktBrokerLifecycleTestMember $assembly 'BindPrimaryWrite' $driver ([object[]]@('LocalIpc',$script))
                $controller.Pump([UInt64]7,1)
                [void]$controller.ReadPeerBytes('LocalIpc',65536,[UInt64]7)
                $reason=$null
                try{$controller.Pump([UInt64]7,1)}
                catch{$reason=$_.Exception.GetBaseException().Message}
                $reason | Should -BeExactly 'transport:indeterminate-write'
                $controller.Pump([UInt64]7,1)
                $controller.GetSnapshot().LocalConnectionPhase | Should -BeExactly 'LocalObservationSealedUnverified'
                $controller.GetSnapshot().OutstandingDispatchLeases | Should -Be 1
                $controller.Pump([UInt64]7,1)
                $snapshot=$controller.GetSnapshot()
                if([object]::ReferenceEquals($assembly,$RuntimeAssembly)){
                    $snapshot.CleanupComplete | Should -BeFalse
                    $snapshot.LocalConnectionPhase | Should -BeExactly 'LocalObservationSealedUnverified'
                }
                else{
                    $snapshot.CleanupComplete | Should -BeTrue
                    $snapshot.LocalConnectionPhase | Should -BeExactly 'TransportClosedUnverified'
                    $snapshot.OutstandingDispatchLeases | Should -Be 1
                    $closureMutant[0].Initialized=$true
                    $closureMutant[0].PositiveControl='Passed'
                    $closureMutant[0].OracleKilled=$true
                    $closureMutant[0].OracleId='close-quiescence'
                }
                $reason=$null
                try{Invoke-PspktBrokerLifecycleTestMember $assembly 'DeliverPrimaryCompletion' $driver ([object[]]@('LocalIpc'))}
                catch{$reason=$_.Exception.GetBaseException().Message}
                $reason | Should -BeExactly 'lifecycle:state'
            }
            finally{Close-TestDrivenController $controller $driver}
            $controller.GetSnapshot().OutstandingDispatchLeases | Should -Be 0
        }
    }

    It '27 primary-failure-atomicity-and-cleanup' {
        $FixtureBytesById.ContainsKey('LifecycleTraces') | Should -BeTrue
        $FixtureBytesById.ContainsKey('ContractExpectations') | Should -BeTrue
        $traces=[Text.Encoding]::UTF8.GetString($FixtureBytesById.LifecycleTraces)|ConvertFrom-Json
        $expectations=[Text.Encoding]::UTF8.GetString($FixtureBytesById.ContractExpectations)|ConvertFrom-Json
        $traces.rows.Count | Should -Be 12
        $expectations.scenarios.Count | Should -Be 9
        @($traces.rows|Where-Object {$_.id -ceq 'LT12'}).Count | Should -Be 1
        $framing=([Text.Encoding]::UTF8.GetString($FixtureBytesById.FramingGoldens)|ConvertFrom-Json).rows
        $ordinary=Convert-TestHex (@($framing|Where-Object {$_.id -ceq 'FG03'})[0].frameHex)
        $incoming=Convert-TestHex (@($framing|Where-Object {$_.id -ceq 'FG04'})[0].frameHex)
        $generated=([Text.Encoding]::UTF8.GetString($FixtureBytesById.GeneratedFrames)|ConvertFrom-Json).rows
        $peerFailure=Convert-TestHex (@($generated|Where-Object {$_.kind -eq 4627 -and $_.direction -ceq 'BrokerToWorker'})[0].frameHex)
        $controller=New-TestWorker (New-TestProtocol)
        $driver=$null
        try{
            Open-TestWorker $controller
            $controller.QueueFrame('LocalIpc',$ordinary,[UInt64]3,[UInt64]1000)
            $controller.Pump([UInt64]3,1)
            $driver=Invoke-PspktBrokerLifecycleTestMember $RuntimeAssembly 'DriverCreate' $null ([object[]]@($controller,$null))
            $script=New-PspktBrokerLifecycleOutcomeScript $RuntimeAssembly ([int[]]@(1)) ([int[]]@(1))
            Invoke-PspktBrokerLifecycleTestMember $RuntimeAssembly 'BindPrimaryWrite' $driver ([object[]]@('LocalIpc',$script))
            $controller.GetSnapshot().ServicePhase | Should -BeExactly 'ControllerActiveUnverified'
            $controller.GetSnapshot().PendingTransportOperations | Should -Be 1
            (Invoke-PspktBrokerLifecycleTestMember $RuntimeAssembly 'PrimaryWriteRetirementReason' $driver) | Should -BeExactly ''
            $controller.ReadPeerBytes('LocalIpc',65536,[UInt64]3).Length | Should -Be 0
            $controller.FeedPeerBytes('LocalIpc',$peerFailure,[UInt64]4,[UInt64]1000)
            Pump-TestUntilFault $controller -Now ([UInt64]4)
            (Invoke-PspktBrokerLifecycleTestMember $RuntimeAssembly 'PrimaryWriteRetirementReason' $driver) | Should -BeExactly 'lifecycle:state'
            (Invoke-PspktBrokerLifecycleTestMember $RuntimeAssembly 'CopyConsumedPrimaryOutcomes' $driver).Length | Should -Be 0
            (Invoke-PspktBrokerLifecycleTestMember $RuntimeAssembly 'HasPrimaryHeldCompletion' $driver) | Should -BeFalse
            $controller.ReadPeerBytes('LocalIpc',65536,[UInt64]4).Length | Should -Be 0
            $snapshot=$controller.GetSnapshot()
            $snapshot.PrimaryReasonCode | Should -BeExactly 'lifecycle:peer-failure-observed'
            $snapshot.LocalConnectionPhase | Should -BeExactly 'TransportDrainingUnverified'
            $snapshot.PendingTransportOperations | Should -Be 0
            $snapshot.OutstandingDispatchLeases | Should -Be 0
            $snapshot.LocalIpcWorkerToBrokerLastObservedSequence | Should -Be 0
            $snapshot.LocalIpcWorkerToBrokerObservedRecordCount | Should -Be 1
            $snapshot.LocalIpcWorkerToBrokerObservedFullSignedFrameBytes | Should -Be 536
            $snapshot.LocalIpcWorkerToBrokerObservedWrapperInclusiveBytes | Should -Be 549
            $snapshot.LocalIpcBrokerToWorkerLastObservedSequence | Should -Be 1
            $snapshot.LocalIpcBrokerToWorkerObservedRecordCount | Should -Be 2
            $snapshot.LocalIpcBrokerToWorkerObservedFullSignedFrameBytes | Should -Be (1579+$peerFailure.Length)
            $snapshot.LocalIpcBrokerToWorkerObservedWrapperInclusiveBytes | Should -Be (1592+$peerFailure.Length+13)
            Assert-TestUnchangedControllerRejection {
                $controller.QueueFrame('LocalIpc',$ordinary,[UInt64]4,[UInt64]1000)
            } 'lifecycle:state' @($controller)
            Assert-TestUnchangedControllerRejection {
                $controller.FeedPeerBytes('LocalIpc',$incoming,[UInt64]4,[UInt64]1000)
            } 'lifecycle:traffic-after-terminal' @($controller)
        }
        finally{Close-TestDrivenController $controller $driver}
        $controller.GetSnapshot().PrimaryReasonCode | Should -BeExactly 'lifecycle:peer-failure-observed'
        $controller.GetSnapshot().ServicePhase | Should -BeExactly 'ControllerFaultedUnverified'
        $controller.GetSnapshot().CleanupComplete | Should -BeTrue
        $cases=@($expectations.scenarios|Where-Object {$_.id -cin @('SC05','SC06')})
        foreach($scenario in $cases){
            foreach($variant in $scenario.variants){
                $controller=New-TestWorker (New-TestProtocol)
                $driver=$null
                try{
                    Open-TestWorker $controller
                    $deadline=[UInt64]1000
                    if($scenario.id -ceq 'SC06'){$deadline=[UInt64]10}
                    $controller.QueueFrame('LocalIpc',$ordinary,[UInt64]3,$deadline)
                    $controller.Pump([UInt64]3,1)
                    $driver=Invoke-PspktBrokerLifecycleTestMember $RuntimeAssembly 'DriverCreate' $null ([object[]]@($controller,$null))
                    $script=New-PspktBrokerLifecycleOutcomeScript $RuntimeAssembly ([int[]]$variant.outcomes) ([int[]]$variant.increments)
                    Invoke-PspktBrokerLifecycleTestMember $RuntimeAssembly 'BindPrimaryWrite' $driver ([object[]]@('LocalIpc',$script))
                    $controller.Pump([UInt64]3,1)
                    $controller.ReadPeerBytes('LocalIpc',65536,[UInt64]3).Length | Should -Be 422
                    $controller.FeedPeerBytes('LocalIpc',$peerFailure,[UInt64]4,[UInt64]1000)
                    Pump-TestUntilFault $controller -Now ([UInt64]4)
                    $first=$controller.GetSnapshot()
                    $first.PrimaryReasonCode | Should -BeExactly 'lifecycle:peer-failure-observed'
                    $failureNow=[UInt64]4
                    $transportReason='transport:indeterminate-write'
                    if($scenario.id -ceq 'SC06'){$failureNow=[UInt64]10;$transportReason='transport:deadline'}
                    $reason=$null
                    try{$controller.Pump($failureNow,1)}
                    catch{$reason=$_.Exception.GetBaseException().Message}
                    $reason | Should -BeExactly $transportReason
                    (Invoke-PspktBrokerLifecycleTestMember $RuntimeAssembly 'PrimaryWriteRetirementReason' $driver) | Should -BeExactly $transportReason
                    $controller.GetSnapshot().PrimaryReasonCode | Should -BeExactly 'lifecycle:peer-failure-observed'
                    $controller.GetSnapshot().CleanupComplete | Should -BeFalse
                    $reason=$null
                    try{$controller.Dispose()}
                    catch{$reason=$_.Exception.GetBaseException().Message}
                    $reason | Should -BeExactly 'lifecycle:dispose-before-quiescence'
                    $reason=$null
                    try{Invoke-PspktBrokerLifecycleTestMember $RuntimeAssembly 'DeliverPrimaryCompletion' $driver ([object[]]@('LocalIpc'))}
                    catch{$reason=$_.Exception.GetBaseException().Message}
                    $reason | Should -BeExactly 'lifecycle:state'
                    $controller.RequestStop([UInt64]20,[UInt64]1000)
                    $controller.Pump([UInt64]20,256)
                    $snapshot=$controller.GetSnapshot()
                    $snapshot.CleanupComplete | Should -BeTrue
                    $snapshot.ServicePhase | Should -BeExactly 'ControllerFaultedUnverified'
                    $snapshot.PrimaryReasonCode | Should -BeExactly 'lifecycle:peer-failure-observed'
                    $snapshot.LocalIpcWorkerToBrokerObservedRecordCount | Should -Be 1
                    $first.CleanupComplete | Should -BeFalse
                    Invoke-PspktBrokerLifecycleTestMember $RuntimeAssembly 'DriverDispose' $driver
                    $driver=$null
                    $controller.Dispose()
                    foreach($send in @($true,$false)){
                        $before=$controller.GetSnapshot()|ConvertTo-Json -Depth 5 -Compress
                        $reason=$null
                        try{
                            if($send){$controller.QueueFrame('LocalIpc',$ordinary,[UInt64]20,[UInt64]1000)}
                            else{$controller.FeedPeerBytes('LocalIpc',$incoming,[UInt64]20,[UInt64]1000)}
                        }
                        catch{$reason=$_.Exception.GetBaseException().Message}
                        $reason | Should -BeExactly 'lifecycle:traffic-after-terminal'
                        ($controller.GetSnapshot()|ConvertTo-Json -Depth 5 -Compress) | Should -BeExactly $before
                    }
                }
                finally{Close-TestDrivenController $controller $driver -Now ([UInt64]20)}
            }
        }
    }

    It '28 one-shot-preload-and-csharp5-custody' {
        $entry='certification\broker-lifecycle\validators\Invoke-PspktPhase4BrokerLifecycleValidators.ps1'
        $SourceSnapshot.RetainedTexts.ContainsKey($entry) | Should -BeTrue
        $text=$SourceSnapshot.RetainedTexts[$entry]
        $tokens=$null
        $errors=$null
        $ast=[Management.Automation.Language.Parser]::ParseInput($text,[ref]$tokens,[ref]$errors)
        @($errors).Count | Should -Be 0
        $ast.ParamBlock.Parameters.Count | Should -Be 3
        ($ast.ParamBlock.Parameters.Name.VariablePath.UserPath -join '|') | Should -BeExactly 'RepositoryRoot|WorkRoot|PesterManifestPath'
        $text | Should -Not -Match '(?im)^\s*#Requires\b|SetData\([^;]*,\s*\$null'
        $claim=$text.IndexOf('.SetData(',[StringComparison]::Ordinal)
        $claim | Should -BeGreaterThan 0
        foreach($operation in @('[IO.File]::Open','[IO.File]::ReadAllBytes','Import-Module','. ([scriptblock]::Create')){
            $position=$text.IndexOf($operation,[StringComparison]::Ordinal)
            if($position -ge 0){$position | Should -BeGreaterThan $claim}
        }
        $CompilationRecords.Count | Should -Be 8
        ($CompilationRecords.Role -join '|') | Should -BeExactly 'Bootstrap|Runtime|M1|M2|M3|M4|M5|M6'
        $expectations=[Text.Encoding]::UTF8.GetString($FixtureBytesById.ContractExpectations)|ConvertFrom-Json
        foreach($record in $CompilationRecords){
            $record.Language | Should -BeExactly 'CSharp5'
            $record.SourceCount | Should -Be $(if($record.Role -ceq 'Bootstrap'){1}else{31})
            [object]::ReferenceEquals($record.Assembly,[Reflection.Assembly]::GetAssembly($record.Assembly.GetTypes()[0])) | Should -BeTrue
            [IO.Path]::GetFullPath($record.Assembly.Location) | Should -BeExactly ([IO.Path]::GetFullPath($record.Path))
            (Get-PspktBrokerLifecycleOracleDigest ([IO.File]::ReadAllBytes($record.Path))) | Should -BeExactly $record.Sha256
            if($record.Role -cne 'Bootstrap'){
                Assert-PspktBrokerLifecyclePublicSurface -Assembly $record.Assembly -Expectations $expectations
                foreach($name in @('LifecycleTestDriver.cs','TransportOutcomeScript.cs','PendingTransportOperation.cs')){
                    $path='certification\broker-lifecycle\lib\'+$name
                    (Get-PspktBrokerLifecycleOracleDigest $record.SourceBytes[$path]) |
                        Should -BeExactly (Get-PspktBrokerLifecycleOracleDigest $CompilationRecords[1].SourceBytes[$path])
                }
            }
        }
        $reason=$null
        try{Assert-PspktBrokerLifecycleNoPreload}
        catch{$reason=$_.Exception.GetBaseException().Message}
        $reason | Should -BeExactly 'validation:preload'
        $reason=$null
        try{Invoke-PspktBrokerLifecycleTestMember $RuntimeAssembly 'ApplyWriteCompletion' $null}
        catch{$reason=$_.Exception.GetBaseException().Message}
        $reason | Should -BeExactly 'validation:public-surface'
        $reason=$null
        try{Invoke-PspktBrokerLifecycleTestMember $RuntimeAssembly 'SetOwnerIdentity' $null}
        catch{$reason=$_.Exception.GetBaseException().Message}
        $reason | Should -BeExactly 'validation:public-surface'
        $enumType=$RuntimeAssembly.GetType('Pspkt.Certification.BrokerLifecycle.TransportOutcomeScript+OutcomeKind',$true)
        $emptyOutcomes=[Array]::CreateInstance($enumType,0)
        foreach($arguments in @([object[]]@($null,[int[]]@()),[object[]]@($emptyOutcomes,$null))){
            Assert-TestUnchangedControllerRejection {
                Invoke-PspktBrokerLifecycleTestMember $RuntimeAssembly 'ScriptCreate' $null $arguments
            } 'argument:null'
        }
        $invalidScripts=@(
            @{Kinds=[int[]]@(1);Increments=[int[]]@();Reason='argument:range'},
            @{Kinds=[int[]](1..17|ForEach-Object {1});Increments=[int[]](1..17|ForEach-Object {1});Reason='argument:range'},
            @{Kinds=[int[]]@(0);Increments=[int[]]@(0);Reason='argument:range'},
            @{Kinds=[int[]]@(6);Increments=[int[]]@(0);Reason='argument:range'},
            @{Kinds=[int[]]@(1);Increments=[int[]]@(-1);Reason='argument:range'},
            @{Kinds=[int[]]@(1);Increments=[int[]]@(0);Reason='argument:range'},
            @{Kinds=[int[]]@(1);Increments=[int[]]@(65537);Reason='argument:range'},
            @{Kinds=[int[]]@(2);Increments=[int[]]@(1);Reason='argument:range'},
            @{Kinds=[int[]]@(5);Increments=[int[]]@(0);Reason='argument:context'},
            @{Kinds=[int[]]@(4,4);Increments=[int[]]@(0,0);Reason='argument:context'},
            @{Kinds=[int[]]@(4,1);Increments=[int[]]@(0,1);Reason='argument:context'},
            @{Kinds=[int[]]@(2,3);Increments=[int[]]@(0,0);Reason='argument:context'},
            @{Kinds=[int[]]@(3,1);Increments=[int[]]@(0,1);Reason='argument:context'},
            @{Kinds=[int[]]@(4,5,2);Increments=[int[]]@(0,0,0);Reason='argument:context'}
        )
        foreach($specification in $invalidScripts){
            Assert-TestUnchangedControllerRejection {
                New-PspktBrokerLifecycleOutcomeScript $RuntimeAssembly $specification.Kinds $specification.Increments
            } $specification.Reason
        }
        $outcomes=[Array]::CreateInstance($enumType,2)
        $outcomes.SetValue([Enum]::ToObject($enumType,1),0)
        $outcomes.SetValue([Enum]::ToObject($enumType,4),1)
        $increments=[int[]]@(1,0)
        $immutable=Invoke-PspktBrokerLifecycleTestMember $RuntimeAssembly 'ScriptCreate' $null ([object[]]@($outcomes,$increments))
        $outcomes.SetValue([Enum]::ToObject($enumType,3),0)
        $increments[0]=99
        $copy=Invoke-PspktBrokerLifecycleTestMember $RuntimeAssembly 'ScriptCopyOutcomes' $immutable
        ($copy -join ',') | Should -BeExactly 'KnownShortWriteIncrement,DelayCompletionDelivery'
        $copy.SetValue([Enum]::ToObject($enumType,2),0)
        ((Invoke-PspktBrokerLifecycleTestMember $RuntimeAssembly 'ScriptCopyOutcomes' $immutable) -join ',') | Should -BeExactly 'KnownShortWriteIncrement,DelayCompletionDelivery'
        $copy=Invoke-PspktBrokerLifecycleTestMember $RuntimeAssembly 'ScriptCopyByteIncrements' $immutable
        ($copy -join ',') | Should -BeExactly '1,0'
        $copy[0]=88
        ((Invoke-PspktBrokerLifecycleTestMember $RuntimeAssembly 'ScriptCopyByteIncrements' $immutable) -join ',') | Should -BeExactly '1,0'
        $controller=New-TestWorker (New-TestProtocol)
        $driver=$null
        try{
            Assert-TestUnchangedControllerRejection {
                Invoke-PspktBrokerLifecycleTestMember $RuntimeAssembly 'DriverCreate' $null ([object[]]@($null,$null))
            } 'argument:null' @($controller)
            Assert-TestUnchangedControllerRejection {
                Invoke-PspktBrokerLifecycleTestMember $RuntimeAssembly 'DriverCreate' $null ([object[]]@($controller,$controller))
            } 'argument:owner' @($controller)
            $driver=Invoke-PspktBrokerLifecycleTestMember $RuntimeAssembly 'DriverCreate' $null ([object[]]@($controller,$null))
            (Invoke-PspktBrokerLifecycleTestMember $RuntimeAssembly 'PrimaryWriteRetirementReason' $driver) | Should -BeExactly ''
            $empty=New-PspktBrokerLifecycleOutcomeScript $RuntimeAssembly ([int[]]@()) ([int[]]@())
            foreach($entry in @(
                @{Member='BindPrimaryWrite';Arguments=[object[]]@('LocalIpc',$null);Reason='argument:null'},
                @{Member='BindPrimaryWrite';Arguments=[object[]]@($null,$empty);Reason='argument:null'},
                @{Member='BindPrimaryWrite';Arguments=[object[]]@('LocalIpc',$empty);Reason='lifecycle:state'},
                @{Member='BindForeignWrite';Arguments=[object[]]@('LocalIpc',$empty);Reason='argument:context'},
                @{Member='DeliverPrimaryCompletion';Arguments=[object[]]@('LocalIpc');Reason='lifecycle:state'},
                @{Member='DeliverPrimaryCompletion';Arguments=[object[]]@($null);Reason='argument:null'},
                @{Member='DeliverForeignCompletionToPrimary';Arguments=[object[]]@('LocalIpc');Reason='argument:context'}
            )){
                Assert-TestUnchangedControllerRejection {
                    Invoke-PspktBrokerLifecycleTestMember $RuntimeAssembly $entry.Member $driver $entry.Arguments
                } $entry.Reason @($controller)
            }
            $row=@(([Text.Encoding]::UTF8.GetString($FixtureBytesById.BootstrapGoldens)|ConvertFrom-Json).rows|Where-Object {$_.id -ceq 'BG04'})[0]
            $frame=Convert-TestHex $row.frames[0].frameHex
            $controller.Start([UInt64]0,[UInt64]1000)
            $controller.Pump([UInt64]0,256)
            $controller.QueueFrame('LocalIpc',$frame,[UInt64]1,[UInt64]1000)
            $controller.Pump([UInt64]1,1)
            foreach($steps in @([int[]]@(536),[int[]]@(530,6),[int[]]@(65536))){
                $kinds=[int[]]@($steps|ForEach-Object {1})
                $script=New-PspktBrokerLifecycleOutcomeScript $RuntimeAssembly $kinds $steps
                Assert-TestUnchangedControllerRejection {
                    Invoke-PspktBrokerLifecycleTestMember $RuntimeAssembly 'BindPrimaryWrite' $driver ([object[]]@('LocalIpc',$script))
                } 'argument:range' @($controller)
            }
            $foreignRoute=New-PspktBrokerLifecycleOutcomeScript $RuntimeAssembly ([int[]]@(4,5)) ([int[]]@(0,0))
            Assert-TestUnchangedControllerRejection {
                Invoke-PspktBrokerLifecycleTestMember $RuntimeAssembly 'BindPrimaryWrite' $driver ([object[]]@('LocalIpc',$foreignRoute))
            } 'argument:context' @($controller)
            Assert-TestUnchangedControllerRejection {
                Invoke-PspktBrokerLifecycleTestMember $RuntimeAssembly 'BindPrimaryWrite' $driver ([object[]]@('BrokerControl',$empty))
            } 'argument:context' @($controller)
            $held=New-PspktBrokerLifecycleOutcomeScript $RuntimeAssembly ([int[]]@(4)) ([int[]]@(0))
            Invoke-PspktBrokerLifecycleTestMember $RuntimeAssembly 'BindPrimaryWrite' $driver ([object[]]@('LocalIpc',$held))
            (Invoke-PspktBrokerLifecycleTestMember $RuntimeAssembly 'PrimaryWriteRetirementReason' $driver) | Should -BeExactly ''
            $controller.Pump([UInt64]1,1)
            [BitConverter]::ToString($controller.ReadPeerBytes('LocalIpc',65536,[UInt64]1)) | Should -BeExactly ([BitConverter]::ToString($frame))
            $controller.GetSnapshot().LocalIpcWorkerToBrokerObservedRecordCount | Should -Be 0
            foreach($entry in @(
                @{Member='BindPrimaryWrite';Arguments=[object[]]@('LocalIpc',$empty);Reason='lifecycle:state'},
                @{Member='DeliverPrimaryCompletion';Arguments=[object[]]@('BrokerControl');Reason='argument:context'},
                @{Member='DriverDispose';Arguments=[object[]]@();Reason='lifecycle:dispose-before-quiescence'}
            )){
                Assert-TestUnchangedControllerRejection {
                    Invoke-PspktBrokerLifecycleTestMember $RuntimeAssembly $entry.Member $driver $entry.Arguments
                } $entry.Reason @($controller)
            }
            $anotherDriver=Invoke-PspktBrokerLifecycleTestMember $RuntimeAssembly 'DriverCreate' $null ([object[]]@($controller,$null))
            try{
                Assert-TestUnchangedControllerRejection {
                    Invoke-PspktBrokerLifecycleTestMember $RuntimeAssembly 'BindPrimaryWrite' $anotherDriver ([object[]]@('LocalIpc',$empty))
                } 'lifecycle:state' @($controller)
            }
            finally{Invoke-PspktBrokerLifecycleTestMember $RuntimeAssembly 'DriverDispose' $anotherDriver}
            Invoke-PspktBrokerLifecycleTestMember $RuntimeAssembly 'DeliverPrimaryCompletion' $driver ([object[]]@('LocalIpc'))
            $controller.GetSnapshot().LocalIpcWorkerToBrokerObservedRecordCount | Should -Be 1
            (Invoke-PspktBrokerLifecycleTestMember $RuntimeAssembly 'PrimaryWriteRetirementReason' $driver) | Should -BeExactly ''
            Invoke-PspktBrokerLifecycleTestMember $RuntimeAssembly 'DriverDispose' $driver
            Assert-TestUnchangedControllerRejection {
                Invoke-PspktBrokerLifecycleTestMember $RuntimeAssembly 'PrimaryWriteRetirementReason' $driver
            } 'lifecycle:disposed' @($controller)
            $driver=$null
            foreach($member in @('set_PrimaryWriteRetirementReason','_primaryOperation','ClearInvocationMarker','ResetPhase')){
                Assert-TestUnchangedControllerRejection {
                    Invoke-PspktBrokerLifecycleTestMember $RuntimeAssembly $member $null
                } 'validation:public-surface' @($controller)
            }
            $otherImage=New-TestWorker (New-TestProtocol $MutantBuilds[0].Assembly)
            try{
                Assert-TestUnchangedControllerRejection {
                    Invoke-PspktBrokerLifecycleTestMember $RuntimeAssembly 'DriverCreate' $null ([object[]]@($controller,$otherImage))
                } 'validation:public-surface' @($controller,$otherImage)
            }
            finally{$otherImage.Dispose()}
        }
        finally{Close-TestDrivenController $controller $driver}
        foreach($mismatch in @('generation','frame')){
            $protocol=New-TestProtocol
            $primary=New-TestWorker $protocol
            if($mismatch -ceq 'generation'){$foreign=New-TestWorker $protocol}else{$foreign=New-TestWorker (New-TestProtocol)}
            $driver=$null
            try{
                foreach($endpoint in @($primary,$foreign)){
                    $bytes=[byte[]]$frame.Clone()
                    if($mismatch -ceq 'frame' -and [object]::ReferenceEquals($endpoint,$foreign)){$bytes[$bytes.Length-1]=$bytes[$bytes.Length-1] -bxor 1}
                    $endpoint.Start([UInt64]0,[UInt64]1000)
                    $endpoint.Pump([UInt64]0,256)
                    $endpoint.QueueFrame('LocalIpc',$bytes,[UInt64]1,[UInt64]1000)
                    $endpoint.Pump([UInt64]1,1)
                }
                $driver=Invoke-PspktBrokerLifecycleTestMember $RuntimeAssembly 'DriverCreate' $null ([object[]]@($primary,$foreign))
                Assert-TestUnchangedControllerRejection {
                    Invoke-PspktBrokerLifecycleTestMember $RuntimeAssembly 'BindPrimaryWrite' $driver ([object[]]@('LocalIpc',$held))
                } 'argument:context' @($primary,$foreign)
            }
            finally{
                if($null -ne $driver){Invoke-PspktBrokerLifecycleTestMember $RuntimeAssembly 'DriverDispose' $driver}
                Close-TestController $primary
                Close-TestController $foreign
            }
        }
        $pairControl=Invoke-TestForeignChallenge $RuntimeAssembly
        $pairControl.ForeignReason | Should -BeExactly 'lifecycle:stale-generation'
        $pairControl.After | Should -BeExactly $pairControl.Before
        $pairControl.OwnReason | Should -BeNullOrEmpty
        $pairControl.FinalRecords | Should -Be 1
    }

    It '29 independent-corpus-and-initialized-mutants' {
        $FixtureBytesById.ContainsKey('ProtectedManifest') | Should -BeTrue
        $manifest=[Text.Encoding]::UTF8.GetString($FixtureBytesById.ProtectedManifest)|ConvertFrom-Json
        $manifest.files.Count | Should -Be 4
        $mapping=@{'framing-goldens.v1.json'='FramingGoldens';'bootstrap-goldens.v1.json'='BootstrapGoldens';
            'lifecycle-traces.v1.json'='LifecycleTraces';'contract-expectations.v1.json'='ContractExpectations'}
        foreach($file in $manifest.files){
            $bytes=$FixtureBytesById[$mapping[$file.path]]
            $bytes.Length | Should -Be $file.bytes
            (Get-PspktBrokerLifecycleOracleDigest $bytes) | Should -BeExactly $file.sha256
        }
        $framing=([Text.Encoding]::UTF8.GetString($FixtureBytesById.FramingGoldens)|ConvertFrom-Json).rows
        $bootstrap=([Text.Encoding]::UTF8.GetString($FixtureBytesById.BootstrapGoldens)|ConvertFrom-Json).rows
        $framing.Count | Should -Be 8
        $bootstrap.Count | Should -Be 10
        ([Text.Encoding]::UTF8.GetString($FixtureBytesById.LifecycleTraces)|ConvertFrom-Json).rows.Count | Should -Be 12
        $generated=[Text.Encoding]::UTF8.GetString($FixtureBytesById.GeneratedFrames)|ConvertFrom-Json
        $generated.rows.Count | Should -Be 22
        foreach($row in $generated.rows){
            $bytes=Convert-TestHex $row.frameHex
            $bytes.Length | Should -Be $row.frameLength
            (Get-PspktBrokerLifecycleOracleDigest $bytes) | Should -BeExactly $row.frameSha256
        }
        $MutantBuilds.Count | Should -Be 6
        foreach($mutant in @($MutantBuilds|Where-Object {$_.Role -cin @('M1','M2','M3','M4')})){
            $protocol=New-TestProtocol $mutant.Assembly
            $controller=New-TestWorker $protocol
            $controller.GetSnapshot().TrustCeiling | Should -BeExactly 'StructuralInProcessOnly'
            $controller.Dispose()
            switch -CaseSensitive ($mutant.Role){
                'M1' {
                    $golden=@($framing|Where-Object {$_.id -ceq 'FG01'})[0]
                    $bytes=Convert-TestHex $golden.frameHex
                    $protocol.Decode($golden.channel,$golden.direction,[byte]2,$bytes).Kind | Should -Be 4372
                    $actual=$protocol.Encode($golden.channel,$golden.direction,[byte]2,[UInt16]4372,[UInt64]1,[byte[]]$bytes[24..37],[byte[]]$bytes[38..421])
                    $wrong=[byte[]]$bytes.Clone()
                    [Array]::Copy(([byte[]]@(14,0,0,0)),0,$wrong,20,4)
                    [BitConverter]::ToString($actual) | Should -BeExactly ([BitConverter]::ToString($wrong))
                    (Get-PspktBrokerLifecycleOracleDigest $actual) | Should -Not -Be $golden.sha256
                    $mutant.OracleId='header-length-endian'
                }
                'M2' {
                    $meta=Convert-TestHex 'b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf'
                    $schema=Convert-TestHex 'd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef'
                    $broker=@($framing|Where-Object {$_.id -ceq 'FG05'})[0].cases[0]
                    $local=@($framing|Where-Object {$_.id -ceq 'FG06'})[0].cases[0]
                    $decoded=$protocol.Decode($broker.channel,$broker.direction,[byte]2,(Convert-TestHex $broker.frameHex))
                    (Get-PspktBrokerLifecycleOracleDigest $protocol.BuildSignaturePreimage($decoded,[byte]$broker.role,(Convert-TestHex $broker.channelIdentifier),$meta,$schema)) | Should -BeExactly $broker.sha256
                    $decoded=$protocol.Decode($local.channel,$local.direction,[byte]2,(Convert-TestHex $local.frameHex))
                    $actual=$protocol.BuildSignaturePreimage($decoded,[byte]$local.role,(Convert-TestHex $local.channelIdentifier),$meta,$schema)
                    $correct=Convert-TestHex $local.preimageHex
                    $wrong=Join-PspktBrokerLifecycleOracleBytes @([Text.Encoding]::ASCII.GetBytes("pspkt-phase4-frame-v1`0"),[byte[]]$correct[28..($correct.Length-1)])
                    [BitConverter]::ToString($actual) | Should -BeExactly ([BitConverter]::ToString($wrong))
                    (Get-PspktBrokerLifecycleOracleDigest $actual) | Should -Not -Be $local.sha256
                    $mutant.OracleId='local-signature-domain'
                }
                'M3' {
                    $rows=@($framing|Where-Object {$_.id -ceq 'FG05'})[0].cases
                    $frames=New-TestFrameArray $protocol $rows
                    $protocol.BuildTranscriptRecord($frames.GetValue(0)).Length | Should -Be 842
                    $parts=@($rows|ForEach-Object {,(Convert-TestHex $_.frameHex)})
                    $expected=Get-PspktBrokerLifecycleOracleDigest (Join-PspktBrokerLifecycleOracleBytes $parts)
                    [BitConverter]::ToString($protocol.ComputeBootstrapBrokerFinishedDigest($frames)).Replace('-','').ToLowerInvariant() | Should -BeExactly $expected
                    $expected | Should -Not -Be '3bf8bfe6897e9ef369d1c99a055e33caab24bf518068e89ce435e7924e3cd7b9'
                    $mutant.OracleId='bootstrap-wrapped-three'
                }
                'M4' {
                    foreach($count in @(255,256)){
                        Invoke-PspktBrokerLifecycleInternal $mutant.Assembly 'ValidateLocalQuota' ([object[]]@([UInt64]$count,[UInt64]($count*422),[UInt64]($count*435)))
                    }
                    $reason=$null
                    try{Invoke-PspktBrokerLifecycleInternal $RuntimeAssembly 'ValidateLocalQuota' ([object[]]@([UInt64]257,[UInt64]108454,[UInt64]111795))}
                    catch{$reason=$_.Exception.GetBaseException().Message}
                    $reason | Should -BeExactly 'quota:record-count'
                    Invoke-PspktBrokerLifecycleInternal $mutant.Assembly 'ValidateLocalQuota' ([object[]]@([UInt64]257,[UInt64]108454,[UInt64]111795))
                    $mutant.OracleId='local-record-limit'
                }
            }
            $mutant.Initialized=$true
            $mutant.PositiveControl='Passed'
            $mutant.OracleKilled=$true
        }
        @($MutantBuilds|Where-Object {$_.Initialized -and $_.PositiveControl -ceq 'Passed' -and $_.OracleKilled}).Count | Should -Be 6
    }

    It '30 retained-pester-complete-census' {
        $SourceSnapshot.ContainsKey('ExpectedData') | Should -BeTrue
        $names=@('BootstrapAssembly','RuntimeAssembly','AuthorityBytesById','FixtureBytesById','SourceSnapshot',
            'CompilationRecords','MutantBuilds','ArtifactRoot','CallerScopeMarker','InvocationContract')
        $SourceSnapshot.ExpectedData.Count | Should -Be 10
        foreach($name in $names){
            [object]::ReferenceEquals((Get-Variable -Name $name -ValueOnly),$SourceSnapshot.ExpectedData[$name]) | Should -BeTrue
        }
        $ExecutionContext.SessionState.Module | Should -BeNullOrEmpty
        $CallerScopeMarker | Should -Match '\Apspkt-broker-lifecycle-validation:[0-9a-f]{32}\z'
        $expected=([Text.Encoding]::UTF8.GetString($FixtureBytesById.ContractExpectations)|ConvertFrom-Json).caseIds
        Assert-PspktBrokerLifecycleCasePopulation -Actual $expected -Expected $expected
        foreach($change in @('missing','duplicate','reordered')){
            $actual=[string[]]$expected.Clone()
            if($change -ceq 'missing'){$actual=$actual[0..30]}
            elseif($change -ceq 'duplicate'){$actual[31]=$actual[30]}
            else{$actual[0]=$expected[1];$actual[1]=$expected[0]}
            $reason=$null
            try{Assert-PspktBrokerLifecycleCasePopulation -Actual $actual -Expected $expected}
            catch{$reason=$_.Exception.GetBaseException().Message}
            $reason | Should -BeExactly 'validation:result-counts'
        }
        $configuration=New-PspktBrokerLifecyclePesterConfiguration $SourceSnapshot.Container
        Assert-PspktBrokerLifecyclePesterConfiguration $configuration $SourceSnapshot.Container
        foreach($change in @('path','filter','tags','exclude','containers','registry','coverage','result','exit','throw','passthru','verbosity')){
            $configuration=New-PspktBrokerLifecyclePesterConfiguration $SourceSnapshot.Container
            switch($change){
                'path' {$configuration.Run.Path=@('unexpected')}
                'filter' {$configuration.Filter.FullName=@('*one*')}
                'tags' {$configuration.Filter.Tag=@('Unit')}
                'exclude' {$configuration.Filter.ExcludeTag=@('Precheck')}
                'containers' {$configuration.Run.Container=@($SourceSnapshot.Container,$SourceSnapshot.Container)}
                'registry' {$configuration.TestRegistry.Enabled=$true}
                'coverage' {$configuration.CodeCoverage.Enabled=$true}
                'result' {$configuration.TestResult.Enabled=$true}
                'exit' {$configuration.Run.Exit=$true}
                'throw' {$configuration.Run.Throw=$true}
                'passthru' {$configuration.Run.PassThru=$false}
                'verbosity' {$configuration.Output.Verbosity='Detailed'}
            }
            $reason=$null
            try{Assert-PspktBrokerLifecyclePesterConfiguration $configuration $SourceSnapshot.Container}
            catch{$reason=$_.Exception.GetBaseException().Message}
            $reason | Should -BeExactly 'validation:pester'
        }
        $SourceSnapshot.CallerScopePassed=$true
    }

    It '31 workflow-export-receipt-boundaries' {
        $ciPath='certification\broker-lifecycle\lib\Pspkt.Certification.BrokerLifecycleCi.ps1'
        $SourceSnapshot.RetainedTexts.ContainsKey($ciPath) | Should -BeTrue
        $expectations=[Text.Encoding]::UTF8.GetString($FixtureBytesById.ContractExpectations)|ConvertFrom-Json
        $fixture=New-TestResultFixture $expectations
        $accepted=Assert-PspktBrokerLifecycleResult -Results @($fixture.Result) -Expected $fixture.Expected
        $accepted.outcome | Should -BeExactly 'ValidationSucceeded'
        foreach($scenario in @('ReturnedFailure','MalformedResult','MissingResult','MultipleResults','CountMismatch')){
            $candidate=ConvertFrom-PspktBrokerLifecycleReceiptJson (ConvertTo-PspktBrokerLifecycleReceiptJson $fixture.Result) 16384
            $objects=@($candidate)
            $wanted='validation:result-shape'
            switch($scenario){
                'ReturnedFailure' {$objects=@([pscustomobject][ordered]@{schemaId='PspktBrokerLifecycleValidationResultV1';schemaVersion=1;outcome='ValidationFailed';callId=$fixture.Result.callId;reasonCode='validation:unexpected';cleanupComplete=$false});$wanted='validation:result-failed'}
                'MalformedResult' {$candidate.PSObject.Properties.Remove('trustCeiling')}
                'MissingResult' {$objects=@();$wanted='validation:result-cardinality'}
                'MultipleResults' {$objects=@($candidate,$candidate);$wanted='validation:result-cardinality'}
                'CountMismatch' {$candidate.counts.passedCount=31;$wanted='validation:result-counts'}
            }
            $reason=$null
            try{[void](Assert-PspktBrokerLifecycleResult -Results $objects -Expected $fixture.Expected)}
            catch{$reason=$_.Exception.GetBaseException().Message}
            $reason | Should -BeExactly $wanted
        }
        $context=[pscustomobject]@{RunId='123';Attempt='2';Revision=('a'*40);Slot=$(if($PSVersionTable.PSEdition -ceq 'Desktop'){'windows_ps51/checkout'}else{'powershell_7/checkout'})}
        $receipt=New-PspktBrokerLifecycleCiReceipt -Result $fixture.Result -Expected $fixture.Expected -Context $context
        [void](Assert-PspktBrokerLifecycleCiReceipt -Json (ConvertTo-PspktBrokerLifecycleReceiptJson $receipt) -Expected $fixture.Expected -Context $context)
        $other=[pscustomobject]@{RunId='123';Attempt='3';Revision=('a'*40);Slot=$context.Slot}
        $reason=$null
        try{[void](Assert-PspktBrokerLifecycleCiReceipt -Json (ConvertTo-PspktBrokerLifecycleReceiptJson $receipt) -Expected $fixture.Expected -Context $other)}
        catch{$reason=$_.Exception.GetBaseException().Message}
        $reason | Should -BeExactly 'validation:workflow-binding'
        $export=Join-Path $ArtifactRoot 'export-check'
        try{
            $records=Export-PspktBrokerLifecycleSource -SourceSnapshot $SourceSnapshot -DestinationRoot $export
            $records.Count | Should -Be 67
            [IO.Directory]::Exists((Join-Path $export '.git')) | Should -BeFalse
            foreach($record in $records){
                $bytes=[IO.File]::ReadAllBytes((Join-Path $export $record.Path))
                (Get-PspktBrokerLifecycleOracleDigest $bytes) | Should -BeExactly $record.Sha256
                [BitConverter]::ToString($bytes) | Should -BeExactly ([BitConverter]::ToString($SourceSnapshot.Files[$record.Path]))
            }
            @($records|Where-Object {$_.Path -cmatch 'authority-input|phase4-r6-final-design|phase4-credential-free-design-delta|dependency1bb-r9-normative-tables'}).Count | Should -Be 0
            $changedPath='certification\broker-lifecycle\lib\LifecycleTestDriver.cs'
            $changedFile=Join-Path $export $changedPath
            $original=[byte[]]$SourceSnapshot.Files[$changedPath]
            foreach($change in @('crlf','bom')){
                $changed=[Text.Encoding]::UTF8.GetBytes([Text.Encoding]::UTF8.GetString($original).Replace("`n","`r`n"))
                if($change -ceq 'bom'){$changed=Join-PspktBrokerLifecycleOracleBytes @([byte[]]@(239,187,191),$original)}
                try{
                    [IO.File]::WriteAllBytes($changedFile,$changed)
                    $reason=$null
                    try{[void](Get-PspktBrokerLifecycleSourceSnapshot $export $SourceSnapshot.Files['certification\broker-lifecycle\lib\Pspkt.Certification.BrokerLifecycleContract.ps1'])}
                    catch{$reason=$_.Exception.GetBaseException().Message}
                    $reason | Should -BeExactly 'validation:source-line-endings'
                    (Get-PspktBrokerLifecycleOracleDigest ([IO.File]::ReadAllBytes($changedFile))) |
                        Should -BeExactly (Get-PspktBrokerLifecycleOracleDigest $changed)
                }
                finally{[IO.File]::WriteAllBytes($changedFile,$original)}
            }
        }
        finally{if([IO.Directory]::Exists($export)){Remove-PspktBrokerLifecycleOwnedExport -SourceSnapshot $SourceSnapshot -DestinationRoot $export}}
    }

    It '32 diagnostics-owned-residue-and-isolation' {
        $directory=Join-Path $ArtifactRoot 'residue-check'
        [void][IO.Directory]::CreateDirectory($directory)
        $created=[Collections.Generic.List[string]]::new()
        try{
            foreach($image in $CompilationRecords){
                $path=Join-Path $directory $image.Name
                [IO.File]::WriteAllBytes($path,[byte[]]$image.Bytes)
                $created.Add($path)
            }
            foreach($name in @('source-records.v1.json','validation-records.v1.json')){
                $path=Join-Path $directory $name
                [IO.File]::WriteAllText($path,'{}',[Text.UTF8Encoding]::new($false))
                $created.Add($path)
            }
            $state=[pscustomobject]@{CleanupComplete=$true}
            Assert-PspktBrokerLifecycleOwnedArtifacts $directory $CompilationRecords $state
            $unowned=Join-Path $directory 'unowned.txt'
            [IO.File]::WriteAllText($unowned,'sensitive-caller-sentinel',[Text.UTF8Encoding]::new($false))
            $created.Add($unowned)
            $reason=$null
            try{Assert-PspktBrokerLifecycleOwnedArtifacts $directory $CompilationRecords $state}
            catch{$reason=$_.Exception.GetBaseException().Message}
            $reason | Should -BeExactly 'validation:cleanup'
            $state.CleanupComplete | Should -BeFalse
            [IO.File]::Exists($unowned) | Should -BeTrue
            $reason | Should -Not -Match 'sensitive-caller-sentinel|residue-check'
        }
        finally{
            foreach($path in $created){if([IO.File]::Exists($path)){[IO.File]::Delete($path)}}
            [IO.Directory]::Delete($directory,$false)
        }
        $caller=Get-PspktBrokerLifecycleCallerState
        $callerDirectory=Join-Path $ArtifactRoot 'caller-state-check'
        [void][IO.Directory]::CreateDirectory($callerDirectory)
        try{
            [Environment]::SetEnvironmentVariable('TEMP',$callerDirectory,'Process')
            [Environment]::SetEnvironmentVariable('TMP',$callerDirectory,'Process')
            [Environment]::SetEnvironmentVariable('PSModuleAnalysisCachePath',(Join-Path $callerDirectory 'cache'),'Process')
            Set-Location -LiteralPath $callerDirectory
            [Environment]::CurrentDirectory=$callerDirectory
            Restore-PspktBrokerLifecycleCallerState $caller
            (Get-Location).ProviderPath | Should -BeExactly $caller.Location
            [Environment]::CurrentDirectory | Should -BeExactly $caller.Directory
            foreach($name in $caller.Environment.Keys){
                [Environment]::GetEnvironmentVariable($name,'Process') | Should -BeExactly $caller.Environment[$name]
            }
        }
        finally{
            Restore-PspktBrokerLifecycleCallerState $caller
            [IO.Directory]::Delete($callerDirectory,$false)
        }
        $protocol=New-TestProtocol
        $controller=New-TestWorker $protocol
        try{
            $reason=$null
            try{$controller.FeedPeerBytes('sensitive-caller-sentinel',[byte[]]@(1),[UInt64]0,[UInt64]1000)}
            catch{$reason=$_.Exception.GetBaseException().Message}
            $reason | Should -BeExactly 'argument:context'
            $reason | Should -Not -Match 'sensitive-caller-sentinel'
        }
        finally{$controller.Dispose()}
        @((Get-Module -Name pspkt)).Count | Should -Be 0
        $SourceSnapshot.Files.Count | Should -Be 67
        foreach($record in $CompilationRecords){
            $allowed=@($record.References.Identity)
            foreach($reference in $record.Assembly.GetReferencedAssemblies()){$reference.FullName | Should -BeIn $allowed}
        }
        foreach($path in @($SourceSnapshot.RetainedTexts.Keys|Where-Object {$_.StartsWith('certification\broker-lifecycle\',[StringComparison]::Ordinal)})){
            $text=$SourceSnapshot.RetainedTexts[$path]
            if($path.EndsWith('.ps1',[StringComparison]::Ordinal)){
                $tokens=$null;$errors=$null
                [void][Management.Automation.Language.Parser]::ParseInput($text,[ref]$tokens,[ref]$errors)
                @($errors).Count | Should -Be 0
                @($tokens|Where-Object {$_.Kind -eq [Management.Automation.Language.TokenKind]::Comment}).Count | Should -Be 0
            }
            elseif($path.EndsWith('.cs',[StringComparison]::Ordinal)){
                $withoutLiterals=[regex]::Replace($text,'(?s)@"(?:[^"]|"")*"|"(?:\\.|[^"\\])*"|''(?:\\.|[^''\\])*''','')
                $withoutLiterals | Should -Not -Match '//|/\*|\*/|\bunsafe\b'
            }
        }
    }
}
