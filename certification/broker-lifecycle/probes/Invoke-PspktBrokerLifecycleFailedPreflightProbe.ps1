[CmdletBinding(PositionalBinding=$false)]
param(
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$RepositoryRoot,
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$WorkRoot,
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$PesterManifestPath
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
try {
    $marker='Pspkt.Certification.BrokerLifecycle.ValidationInvocation'
    if($null -ne [AppDomain]::CurrentDomain.GetData($marker)){throw 'validation:preflight-probe'}
    foreach($assembly in [AppDomain]::CurrentDomain.GetAssemblies()){
        if($assembly.GetName().Name.StartsWith('PspktBrokerLifecycle_',[StringComparison]::Ordinal) -or
            $null -ne $assembly.GetType('Pspkt.Certification.SchemaBootstrap',$false) -or
            $null -ne $assembly.GetType('Pspkt.Certification.BrokerLifecycle.BrokerLifecycleProtocol',$false)){
            throw 'validation:preflight-probe'
        }
    }
    if([IO.File]::Exists($WorkRoot) -or [IO.Directory]::Exists($WorkRoot)){throw 'validation:preflight-probe'}
    $validator=Join-Path $RepositoryRoot 'certification\broker-lifecycle\validators\Invoke-PspktPhase4BrokerLifecycleValidators.ps1'
    $outputs=[Collections.Generic.List[object]]::new()
    $first=$null
    try { & $validator -RepositoryRoot $RepositoryRoot -WorkRoot $RepositoryRoot -PesterManifestPath $PesterManifestPath |
            ForEach-Object {$outputs.Add($_)} }
    catch {$first=$_.Exception.GetBaseException().Message}
    $second=$null
    try { & $validator -RepositoryRoot $RepositoryRoot -WorkRoot $WorkRoot -PesterManifestPath $PesterManifestPath |
            ForEach-Object {$outputs.Add($_)} }
    catch {$second=$_.Exception.GetBaseException().Message}
    if($first -cne 'validation:work-root' -or $second -cne 'validation:invocation-repeat' -or
        $null -eq [AppDomain]::CurrentDomain.GetData($marker) -or
        [IO.File]::Exists($WorkRoot) -or [IO.Directory]::Exists($WorkRoot)){throw 'validation:preflight-probe'}
    foreach($output in $outputs){
        if($null -ne $output.PSObject.Properties['outcome'] -and $output.outcome -ceq 'ValidationSucceeded'){throw 'validation:preflight-probe'}
    }
    foreach($assembly in [AppDomain]::CurrentDomain.GetAssemblies()){
        if($assembly.GetName().Name.StartsWith('PspktBrokerLifecycle_',[StringComparison]::Ordinal) -or
            $null -ne $assembly.GetType('Pspkt.Certification.SchemaBootstrap',$false)){throw 'validation:preflight-probe'}
    }
    $hosted=-not [string]::IsNullOrEmpty($env:GITHUB_RUN_ID)
    if($hosted){
        if($env:GITHUB_RUN_ID -cnotmatch '\A[1-9][0-9]{0,19}\z' -or $env:GITHUB_RUN_ATTEMPT -cnotmatch '\A[1-9][0-9]{0,9}\z' -or
            $env:GITHUB_SHA -cnotmatch '\A[0-9a-f]{40}\z' -or $env:PSPKT_BROKER_HOST_SLOT -cnotin @('windows_ps51','powershell_7')){
            throw 'validation:workflow-binding'
        }
        $receipt=[ordered]@{schemaId='PspktBrokerLifecyclePreflightProbeV1';schemaVersion=1;workflowRunId=$env:GITHUB_RUN_ID;
            workflowRunAttempt=$env:GITHUB_RUN_ATTEMPT;revision=$env:GITHUB_SHA;hostSlot=$env:PSPKT_BROKER_HOST_SLOT}
    }
    else{$receipt=[ordered]@{schemaId='PspktBrokerLifecycleLocalPreflightProbeV1';schemaVersion=1}}
    $receipt.probeId='FailedPreflightConsumesHost'
    $receipt.positiveControl=$true
    $receipt.firstReasonCode=$first
    $receipt.secondReasonCode=$second
    $receipt.markerRemainsConsumed=$true
    $receipt.compilationCount=0
    $receipt.loadCount=0
    $receipt.successObjectsEmitted=0
    $receipt.secondWorkRootCreated=$false
    $receipt.cleanupComplete=$true
    $json=ConvertTo-Json -InputObject ([pscustomobject]$receipt) -Depth 8 -Compress
    if([Text.Encoding]::UTF8.GetByteCount($json) -gt 1024){throw 'validation:preflight-probe'}
    [Console]::WriteLine($json)
    if($hosted -and -not [string]::IsNullOrEmpty($env:GITHUB_OUTPUT)){
        $encoded=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))
        [IO.File]::AppendAllText($env:GITHUB_OUTPUT,'probe='+$encoded+"`n",[Text.UTF8Encoding]::new($false))
    }
    exit 1
}
catch {
    [Console]::Error.WriteLine('validation:preflight-probe')
    exit 1
}
