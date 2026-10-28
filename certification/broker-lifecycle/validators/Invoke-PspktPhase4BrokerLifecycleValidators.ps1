[CmdletBinding(PositionalBinding=$false)]
param(
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$RepositoryRoot,
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$WorkRoot,
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$PesterManifestPath
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$domain=[AppDomain]::CurrentDomain
[Threading.Monitor]::Enter($domain)
try {
    if($null -ne $domain.GetData('Pspkt.Certification.BrokerLifecycle.ValidationInvocation')) {
        throw 'validation:invocation-repeat'
    }
    $domain.SetData('Pspkt.Certification.BrokerLifecycle.ValidationInvocation','Consumed')
}
finally {
    [Threading.Monitor]::Exit($domain)
}
$callId=[guid]::NewGuid().ToString('N')
$executionState=[pscustomobject]@{CleanupComplete=$true}
try {
    if($RepositoryRoot -cnotmatch '\A[A-Za-z]:\\' -or $WorkRoot -cnotmatch '\A[A-Za-z]:\\') {
        throw 'validation:work-root'
    }
    $source=[IO.Path]::GetFullPath($RepositoryRoot).TrimEnd([char]92)
    $work=[IO.Path]::GetFullPath($WorkRoot).TrimEnd([char]92)
    if(-not [IO.Directory]::Exists($source) -or $source.Length -le 3 -or $work.Length -le 3 -or $work.Length -gt 100 -or
        ($source+'\').StartsWith($work+'\',[StringComparison]::OrdinalIgnoreCase) -or
        ($work+'\').StartsWith($source+'\',[StringComparison]::OrdinalIgnoreCase) -or
        [IO.File]::Exists($work) -or [IO.Directory]::Exists($work)) {
        throw 'validation:work-root'
    }
    foreach($root in @($source,$work)) {
        if([IO.DriveInfo]::new($root.Substring(0,3)).DriveType -ne [IO.DriveType]::Fixed) { throw 'validation:work-root' }
        foreach($component in $root.Substring(3).Split([char]92)) {
            if($component.EndsWith(' ',[StringComparison]::Ordinal) -or $component.EndsWith('.',[StringComparison]::Ordinal) -or
                $component.IndexOfAny([IO.Path]::GetInvalidFileNameChars()) -ge 0) { throw 'validation:work-root' }
        }
        $current=$root
        while(-not [string]::IsNullOrEmpty($current)) {
            if(([IO.File]::Exists($current) -or [IO.Directory]::Exists($current)) -and
                ([IO.File]::GetAttributes($current) -band [IO.FileAttributes]::ReparsePoint)) {
                throw 'validation:work-root'
            }
            $parent=[IO.Directory]::GetParent($current)
            if($null -eq $parent) { break }
            $current=$parent.FullName
        }
    }
    $contractPath=Join-Path $source 'certification\broker-lifecycle\lib\Pspkt.Certification.BrokerLifecycleContract.ps1'
    $stream=[IO.File]::Open($contractPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {
        if($stream.Length -le 0 -or $stream.Length -gt 1048576) { throw 'validation:source-length' }
        $contractBytes=[byte[]]::new([int]$stream.Length)
        $offset=0
        while($offset -lt $contractBytes.Length) {
            $read=$stream.Read($contractBytes,$offset,$contractBytes.Length-$offset)
            if($read -le 0) { throw 'validation:source-length' }
            $offset+=$read
        }
        if($stream.ReadByte() -ne -1) { throw 'validation:source-length' }
    }
    finally { $stream.Dispose() }
    $contractText=[Text.UTF8Encoding]::new($false,$true).GetString($contractBytes)
    if($contractText.Contains("`r") -or $contractText.StartsWith([string][char]0xfeff,[StringComparison]::Ordinal)) {
        throw 'validation:source-line-endings'
    }
    . ([scriptblock]::Create($contractText))
    Invoke-PspktBrokerLifecycleValidation -RepositoryRoot $source -WorkRoot $work -PesterManifestPath $PesterManifestPath `
        -CallId $callId -ContractBytes $contractBytes -ExecutionState $executionState
}
catch {
    $reason='validation:unexpected'
    $allowed=@('validation:invocation-repeat','validation:work-root','validation:source-membership','validation:source-length',
        'validation:source-pin','validation:source-line-endings','validation:authority','validation:design-review-pending',
        'validation:preload','validation:compilation','validation:reference','validation:assembly-custody',
        'validation:public-surface','validation:fixture','validation:oracle','validation:mutant','validation:pester',
        'validation:result-failed','validation:result-shape','validation:result-cardinality','validation:result-counts',
        'validation:workflow-binding','validation:receipt','validation:preflight-probe','validation:cleanup','validation:unexpected')
    if($_.Exception.Message -cin $allowed) { $reason=$_.Exception.Message }
    [pscustomobject][ordered]@{schemaId='PspktBrokerLifecycleValidationResultV1';schemaVersion=1;outcome='ValidationFailed';
        callId=$callId;reasonCode=$reason;cleanupComplete=[bool]$executionState.CleanupComplete}
    throw [IO.InvalidDataException]::new($reason)
}
