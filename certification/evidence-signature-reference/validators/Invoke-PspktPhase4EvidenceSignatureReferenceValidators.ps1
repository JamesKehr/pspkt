[CmdletBinding(PositionalBinding=$false)]
param(
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$RepositoryRoot,
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$WorkRoot,
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$PesterManifestPath
)

function Enter-PspktSignatureReferenceInvocation {
    param([string]$MarkerName='Pspkt.Certification.EvidenceSignatureReference.ValidationInvocation')
    $domain=[AppDomain]::CurrentDomain
    [Threading.Monitor]::Enter($domain)
    try {
        if($null -ne $domain.GetData($MarkerName)) { throw 'validation:invocation-repeat' }
        $identifier=[Guid]::NewGuid().ToString('N')
        $domain.SetData($MarkerName,$identifier)
        return $identifier
    }
    finally { [Threading.Monitor]::Exit($domain) }
}

function Assert-PspktSignatureReferenceInvocationRoots {
    [CmdletBinding(PositionalBinding=$false)]
    param([Parameter(Mandatory=$true)][string]$RepositoryRoot,[Parameter(Mandatory=$true)][string]$WorkRoot)
    if($RepositoryRoot -notmatch '\A[A-Za-z]:\\' -or $WorkRoot -notmatch '\A[A-Za-z]:\\') { throw 'validation:work-root' }
    try {
        $source=[IO.Path]::GetFullPath($RepositoryRoot).TrimEnd([char]92)
        $work=[IO.Path]::GetFullPath($WorkRoot).TrimEnd([char]92)
        if(-not [IO.Directory]::Exists($source) -or $work.Length -gt 100 -or $source.Length -le 2 -or $work.Length -le 2 -or
            [string]::Equals($source,$work,[StringComparison]::OrdinalIgnoreCase) -or
            ($source+'\').StartsWith($work+'\',[StringComparison]::OrdinalIgnoreCase) -or
            ($work+'\').StartsWith($source+'\',[StringComparison]::OrdinalIgnoreCase)) { throw 'validation:work-root' }
        foreach($root in @($source,$work)) {
            foreach($component in $root.Substring(3).Split([char]92)) {
                if($component.EndsWith(' ',[StringComparison]::Ordinal) -or $component.EndsWith('.',[StringComparison]::Ordinal) -or
                    $component.IndexOfAny([IO.Path]::GetInvalidFileNameChars()) -ge 0) { throw 'validation:work-root' }
            }
            if([IO.DriveInfo]::new($root.Substring(0,3)).DriveType -eq [IO.DriveType]::Network) { throw 'validation:work-root' }
            $current=$root
            while(-not [string]::IsNullOrEmpty($current)) {
                if([IO.File]::Exists($current) -or ([IO.Directory]::Exists($current) -and
                    ([IO.File]::GetAttributes($current) -band [IO.FileAttributes]::ReparsePoint))) { throw 'validation:work-root' }
                $parent=[IO.Directory]::GetParent($current)
                if($null -eq $parent) { break }
                $current=$parent.FullName
            }
        }
        return [pscustomobject]@{RepositoryRoot=$source;WorkRoot=$work}
    }
    catch { throw 'validation:work-root' }
}

Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$callId=[Guid]::NewGuid().ToString('N')
$executionState=[pscustomobject]@{CleanupComplete=$true}
try {
    $callId=Enter-PspktSignatureReferenceInvocation
    $roots=Assert-PspktSignatureReferenceInvocationRoots -RepositoryRoot $RepositoryRoot -WorkRoot $WorkRoot
    $contractPath=Join-Path $roots.RepositoryRoot 'certification\evidence-signature-reference\lib\Pspkt.Certification.EvidenceSignatureReferenceContract.ps1'
    $stream=[IO.File]::Open($contractPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {
        if($stream.Length -le 0 -or $stream.Length -gt 16777216) { throw 'validation:contract' }
        $contractBytes=[byte[]]::new([int]$stream.Length);$offset=0
        while($offset -lt $contractBytes.Length) {
            $read=$stream.Read($contractBytes,$offset,$contractBytes.Length-$offset)
            if($read -le 0) { throw 'validation:contract' }
            $offset+=$read
        }
    }
    finally { $stream.Dispose() }
    $contractText=[Text.UTF8Encoding]::new($false,$true).GetString($contractBytes)
    . ([scriptblock]::Create($contractText))
    $validationExecution=Invoke-PspktSignatureReferenceValidation -RepositoryRoot $roots.RepositoryRoot -WorkRoot $roots.WorkRoot `
        -PesterManifestPath $PesterManifestPath -CallId $callId -ContractBytes $contractBytes -ExecutionState $executionState
    $validationExpected=$validationExecution.Expected
    $validationExecution.Result
}
catch {
    $reason='validation:unexpected'
    $allowed=@('validation:contract','validation:work-root','validation:invocation-repeat','validation:source-length','validation:source-pin',
        'validation:source-membership','validation:source-policy','validation:source-export','validation:authority-routing','validation:public-surface',
        'validation:residual-contract','validation:fixture-pin','validation:generator-isolation','validation:oracle','validation:mutant-transform',
        'validation:mutant-control','validation:mutant-observation','validation:compilation','validation:reference','validation:preload',
        'validation:assembly-custody','validation:pester-manifest','validation:pester-version','validation:pester-package','validation:pester-container',
        'validation:pester-result','validation:result-cardinality','validation:result-shape','validation:returned-failure','validation:result-counts',
        'validation:result-identity','validation:workflow-contract','validation:workflow-binding','validation:receipt-json','validation:receipt-size',
        'validation:probe','validation:registry','validation:cleanup','validation:unexpected')
    if($_.Exception.Message -cin $allowed) { $reason=$_.Exception.Message }
    [pscustomobject][ordered]@{schemaId='PspktEvidenceSignatureReferenceValidationResultV1';schemaVersion=1;outcome='ValidationFailed';
        callId=$callId;reasonCode=$reason;cleanupComplete=[bool]$executionState.CleanupComplete}
    [Console]::Error.WriteLine($reason)
    exit 1
}
