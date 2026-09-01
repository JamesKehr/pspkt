Set-StrictMode -Version Latest

$script:PspktAcceptedHostKeys = @(
    'windows-terminal|powershell-7|x64',
    'windows-terminal|windows-powershell-5.1|x64',
    'conhost|powershell-7|x64',
    'conhost|windows-powershell-5.1|x64'
)

function Test-PspktAncestryContains {
    [OutputType([bool])]
    param(
        [AllowNull()][object[]]$Ancestry,
        [Parameter(Mandatory = $true)][string]$ImageName
    )
    if ($null -eq $Ancestry) { return $false }
    foreach ($item in $Ancestry) {
        if ($null -eq $item) { continue }
        $leaf = [System.IO.Path]::GetFileName([string]$item)
        if ($leaf -and ($leaf -ieq $ImageName)) {
            return $true
        }
    }
    return $false
}

function Test-PspktGuid {
    [OutputType([bool])]
    param([AllowNull()][string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    $parsed = [guid]::Empty
    if (-not [guid]::TryParse($Value, [ref]$parsed)) { return $false }
    return ($parsed -ne [guid]::Empty)
}

function Resolve-PspktShellKind {

    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)][string]$Edition,
        [Parameter(Mandatory = $true)][int]$VersionMajor,
        [int]$VersionMinor = 0
    )
    if ($Edition -ieq 'Desktop' -and $VersionMajor -eq 5 -and $VersionMinor -eq 1) {
        return 'windows-powershell-5.1'
    }
    if ($Edition -ieq 'Core' -and $VersionMajor -eq 7) {
        return 'powershell-7'
    }
    return 'unknown'
}

function Resolve-PspktTerminalKind {

    param(
        [Parameter(Mandatory = $true)][hashtable]$Probe
    )

    $wtSession = $null
    if ($Probe.ContainsKey('WtSession')) { $wtSession = [string]$Probe['WtSession'] }
    $consoleWindow = 0
    if ($Probe.ContainsKey('ConsoleWindow')) { $consoleWindow = [int64]$Probe['ConsoleWindow'] }
    $ownerImagePath = ''
    if ($Probe.ContainsKey('OwnerImagePath') -and $null -ne $Probe['OwnerImagePath']) { $ownerImagePath = [string]$Probe['OwnerImagePath'] }
    $ancestry = @()
    if ($Probe.ContainsKey('Ancestry') -and $null -ne $Probe['Ancestry']) { $ancestry = @($Probe['Ancestry']) }
    $systemRoot = 'C:\WINDOWS'
    if ($Probe.ContainsKey('SystemRoot') -and -not [string]::IsNullOrEmpty([string]$Probe['SystemRoot'])) {
        $systemRoot = [string]$Probe['SystemRoot']
    }

    $conhostCanonical = [System.IO.Path]::Combine($systemRoot, 'System32', 'conhost.exe')
    $ownerLeaf = ''
    if (-not [string]::IsNullOrEmpty($ownerImagePath)) {
        $ownerLeaf = [System.IO.Path]::GetFileName($ownerImagePath)
    }

    $hasValidWtSession = Test-PspktGuid -Value $wtSession
    $hasWtAncestor = Test-PspktAncestryContains -Ancestry $ancestry -ImageName 'WindowsTerminal.exe'
    $hasConhostAncestor = Test-PspktAncestryContains -Ancestry $ancestry -ImageName 'conhost.exe'
    $hasOpenConsoleAncestor = Test-PspktAncestryContains -Ancestry $ancestry -ImageName 'OpenConsole.exe'
    $consoleWindowPresent = ($consoleWindow -ne 0)
    $ownerIsConhost = ($ownerImagePath -and ($ownerImagePath -ieq $conhostCanonical))
    $ownerIsOpenConsole = ($ownerLeaf -and ($ownerLeaf -ieq 'OpenConsole.exe'))

    $wtSignature = ($hasValidWtSession -and $hasWtAncestor)
    $conhostSignature = ($consoleWindowPresent -and $ownerIsConhost -and $hasConhostAncestor)

    if ($wtSignature -and $conhostSignature) {
        return [pscustomobject]@{ TerminalKind = 'unknown'; Status = 'fail'; Reason = 'simultaneous-positive-classification' }
    }
    if ($wtSignature) {
        return [pscustomobject]@{ TerminalKind = 'windows-terminal'; Status = 'pass'; Reason = 'windows-terminal-signature' }
    }
    if ($hasWtAncestor -and -not $hasValidWtSession) {
        return [pscustomobject]@{ TerminalKind = 'unknown'; Status = 'fail'; Reason = 'ambiguous-ancestry-windows-terminal-without-session' }
    }
    if ($conhostSignature) {

        return [pscustomobject]@{ TerminalKind = 'conhost'; Status = 'pass'; Reason = 'conhost-signature' }
    }
    if ($consoleWindowPresent -and $ownerIsConhost -and -not $hasConhostAncestor) {
        return [pscustomobject]@{ TerminalKind = 'unknown'; Status = 'fail'; Reason = 'ambiguous-ancestry-conhost-owner-without-ancestor' }
    }
    if ($consoleWindowPresent -and [string]::IsNullOrEmpty($ownerImagePath)) {
        return [pscustomobject]@{ TerminalKind = 'unknown'; Status = 'fail'; Reason = 'missing-owner-image' }
    }
    if ($ownerIsOpenConsole -or $hasOpenConsoleAncestor) {
        return [pscustomobject]@{ TerminalKind = 'unknown'; Status = 'unknown'; Reason = 'openconsole-not-sufficient-for-conhost' }
    }
    if (-not $consoleWindowPresent) {
        return [pscustomobject]@{ TerminalKind = 'unknown'; Status = 'fail'; Reason = 'missing-console-window' }
    }
    if ($consoleWindowPresent -and -not $ownerIsConhost) {
        return [pscustomobject]@{ TerminalKind = 'unknown'; Status = 'fail'; Reason = 'unexpected-console-owner' }
    }
    return [pscustomobject]@{ TerminalKind = 'unknown'; Status = 'unknown'; Reason = 'unclassified' }
}

function Resolve-PspktHostSeat {

    param(
        [Parameter(Mandatory = $true)][hashtable]$Probe
    )

    $terminal = Resolve-PspktTerminalKind -Probe $Probe

    $edition = ''
    if ($Probe.ContainsKey('ShellEdition') -and $null -ne $Probe['ShellEdition']) { $edition = [string]$Probe['ShellEdition'] }
    $versionMajor = 0
    if ($Probe.ContainsKey('ShellVersionMajor') -and $null -ne $Probe['ShellVersionMajor']) { $versionMajor = [int]$Probe['ShellVersionMajor'] }
    $versionMinor = 0
    if ($Probe.ContainsKey('ShellVersionMinor') -and $null -ne $Probe['ShellVersionMinor']) { $versionMinor = [int]$Probe['ShellVersionMinor'] }
    $architecture = ''
    if ($Probe.ContainsKey('Architecture') -and $null -ne $Probe['Architecture']) {
        $architecture = ([string]$Probe['Architecture']).ToLowerInvariant()
    }

    $shellKind = Resolve-PspktShellKind -Edition $edition -VersionMajor $versionMajor -VersionMinor $versionMinor

    $status = 'pass'
    $reason = $terminal.Reason
    if ($terminal.Status -ne 'pass') {
        $status = $terminal.Status
    }
    if ($shellKind -eq 'unknown') {
        if ($status -eq 'pass') { $status = 'fail' }
        $reason = ('{0}; unsupported-shell-edition-or-version' -f $reason)
    }
    if ($architecture -ne 'x64') {
        if ($status -eq 'pass') { $status = 'fail' }
        $reason = ('{0}; architecture-must-be-x64 (got "{1}")' -f $reason, $architecture)
    }

    $hostKey = $null
    if ($status -eq 'pass') {
        $candidate = ('{0}|{1}|{2}' -f $terminal.TerminalKind, $shellKind, $architecture)
        if ($script:PspktAcceptedHostKeys -ccontains $candidate) {
            $hostKey = @($terminal.TerminalKind, $shellKind, $architecture)
        }
        else {
            $status = 'fail'
            $reason = ('{0}; host-key-not-in-accepted-set ("{1}")' -f $reason, $candidate)
        }
    }

    return [pscustomobject]@{
        TerminalKind = $terminal.TerminalKind
        ShellKind    = $shellKind
        Architecture = $architecture
        HostKey      = $hostKey
        Status       = $status
        Reason       = $reason
    }
}

function Get-PspktAcceptedHostKeys {

    [OutputType([string[]])]
    param()
    return $script:PspktAcceptedHostKeys
}
