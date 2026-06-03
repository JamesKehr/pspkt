[CmdletBinding()]
param(
    [string]$Path = $PSScriptRoot,
    [ValidateSet('None','Normal','Detailed','Diagnostic')]
    [string]$Verbosity = 'Detailed',
    [ValidateSet('Auto','Unit','Precheck')]
    [string]$Mode = 'Auto'
)

$ErrorActionPreference = 'Stop'

<#
.SYNOPSIS
Determines whether the current PowerShell process is elevated.

.OUTPUTS
System.Boolean
#>
function Test-IsAdministrator {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = [Security.Principal.WindowsPrincipal]::new($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        return $false
    }
}

$pester = Get-Module -ListAvailable -Name Pester | Sort-Object Version -Descending | Select-Object -First 1
if ($null -eq $pester) {
    throw 'Pester module is not installed. Install it with: Install-Module Pester -Scope CurrentUser -Force -SkipPublisherCheck'
}

Import-Module Pester -MinimumVersion 5.0.0 -ErrorAction Stop

$config = New-PesterConfiguration
$config.Run.Path = $Path
$config.Run.PassThru = $true
$config.Output.Verbosity = $Verbosity

switch ($Mode) {
    'Unit' {
        $config.Filter.Tag = @('Unit')
    }
    'Precheck' {
        $config.Filter.Tag = @('Precheck')
    }
    default {
        if (Test-IsAdministrator) {
            $config.Filter.Tag = @('Unit', 'Precheck')
        }
        else {
            $config.Filter.Tag = @('Precheck')
        }
    }
}

$result = Invoke-Pester -Configuration $config
if ($result.FailedCount -gt 0) {
    throw "Pester failures: $($result.FailedCount)"
}
