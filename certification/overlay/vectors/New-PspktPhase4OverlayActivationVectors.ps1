[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$OutputRoot,
    [string]$RepositoryRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$arguments = @{ Mode='Generate'; OutputRoot=$OutputRoot }
if ($RepositoryRoot) { $arguments.RepositoryRoot = $RepositoryRoot }
& (Join-Path $PSScriptRoot '..\validators\Invoke-PspktPhase4OverlayActivationAuthorityValidators.ps1') @arguments
