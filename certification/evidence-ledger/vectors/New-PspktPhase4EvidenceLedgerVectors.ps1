[CmdletBinding()]
param([Parameter(Mandatory = $true)][string]$OutputRoot)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
& (Join-Path $PSScriptRoot '..\validators\Invoke-PspktPhase4EvidenceLedgerAuthorityValidators.ps1') -Mode Generate -OutputRoot $OutputRoot
