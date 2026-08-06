[CmdletBinding()]
param(
    [string]$Path,
    [ValidateSet('None','Normal','Detailed','Diagnostic')]
    [string]$Verbosity = 'Detailed',
    [ValidateSet('Auto','Unit','Precheck','Concurrency')]
    [string]$Mode = 'Auto',
    [switch]$PassThru,
    [switch]$AllowPesterInstall,
    [string]$PesterManifestPath
)

$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrEmpty($Path)) {
    $Path = $PSScriptRoot
}

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

function Get-NormalizedModuleBase {
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $ModuleBase
    )

    return [System.IO.Path]::GetFullPath($ModuleBase).TrimEnd([char[]]@('\', '/'))
}

function Test-SupportedPesterVersion {
    param(
        [Parameter(Mandatory = $true)]
        [version]
        $Version
    )

    return $Version -ge [version]'5.3.3' -and $Version -lt [version]'6.0.0'
}

function Get-PesterAssemblyInventory {
    return @(
        [AppDomain]::CurrentDomain.GetAssemblies() |
            Where-Object { $_.GetName().Name -eq 'Pester' }
    )
}

function Assert-PesterAssemblyIdentity {
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSModuleInfo]
        $Module
    )

    $moduleBase = Get-NormalizedModuleBase -ModuleBase $Module.ModuleBase
    $assemblies = @(Get-PesterAssemblyInventory)
    foreach ($assembly in $assemblies) {
        if ([string]::IsNullOrEmpty($assembly.Location)) {
            throw 'A loaded Pester assembly cannot be mapped to an installation. Start a fresh PowerShell process.'
        }
        $assemblyPath = [System.IO.Path]::GetFullPath($assembly.Location)
        if (-not $assemblyPath.StartsWith(
            $moduleBase + [System.IO.Path]::DirectorySeparatorChar,
            [System.StringComparison]::OrdinalIgnoreCase
        )) {
            throw 'A loaded Pester assembly conflicts with the selected Pester module. Start a fresh PowerShell process.'
        }
    }
}

$loadedModules = @(Get-Module -Name Pester)
if ($loadedModules | Where-Object { $_.Version -ge [version]'6.0.0' }) {
    throw 'Loaded Pester 6 or later is unsupported. Start a fresh PowerShell process and use Pester 5.3.3 through 5.x.'
}

$loadedSupported = @(
    $loadedModules |
        Where-Object { Test-SupportedPesterVersion -Version $_.Version }
)
$loadedUnsupportedFive = @(
    $loadedModules |
        Where-Object { $_.Version.Major -eq 5 -and -not (Test-SupportedPesterVersion -Version $_.Version) }
)
if ($loadedUnsupportedFive.Count -gt 0) {
    throw 'Loaded Pester 5 is older than the supported minimum 5.3.3. Start a fresh PowerShell process.'
}
if ($loadedSupported.Count -gt 1) {
    throw 'Multiple supported Pester identities are loaded. Start a fresh PowerShell process.'
}

$loadedAssemblies = @(Get-PesterAssemblyInventory)
if ($loadedAssemblies.Count -gt 0 -and $loadedModules.Count -eq 0) {
    throw 'A Pester assembly is loaded without its module. Start a fresh PowerShell process.'
}

$legacyModules = @($loadedModules | Where-Object { $_.Version.Major -lt 5 })
if ($legacyModules.Count -gt 0) {
    $legacyModules | Remove-Module -Force -ErrorAction Stop
    if (@(Get-PesterAssemblyInventory).Count -gt 0) {
        throw 'Removing legacy Pester left an assembly loaded. Start a fresh PowerShell process.'
    }
}

$selectedModule = $null
if (-not [string]::IsNullOrEmpty($PesterManifestPath)) {
    $resolvedManifest = (Resolve-Path -LiteralPath $PesterManifestPath -ErrorAction Stop).Path
    $manifestData = Import-PowerShellDataFile -LiteralPath $resolvedManifest
    $manifestVersion = [version]$manifestData.ModuleVersion
    if (-not (Test-SupportedPesterVersion -Version $manifestVersion)) {
        throw "Pester manifest version $manifestVersion is outside the supported range 5.3.3 through 5.x."
    }
    $manifestBase = Get-NormalizedModuleBase -ModuleBase (Split-Path -Parent $resolvedManifest)
    if ($loadedSupported.Count -eq 1) {
        $loadedBase = Get-NormalizedModuleBase -ModuleBase $loadedSupported[0].ModuleBase
        if ($loadedSupported[0].Version -ne $manifestVersion -or $loadedBase -ne $manifestBase) {
            throw 'The explicit Pester manifest conflicts with the loaded Pester identity.'
        }
        $selectedModule = $loadedSupported[0]
    } else {
        Import-Module $resolvedManifest -Force -ErrorAction Stop
        $selectedModule = Get-Module -Name Pester
    }
} elseif ($loadedSupported.Count -eq 1) {
    $selectedModule = $loadedSupported[0]
} else {
    $available = @(
        Get-Module -ListAvailable -Name Pester |
            Where-Object { Test-SupportedPesterVersion -Version $_.Version }
    )
    if ($available.Count -eq 0) {
        if (-not $AllowPesterInstall.IsPresent) {
            throw 'No supported Pester installation was found. Re-run with -AllowPesterInstall to install Pester 5 for CurrentUser.'
        }
        Install-Module Pester `
            -Scope CurrentUser `
            -MinimumVersion 5.3.3 `
            -MaximumVersion 5.999.999 `
            -Force `
            -SkipPublisherCheck `
            -ErrorAction Stop
        $available = @(
            Get-Module -ListAvailable -Name Pester |
                Where-Object { Test-SupportedPesterVersion -Version $_.Version }
        )
        if ($available.Count -eq 0) {
            throw 'Pester installation completed without producing a supported installation.'
        }
    }

    $highestVersion = ($available | Sort-Object Version -Descending | Select-Object -First 1).Version
    $highestCandidates = @($available | Where-Object { $_.Version -eq $highestVersion })
    $highestBases = @(
        $highestCandidates |
            ForEach-Object { Get-NormalizedModuleBase -ModuleBase $_.ModuleBase } |
            Sort-Object -Unique
    )
    if ($highestBases.Count -ne 1) {
        throw 'Multiple Pester installations share the highest supported version. Use -PesterManifestPath.'
    }
    $selectedCandidate = $highestCandidates | Select-Object -First 1
    Import-Module $selectedCandidate.Path -Force -ErrorAction Stop
    $selectedModule = Get-Module -Name Pester
}

$verifiedModules = @(
    Get-Module -Name Pester |
        Where-Object { Test-SupportedPesterVersion -Version $_.Version }
)
if ($verifiedModules.Count -ne 1) {
    throw 'Exactly one supported Pester identity must be loaded before tests run.'
}
if (Get-Module -Name Pester | Where-Object { $_.Version -ge [version]'6.0.0' }) {
    throw 'Unsupported Pester remains loaded.'
}
Assert-PesterAssemblyIdentity -Module $verifiedModules[0]

if ($null -ne $selectedModule) {
    $selectedBase = Get-NormalizedModuleBase -ModuleBase $selectedModule.ModuleBase
    $verifiedBase = Get-NormalizedModuleBase -ModuleBase $verifiedModules[0].ModuleBase
    if ($selectedModule.Version -ne $verifiedModules[0].Version -or $selectedBase -ne $verifiedBase) {
        throw 'Loaded Pester identity does not match the selected identity.'
    }
}

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
    'Concurrency' {
        $config.Filter.Tag = @('Concurrency')
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
if (
    $result.Result -ne 'Passed' -or
    $result.FailedCount -gt 0 -or
    $result.FailedBlocksCount -gt 0 -or
    $result.FailedContainersCount -gt 0
) {
    throw "Pester run failed: tests=$($result.FailedCount), blocks=$($result.FailedBlocksCount), containers=$($result.FailedContainersCount), result=$($result.Result)."
}

$selectedTests = @($result.Tests | Where-Object { $_.ShouldRun })
if ($selectedTests.Count -eq 0) {
    throw 'Pester selected zero tests.'
}
$executedPassedTests = @(
    $selectedTests |
        Where-Object { $_.Executed -and $_.Result -eq 'Passed' }
)
if (@($selectedTests | Where-Object { $_.Result -ne 'Skipped' }).Count -eq 0) {
    throw 'Pester selected only skipped tests.'
}
if ($executedPassedTests.Count -eq 0 -or $result.PassedCount -eq 0) {
    throw 'Pester selected tests but none executed and passed.'
}

if ($PassThru.IsPresent) {
    return ,$result
}
