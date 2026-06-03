# Load pspkt C# types before any module code runs
# This script is referenced in ScriptsToProcess in pspkt.psd1

$classPath = Join-Path -Path $PSScriptRoot -ChildPath '.'
$parsersPath = Join-Path -Path (Split-Path $PSScriptRoot -Parent) -ChildPath 'Parsers'

# Collect .cs files from class/ and Parsers/ (recursively).
$csFiles = @()
$csFiles += Get-ChildItem -Path $classPath -Filter '*.cs' -File -ErrorAction SilentlyContinue
if (Test-Path $parsersPath) {
    $csFiles += Get-ChildItem -Path $parsersPath -Filter '*.cs' -File -Recurse -ErrorAction SilentlyContinue
}

if (-not $csFiles -or $csFiles.Count -eq 0) {
    throw "No C# source files found in $classPath or $parsersPath. Module installation may be corrupt."
}

$typeCheck = 'PktMonApi' -as [type]
if ($null -eq $typeCheck) {
    # Collect all source, deduplicate using directives at the top.
    $usingSet = [System.Collections.Generic.HashSet[string]]::new()
    $bodyParts = @()
    foreach ($file in $csFiles) {
        $content = Get-Content -Path $file.FullName -Raw
        # Extract using lines and body separately.
        $lines = $content -split "`n"
        $bodyLines = [System.Collections.ArrayList]::new()
        foreach ($line in $lines) {
            $trimmed = $line.TrimStart()
            if ($trimmed -match '^using\s+[^(]') {
                $null = $usingSet.Add($trimmed.TrimEnd("`r"))
            } else {
                $null = $bodyLines.Add($line)
            }
        }
        $bodyParts += ($bodyLines -join "`n")
    }
    $combinedSource = ($usingSet -join "`n") + "`n`n" + ($bodyParts -join "`n")
    try {
        Add-Type -TypeDefinition $combinedSource -Language CSharp -ErrorAction Stop
    } catch {
        throw "Failed to compile pspkt C# classes: $_"
    }

    # create the type accelerator
    $ExportableTypes =@(
        [PktMonApi]
        [SpscPacketRingBuffer]
        [PacketParseHelper]
        [PacketFormatter]
        [PacketLineFormatter]
        [ComponentInfo]
        [TcpParser]
        [DnsParser]
        [Smb2Parser]
        [PACKETMONITOR_REALTIME_STREAM_CONFIGURATION]
        [PACKETMONITOR_STREAM_DATA_DESCRIPTOR]
        [PSPacketData]
        [PACKETMONITOR_STREAM_DATA_CALLBACK]
    )

    # Get the internal TypeAccelerators class to use its static methods.
    $TypeAcceleratorsClass = [psobject].Assembly.GetType(
        'System.Management.Automation.TypeAccelerators'
    )

    # Ensure none of the types would clobber an existing type accelerator.
    # If a type accelerator with the same name exists, throw an exception.
    $ExistingTypeAccelerators = $TypeAcceleratorsClass::Get
    foreach ($Type in $ExportableTypes) {
        if ($Type.FullName -in $ExistingTypeAccelerators.Keys) {
            # silently throw a message to the verbose stream
            Write-Verbose @"
Unable to register type accelerator[$($Type.FullName)]. The Accelerator already exists.
"@

        } else {
            $TypeAcceleratorsClass::Add($Type.FullName, $Type)
        }
    }

    # Remove type accelerators when the module is removed.
    $MyInvocation.MyCommand.ScriptBlock.Module.OnRemove = {
        foreach($Type in $ExportableTypes) {
            $TypeAcceleratorsClass::Remove($Type.FullName)
        }
    }.GetNewClosure()
}
