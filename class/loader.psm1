# Load pspkt C# types before any module code runs
# This script is referenced in ScriptsToProcess in pspkt.psd1

$classPath = Join-Path -Path $PSScriptRoot -ChildPath '.'
$parsersPath = Join-Path -Path (Split-Path $PSScriptRoot -Parent) -ChildPath 'Parsers'
$tuiPath = Join-Path -Path (Split-Path $PSScriptRoot -Parent) -ChildPath 'TUI'

# Collect .cs files from class/, Parsers/, and TUI/ (recursively).
$csFiles = @()
$csFiles += Get-ChildItem -Path $classPath -Filter '*.cs' -File -ErrorAction SilentlyContinue
if (Test-Path $parsersPath) {
    $csFiles += Get-ChildItem -Path $parsersPath -Filter '*.cs' -File -Recurse -ErrorAction SilentlyContinue
}
if (Test-Path $tuiPath) {
    $csFiles += Get-ChildItem -Path $tuiPath -Filter '*.cs' -File -Recurse -ErrorAction SilentlyContinue
}

if (-not $csFiles -or $csFiles.Count -eq 0) {
    throw "No C# source files found in $classPath or $parsersPath. Module installation may be corrupt."
}

$typeCheck = 'PktMonApi' -as [type]
if ($null -eq $typeCheck) {
    # Collect all source, deduplicate using directives at the top.
    $usingSet = [System.Collections.Generic.HashSet[string]]::new()
    # List (O(1) append) rather than array += (which reallocates the whole array each
    # iteration). Produces the identical combined source string.
    $bodyParts = [System.Collections.Generic.List[string]]::new()
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
        $null = $bodyParts.Add($bodyLines -join "`n")
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
        [DnsContext]
        [DnsAppPredicate]
        [TlsParser]
        [TlsContext]
        [TlsAppPredicate]
        [SshParser]
        [HttpParser]
        [HttpContext]
        [HttpAppPredicate]
        [HttpParseFields]
        [DhcpParser]
        [DhcpContext]
        [DhcpAppPredicate]
        [Smb2Parser]
        [Smb2Context]
        [Smb2AppPredicate]
        [IcmpContext]
        [IcmpAppPredicate]
        [NdpParser]
        [PacketDetailStore]
        [PacketDetailExtractor]
        [BoxyBox.AnsiText]
        [BoxyBox.TextJustify]
        [BoxyBox.BoxChars]
        [BoxyBox.MenuBar]
        [BoxyBox.Box]
        [BoxyBox.ScreenRegion]
        [BoxyBox.FrameBuffer]
        [BoxyBox.TextBox]
        [BoxyBox.TreeNode]
        [BoxyBox.TreeRow]
        [BoxyBox.TreeFlattener]
        [BoxyBox.DetailsBox]
        [BoxyBox.MenuItem]
        [BoxyBox.MenuDefinition]
        [BoxyBox.MenuRenderer]
        [BoxyBox.OverlayBox]
        [BoxyBox.Justify]
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
