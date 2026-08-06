
class BitUtils {
    static [uint16] ToUInt16BigEndian([Byte[]] $ByteArray, [int] $offset)
    {
        $byte1 = [uint16]$ByteArray[0 + $offset]   
        $byte2 = [uint16]$ByteArray[1 + $offset] 
        return [uint16](($byte1 -shl 8) -bor $byte2)
    } 
    
    static [uint32] ToUInt32BigEndian([byte[]] $ByteArray, [int] $offset)
    {
        $b1 = [uint32]$ByteArray[$offset]
        $b2 = [uint32]$ByteArray[$offset + 1]
        $b3 = [uint32]$ByteArray[$offset + 2]
        $b4 = [uint32]$ByteArray[$offset + 3]

        return [uint32](($b1 -shl 24) -bor ($b2 -shl 16) -bor ($b3 -shl 8)  -bor $b4)
    }

    static [void] ToHex([Byte[]] $ByteArray)
    {
        $bytesPerLine = 16
        for($i = 0; $i -lt $ByteArray.Count; $i+= 16)
        {
            $hex = ""
            $ascii = ""
            for ($j = $i; $j -lt $ByteArray.Count -and $j -lt ($bytesPerLine + $i); $j++) 
            {
                [Byte] $byte = $ByteArray[$j]
                $tmpHex = "{0:X2} " -f $byte
                $hex += $tmpHex
                if ($byte -ge 32 -and $byte -le 126) 
                {
                    $ascii += [char]$byte
                } 
                else 
                {
                    $ascii += "."
                }
            }
            $output = "{0:X8}:  {1,-48}  {2}" -f $i, $hex, $ascii
            write-host $output   
        }
    }
}


class PAUtils {
    hidden static [PhysicalAddress] ParseStandardPhysicalAddressOrNull([string]$rawMac) {
        if ([string]::IsNullOrWhiteSpace($rawMac)) {
            return $null
        }

        $candidate = $rawMac.Trim()
        $isPlain = [regex]::IsMatch($candidate, '^[0-9A-Fa-f]{12}$')
        $isColon = [regex]::IsMatch($candidate, '^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$')
        $isHyphen = [regex]::IsMatch($candidate, '^(?:[0-9A-Fa-f]{2}-){5}[0-9A-Fa-f]{2}$')
        $isCisco = [regex]::IsMatch($candidate, '^(?:[0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}$')
        if (-not ($isPlain -or $isColon -or $isHyphen -or $isCisco)) {
            return $null
        }

        $normalized = ($candidate -replace '[:\.-]', '').ToUpperInvariant()
        try {
            $physicalAddress = [PhysicalAddress]::Parse($normalized)
        } catch [FormatException] {
            return $null
        }

        if ($physicalAddress.GetAddressBytes().Length -ne 6) {
            return $null
        }

        return $physicalAddress
    }

    static [PhysicalAddress] ConvertString2PhysicalAddress([string]$rawMac) {
        $physicalAddress = [PAUtils]::ParseStandardPhysicalAddressOrNull($rawMac)
        if ($null -ne $physicalAddress) {
            return $physicalAddress
        }

        throw "The value is not a valid MAC address. MacAddress: $rawMac"
    }

    static [string] FormatPhysicalAddress([string]$macAddress) {
        $physicalAddress = [PAUtils]::ParseStandardPhysicalAddressOrNull($macAddress)
        if ($null -eq $physicalAddress) {
            throw "The MAC address is invalid. MacAddress: $macAddress"
        }

        return [PAUtils]::FormatPhysicalAddress($physicalAddress.GetAddressBytes())
    }

    static [string] FormatPhysicalAddress([byte[]]$macAddress) {
        if ($null -eq $macAddress -or $macAddress.Length -ne 6) {
            return ''
        }

        $parts = [string[]]::new(6)
        for ($index = 0; $index -lt 6; $index++) {
            $parts[$index] = '{0:X2}' -f $macAddress[$index]
        }

        return $parts -join ':'
    }
}


# create the type accelerator
$ExportableTypes = @(
    [BitUtils]
    [PAUtils]
)

# Get the internal TypeAccelerators class to use its static methods.
$TypeAcceleratorsClass = [psobject].Assembly.GetType(
    'System.Management.Automation.TypeAccelerators'
)

# Ensure none of the types would clobber an existing type accelerator.
# If a type accelerator with the same name exists, throw an exception.
$ExistingTypeAccelerators = $TypeAcceleratorsClass::Get
$RegisteredTypeAccelerators = [System.Collections.ArrayList]::new()
$PspktOwnedAcceleratorTypes = [AppDomain]::CurrentDomain.GetData('pspkt-owned-accelerators')
if ($null -eq $PspktOwnedAcceleratorTypes) { $PspktOwnedAcceleratorTypes = [hashtable]::Synchronized(@{}); [AppDomain]::CurrentDomain.SetData('pspkt-owned-accelerators', $PspktOwnedAcceleratorTypes) }
foreach ($Type in $ExportableTypes) {
    if ($Type.FullName -in $ExistingTypeAccelerators.Keys) {
        if (-not $PspktOwnedAcceleratorTypes.ContainsKey($Type.FullName) -or -not [object]::ReferenceEquals($PspktOwnedAcceleratorTypes[$Type.FullName], $ExistingTypeAccelerators[$Type.FullName])) {
            throw "Type accelerator '$($Type.FullName)' is already registered to a different type."
        }
        # silently throw a message to the verbose stream
        Write-Verbose @"
Unable to register type accelerator[$($Type.FullName)]. The Accelerator already exists.
"@

    } else {
        $TypeAcceleratorsClass::Add($Type.FullName, $Type)
        $PspktOwnedAcceleratorTypes[$Type.FullName] = $Type
        $null = $RegisteredTypeAccelerators.Add($Type)
    }
}

# Remove type accelerators when the module is removed.
$MyInvocation.MyCommand.ScriptBlock.Module.OnRemove = {
    $CurrentTypeAccelerators = $TypeAcceleratorsClass::Get
    foreach($Type in $RegisteredTypeAccelerators) {
        if (
            $CurrentTypeAccelerators.ContainsKey($Type.FullName) -and
            [object]::ReferenceEquals($CurrentTypeAccelerators[$Type.FullName], $Type)
        ) {
            $null = $TypeAcceleratorsClass::Remove($Type.FullName)
            $null = $PspktOwnedAcceleratorTypes.Remove($Type.FullName)
        }
    }
}.GetNewClosure()
