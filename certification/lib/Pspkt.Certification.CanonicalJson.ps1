Set-StrictMode -Version Latest

function Get-PspktUtf8NoBom {
    [OutputType([System.Text.UTF8Encoding])]
    param()
    return [System.Text.UTF8Encoding]::new($false)
}

function ConvertTo-PspktNfc {

    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Value
    )
    return $Value.Normalize([System.Text.NormalizationForm]::FormC)
}

function Test-PspktStringIsNfc {

    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Value
    )
    return $Value.IsNormalized([System.Text.NormalizationForm]::FormC)
}

function ConvertTo-PspktCanonicalJsonString {

    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Value
    )

    $normalized = ConvertTo-PspktNfc -Value $Value
    $builder = [System.Text.StringBuilder]::new($normalized.Length + 2)
    [void]$builder.Append('"')
    foreach ($ch in $normalized.ToCharArray()) {
        $code = [int][char]$ch
        if ($ch -eq '"') {
            [void]$builder.Append('\"')
        }
        elseif ($ch -eq '\') {
            [void]$builder.Append('\\')
        }
        elseif ($code -le 0x1F) {
            [void]$builder.Append('\u')
            [void]$builder.Append(('{0:X4}' -f $code))
        }
        else {
            [void]$builder.Append($ch)
        }
    }
    [void]$builder.Append('"')
    return $builder.ToString()
}

function ConvertTo-PspktCanonicalJsonInteger {

    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        $Value
    )

    if ($Value -is [double] -or $Value -is [single] -or $Value -is [decimal]) {
        throw ('Canonical JSON: floating-point numbers are forbidden (got {0}).' -f $Value)
    }

    if ($Value -is [System.Numerics.BigInteger]) {
        return $Value.ToString([System.Globalization.CultureInfo]::InvariantCulture)
    }

    if ($Value -is [byte] -or $Value -is [sbyte] -or `
        $Value -is [int16] -or $Value -is [uint16] -or `
        $Value -is [int32] -or $Value -is [uint32] -or `
        $Value -is [int64] -or $Value -is [uint64]) {
        return ([System.Numerics.BigInteger]$Value).ToString([System.Globalization.CultureInfo]::InvariantCulture)
    }

    throw ('Canonical JSON: value of type {0} is not an integer.' -f $Value.GetType().FullName)
}

function Get-PspktUtf8SortKey {
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Key
    )
    $encoding = Get-PspktUtf8NoBom
    return $encoding.GetBytes((ConvertTo-PspktNfc -Value $Key))
}

function Compare-PspktUtf8Bytes {

    [OutputType([int])]
    param(
        [Parameter(Mandatory = $true)][byte[]]$Left,
        [Parameter(Mandatory = $true)][byte[]]$Right
    )
    $min = [Math]::Min($Left.Length, $Right.Length)
    for ($i = 0; $i -lt $min; $i++) {
        $l = [int]$Left[$i]
        $r = [int]$Right[$i]
        if ($l -ne $r) {
            if ($l -lt $r) { return -1 }
            return 1
        }
    }
    if ($Left.Length -eq $Right.Length) { return 0 }
    if ($Left.Length -lt $Right.Length) { return -1 }
    return 1
}

function ConvertTo-PspktCanonicalJsonObject {

    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Entries
    )

    $ordered = [System.Collections.Generic.List[object]]::new()
    foreach ($entry in $Entries) {
        $inserted = $false
        for ($i = 0; $i -lt $ordered.Count; $i++) {
            if ((Compare-PspktUtf8Bytes -Left $entry.SortKey -Right $ordered[$i].SortKey) -lt 0) {
                $ordered.Insert($i, $entry)
                $inserted = $true
                break
            }
        }
        if (-not $inserted) {
            $ordered.Add($entry)
        }
    }

    $builder = [System.Text.StringBuilder]::new()
    [void]$builder.Append('{')
    $first = $true
    $previousSortKey = $null
    foreach ($entry in $ordered) {
        if (-not $first) {
            [void]$builder.Append(',')
        }
        if ($null -ne $previousSortKey) {
            if ((Compare-PspktUtf8Bytes -Left $entry.SortKey -Right $previousSortKey) -eq 0) {
                throw ('Canonical JSON: duplicate object key "{0}".' -f $entry.Key)
            }
        }
        $previousSortKey = $entry.SortKey
        [void]$builder.Append((ConvertTo-PspktCanonicalJsonString -Value $entry.Key))
        [void]$builder.Append(':')
        [void]$builder.Append((ConvertTo-PspktCanonicalJson -Value $entry.Value))
        $first = $false
    }
    [void]$builder.Append('}')
    return $builder.ToString()
}

function ConvertTo-PspktCanonicalJson {

    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        $Value
    )

    if ($null -eq $Value) {
        return 'null'
    }

    if ($Value -is [bool]) {
        if ($Value) { return 'true' }
        return 'false'
    }

    if ($Value -is [string]) {
        return ConvertTo-PspktCanonicalJsonString -Value $Value
    }

    if ($Value -is [System.Collections.IDictionary]) {
        $keys = @()
        foreach ($k in $Value.Keys) {
            if ($null -eq $k) {
                throw 'Canonical JSON: object key is null.'
            }
            $keys += ,([string]$k)
        }
        $entries = @()
        foreach ($key in $keys) {
            $entries += ,[pscustomobject]@{
                Key     = $key
                SortKey = (Get-PspktUtf8SortKey -Key $key)
                Value   = $Value[$key]
            }
        }
        return (ConvertTo-PspktCanonicalJsonObject -Entries $entries)
    }

    if ($Value -is [psobject] -and $Value.PSObject.BaseObject -is [System.Management.Automation.PSCustomObject]) {
        $entries = @()
        foreach ($property in $Value.PSObject.Properties) {
            $entries += ,[pscustomobject]@{
                Key     = $property.Name
                SortKey = (Get-PspktUtf8SortKey -Key $property.Name)
                Value   = $property.Value
            }
        }
        return (ConvertTo-PspktCanonicalJsonObject -Entries $entries)
    }

    if ($Value -is [System.Collections.IEnumerable]) {
        $builder = [System.Text.StringBuilder]::new()
        [void]$builder.Append('[')
        $first = $true
        foreach ($item in $Value) {
            if (-not $first) {
                [void]$builder.Append(',')
            }
            [void]$builder.Append((ConvertTo-PspktCanonicalJson -Value $item))
            $first = $false
        }
        [void]$builder.Append(']')
        return $builder.ToString()
    }

    return ConvertTo-PspktCanonicalJsonInteger -Value $Value
}

function Get-PspktCanonicalJsonBytes {

    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        $Value
    )
    $text = ConvertTo-PspktCanonicalJson -Value $Value
    return (Get-PspktUtf8NoBom).GetBytes($text)
}

function Get-PspktSha256Hex {

    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$Bytes
    )
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hash = $sha.ComputeHash($Bytes)
    }
    finally {
        $sha.Dispose()
    }
    $builder = [System.Text.StringBuilder]::new($hash.Length * 2)
    foreach ($b in $hash) {
        [void]$builder.Append(('{0:x2}' -f [int]$b))
    }
    return $builder.ToString()
}

function Get-PspktCanonicalJsonSha256 {

    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        $Value
    )
    return Get-PspktSha256Hex -Bytes (Get-PspktCanonicalJsonBytes -Value $Value)
}

function ConvertTo-PspktHexString {

    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$Bytes
    )
    $builder = [System.Text.StringBuilder]::new($Bytes.Length * 2)
    foreach ($b in $Bytes) {
        [void]$builder.Append(('{0:x2}' -f [int]$b))
    }
    return $builder.ToString()
}

function Read-PspktUtf8Text {

    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw ('Read-PspktUtf8Text: file not found: {0}' -f $Path)
    }
    $full = (Resolve-Path -LiteralPath $Path).ProviderPath
    return [System.IO.File]::ReadAllText($full, [System.Text.UTF8Encoding]::new($false, $true))
}

function Read-PspktJsonFile {

    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )
    return (Read-PspktUtf8Text -Path $Path | ConvertFrom-Json)
}
