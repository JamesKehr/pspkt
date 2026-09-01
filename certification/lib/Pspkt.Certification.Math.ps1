Set-StrictMode -Version Latest

$script:PspktInt64Max = [System.Numerics.BigInteger]::Parse('9223372036854775807')
$script:PspktInt64Min = [System.Numerics.BigInteger]::Parse('-9223372036854775808')
$script:PspktBigZero  = [System.Numerics.BigInteger]::Zero
$script:PspktBigTwo   = [System.Numerics.BigInteger]2
$script:PspktBigHundred = [System.Numerics.BigInteger]100
$script:PspktBigNinetyNine = [System.Numerics.BigInteger]99

function ConvertTo-PspktBigInteger {

    [OutputType([System.Numerics.BigInteger])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        $Value
    )

    if ($null -eq $Value) {
        throw 'ConvertTo-PspktBigInteger: value is null; an integer is required.'
    }

    if ($Value -is [System.Numerics.BigInteger]) {
        return $Value
    }

    if ($Value -is [double] -or $Value -is [single] -or $Value -is [decimal]) {
        throw ('ConvertTo-PspktBigInteger: floating-point values are forbidden (got {0}).' -f $Value.GetType().FullName)
    }

    if ($Value -is [byte] -or $Value -is [sbyte] -or `
        $Value -is [int16] -or $Value -is [uint16] -or `
        $Value -is [int32] -or $Value -is [uint32] -or `
        $Value -is [int64] -or $Value -is [uint64]) {
        return [System.Numerics.BigInteger]$Value
    }

    if ($Value -is [string]) {
        $parsed = [System.Numerics.BigInteger]::Zero
        if ([System.Numerics.BigInteger]::TryParse($Value, [ref]$parsed)) {

            if ($parsed.ToString() -ceq $Value) {
                return $parsed
            }
        }
        throw ('ConvertTo-PspktBigInteger: string "{0}" is not a minimal base-10 integer.' -f $Value)
    }

    throw ('ConvertTo-PspktBigInteger: unsupported type {0}.' -f $Value.GetType().FullName)
}

function Test-PspktInt64Domain {

    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [System.Numerics.BigInteger]$Value
    )
    return ($Value -ge $script:PspktInt64Min -and $Value -le $script:PspktInt64Max)
}

function Invoke-PspktScaleRoundHalfUp {

    [OutputType([System.Numerics.BigInteger])]
    param(
        [Parameter(Mandatory = $true)] $Value,
        [Parameter(Mandatory = $true)] $Scale,
        [Parameter(Mandatory = $true)] $Denominator
    )

    $bigValue = ConvertTo-PspktBigInteger -Value $Value
    $bigScale = ConvertTo-PspktBigInteger -Value $Scale
    $bigDenominator = ConvertTo-PspktBigInteger -Value $Denominator

    if ($bigDenominator -le $script:PspktBigZero) {
        throw ('Invoke-PspktScaleRoundHalfUp: denominator must be positive (got {0}).' -f $bigDenominator)
    }
    if ($bigValue -lt $script:PspktBigZero) {
        throw ('Invoke-PspktScaleRoundHalfUp: value must be nonnegative (got {0}).' -f $bigValue)
    }
    if ($bigScale -lt $script:PspktBigZero) {
        throw ('Invoke-PspktScaleRoundHalfUp: scale must be nonnegative (got {0}).' -f $bigScale)
    }

    $whole = [System.Numerics.BigInteger]::Divide($bigValue, $bigDenominator) * $bigScale
    if (-not (Test-PspktInt64Domain -Value $whole)) {
        throw ('Invoke-PspktScaleRoundHalfUp: overflow computing whole ({0}).' -f $whole)
    }

    $remainder = [System.Numerics.BigInteger]::Remainder($bigValue, $bigDenominator)
    $halfDenominator = [System.Numerics.BigInteger]::Divide($bigDenominator, $script:PspktBigTwo)
    $fractionNumerator = $remainder * $bigScale + $halfDenominator
    if (-not (Test-PspktInt64Domain -Value $fractionNumerator)) {
        throw ('Invoke-PspktScaleRoundHalfUp: overflow computing fraction numerator ({0}).' -f $fractionNumerator)
    }

    $fraction = [System.Numerics.BigInteger]::Divide($fractionNumerator, $bigDenominator)
    $result = $whole + $fraction
    if (-not (Test-PspktInt64Domain -Value $result)) {
        throw ('Invoke-PspktScaleRoundHalfUp: overflow computing result ({0}).' -f $result)
    }

    return $result
}

function Convert-PspktQpcDeltaToMicroseconds {

    [OutputType([System.Numerics.BigInteger])]
    param(
        [Parameter(Mandatory = $true)] $DeltaTicks,
        [Parameter(Mandatory = $true)] $FrequencyHz
    )
    return Invoke-PspktScaleRoundHalfUp -Value $DeltaTicks -Scale 1000000 -Denominator $FrequencyHz
}

function Convert-PspktQpcDeltaTo100ns {

    [OutputType([System.Numerics.BigInteger])]
    param(
        [Parameter(Mandatory = $true)] $DeltaTicks,
        [Parameter(Mandatory = $true)] $FrequencyHz
    )
    return Invoke-PspktScaleRoundHalfUp -Value $DeltaTicks -Scale 10000000 -Denominator $FrequencyHz
}

function Get-PspktCpuUtilizationPpm {

    [OutputType([System.Numerics.BigInteger])]
    param(
        [Parameter(Mandatory = $true)] $Cpu100ns,
        [Parameter(Mandatory = $true)] $WallElapsed100ns
    )
    return Invoke-PspktScaleRoundHalfUp -Value $Cpu100ns -Scale 1000000 -Denominator $WallElapsed100ns
}

function Get-PspktNearestRankPercentile {

    [OutputType([System.Numerics.BigInteger])]
    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.IEnumerable]$SortedAscending,
        [Parameter(Mandatory = $true)]
        [int]$Percentile
    )

    $items = [System.Collections.Generic.List[System.Numerics.BigInteger]]::new()
    foreach ($raw in $SortedAscending) {
        $items.Add((ConvertTo-PspktBigInteger -Value $raw))
    }

    $count = $items.Count
    if ($count -lt 1) {
        throw 'Get-PspktNearestRankPercentile: N must be >= 1.'
    }
    if ($Percentile -lt 1 -or $Percentile -gt 100) {
        throw ('Get-PspktNearestRankPercentile: percentile must be in 1..100 (got {0}).' -f $Percentile)
    }
    for ($i = 1; $i -lt $count; $i++) {
        if ($items[$i] -lt $items[$i - 1]) {
            throw 'Get-PspktNearestRankPercentile: input is not sorted ascending.'
        }
    }

    $rankNumerator = [System.Numerics.BigInteger]$Percentile * [System.Numerics.BigInteger]$count + $script:PspktBigNinetyNine
    if (-not (Test-PspktInt64Domain -Value $rankNumerator)) {
        throw ('Get-PspktNearestRankPercentile: overflow computing rank numerator ({0}).' -f $rankNumerator)
    }
    $rank = [System.Numerics.BigInteger]::Divide($rankNumerator, $script:PspktBigHundred)
    return $items[[int]$rank - 1]
}

function Get-PspktLatencyPercentile {

    [OutputType([System.Numerics.BigInteger])]
    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.IEnumerable]$Samples,
        [Parameter(Mandatory = $true)]
        [int]$Percentile
    )

    $values = [System.Collections.Generic.List[System.Numerics.BigInteger]]::new()
    foreach ($raw in $Samples) {
        $values.Add((ConvertTo-PspktBigInteger -Value $raw))
    }
    $values.Sort()
    return Get-PspktNearestRankPercentile -SortedAscending $values -Percentile $Percentile
}
