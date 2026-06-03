class test {
    [double]$a
    [double]$b
    [double]$sum
    [double]$diff
    [double]$mult
    [double]$div
    [System.Diagnostics.Stopwatch]$local
    [System.Diagnostics.Stopwatch]$static

    test($n1, $n2) {
        $this.a = $n1
        $this.b = $n2
    
        $sw1 = [System.Diagnostics.Stopwatch]::StartNew()
        $this.Add()
        $this.Subtract()
        $this.Multiply()
        $this.Divide()
        $sw1.Stop()

        $sw2 = [System.Diagnostics.Stopwatch]::StartNew()
        $this.Sum = [test]::Add2($this.a, $this.b)
        $this.diff = [test]::Subtract2($this.a, $this.b)
        $this.mult = [test]::Multiply2($this.a, $this.b)
        $this.div = [test]::Divide2($this.a, $this.b)
        $sw2.Stop()

        $this.Local = $sw1
        $this.static = $sw2

    }

    Add() {
        $this.Sum = $this.a + $this.b
    }

    Subtract() {
        $this.diff = $this.a - $this.b
    }

    Multiply() {
        $this.mult = $this.a * $this.b
    }

    Divide() {
        $this.div = $this.a / $this.b
    }

    static
    [double]
    Add2([double]$n1, [double]$n2) {
        return ($n1 + $n2)
    }

    static
    [double]
    Subtract2([double]$n1, [double]$n2) {
        return ($n1 - $n2)
    }

    static
    [double]
    Multiply2([double]$n1, [double]$n2) {
        return ($n1 * $n2)
    }

    static
    [double]
    Divide2([double]$n1, [double]$n2) {
        return ($n1 / $n2)
    }
}


[double]$min = 100.0
[double]$max = 10000.0
$count = 0
$totLocal = 0
$totStatic = 0
for ($i = 1; $i -le 1000; $i++) {
    # increment count
    $count = $count + 1

    # get two random numbers
    $n1 = Get-Random -Minimum $min -Maximum $max
    $n2 = Get-Random -Minimum $min -Maximum $max

    # run the class test
    $tmp = [test]::new($n1, $n2)

    # update values
    $totLocal = $totLocal + $tmp.local.Elapsed.Microseconds
    $totStatic = $totStatic + $tmp.static.Elapsed.Microseconds

    Write-Verbose "Count: $count`ntmp:`n$($tmp | Out-String)`n"
}

$avgLocal = [math]::Round($totLocal / $count, 2)
$avgStatic = [math]::Round($totStatic / $count, 2)

Write-Host -ForegroundColor Green @"
Avg. Local (us)  : $avgLocal
Avg. Static (us) : $avgStatic
"@
