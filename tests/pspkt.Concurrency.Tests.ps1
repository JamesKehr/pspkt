#Requires -Modules Pester

<#
    pspkt concurrency + benchmark harness
    -------------------------------------
    Validates the shared, ref-counted packet-buffer pooling used during a -WriteFile capture
    (class/pspkt.cs: PacketBytePool lease refcount, PktMonApi.DispatchCapturedPacket, the console
    SpscPacketRingBuffer, and the async PcapngWriter). The live capture path is normally driven by
    the native pktmon callback on one producer thread, a console consumer on the PowerShell loop,
    and the PcapngWriter's own writer thread. The unit suite exercises none of those threads, so a
    refcount/lease bug (early free -> corruption, late free -> leak) would pass silently.

    This harness drives the EXACT production static methods from real in-process threads
    (runspaces share the loaded assembly's static state) under contention, then asserts:
      * no double-release          -> PacketBytePool.LeaseUnderflowCount == 0
      * no buffer leak / no missing return -> RentCount == ReturnCount == packets produced
      * no console-path corruption -> every consumed packet's payload matches its embedded seq,
                                      with no duplicate sequence numbers
      * no writer-path corruption  -> every pcapng EPB's payload matches its embedded seq,
                                      with no duplicate sequence numbers, and EPB count == PacketCount
      * pooling actually reuses     -> BucketAllocCount stays near the working set, not the packet count

    Tagged 'Concurrency' so it is opt-in (Invoke-Tests.ps1 -Mode Concurrency); it is admin-free
    (no live pktmon) but slower than the unit suite.
#>

BeforeAll {
    $script:ModuleRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $script:ModuleRoot 'pspkt.psm1') -Force -ErrorAction Stop

    # Producer scriptblock — mimics the native pktmon callback on a single thread: rent a pooled
    # buffer, stamp it with the sequence number + two derived check bytes, and run the real
    # DispatchCapturedPacket ownership orchestration. Runs in its own runspace.
    $script:ProducerScript = {
        param($ctrl, $packetCount, $payloadSize, $spinPerPacket)
        try {
            $last = $payloadSize - 1
            for ($seq = 0; $seq -lt $packetCount; $seq++) {
                $b = [PacketBytePool]::Rent($payloadSize)
                # Embed seq (LE) in bytes 0..3 and two derived check bytes at [4] and [last].
                $b[0] = [byte]($seq -band 0xFF)
                $b[1] = [byte](($seq -shr 8) -band 0xFF)
                $b[2] = [byte](($seq -shr 16) -band 0xFF)
                $b[3] = [byte](($seq -shr 24) -band 0xFF)
                $d = [int64]$seq * 31
                $b[4]     = [byte](($d + 4) -band 0xFF)
                $b[$last] = [byte](($d + $last) -band 0xFF)
                $qpc = [System.Diagnostics.Stopwatch]::GetTimestamp()
                # metadataOffset = payloadSize keeps hasComment false; packetOffset 0, length = size.
                [PktMonApi]::DispatchCapturedPacket($b, [int]$payloadSize, [uint32]$payloadSize,
                    [uint32]0, [uint32]$payloadSize, [uint32]0, [uint32]0, [int64]$qpc)
                if ($spinPerPacket -gt 0) {
                    $s = 0; for ($k = 0; $k -lt $spinPerPacket; $k++) { $s += $k }
                }
            }
        }
        finally {
            $ctrl['ProducerDone'] = $true
        }
    }

    # Consumer scriptblock — mimics the Start-Pspkt console loop: drain the console ring, validate
    # each packet's payload against its embedded seq (detecting torn reads and duplicate delivery),
    # then release the buffers. Runs in its own runspace.
    $script:ConsumerScript = {
        param($ctrl, $packetCount, $payloadSize, $seenBits, $consumerSlowSpin)
        $drain = [PSPacketData[]]::new(1024)
        $last = $payloadSize - 1
        $count = 0; $corrupt = 0; $dup = 0
        $emptyStreak = 0
        while ($true) {
            $n = [PktMonApi]::GetPacketData($drain)
            if ($n -le 0) {
                if ($ctrl['ProducerDone']) {
                    $emptyStreak++
                    if ($emptyStreak -ge 3) { break }
                }
                [System.Threading.Thread]::Sleep(1)
                continue
            }
            $emptyStreak = 0
            for ($i = 0; $i -lt $n; $i++) {
                $data = $drain[$i].Data
                if ($null -eq $data -or $drain[$i].DataSize -lt $payloadSize) { $corrupt++; continue }
                $seq = [BitConverter]::ToUInt32($data, 0)
                if ($seq -ge $packetCount) { $corrupt++; continue }
                $d = [int64]$seq * 31
                $exp4 = [byte](($d + 4) -band 0xFF)
                $expL = [byte](($d + $last) -band 0xFF)
                if ($data[4] -ne $exp4 -or $data[$last] -ne $expL) { $corrupt++; continue }
                if ($seenBits[$seq]) { $dup++ } else { $seenBits[$seq] = $true }
                $count++
            }
            [PktMonApi]::ReturnPacketBuffers($drain, $n)
            if ($consumerSlowSpin -gt 0) {
                $s = 0; for ($k = 0; $k -lt $consumerSlowSpin; $k++) { $s += $k }
            }
        }
        $ctrl['ConsumerCount']   = $count
        $ctrl['ConsumerCorrupt'] = $corrupt
        $ctrl['ConsumerDup']     = $dup
    }

    # Walk a pcapng file and validate every Enhanced Packet Block payload against its embedded seq.
    # Generic block walk: type@+0, totalLen@+4; EPB (type 6) capturedLen@+20, packet data@+28.
    function Test-PspktPcapngIntegrity {
        param([string]$Path, [int]$PayloadSize, [int]$PacketCount)
        $bytes = [System.IO.File]::ReadAllBytes($Path)
        $len = $bytes.Length
        $last = $PayloadSize - 1
        $epb = 0; $corrupt = 0; $dup = 0; $badLen = 0
        $seen = [bool[]]::new($PacketCount)
        $offset = 0
        while ($offset + 12 -le $len) {
            $type  = [BitConverter]::ToUInt32($bytes, $offset)
            $total = [BitConverter]::ToUInt32($bytes, $offset + 4)
            if ($total -lt 12 -or ($offset + $total) -gt $len) { break }
            if ($type -eq 6) {
                $capLen  = [BitConverter]::ToUInt32($bytes, $offset + 20)
                $dataOff = $offset + 28
                if ($capLen -ne $PayloadSize) {
                    $badLen++
                } else {
                    $seq = [BitConverter]::ToUInt32($bytes, $dataOff)
                    if ($seq -ge $PacketCount) {
                        $corrupt++
                    } else {
                        $d = [int64]$seq * 31
                        $exp4 = [byte](($d + 4) -band 0xFF)
                        $expL = [byte](($d + $last) -band 0xFF)
                        if ($bytes[$dataOff + 4] -ne $exp4 -or $bytes[$dataOff + $last] -ne $expL) {
                            $corrupt++
                        } elseif ($seen[$seq]) {
                            $dup++
                        } else {
                            $seen[$seq] = $true
                        }
                    }
                }
                $epb++
            }
            $offset += [int]$total
        }
        return [pscustomobject]@{ Epb = $epb; Corrupt = $corrupt; Dup = $dup; BadLen = $badLen }
    }

    # Orchestrates one simulated capture: configure rings, start writer, run producer + consumer
    # threads to completion, stop the writer, and collect all accounting/integrity metrics.
    function Invoke-PspktCaptureSimulation {
        param(
            [int]$PacketCount,
            [int]$PayloadSize    = 256,
            [int]$ConsoleRingCap = 2048,
            [int]$FileRingCap    = 2048,
            [switch]$NoFile,
            [int]$ProducerSpin   = 0,
            [int]$ConsumerSpin   = 0,
            [int]$StopWriterAfterMs = 0
        )

        [PktMonApi]::SetCaptureActive($false) | Out-Null
        [PktMonApi]::ConfigureRingBuffer($ConsoleRingCap) | Out-Null
        [PktMonApi]::ClearPacketBuffer()
        [PktMonApi]::ResetDroppedCount()

        $outFile = $null
        $writer  = $null
        if (-not $NoFile) {
            $outFile = Join-Path ([System.IO.Path]::GetTempPath()) ("pspkt-conc-{0}.pcapng" -f ([guid]::NewGuid().ToString('N')))
            $writer = [PcapngWriter]::new()
            $writer.Start($outFile, $true, $FileRingCap, $false)
            [PktMonApi]::FileWriter = $writer
        }

        # Reset pool counters AFTER warmup allocations from Start().
        [PacketBytePool]::ResetCounters()

        $ctrl = [hashtable]::Synchronized(@{
            ProducerDone   = $false
            ConsumerCount  = 0
            ConsumerCorrupt = 0
            ConsumerDup    = 0
        })
        $seenBits = [bool[]]::new($PacketCount)

        $consRs = [runspacefactory]::CreateRunspace(); $consRs.Open()
        $consPs = [powershell]::Create(); $consPs.Runspace = $consRs
        [void]$consPs.AddScript($script:ConsumerScript).AddArgument($ctrl).AddArgument($PacketCount).AddArgument($PayloadSize).AddArgument($seenBits).AddArgument($ConsumerSpin)

        $prodRs = [runspacefactory]::CreateRunspace(); $prodRs.Open()
        $prodPs = [powershell]::Create(); $prodPs.Runspace = $prodRs
        [void]$prodPs.AddScript($script:ProducerScript).AddArgument($ctrl).AddArgument($PacketCount).AddArgument($PayloadSize).AddArgument($ProducerSpin)

        $consHandle = $consPs.BeginInvoke()
        $prodHandle = $prodPs.BeginInvoke()

        # Optionally stop the writer WHILE the producer is still delivering, to exercise the
        # shutdown race (packets in flight when the file writer stops). Stress-tests that the
        # in-flight/orphaned buffers can't cause a double-free or corruption.
        $stoppedMidFlight = $false
        if ($StopWriterAfterMs -gt 0 -and $writer) {
            Start-Sleep -Milliseconds $StopWriterAfterMs
            [PktMonApi]::FileWriter = $null
            $writer.Stop()
            $stoppedMidFlight = $true
        }

        $prodPs.EndInvoke($prodHandle)
        $ctrl['ProducerDone'] = $true
        $consPs.EndInvoke($consHandle)

        $prodErrors = @($prodPs.Streams.Error)
        $consErrors = @($consPs.Streams.Error)

        $consPs.Dispose(); $consRs.Close()
        $prodPs.Dispose(); $prodRs.Close()

        $writerPackets = 0L; $fileDropped = 0L; $writerError = $null
        if ($writer) {
            if (-not $stoppedMidFlight) {
                $writer.Stop()
                [PktMonApi]::FileWriter = $null
            }
            $writerPackets = $writer.PacketCount
            $fileDropped   = $writer.FileDroppedCount
            $writerError   = $writer.LastError
        }

        # Release any packets still parked in the console ring (should be none after the consumer
        # drains, but guarantees all refs are dropped before the leak assertion reads the counters).
        [PktMonApi]::ClearPacketBuffer()

        $fileIntegrity = $null
        if ($outFile) {
            $fileIntegrity = Test-PspktPcapngIntegrity -Path $outFile -PayloadSize $PayloadSize -PacketCount $PacketCount
            Remove-Item -LiteralPath $outFile -Force -ErrorAction SilentlyContinue
        }

        return [pscustomobject]@{
            PacketCount    = $PacketCount
            RentCount      = [PacketBytePool]::RentCount
            ReturnCount    = [PacketBytePool]::ReturnCount
            LeaseUnderflow = [PacketBytePool]::LeaseUnderflowCount
            BucketAlloc    = [PacketBytePool]::BucketAllocCount
            ConsoleDropped = [PktMonApi]::DroppedCount
            ConsumerCount  = [int]$ctrl['ConsumerCount']
            ConsumerCorrupt= [int]$ctrl['ConsumerCorrupt']
            ConsumerDup    = [int]$ctrl['ConsumerDup']
            WriterPackets  = $writerPackets
            FileDropped    = $fileDropped
            WriterError    = $writerError
            FileIntegrity  = $fileIntegrity
            StoppedMidFlight = $stoppedMidFlight
            ProducerErrors = $prodErrors
            ConsumerErrors = $consErrors
        }
    }
}

Describe 'Buffer pooling concurrency (file capture)' -Tag 'Concurrency' {

    It 'runs producer + console consumer + async writer with no leak, no double-free, and no corruption' {
        $r = Invoke-PspktCaptureSimulation -PacketCount 100000 -PayloadSize 256 -ConsoleRingCap 2048 -FileRingCap 2048

        $r.ProducerErrors.Count | Should -Be 0 -Because 'the producer thread should not throw'
        $r.ConsumerErrors.Count | Should -Be 0 -Because 'the consumer thread should not throw'
        $r.WriterError          | Should -BeNullOrEmpty -Because 'the async writer should not error'

        # No double-release and no leak: every rented buffer returns exactly once.
        $r.LeaseUnderflow | Should -Be 0 -Because 'a non-zero underflow means a buffer was released more than once'
        $r.RentCount      | Should -Be $r.PacketCount
        $r.ReturnCount    | Should -Be $r.PacketCount
        $r.ReturnCount    | Should -Be $r.RentCount -Because 'rent/return must balance -> no pool leak'

        # Console path integrity: no torn reads, no duplicate delivery, accounting balances.
        $r.ConsumerCorrupt | Should -Be 0 -Because 'a shared buffer freed early would corrupt console output'
        $r.ConsumerDup     | Should -Be 0 -Because 'a buffer reused before the consumer read it appears as a duplicate seq'
        ($r.ConsumerCount + $r.ConsoleDropped) | Should -Be $r.PacketCount -Because 'every produced packet is either consumed or dropped'

        # Writer path integrity: the pcapng must be a faithful copy of the shared buffers.
        $r.FileIntegrity.Corrupt | Should -Be 0 -Because 'a shared buffer freed early would corrupt the pcapng'
        $r.FileIntegrity.Dup     | Should -Be 0 -Because 'a buffer reused before the writer read it appears as a duplicate seq in the file'
        $r.FileIntegrity.BadLen  | Should -Be 0
        ($r.WriterPackets + $r.FileDropped) | Should -Be $r.PacketCount -Because 'every produced packet is either written or dropped by the file ring'
        $r.FileIntegrity.Epb     | Should -Be $r.WriterPackets -Because 'the file should contain exactly the packets the writer reported'
    }

    It 'reuses pooled buffers instead of allocating one per packet' {
        $r = Invoke-PspktCaptureSimulation -PacketCount 100000 -PayloadSize 256 -ConsoleRingCap 2048 -FileRingCap 2048
        $r.LeaseUnderflow | Should -Be 0
        $r.ReturnCount    | Should -Be $r.RentCount
        # With pooling working the number of fresh allocations tracks the working set (a few
        # thousand), not the packet count. The pre-pooling code allocated one byte[] per packet
        # (100000); this gate fails hard if that regresses.
        $r.BucketAlloc | Should -BeLessThan 20000 -Because 'pooled buffers should be recycled, not reallocated per packet'
    }

    It 'stays correct under heavy ring pressure (small rings, fast producer, slow consumer)' {
        $r = Invoke-PspktCaptureSimulation -PacketCount 60000 -PayloadSize 256 -ConsoleRingCap 1024 -FileRingCap 64 -ConsumerSpin 40

        $r.LeaseUnderflow | Should -Be 0 -Because 'the drop paths must release refs without double-freeing'
        $r.RentCount      | Should -Be $r.PacketCount
        $r.ReturnCount    | Should -Be $r.PacketCount -Because 'dropped packets must still return their buffers -> no leak'
        $r.ConsumerCorrupt| Should -Be 0
        $r.ConsumerDup    | Should -Be 0
        $r.FileIntegrity.Corrupt | Should -Be 0
        $r.FileIntegrity.Dup     | Should -Be 0
        # Under this pressure both rings should drop some packets, exercising the release-on-drop paths.
        ($r.ConsoleDropped + $r.FileDropped) | Should -BeGreaterThan 0 -Because 'the scenario is designed to force drops'
        ($r.WriterPackets + $r.FileDropped)  | Should -Be $r.PacketCount
    }

    It 'survives the writer stopping mid-capture with no double-free and no corruption' {
        # Stop the async writer while the producer is still delivering — the shutdown race the
        # rubber-duck flagged (packets in flight when the file writer stops). The safety-critical
        # properties (no double-free, no corruption) must hold; a small, bounded number of buffers
        # in flight at the moment of Stop may not return to the pool (they are GC-reclaimed with the
        # discarded writer), so the leak check is bounded rather than exact for this scenario.
        $r = Invoke-PspktCaptureSimulation -PacketCount 150000 -PayloadSize 256 -ConsoleRingCap 2048 -FileRingCap 512 -StopWriterAfterMs 25

        $r.StoppedMidFlight | Should -BeTrue
        $r.ProducerErrors.Count | Should -Be 0
        $r.ConsumerErrors.Count | Should -Be 0
        $r.LeaseUnderflow  | Should -Be 0 -Because 'the shutdown race must never double-free a shared buffer'
        $r.ConsumerCorrupt | Should -Be 0 -Because 'stopping the writer must not corrupt console output'
        $r.ConsumerDup     | Should -Be 0
        $r.FileIntegrity.Corrupt | Should -Be 0 -Because 'packets written before the stop must be intact'
        $r.FileIntegrity.Dup     | Should -Be 0
        $r.FileIntegrity.Epb     | Should -Be $r.WriterPackets
        # Bounded leak: at most a handful of in-flight buffers can be stranded by the stop race.
        ($r.RentCount - $r.ReturnCount) | Should -BeLessThan 4096 -Because 'only in-flight buffers may be stranded, not a growing leak'
    }
}

Describe 'Buffer pooling concurrency (console only, unshared)' -Tag 'Concurrency' {

    It 'returns unshared buffers directly with no leak or corruption when no file writer is active' {
        $r = Invoke-PspktCaptureSimulation -PacketCount 80000 -PayloadSize 256 -ConsoleRingCap 2048 -NoFile

        $r.ProducerErrors.Count | Should -Be 0
        $r.ConsumerErrors.Count | Should -Be 0
        $r.LeaseUnderflow | Should -Be 0 -Because 'the unshared path never creates a lease, so it can never underflow'
        $r.RentCount      | Should -Be $r.PacketCount
        $r.ReturnCount    | Should -Be $r.PacketCount
        $r.ConsumerCorrupt| Should -Be 0
        $r.ConsumerDup    | Should -Be 0
        ($r.ConsumerCount + $r.ConsoleDropped) | Should -Be $r.PacketCount
        $r.BucketAlloc | Should -BeLessThan 20000
    }
}
