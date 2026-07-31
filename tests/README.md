# Pester tests

## Prerequisites

- PowerShell 5.1 or newer
- Pester 5.3.3 through 5.x
- Elevated PowerShell session (the module import requires administrator privileges)

## Run tests

```powershell
pwsh -File .\tests\Invoke-Tests.ps1
```

Auto mode runs `Precheck` when not elevated, and `Precheck` + `Unit` when elevated.
The runner reuses one loaded supported Pester identity or selects the unique highest installed
supported version. Use `-PesterManifestPath` to pin an exact installation. Pester 6 is not yet
supported.

Run only fast non-admin prechecks:

```powershell
pwsh -File .\tests\Invoke-Tests.ps1 -Mode Precheck
```

Run only full unit tests (requires elevated shell):

```powershell
pwsh -File .\tests\Invoke-Tests.ps1 -Mode Unit
```

Return the verified Pester result object:

```powershell
$result = .\tests\Invoke-Tests.ps1 -Mode Precheck -PassThru
```

If no supported Pester 5 installation exists, installation is disabled by default. Opt in with:

```powershell
pwsh -File .\tests\Invoke-Tests.ps1 -AllowPesterInstall
```

Run the concurrency + benchmark harness (opt-in, admin **not** required):

```powershell
pwsh -File .\tests\Invoke-Tests.ps1 -Mode Concurrency
```

Or with custom verbosity:

```powershell
pwsh -File .\tests\Invoke-Tests.ps1 -Verbosity Normal
```

## Notes

- The unit suite is in `tests\pspkt.Unit.Tests.ps1`.
- `Precheck` tests are safe for non-admin CI agents.
- `Unit` tests are focused on command exports and stateful behavior that does not require live pktmon handles.
- Native lifecycle paths are exercised through an injected test API; unit tests do not require live pktmon handles.
- The concurrency harness (`tests\pspkt.Concurrency.Tests.ps1`, tag `Concurrency`) drives the real
  producer/console-consumer/pcapng-writer buffer-pooling code from in-process threads to validate the
  shared ref-counted buffer lease (no leak, no double-free, no corruption). It is excluded from `Auto`
  because it is a slower stress/benchmark run; it needs no elevation (no live pktmon).
