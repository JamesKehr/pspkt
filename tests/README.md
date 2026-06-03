# Pester tests

## Prerequisites

- PowerShell 5.1 or newer
- Pester 5+
- Elevated PowerShell session (the module import requires administrator privileges)

## Run tests

```powershell
pwsh -File .\tests\Invoke-Tests.ps1
```

Auto mode runs `Precheck` when not elevated, and `Precheck` + `Unit` when elevated.

Run only fast non-admin prechecks:

```powershell
pwsh -File .\tests\Invoke-Tests.ps1 -Mode Precheck
```

Run only full unit tests (requires elevated shell):

```powershell
pwsh -File .\tests\Invoke-Tests.ps1 -Mode Unit
```

Or with custom verbosity:

```powershell
pwsh -File .\tests\Invoke-Tests.ps1 -Verbosity Normal
```

## Notes

- The unit suite is in `tests\pspkt.Unit.Tests.ps1`.
- `Precheck` tests are safe for non-admin CI agents.
- `Unit` tests are focused on command exports and stateful behavior that does not require live pktmon handles.
- Commands that require native pktmon session handles are intentionally not invoked in unit tests.
