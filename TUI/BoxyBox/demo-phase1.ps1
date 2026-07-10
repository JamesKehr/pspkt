# BoxyBox Phase 1 demo — renders a static box with sample packet lines to the console
# using the fixed-region renderer. Demonstrates left/right justification and truncation.
#
# Usage: pwsh -File .\TUI\BoxyBox\demo-phase1.ps1

Set-Location (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
Import-Module .\pspkt.psm1 -Force -ErrorAction Stop -WarningAction SilentlyContinue

# Force UTF-8 so box-drawing glyphs and arrows render.
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }

$width = 100
try {
    if ([Console]::WindowWidth -gt 0) { $width = [Math]::Min([Console]::WindowWidth, 100) }
} catch { $width = 100 }
$height = 12

$sampleLines = [System.Collections.Generic.List[string]]::new()
$sampleLines.Add('130:138[' + [char]0x2191 + [char]0x2192 + ']: Eth: IPv4.UDP 10.24.0.72.63485 > 51.5.2.65.53662: RDP')
$sampleLines.Add('...re.windows.net. CNAME gnet. gig-warm-prod-shared-eastus2.trafficmanager.net. A 20.98.192.20 (512)')
$sampleLines.Add('096:104[' + [char]0x2191 + [char]0x2192 + ']: Eth: IPv4.UDP: 10.24.0.72.50651 > 1.1.1.1.53: DNS')

# Left-justified box
$box = [BoxyBox.Box]::new($width, $height)
$box.Justification = [BoxyBox.Justify]::Left
$box.MenuOptions = [System.Collections.Generic.List[string]]@('(F)ocus', '(S)top', 'Save to (F)ile')

$rendered = $box.Render($sampleLines)

Write-Host "`n=== Left-justified (long lines truncated with trailing ellipsis) ===`n"
$rendered | ForEach-Object { Write-Host $_ }

# Right-justified box
$box.Justification = [BoxyBox.Justify]::Right
$rendered2 = $box.Render($sampleLines)
Write-Host "`n=== Right-justified (long lines truncated with leading ellipsis) ===`n"
$rendered2 | ForEach-Object { Write-Host $_ }

Write-Host "`nDemo complete."
