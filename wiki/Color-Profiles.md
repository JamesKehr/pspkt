# Color Profiles

pspkt colors packet output by network layer. Each layer (Component, DataLink, Network, Transport, Application) has a **Bright** and **Muted** variant — adjacent packet lines alternate between them for readability. Colors are defined as ANSI SGR parameter strings (e.g. `38;2;100;200;255` for truecolor RGB or `94` for the 16-color "bright blue").

Profiles live as `.psd1` files in the module's `ColorProfiles\` directory. The active profile is recorded in `ColorProfiles\active.txt` and loaded on module import.

| Command | Purpose |
|---|---|
| [`Get-PspktParserColorProfile`](#get-pspktparsercolorprofile) | List installed profiles |
| [`Import-PspktParserColorProfile`](#import-pspktparsercolorprofile) | Activate a profile in memory (no persistence) |
| [`Set-PspktParserColorProfile`](#set-pspktparsercolorprofile) | Set the default profile (persists on disk) |
| [`New-PspktParserColorProfile`](#new-pspktparsercolorprofile) | Build a profile hashtable in memory |
| [`Test-PspktParserColorProfile`](#test-pspktparsercolorprofile) | Preview one or all profiles |
| [`Save-PspktParserColorProfile`](#save-pspktparsercolorprofile) | Persist a profile hashtable as a `.psd1` |

## Profile data shape

```powershell
@{
    Component   = @{ Bright = '95'; Muted = '38;5;134' }
    DataLink    = @{ Bright = '94'; Muted = '38;5;26'  }
    Network     = @{ Bright = '92'; Muted = '38;5;22'  }
    Transport   = @{ Bright = '93'; Muted = '38;5;94'  }
    Application = @{ Bright = '96'; Muted = '38;5;30'  }
    Reset       = '0'
}
```

`Bright`/`Muted` accept any valid ANSI SGR parameter string (semicolon-separated). The module emits `\x1b[<value>m` to apply.

---

## Get-PspktParserColorProfile

### Synopsis
Lists all available color profiles.

### Description
Returns the names of all `.psd1` files in the ColorProfiles directory. The active profile is indicated with an asterisk (`*`).

### Syntax
```powershell
Get-PspktParserColorProfile
```

### Output
`string[]` — profile names, one of which is marked active.

---

## Import-PspktParserColorProfile

### Synopsis
Imports (activates in memory) a color profile by name or path.

### Description
Activates a profile for the current session only. Use [`Set-PspktParserColorProfile`](#set-pspktparsercolorprofile) to persist as the default.

### Syntax
```powershell
Import-PspktParserColorProfile [-Name <string>]
Import-PspktParserColorProfile -Path <string>
```

### Parameters

| Parameter | Type | Set | Description |
|---|---|---|---|
| `-Name` | `string` | `ByName` (default) | Profile name (basename of a `.psd1` in ColorProfiles). Empty/omitted uses `active.txt` or `default`. |
| `-Path` | `string` | `ByPath` | Full path to a `.psd1` file (anywhere on disk). |

### Examples
```powershell
# Activate the 'high-contrast' profile in memory
Import-PspktParserColorProfile -Name 'high-contrast'

# Activate a custom profile from a path
Import-PspktParserColorProfile -Path C:\Profiles\MyTheme.psd1
```

---

## Set-PspktParserColorProfile

### Synopsis
Sets the default color profile used on module load.

### Description
Writes the profile name to `active.txt` and imports it into memory immediately.

### Syntax
```powershell
Set-PspktParserColorProfile -Name <string>
```

### Parameters

| Parameter | Type | Mandatory | Description |
|---|---|---|---|
| `-Name` | `string` | Yes | The profile name (must exist in `ColorProfiles\`). |

### Example
```powershell
Set-PspktParserColorProfile high-contrast
```

---

## New-PspktParserColorProfile

### Synopsis
Creates a new color profile hashtable in memory.

### Description
Returns a hashtable with all 10 ANSI SGR slots populated. Pipe to [`Save-PspktParserColorProfile`](#save-pspktparsercolorprofile) to persist.

### Syntax
```powershell
New-PspktParserColorProfile -ComponentBright <string> -ComponentMuted <string>
                            -DataLinkBright <string> -DataLinkMuted <string>
                            -NetworkBright <string> -NetworkMuted <string>
                            -TransportBright <string> -TransportMuted <string>
                            -ApplicationBright <string> -ApplicationMuted <string>
```

All parameters are **mandatory** ANSI SGR parameter strings.

### Output
`hashtable`

### Example
```powershell
$profile = New-PspktParserColorProfile `
    -ComponentBright '95'   -ComponentMuted '38;5;134' `
    -DataLinkBright  '94'   -DataLinkMuted  '38;5;26'  `
    -NetworkBright   '92'   -NetworkMuted   '38;5;22'  `
    -TransportBright '93'   -TransportMuted '38;5;94'  `
    -ApplicationBright '96' -ApplicationMuted '38;5;30'

Save-PspktParserColorProfile -Name 'mytheme' -Profile $profile
Set-PspktParserColorProfile mytheme
```

---

## Test-PspktParserColorProfile

### Synopsis
Displays sample output lines using a color profile to preview terminal appearance.

### Description
Prints sample lines (one Bright, one Muted) showing all layers. When no arguments are given, shows samples for every available profile.

### Syntax
```powershell
Test-PspktParserColorProfile [-Name <string>]
Test-PspktParserColorProfile -Profile <hashtable>
```

### Parameters

| Parameter | Type | Set | Description |
|---|---|---|---|
| `-Name` | `string` | `ByName` (default) | Profile name. Omit to preview all installed profiles side by side. |
| `-Profile` | `hashtable` | `ByHashtable` | Preview a profile hashtable without saving it. |

### Examples
```powershell
# Preview all profiles
Test-PspktParserColorProfile

# Preview one
Test-PspktParserColorProfile -Name 'high-contrast'

# Preview a custom hashtable
$p = New-PspktParserColorProfile -ComponentBright '95' ...
Test-PspktParserColorProfile -Profile $p
```

---

## Save-PspktParserColorProfile

### Synopsis
Saves a color profile hashtable to a `.psd1` file in the ColorProfiles directory.

### Description
Persists a profile hashtable (from [`New-PspktParserColorProfile`](#new-pspktparsercolorprofile)) as a named `.psd1` file. Use [`Set-PspktParserColorProfile`](#set-pspktparsercolorprofile) to make it the active default.

### Syntax
```powershell
Save-PspktParserColorProfile -Name <string> -Profile <hashtable> [-Force]
```

### Parameters

| Parameter | Type | Mandatory | Description |
|---|---|---|---|
| `-Name` | `string` | Yes (pos 0) | Profile name (becomes the filename without extension). |
| `-Profile` | `hashtable` | Yes (pos 1) | The color profile hashtable to save. |
| `-Force` | `switch` | No | Overwrite an existing profile with the same name. |

### Example
```powershell
Save-PspktParserColorProfile -Name 'mytheme' -Profile $profile -Force
```

## See also

- [Display](./Display.md) — detail level, spacing, timestamp
- [Start-Pspkt](./Start-Pspkt.md)
