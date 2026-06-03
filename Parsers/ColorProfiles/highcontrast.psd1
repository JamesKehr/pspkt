@{
    # High-contrast color profile for pspkt real-time output.
    # Uses vivid, saturated colors for maximum readability on dark terminals.

    Component = @{
        Bright = '38;2;255;120;50'    # bright orange
        Muted  = '38;2;200;90;35'     # dimmed orange
    }

    DataLink = @{
        Bright = '38;2;0;255;255'     # cyan
        Muted  = '38;2;0;180;180'     # dimmed cyan
    }

    Network = @{
        Bright = '38;2;0;255;0'       # bright green
        Muted  = '38;2;0;180;0'       # dimmed green
    }

    Transport = @{
        Bright = '38;2;255;255;0'     # bright yellow
        Muted  = '38;2;200;200;0'     # dimmed yellow
    }

    Application = @{
        Bright = '38;2;255;100;255'   # bright magenta
        Muted  = '38;2;200;70;200'    # dimmed magenta
    }

    Drop = @{
        Bright = '38;2;255;0;0'       # pure red
        Muted  = '38;2;200;0;0'       # dimmed red
    }

    # Reset sequence (appended at end of each line).
    Reset = '0'
}
