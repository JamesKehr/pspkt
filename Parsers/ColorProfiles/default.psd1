@{
    # Each layer has two variants: Bright (odd lines) and Muted (even lines).
    # Values are ANSI SGR parameters inserted between ESC[ and m.
    # Use 24-bit: "38;2;R;G;B" or standard: "36" (cyan), "33" (yellow), etc.

    Component = @{
        Bright = '38;2;255;140;90'    # bright coral
        Muted  = '38;2;180;100;65'    # muted coral
    }

    DataLink = @{
        Bright = '38;2;100;200;255'   # light blue
        Muted  = '38;2;70;140;180'    # muted blue
    }

    Network = @{
        Bright = '38;2;180;255;140'   # light green
        Muted  = '38;2;120;180;100'   # muted green
    }

    Transport = @{
        Bright = '38;2;255;200;100'   # light gold
        Muted  = '38;2;180;140;70'    # muted gold
    }

    Application = @{
        Bright = '38;2;220;160;255'   # light purple
        Muted  = '38;2;155;110;180'   # muted purple
    }

    Drop = @{
        Bright = '38;2;255;60;60'     # bright red
        Muted  = '38;2;180;40;40'     # muted red
    }

    # Reset sequence (appended at end of each line).
    Reset = '0'
}
