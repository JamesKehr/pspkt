// BoxyBox — a project-independent text user interface (TUI) rendering engine.
//
// Phase 1: core render primitives.
//   * AnsiText       — visible-length + column-accurate helpers that ignore SGR escapes.
//   * TextJustify    — left/right justification and ellipsis truncation to a fixed width.
//   * BoxChars       — the box-drawing glyph set (single-line body, double-line menu bar).
//   * MenuBar        — composes a bottom border with embedded "══(H)otkey text══" items.
//   * Box            — composes a full bordered box (top border, content rows, menu bar)
//                      into an array of fixed-width lines.
//   * ScreenRegion   — emits a frame to a fixed console region using absolute cursor
//                      positioning so the console itself never scrolls.
//
// The engine intentionally has no dependency on pspkt types so it can be lifted out
// and reused by any project.

using System;
using System.Collections.Generic;
using System.Text;

namespace BoxyBox
{
    /// <summary>Text alignment within a fixed-width column.</summary>
    public enum Justify
    {
        Left,
        Right
    }

    /// <summary>
    /// Helpers for measuring and slicing text that may contain ANSI SGR (color) escape
    /// sequences. Visible length counts printable columns only — escape sequences occupy
    /// zero columns — so justification and truncation line up on screen.
    /// </summary>
    public static class AnsiText
    {
        private const char ESC = '\x1b';

        /// <summary>SGR reset sequence, appended after a truncated run to avoid color bleed.</summary>
        public const string Reset = "\x1b[0m";

        /// <summary>
        /// Returns true when the string contains at least one ANSI escape sequence.
        /// Lets callers skip the slower ANSI-aware path for plain text.
        /// </summary>
        public static bool ContainsAnsi(string text)
        {
            if (string.IsNullOrEmpty(text)) return false;
            return text.IndexOf(ESC) >= 0;
        }

        /// <summary>
        /// Number of visible columns in <paramref name="text"/>, ignoring CSI escape
        /// sequences (ESC '[' ... final-byte in 0x40-0x7E).
        /// </summary>
        public static int VisibleLength(string text)
        {
            if (string.IsNullOrEmpty(text)) return 0;
            int len = 0;
            int i = 0;
            int n = text.Length;
            while (i < n)
            {
                char c = text[i];
                if (c == ESC && i + 1 < n && text[i + 1] == '[')
                {
                    // Skip the CSI sequence: ESC [ ... <final byte 0x40-0x7E>
                    i += 2;
                    while (i < n)
                    {
                        char f = text[i];
                        i++;
                        if (f >= '\x40' && f <= '\x7e') break;
                    }
                    continue;
                }
                len++;
                i++;
            }
            return len;
        }

        /// <summary>
        /// Returns the first <paramref name="visibleCols"/> visible columns of the text,
        /// preserving every escape sequence encountered (so colors stay intact) and
        /// appending a reset when any escape sequence was emitted.
        /// </summary>
        public static string TakeVisiblePrefix(string text, int visibleCols)
        {
            if (string.IsNullOrEmpty(text) || visibleCols <= 0) return string.Empty;
            var sb = new StringBuilder(text.Length);
            int shown = 0;
            int i = 0;
            int n = text.Length;
            bool sawEscape = false;
            while (i < n && shown < visibleCols)
            {
                char c = text[i];
                if (c == ESC && i + 1 < n && text[i + 1] == '[')
                {
                    sawEscape = true;
                    int start = i;
                    i += 2;
                    while (i < n)
                    {
                        char f = text[i];
                        i++;
                        if (f >= '\x40' && f <= '\x7e') break;
                    }
                    sb.Append(text, start, i - start);
                    continue;
                }
                sb.Append(c);
                shown++;
                i++;
            }
            if (sawEscape) sb.Append(Reset);
            return sb.ToString();
        }

        /// <summary>
        /// Returns the last <paramref name="visibleCols"/> visible columns of the text.
        /// Escape sequences within the kept range are preserved; a reset is prepended so the
        /// kept suffix renders with default attributes (full color-state reconstruction is
        /// out of scope for Phase 1).
        /// </summary>
        public static string TakeVisibleSuffix(string text, int visibleCols)
        {
            if (string.IsNullOrEmpty(text) || visibleCols <= 0) return string.Empty;
            int total = VisibleLength(text);
            if (total <= visibleCols) return text;
            int skip = total - visibleCols;

            var sb = new StringBuilder(text.Length);
            int seen = 0;
            int i = 0;
            int n = text.Length;
            bool started = false;
            bool sawEscape = false;
            while (i < n)
            {
                char c = text[i];
                if (c == ESC && i + 1 < n && text[i + 1] == '[')
                {
                    int start = i;
                    i += 2;
                    while (i < n)
                    {
                        char f = text[i];
                        i++;
                        if (f >= '\x40' && f <= '\x7e') break;
                    }
                    if (started) sb.Append(text, start, i - start);
                    else sawEscape = true; // an escape occurred before the kept range
                    continue;
                }
                if (!started && seen >= skip)
                {
                    started = true;
                    if (sawEscape) sb.Append(Reset);
                }
                if (started) sb.Append(c);
                seen++;
                i++;
            }
            return sb.ToString();
        }
    }

    /// <summary>
    /// Fits text into a fixed column width by padding (when shorter) or truncating with an
    /// ellipsis (when longer). Left justification anchors text to the left and truncates the
    /// tail ("head..."); right justification anchors to the right and truncates the head
    /// ("...tail"). Width is measured in visible columns so embedded ANSI colors don't shift
    /// alignment.
    /// </summary>
    public static class TextJustify
    {
        /// <summary>Marker appended/prepended to indicate hidden text. Three dots per spec.</summary>
        public const string Ellipsis = "...";

        public static string Fit(string text, int width, Justify justify)
        {
            if (width <= 0) return string.Empty;
            if (text == null) text = string.Empty;

            bool ansi = AnsiText.ContainsAnsi(text);
            int visible = ansi ? AnsiText.VisibleLength(text) : text.Length;

            if (visible == width) return text;

            if (visible < width)
            {
                string pad = new string(' ', width - visible);
                return justify == Justify.Left ? text + pad : pad + text;
            }

            // Too long - truncate with ellipsis.
            int ellipsisLen = Ellipsis.Length;
            if (width <= ellipsisLen)
            {
                // No room for the ellipsis; hard-slice to width.
                if (justify == Justify.Left)
                    return ansi ? AnsiText.TakeVisiblePrefix(text, width) : text.Substring(0, width);
                return ansi ? AnsiText.TakeVisibleSuffix(text, width) : text.Substring(text.Length - width);
            }

            int keep = width - ellipsisLen;
            if (justify == Justify.Left)
            {
                string head = ansi ? AnsiText.TakeVisiblePrefix(text, keep) : text.Substring(0, keep);
                return head + Ellipsis;
            }
            else
            {
                string tail = ansi ? AnsiText.TakeVisibleSuffix(text, keep) : text.Substring(text.Length - keep);
                return Ellipsis + tail;
            }
        }
    }

    /// <summary>
    /// Box-drawing glyphs. Body uses single-line borders; the menu bar (bottom border with
    /// embedded options) uses double-line borders to visually separate content from actions,
    /// matching the sample drawings in the TUI spec.
    /// </summary>
    public static class BoxChars
    {
        public const char Horizontal  = '\u2500'; // horizontal single
        public const char Vertical    = '\u2502'; // vertical single
        public const char TopLeft     = '\u250c'; // top-left corner
        public const char TopRight    = '\u2510'; // top-right corner
        public const char BottomLeft  = '\u2514'; // bottom-left corner
        public const char BottomRight = '\u2518'; // bottom-right corner

        // Double-line variants used for the menu bar.
        public const char DblHorizontal   = '\u2550'; // horizontal double
        public const char MenuBottomLeft  = '\u2558'; // up-single/right-double bottom-left
        public const char MenuBottomRight = '\u255b'; // up-single/left-double bottom-right
        public const char MenuMidLeft     = '\u255e'; // vertical-single/right-double
        public const char MenuMidRight    = '\u2561'; // vertical-single/left-double
    }

    /// <summary>
    /// Renders a bottom-border menu bar with embedded options. Options are joined with the
    /// double-line rule and the bar is filled to the requested width. Two cap styles are
    /// supported: a terminal bar for the outer bottom border and a mid-bar used between the
    /// text region and the details region.
    /// </summary>
    public static class MenuBar
    {
        public enum Cap
        {
            Terminal, // outer bottom border
            Mid       // divider between two stacked boxes
        }

        /// <summary>
        /// Builds a menu bar line of exactly <paramref name="width"/> visible columns.
        /// Each option is prefixed by the double-line rule; options that would overflow are
        /// dropped from the right (caller supplies pre-ordered items, most important first).
        /// Width includes the two cap characters.
        /// </summary>
        public static string Build(IList<string> options, int width, Cap cap)
        {
            if (width < 2) return string.Empty;
            char left  = cap == Cap.Terminal ? BoxChars.MenuBottomLeft : BoxChars.MenuMidLeft;
            char right = cap == Cap.Terminal ? BoxChars.MenuBottomRight : BoxChars.MenuMidRight;

            int inner = width - 2; // columns available between the caps
            var sb = new StringBuilder(width);
            sb.Append(left);

            var content = new StringBuilder(inner);
            if (options != null)
            {
                for (int i = 0; i < options.Count; i++)
                {
                    string opt = options[i] ?? string.Empty;
                    string chunk = new string(BoxChars.DblHorizontal, 2) + opt;
                    if (AnsiText.VisibleLength(content.ToString()) + AnsiText.VisibleLength(chunk) > inner) break;
                    content.Append(chunk);
                }
            }

            string contentStr = content.ToString();
            sb.Append(contentStr);
            int fill = inner - AnsiText.VisibleLength(contentStr);
            if (fill > 0) sb.Append(new string(BoxChars.DblHorizontal, fill));
            sb.Append(right);
            return sb.ToString();
        }
    }

    /// <summary>
    /// Composes a bordered box: a top border, a fixed number of content rows (each justified
    /// and padded to the inner width), and a bottom menu bar. Output is an array of lines,
    /// each exactly <c>Width</c> visible columns wide, ready to hand to a
    /// <see cref="ScreenRegion"/> for positioning.
    /// </summary>
    public sealed class Box
    {
        public int Width { get; private set; }
        public int Height { get; private set; } // total rows including borders/menu

        /// <summary>Number of content rows (Height minus the top border and menu bar).</summary>
        public int ContentRows { get { return Height - 2; } }

        public Justify Justification { get; set; }
        public IList<string> MenuOptions { get; set; }
        public MenuBar.Cap MenuStyle { get; set; }

        public Box(int width, int height)
        {
            if (width < 2) width = 2;
            if (height < 2) height = 2;
            Width = width;
            Height = height;
            Justification = Justify.Left;
            MenuStyle = MenuBar.Cap.Terminal;
            MenuOptions = new List<string>();
        }

        /// <summary>Builds the top border line.</summary>
        private string TopBorder()
        {
            var sb = new StringBuilder(Width);
            sb.Append(BoxChars.TopLeft);
            sb.Append(new string(BoxChars.Horizontal, Width - 2));
            sb.Append(BoxChars.TopRight);
            return sb.ToString();
        }

        /// <summary>Builds a single content row with side borders.</summary>
        private string ContentLine(string text)
        {
            int inner = Width - 2;
            string body = TextJustify.Fit(text ?? string.Empty, inner, Justification);
            var sb = new StringBuilder(Width);
            sb.Append(BoxChars.Vertical);
            sb.Append(body);
            sb.Append(BoxChars.Vertical);
            return sb.ToString();
        }

        /// <summary>
        /// Renders the full box. <paramref name="lines"/> supplies content rows top-to-bottom;
        /// missing rows are rendered blank, extra rows are ignored.
        /// </summary>
        public string[] Render(IList<string> lines)
        {
            var result = new string[Height];
            result[0] = TopBorder();
            for (int r = 0; r < ContentRows; r++)
            {
                string text = (lines != null && r < lines.Count) ? lines[r] : string.Empty;
                result[r + 1] = ContentLine(text);
            }
            result[Height - 1] = MenuBar.Build(MenuOptions, Width, MenuStyle);
            return result;
        }
    }

    /// <summary>
    /// Emits a frame to a fixed rectangular console region using absolute cursor positioning,
    /// so writing never advances (scrolls) the console. Rows/columns are 1-based.
    /// The renderer does not write to the console itself — <see cref="BuildFrame"/> returns
    /// the full escape-sequence string so the caller controls output (and can unit-test it).
    /// </summary>
    public sealed class ScreenRegion
    {
        private const string CSI = "\x1b[";

        public int Top { get; private set; }
        public int Left { get; private set; }
        public int Width { get; private set; }
        public int Height { get; private set; }

        public ScreenRegion(int top, int left, int width, int height)
        {
            Top = top < 1 ? 1 : top;
            Left = left < 1 ? 1 : left;
            Width = width < 1 ? 1 : width;
            Height = height < 1 ? 1 : height;
        }

        /// <summary>
        /// Builds the escape-sequence string that positions the cursor at each row of the
        /// region, clears that row, and writes the corresponding line. Never emits a trailing
        /// newline, so the console does not scroll.
        /// </summary>
        public string BuildFrame(IList<string> lines)
        {
            var sb = new StringBuilder();
            for (int i = 0; i < Height; i++)
            {
                int row = Top + i;
                sb.Append(CSI).Append(row).Append(';').Append(Left).Append('H');
                sb.Append(CSI).Append("2K");
                if (lines != null && i < lines.Count && lines[i] != null)
                {
                    sb.Append(lines[i]);
                }
            }
            return sb.ToString();
        }

        public static string HideCursor() { return CSI + "?25l"; }
        public static string ShowCursor() { return CSI + "?25h"; }
        public static string ClearScreen() { return CSI + "2J" + CSI + "H"; }
    }
}
