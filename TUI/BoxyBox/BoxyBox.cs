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
        /// Applies a background-color SGR to <paramref name="text"/> while preserving its own
        /// foreground colors: the background is emitted first and re-emitted after every reset
        /// sequence in the text (which would otherwise clear it), then a final reset is added.
        /// Used to highlight a selected row without stripping the parsing colors.
        /// </summary>
        public static string ApplyBackground(string text, string bgSeq, string resetSeq)
        {
            if (string.IsNullOrEmpty(text)) return string.Empty;
            if (string.IsNullOrEmpty(bgSeq)) return text;
            if (string.IsNullOrEmpty(resetSeq)) resetSeq = Reset;
            string body = text.Replace(resetSeq, resetSeq + bgSeq);
            return bgSeq + body + resetSeq;
        }

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
        /// Removes all CSI escape sequences, returning the plain visible text. Used when a
        /// line must be re-colored wholesale (e.g. a selected/highlighted row) — inner reset
        /// sequences would otherwise punch holes in a background highlight.
        /// </summary>
        public static string StripAnsi(string text)
        {
            if (string.IsNullOrEmpty(text)) return text ?? string.Empty;
            if (text.IndexOf(ESC) < 0) return text;
            var sb = new StringBuilder(text.Length);
            int i = 0;
            int n = text.Length;
            while (i < n)
            {
                char c = text[i];
                if (c == ESC && i + 1 < n && text[i + 1] == '[')
                {
                    i += 2;
                    while (i < n)
                    {
                        char f = text[i];
                        i++;
                        if (f >= '\x40' && f <= '\x7e') break;
                    }
                    continue;
                }
                sb.Append(c);
                i++;
            }
            return sb.ToString();
        }

        // ---------------------------------------------------------------------------------
        // Character cell width (wcwidth-style). Terminal display widths are measured in cells,
        // not UTF-16 code units: a wide (East-Asian / emoji) glyph occupies 2 cells, a combining
        // mark or zero-width joiner occupies 0, and a surrogate pair is a single codepoint. The
        // measurement/clipping helpers below iterate by codepoint and sum CharWidth so box borders,
        // padding, and truncation stay aligned for non-ASCII content. Pure-ASCII text is unaffected
        // (every codepoint is width 1, no surrogates), so existing output is byte-identical.
        //
        // Zero-width interval table ported from Markus Kuhn's wcwidth() reference
        // (https://www.cl.cam.ac.uk/~mgk25/ucs/wcwidth.c), extended with modern combining blocks
        // and emoji ranges. Flattened, ascending, non-overlapping [lo,hi] pairs for binary search.
        //
        // Scope: measurement is codepoint-level (each codepoint 0/1/2 cells), NOT grapheme-cluster.
        // Emoji skin-tone modifiers are treated as zero-width so a modified emoji measures 2 cells,
        // but VS16 promotion (e.g. U+2764 U+FE0F), ZWJ emoji sequences, and regional-indicator flag
        // pairs are not composed and may over-measure. This is intentional: full grapheme width is
        // terminal-dependent and pspkt's own content is ASCII; the target is correct alignment for
        // CJK/wide text (e.g. a non-ASCII file path in a notification), which this handles exactly.
        private static readonly int[] ZeroWidthRanges =
        {
            0x0300,0x036F, 0x0483,0x0486, 0x0488,0x0489, 0x0591,0x05BD, 0x05BF,0x05BF,
            0x05C1,0x05C2, 0x05C4,0x05C5, 0x05C7,0x05C7, 0x0600,0x0603, 0x0610,0x0615,
            0x064B,0x065E, 0x0670,0x0670, 0x06D6,0x06E4, 0x06E7,0x06E8, 0x06EA,0x06ED,
            0x070F,0x070F, 0x0711,0x0711, 0x0730,0x074A, 0x07A6,0x07B0, 0x07EB,0x07F3,
            0x0901,0x0902, 0x093C,0x093C, 0x0941,0x0948, 0x094D,0x094D, 0x0951,0x0954,
            0x0962,0x0963, 0x0981,0x0981, 0x09BC,0x09BC, 0x09C1,0x09C4, 0x09CD,0x09CD,
            0x09E2,0x09E3, 0x0A01,0x0A02, 0x0A3C,0x0A3C, 0x0A41,0x0A42, 0x0A47,0x0A48,
            0x0A4B,0x0A4D, 0x0A70,0x0A71, 0x0A81,0x0A82, 0x0ABC,0x0ABC, 0x0AC1,0x0AC5,
            0x0AC7,0x0AC8, 0x0ACD,0x0ACD, 0x0AE2,0x0AE3, 0x0B01,0x0B01, 0x0B3C,0x0B3C,
            0x0B3F,0x0B3F, 0x0B41,0x0B43, 0x0B4D,0x0B4D, 0x0B56,0x0B56, 0x0B82,0x0B82,
            0x0BC0,0x0BC0, 0x0BCD,0x0BCD, 0x0C3E,0x0C40, 0x0C46,0x0C48, 0x0C4A,0x0C4D,
            0x0C55,0x0C56, 0x0CBC,0x0CBC, 0x0CBF,0x0CBF, 0x0CC6,0x0CC6, 0x0CCC,0x0CCD,
            0x0CE2,0x0CE3, 0x0D41,0x0D43, 0x0D4D,0x0D4D, 0x0DCA,0x0DCA, 0x0DD2,0x0DD4,
            0x0DD6,0x0DD6, 0x0E31,0x0E31, 0x0E34,0x0E3A, 0x0E47,0x0E4E, 0x0EB1,0x0EB1,
            0x0EB4,0x0EB9, 0x0EBB,0x0EBC, 0x0EC8,0x0ECD, 0x0F18,0x0F19, 0x0F35,0x0F35,
            0x0F37,0x0F37, 0x0F39,0x0F39, 0x0F71,0x0F7E, 0x0F80,0x0F84, 0x0F86,0x0F87,
            0x0F90,0x0F97, 0x0F99,0x0FBC, 0x0FC6,0x0FC6, 0x102D,0x1030, 0x1032,0x1032,
            0x1036,0x1037, 0x1039,0x1039, 0x1058,0x1059, 0x1160,0x11FF, 0x135F,0x135F,
            0x1712,0x1714, 0x1732,0x1734, 0x1752,0x1753, 0x1772,0x1773, 0x17B4,0x17B5,
            0x17B7,0x17BD, 0x17C6,0x17C6, 0x17C9,0x17D3, 0x17DD,0x17DD, 0x180B,0x180D,
            0x18A9,0x18A9, 0x1920,0x1922, 0x1927,0x1928, 0x1932,0x1932, 0x1939,0x193B,
            0x1A17,0x1A18, 0x1AB0,0x1AFF, 0x1B00,0x1B03, 0x1B34,0x1B34, 0x1B36,0x1B3A, 0x1B3C,0x1B3C,
            0x1B42,0x1B42, 0x1B6B,0x1B73, 0x1DC0,0x1DFF, 0x200B,0x200F,
            0x202A,0x202E, 0x2060,0x2063, 0x206A,0x206F, 0x20D0,0x20EF, 0x302A,0x302F,
            0x3099,0x309A, 0xA806,0xA806, 0xA80B,0xA80B, 0xA825,0xA826, 0xFB1E,0xFB1E,
            0xFE00,0xFE0F, 0xFE20,0xFE2F, 0xFEFF,0xFEFF, 0xFFF9,0xFFFB,
            0x10A01,0x10A03, 0x10A05,0x10A06, 0x10A0C,0x10A0F, 0x10A38,0x10A3A,
            0x10A3F,0x10A3F, 0x1D167,0x1D169, 0x1D173,0x1D182, 0x1D185,0x1D18B,
            0x1D1AA,0x1D1AD, 0x1D242,0x1D244, 0x1F3FB,0x1F3FF, 0xE0001,0xE0001,
            0xE0020,0xE007F, 0xE0100,0xE01EF
        };

        private static bool InRanges(int cp, int[] ranges)
        {
            int lo = 0;
            int hi = ranges.Length / 2 - 1;
            if (cp < ranges[0] || cp > ranges[hi * 2 + 1]) return false;
            while (lo <= hi)
            {
                int mid = (lo + hi) / 2;
                if (cp > ranges[mid * 2 + 1]) lo = mid + 1;
                else if (cp < ranges[mid * 2]) hi = mid - 1;
                else return true;
            }
            return false;
        }

        private static bool IsWide(int cp)
        {
            return cp >= 0x1100 && (
                cp <= 0x115F ||                              // Hangul Jamo leading consonants
                cp == 0x2329 || cp == 0x232A ||             // angle brackets
                (cp >= 0x2E80 && cp <= 0xA4CF && cp != 0x303F) || // CJK .. Yi
                (cp >= 0xAC00 && cp <= 0xD7A3) ||           // Hangul syllables
                (cp >= 0xF900 && cp <= 0xFAFF) ||           // CJK compatibility ideographs
                (cp >= 0xFE10 && cp <= 0xFE19) ||           // vertical forms
                (cp >= 0xFE30 && cp <= 0xFE6F) ||           // CJK compatibility forms
                (cp >= 0xFF00 && cp <= 0xFF60) ||           // fullwidth forms
                (cp >= 0xFFE0 && cp <= 0xFFE6) ||           // fullwidth signs
                (cp >= 0x1F000 && cp <= 0x1FAFF) ||         // emoji, tiles, playing cards
                (cp >= 0x20000 && cp <= 0x3FFFD));          // CJK extension planes
        }

        /// <summary>
        /// Terminal cell width of a Unicode codepoint: 0 for zero-width (combining marks, joiners,
        /// variation selectors), 2 for East-Asian Wide / Fullwidth and emoji, 1 otherwise. Control
        /// characters keep width 1 to preserve prior per-char counting (they should not appear in
        /// TUI text; matching the old behavior avoids output drift).
        /// </summary>
        public static int CharWidth(int codepoint)
        {
            if (codepoint == 0) return 0;
            if (codepoint < 32 || (codepoint >= 0x7F && codepoint < 0xA0)) return 1;
            if (codepoint < 0x0300) return 1; // fast path: Latin/ASCII/Latin-1, no combining/wide
            if (InRanges(codepoint, ZeroWidthRanges)) return 0;
            return IsWide(codepoint) ? 2 : 1;
        }

        /// <summary>
        /// Decodes the Unicode codepoint at <paramref name="i"/>, combining a surrogate pair into
        /// a single codepoint. Returns the number of UTF-16 units consumed (1 or 2).
        /// </summary>
        private static int NextCodepoint(string text, int i, int n, out int codepoint)
        {
            char c = text[i];
            if (char.IsHighSurrogate(c) && i + 1 < n && char.IsLowSurrogate(text[i + 1]))
            {
                codepoint = char.ConvertToUtf32(c, text[i + 1]);
                return 2;
            }
            codepoint = c;
            return 1;
        }

        /// <summary>
        /// Number of visible columns in <paramref name="text"/>, ignoring CSI escape
        /// sequences (ESC '[' ... final-byte in 0x40-0x7E) and measuring each codepoint by its
        /// terminal cell width (wide glyphs = 2, combining/zero-width = 0).
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
                int cp;
                int units = NextCodepoint(text, i, n, out cp);
                len += CharWidth(cp);
                i += units;
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
                int cp;
                int units = NextCodepoint(text, i, n, out cp);
                int w = CharWidth(cp);
                // A wide glyph that would straddle the boundary is dropped; the caller pads the
                // leftover cell so a surrogate pair is never split and the column count is exact.
                if (shown + w > visibleCols) break;
                sb.Append(text, i, units);
                shown += w;
                i += units;
            }
            // Keep any trailing zero-width marks (combining accents) attached to the last kept
            // base glyph rather than orphaning them past the clip. Stops at an escape or base char
            // so pure-ASCII (and colored) output stays byte-identical.
            while (i < n && text[i] != ESC)
            {
                int cp2;
                int units2 = NextCodepoint(text, i, n, out cp2);
                if (CharWidth(cp2) != 0) break;
                sb.Append(text, i, units2);
                i += units2;
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
                int cp;
                int units = NextCodepoint(text, i, n, out cp);
                if (started) sb.Append(text, i, units);
                seen += CharWidth(cp);
                i += units;
            }
            return sb.ToString();
        }

        /// <summary>
        /// Returns <paramref name="line"/> fitted to exactly <paramref name="width"/> visible
        /// columns: null/short lines are right-padded with spaces (a reset is inserted first when
        /// the line contains ANSI so the padding doesn't inherit a background), and over-long
        /// lines are clipped ANSI-aware. This is the single fitting used by both
        /// <see cref="ScreenRegion.BuildFrame"/> and <see cref="FrameBuffer.Diff"/> so an
        /// overwrite and a diff of the same content produce byte-identical rows.
        /// </summary>
        public static string FitToWidth(string line, int width)
        {
            if (width <= 0) return string.Empty;
            if (string.IsNullOrEmpty(line)) return new string(' ', width);
            int visible = VisibleLength(line);
            if (visible == width) return line;
            if (visible < width)
            {
                string pad = new string(' ', width - visible);
                return ContainsAnsi(line) ? (line + Reset + pad) : (line + pad);
            }
            // Over-long: clip to width columns. A wide glyph straddling the boundary leaves the
            // prefix one cell short, so pad the remainder to keep the row exactly width cells.
            string clipped = TakeVisiblePrefix(line, width);
            int clippedCols = VisibleLength(clipped);
            if (clippedCols < width) clipped += new string(' ', width - clippedCols);
            return clipped;
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

            int visible = AnsiText.VisibleLength(text);

            if (visible == width) return text;

            if (visible < width)
            {
                string pad = new string(' ', width - visible);
                return justify == Justify.Left ? text + pad : pad + text;
            }

            // Too long - truncate with ellipsis. The cell-aware helpers measure/slice by terminal
            // column (wide glyphs = 2 cells) and never split a surrogate pair. Each result is padded
            // to exactly `width` cells so a straddling wide glyph can never shift a following border.
            int ellipsisLen = Ellipsis.Length;
            if (width <= ellipsisLen)
            {
                // No room for the ellipsis; hard-slice to width columns.
                string sliced = justify == Justify.Left
                    ? AnsiText.TakeVisiblePrefix(text, width)
                    : AnsiText.TakeVisibleSuffix(text, width);
                return PadToWidth(sliced, width, justify);
            }

            int keep = width - ellipsisLen;
            if (justify == Justify.Left)
            {
                return PadToWidth(AnsiText.TakeVisiblePrefix(text, keep) + Ellipsis, width, justify);
            }
            else
            {
                return PadToWidth(Ellipsis + AnsiText.TakeVisibleSuffix(text, keep), width, justify);
            }
        }

        // Pads a truncated result out to exactly <paramref name="width"/> visible cells. Only a
        // wide glyph straddling the truncation boundary leaves a 1-cell gap; for pure-ASCII the
        // result already measures exactly width, so no padding is added (byte-identical).
        private static string PadToWidth(string text, int width, Justify justify)
        {
            int vis = AnsiText.VisibleLength(text);
            if (vis >= width) return text;
            string pad = new string(' ', width - vis);
            return justify == Justify.Left ? text + pad : pad + text;
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
            Terminal,       // outer bottom border, double line (live/collapsed bottom)
            Mid,            // divider between two stacked boxes, double line
            TerminalSingle  // outer bottom border, single line (expanded Details box bottom)
        }

        /// <summary>
        /// Builds a menu bar line of exactly <paramref name="width"/> visible columns.
        /// Each option is prefixed by the rule; options that would overflow are dropped from the
        /// right (caller supplies pre-ordered items, most important first). The rule and caps are
        /// double-line for <see cref="Cap.Terminal"/> / <see cref="Cap.Mid"/> and single-line for
        /// <see cref="Cap.TerminalSingle"/>. Width includes the two cap characters.
        /// </summary>
        public static string Build(IList<string> options, int width, Cap cap)
        {
            if (width < 2) return string.Empty;
            char left, right, rule;
            switch (cap)
            {
                case Cap.Mid:
                    left = BoxChars.MenuMidLeft; right = BoxChars.MenuMidRight; rule = BoxChars.DblHorizontal;
                    break;
                case Cap.TerminalSingle:
                    left = BoxChars.BottomLeft; right = BoxChars.BottomRight; rule = BoxChars.Horizontal;
                    break;
                default: // Cap.Terminal
                    left = BoxChars.MenuBottomLeft; right = BoxChars.MenuBottomRight; rule = BoxChars.DblHorizontal;
                    break;
            }

            int inner = width - 2; // columns available between the caps
            var sb = new StringBuilder(width);
            sb.Append(left);

            var content = new StringBuilder(inner);
            int contentVis = 0;
            if (options != null)
            {
                for (int i = 0; i < options.Count; i++)
                {
                    string opt = options[i] ?? string.Empty;
                    string chunk = new string(rule, 2) + opt;
                    int chunkVis = AnsiText.VisibleLength(chunk);
                    // Track accumulated visible width numerically instead of materializing
                    // content.ToString() (an O(n^2) allocation) on every option.
                    if (contentVis + chunkVis > inner) break;
                    content.Append(chunk);
                    contentVis += chunkVis;
                }
            }

            string contentStr = content.ToString();
            sb.Append(contentStr);
            int fill = inner - contentVis;
            if (fill > 0) sb.Append(new string(rule, fill));
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

        /// <summary>
        /// When false, the top border row is omitted so the box can sit flush beneath another
        /// box (the box above's menu bar becomes the shared divider). Default true.
        /// </summary>
        public bool ShowTopBorder { get; set; }

        /// <summary>Number of content rows (Height minus the menu bar and optional top border).</summary>
        public int ContentRows { get { return Height - (ShowTopBorder ? 2 : 1); } }

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
            ShowTopBorder = true;
        }

        /// <summary>
        /// Updates the box dimensions in place (e.g. when the console is resized). Other state
        /// (menu options/style, justification, top-border flag) is preserved.
        /// </summary>
        public void Resize(int width, int height)
        {
            if (width < 2) width = 2;
            if (height < 2) height = 2;
            Width = width;
            Height = height;
        }

        /// <summary>Builds the top border line (cached; rebuilt only when Width changes).</summary>
        private string _cachedTopBorder;
        private int _cachedTopBorderWidth = -1;
        private string TopBorder()
        {
            if (_cachedTopBorder != null && _cachedTopBorderWidth == Width) return _cachedTopBorder;
            var sb = new StringBuilder(Width);
            sb.Append(BoxChars.TopLeft);
            sb.Append(new string(BoxChars.Horizontal, Width - 2));
            sb.Append(BoxChars.TopRight);
            _cachedTopBorder = sb.ToString();
            _cachedTopBorderWidth = Width;
            return _cachedTopBorder;
        }

        /// <summary>
        /// Builds the bottom menu bar (cached; rebuilt only when Width, MenuStyle, or the
        /// MenuOptions reference changes — the options list is assigned wholesale, not mutated
        /// in place, so reference identity is a sufficient cache key).
        /// </summary>
        private string _cachedMenu;
        private IList<string> _cachedMenuOptions;
        private int _cachedMenuWidth = -1;
        private MenuBar.Cap _cachedMenuStyle;
        private string MenuRow()
        {
            if (_cachedMenu != null && ReferenceEquals(_cachedMenuOptions, MenuOptions) &&
                _cachedMenuWidth == Width && _cachedMenuStyle == MenuStyle)
            {
                return _cachedMenu;
            }
            _cachedMenu = MenuBar.Build(MenuOptions, Width, MenuStyle);
            _cachedMenuOptions = MenuOptions;
            _cachedMenuWidth = Width;
            _cachedMenuStyle = MenuStyle;
            return _cachedMenu;
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
        /// Builds a highlighted content row: the text is fitted to the inner width (preserving
        /// its own foreground colors), then a highlight background is applied across the whole
        /// row — re-emitted after every inner reset so the parsing colors show on a distinct
        /// selection background rather than being erased.
        /// </summary>
        private string HighlightedContentLine(string text, string highlightOn, string highlightOff)
        {
            int inner = Width - 2;
            string body = TextJustify.Fit(text ?? string.Empty, inner, Justification);
            string hl = AnsiText.ApplyBackground(body, highlightOn, highlightOff ?? AnsiText.Reset);
            var sb = new StringBuilder(Width + 32);
            sb.Append(BoxChars.Vertical);
            sb.Append(hl);
            sb.Append(BoxChars.Vertical);
            return sb.ToString();
        }

        /// <summary>
        /// Renders the full box. <paramref name="lines"/> supplies content rows top-to-bottom;
        /// missing rows are rendered blank, extra rows are ignored.
        /// </summary>
        public string[] Render(IList<string> lines)
        {
            return Render(lines, -1, null, null);
        }

        /// <summary>
        /// Renders the box, highlighting the content row at <paramref name="selectedRow"/>
        /// (0-based within the content area) with the supplied highlight sequences. Pass
        /// selectedRow &lt; 0 for no highlight. When <see cref="ShowTopBorder"/> is false the
        /// top border row is omitted (the box sits flush under another box).
        /// </summary>
        public string[] Render(IList<string> lines, int selectedRow, string highlightOn, string highlightOff)
        {
            var result = new string[Height];
            int row = 0;
            if (ShowTopBorder)
            {
                result[0] = TopBorder();
                row = 1;
            }
            for (int r = 0; r < ContentRows; r++)
            {
                string text = (lines != null && r < lines.Count) ? lines[r] : string.Empty;
                if (r == selectedRow && highlightOn != null)
                {
                    result[row + r] = HighlightedContentLine(text, highlightOn, highlightOff ?? AnsiText.Reset);
                }
                else
                {
                    result[row + r] = ContentLine(text);
                }
            }
            result[Height - 1] = MenuRow();
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
        /// region and writes the corresponding line, each fitted to exactly <see cref="Width"/>
        /// visible columns so it overwrites the previous frame's row in place. It deliberately
        /// does NOT erase the row first (no <c>CSI 2K</c>): erasing the whole physical line
        /// blanks the cells — including box-border cells and, for a region narrower than the
        /// terminal, the cells of any box underneath — for the instant before the content is
        /// rewritten, which the terminal's render thread can present as flicker. Overwriting a
        /// fixed-width line has no such blank gap and never touches cells outside the region.
        /// Never emits a trailing newline, so the console does not scroll.
        /// </summary>
        public string BuildFrame(IList<string> lines)
        {
            var sb = new StringBuilder(Height * (Width + 16));
            for (int i = 0; i < Height; i++)
            {
                int row = Top + i;
                sb.Append(CSI).Append(row).Append(';').Append(Left).Append('H');
                string line = (lines != null && i < lines.Count) ? lines[i] : null;
                AppendFitted(sb, line);
            }
            return sb.ToString();
        }

        /// <summary>
        /// Appends <paramref name="line"/> to <paramref name="sb"/> fitted to exactly
        /// <see cref="Width"/> visible columns (see <see cref="AnsiText.FitToWidth"/>), in place
        /// of a <c>CSI 2K</c> erase. Shares the fitting with <see cref="FrameBuffer.Diff"/> so an
        /// overwrite and a diff of the same content are byte-identical.
        /// Width is measured in UTF-16 units — the same single-cell assumption the whole engine
        /// uses (see <see cref="TextJustify.Fit"/>); wide (CJK/emoji) or combining characters are
        /// not cell-accurate. pspkt's rendered content is ASCII, so this is not hit in practice.
        /// </summary>
        private void AppendFitted(StringBuilder sb, string line)
        {
            sb.Append(AnsiText.FitToWidth(line, Width));
        }

        public static string HideCursor() { return CSI + "?25l"; }
        public static string ShowCursor() { return CSI + "?25h"; }
        public static string ClearScreen() { return CSI + "2J" + CSI + "H"; }

        /// <summary>
        /// DEC private mode 2026 "synchronized output" begin/end. Wrapping a full frame in
        /// <c>BeginSyncOutput()</c> ... <c>EndSyncOutput()</c> tells a supporting terminal
        /// (e.g. Windows Terminal) to buffer every cell update and present the whole frame
        /// atomically, so no partially-drawn (torn) frame is ever shown. Terminals that don't
        /// support it ignore the unknown private mode and render normally. The pair MUST be
        /// emitted around a single self-contained frame write and MUST NOT straddle a blocking
        /// read (e.g. Console.ReadLine) or a sleep, or the terminal stays frozen.
        /// </summary>
        public static string BeginSyncOutput() { return CSI + "?2026h"; }
        public static string EndSyncOutput() { return CSI + "?2026l"; }
    }

    /// <summary>
    /// A row-diffing companion to <see cref="ScreenRegion"/>: it remembers the fitted content
    /// last emitted for each row of a fixed rectangular region and, on the next frame, emits a
    /// cursor-move + content ONLY for the rows whose content actually changed. Static rows (box
    /// borders, menu bars, unchanged text) are therefore not re-sent every frame, which both cuts
    /// the bytes written and — because a row that isn't re-sent can't blank — removes redundant
    /// work on the hot repaint path.
    ///
    /// Ownership rule for overlapping content: the caller draws overlays (notifications, prompts,
    /// the warning panel, transition animations) ON TOP of the diffed base frame and MUST call
    /// <see cref="InvalidateRows"/> for the rows an overlay covered (or <see cref="Invalidate"/>
    /// after a full-screen clear), so the next base frame re-emits those rows and reclaims them.
    /// Without that, the diff would see the base content unchanged and skip the row, leaving the
    /// overlay on screen.
    /// </summary>
    public sealed class FrameBuffer
    {
        private const string CSI = "\x1b[";

        public int Top { get; private set; }
        public int Left { get; private set; }
        public int Width { get; private set; }
        public int Height { get; private set; }

        // Fitted content last emitted for each row (index 0 = Top). null means "unknown" — the
        // next Diff re-emits the row unconditionally.
        private readonly string[] _prev;

        public FrameBuffer(int top, int left, int width, int height)
        {
            Top = top < 1 ? 1 : top;
            Left = left < 1 ? 1 : left;
            Width = width < 1 ? 1 : width;
            Height = height < 1 ? 1 : height;
            _prev = new string[Height];
        }

        /// <summary>
        /// Emits cursor-move + fitted content for each row whose fitted content differs from the
        /// last <see cref="Diff"/> (or that was invalidated). Returns the escape-sequence string
        /// (empty when nothing changed). <paramref name="lines"/> supplies the desired rows
        /// top-to-bottom; missing/null rows become blank (a full-width run of spaces).
        /// </summary>
        public string Diff(IList<string> lines)
        {
            StringBuilder sb = null;
            for (int i = 0; i < Height; i++)
            {
                string src = (lines != null && i < lines.Count) ? lines[i] : null;
                string fitted = AnsiText.FitToWidth(src, Width);
                if (!string.Equals(fitted, _prev[i], StringComparison.Ordinal))
                {
                    if (sb == null) sb = new StringBuilder(Height * (Width + 16));
                    sb.Append(CSI).Append(Top + i).Append(';').Append(Left).Append('H').Append(fitted);
                    _prev[i] = fitted;
                }
            }
            return sb == null ? string.Empty : sb.ToString();
        }

        /// <summary>Forces the next <see cref="Diff"/> to re-emit every row (e.g. after a full-screen clear).</summary>
        public void Invalidate()
        {
            for (int i = 0; i < Height; i++) _prev[i] = null;
        }

        /// <summary>
        /// Forces the next <see cref="Diff"/> to re-emit the rows in the absolute row range
        /// [<paramref name="absoluteTop"/>, absoluteTop + <paramref name="count"/>) that fall
        /// within this region (e.g. the rows an overlay just drew over). Out-of-range rows are
        /// ignored.
        /// </summary>
        public void InvalidateRows(int absoluteTop, int count)
        {
            for (int r = absoluteTop; r < absoluteTop + count; r++)
            {
                int i = r - Top;
                if (i >= 0 && i < Height) _prev[i] = null;
            }
        }
    }

    /// <summary>
    /// A scrolling text box: a bounded buffer of recent lines rendered inside a
    /// <see cref="Box"/>. In live mode it shows the most recent <c>ContentRows</c> lines
    /// (packets scroll upward as new lines arrive). The buffer is bounded — once it exceeds
    /// capacity plus a slack margin, the oldest lines are trimmed in a single batch so
    /// appends stay amortized O(1).
    ///
    /// Every appended line gets a monotonically increasing absolute sequence number that
    /// never resets even as old lines are trimmed. Focus mode addresses lines by sequence
    /// number so a selection stays pinned to the same packet while ingestion continues to
    /// append (and possibly trim) in the background.
    /// </summary>
    public sealed class TextBox
    {
        private readonly List<string> _lines = new List<string>();
        private readonly int _capacity;
        private readonly int _trimSlack;
        private readonly Box _box;
        // Sequence number of _lines[0]. Increases when the front is trimmed.
        private long _baseSeq = 0;

        public TextBox(int width, int height, int capacity)
        {
            _box = new Box(width, height);
            _capacity = capacity < 16 ? 16 : capacity;
            _trimSlack = Math.Max(64, _capacity / 8);
        }

        public Box Box { get { return _box; } }

        /// <summary>Absolute sequence number of the oldest retained line.</summary>
        public long BaseSeq { get { return _baseSeq; } }

        /// <summary>Exclusive upper bound: the sequence number the next appended line will get.</summary>
        public long TotalSeq { get { return _baseSeq + _lines.Count; } }

        public Justify Justification
        {
            get { return _box.Justification; }
            set { _box.Justification = value; }
        }

        public IList<string> MenuOptions
        {
            get { return _box.MenuOptions; }
            set { _box.MenuOptions = value; }
        }

        public MenuBar.Cap MenuStyle
        {
            get { return _box.MenuStyle; }
            set { _box.MenuStyle = value; }
        }

        /// <summary>Total lines currently retained (post-trim).</summary>
        public int LineCount { get { return _lines.Count; } }

        /// <summary>Number of visible content rows.</summary>
        public int ContentRows { get { return _box.ContentRows; } }

        /// <summary>Bounded capacity (retained line count target).</summary>
        public int Capacity { get { return _capacity; } }

        /// <summary>Returns the line at an absolute index, or null if out of range.</summary>
        public string GetLine(int index)
        {
            if (index < 0 || index >= _lines.Count) return null;
            return _lines[index];
        }

        /// <summary>Appends a single line, trimming the oldest lines when over capacity.</summary>
        public void Append(string line)
        {
            _lines.Add(line ?? string.Empty);
            TrimIfNeeded();
        }

        /// <summary>Appends a batch of lines, trimming once at the end.</summary>
        public void AppendRange(IList<string> lines)
        {
            if (lines == null) return;
            for (int i = 0; i < lines.Count; i++)
            {
                _lines.Add(lines[i] ?? string.Empty);
            }
            TrimIfNeeded();
        }

        private void TrimIfNeeded()
        {
            if (_lines.Count > _capacity + _trimSlack)
            {
                int removed = _lines.Count - _capacity;
                _lines.RemoveRange(0, removed);
                _baseSeq += removed;
            }
        }

        /// <summary>Clears all buffered lines (sequence numbering continues).</summary>
        public void Clear()
        {
            _baseSeq += _lines.Count;
            _lines.Clear();
        }

        /// <summary>Returns the line for an absolute sequence number, or null if not retained.</summary>
        public string GetLineBySeq(long seq)
        {
            long idx = seq - _baseSeq;
            if (idx < 0 || idx >= _lines.Count) return null;
            return _lines[(int)idx];
        }

        /// <summary>
        /// Clamps a sequence number into the retained range [BaseSeq, TotalSeq-1]. Returns
        /// BaseSeq when the buffer is empty.
        /// </summary>
        public long ClampSeq(long seq)
        {
            if (_lines.Count == 0) return _baseSeq;
            long lo = _baseSeq;
            long hi = _baseSeq + _lines.Count - 1;
            if (seq < lo) return lo;
            if (seq > hi) return hi;
            return seq;
        }

        /// <summary>
        /// Returns <paramref name="rows"/> visible line strings starting at absolute sequence
        /// <paramref name="topSeq"/> (blank-padded where out of range). Lets a caller render
        /// the buffer into a box it sizes itself (e.g. a shorter box while the Details box is
        /// open), independent of this TextBox's own Box height.
        /// </summary>
        public List<string> GetWindow(long topSeq, int rows)
        {
            var window = new List<string>(rows);
            for (int i = 0; i < rows; i++)
            {
                string line = GetLineBySeq(topSeq + i);
                window.Add(line ?? string.Empty);
            }
            return window;
        }

        /// <summary>
        /// Returns the live-tail window (the most recent <paramref name="rows"/> lines, newest
        /// anchored at the bottom, top blank-padded), for rendering into an arbitrary box.
        /// </summary>
        public List<string> GetTailWindow(int rows)
        {
            var window = new List<string>(rows);
            int start = _lines.Count - rows;
            if (start < 0) start = 0;
            int pad = rows - (_lines.Count - start);
            for (int p = 0; p < pad; p++) window.Add(string.Empty);
            for (int i = start; i < _lines.Count; i++) window.Add(_lines[i]);
            return window;
        }

        /// <summary>
        /// Renders the live tail: the most recent <c>ContentRows</c> lines, top-aligned so
        /// the newest line sits at the bottom of the content area.
        /// </summary>
        public string[] RenderTail()
        {
            int rows = _box.ContentRows;
            var window = new List<string>(rows);
            int start = _lines.Count - rows;
            if (start < 0) start = 0;
            // Pad the top so the newest line anchors to the bottom row when fewer than
            // ContentRows lines are available.
            int pad = rows - (_lines.Count - start);
            for (int p = 0; p < pad; p++) window.Add(string.Empty);
            for (int i = start; i < _lines.Count; i++) window.Add(_lines[i]);
            return _box.Render(window);
        }

        /// <summary>
        /// Renders a window anchored so the line at <paramref name="topIndex"/> is the first
        /// visible content row. Out-of-range indices are clamped.
        /// </summary>
        public string[] RenderFrom(int topIndex)
        {
            int rows = _box.ContentRows;
            if (topIndex < 0) topIndex = 0;
            if (topIndex > _lines.Count - 1) topIndex = Math.Max(0, _lines.Count - 1);
            var window = new List<string>(rows);
            for (int i = 0; i < rows; i++)
            {
                int idx = topIndex + i;
                window.Add(idx < _lines.Count ? _lines[idx] : string.Empty);
            }
            return _box.Render(window);
        }

        /// <summary>
        /// Focus-mode render: shows <c>ContentRows</c> lines starting at absolute sequence
        /// <paramref name="topSeq"/>, highlighting the line at <paramref name="selectedSeq"/>
        /// with the supplied highlight sequences. Sequence numbers outside the retained range
        /// render as blank rows; the highlight is applied only when the selected line is
        /// currently visible and retained.
        /// </summary>
        public string[] RenderWindow(long topSeq, long selectedSeq, string highlightOn, string highlightOff)
        {
            int rows = _box.ContentRows;
            var window = new List<string>(rows);
            for (int i = 0; i < rows; i++)
            {
                long seq = topSeq + i;
                string line = GetLineBySeq(seq);
                window.Add(line ?? string.Empty);
            }
            int selectedRow = -1;
            long rel = selectedSeq - topSeq;
            if (rel >= 0 && rel < rows && GetLineBySeq(selectedSeq) != null)
            {
                selectedRow = (int)rel;
            }
            return _box.Render(window, selectedRow, highlightOn, highlightOff);
        }
    }

    /// <summary>
    /// A node in a Wireshark-style detail tree. Leaf nodes are single fields; parent nodes
    /// group children under a header (protocol name) that can be expanded or collapsed.
    /// An optional <see cref="Key"/> lets a <see cref="DetailsBox"/> persist expand/collapse
    /// state across packets (e.g. keep IPv4 expanded and Eth collapsed as you step through).
    /// </summary>
    public sealed class TreeNode
    {
        public string Text;
        public List<TreeNode> Children;
        public bool IsExpanded;
        /// <summary>Stable key for expand-state persistence (usually the protocol name).</summary>
        public string Key;

        public TreeNode(string text)
        {
            Text = text ?? string.Empty;
            Children = new List<TreeNode>();
            IsExpanded = true;
        }

        public TreeNode(string text, string key, bool expanded)
        {
            Text = text ?? string.Empty;
            Children = new List<TreeNode>();
            Key = key;
            IsExpanded = expanded;
        }

        public bool HasChildren { get { return Children != null && Children.Count > 0; } }

        /// <summary>Adds a child node and returns it (for chaining).</summary>
        public TreeNode Add(TreeNode child)
        {
            if (child != null) Children.Add(child);
            return child;
        }

        /// <summary>Adds a leaf child with the given text and returns this node.</summary>
        public TreeNode AddLeaf(string text)
        {
            Children.Add(new TreeNode(text));
            return this;
        }
    }

    /// <summary>
    /// A visible row produced by flattening a tree: the display string (with glyphs) plus a
    /// reference to the originating node so the caller can expand/collapse by row.
    /// </summary>
    public sealed class TreeRow
    {
        public string Display;
        public TreeNode Node;
        public int Depth;

        public TreeRow(string display, TreeNode node, int depth)
        {
            Display = display;
            Node = node;
            Depth = depth;
        }
    }

    /// <summary>
    /// Flattens a tree into visible rows honoring each node's expanded state. Expandable nodes
    /// show '+' (collapsed) or '-' (expanded). Leaf indentation depends on <see cref="UseConnectors"/>:
    /// by default leaves use a plain two-space indent (no tree connectors); when connectors are
    /// enabled, leaf nodes below the top level show '├' (mid-sibling) / '└' (last sibling)
    /// glyphs. Indent is two spaces per depth level plus a two-space left margin.
    /// </summary>
    public static class TreeFlattener
    {
        public const char MidChild  = '\u251c'; // ├
        public const char LastChild = '\u2514'; // └

        /// <summary>
        /// When true, leaf rows below the top level are drawn with '├'/'└' tree connectors.
        /// Default false: leaves use a plain two-space indent instead. Kept as a toggle so the
        /// connector rendering can be re-enabled without restoring the removed code.
        /// </summary>
        public static bool UseConnectors = false;

        public static List<TreeRow> Flatten(IList<TreeNode> roots)
        {
            return FlattenInternal(roots, false);
        }

        /// <summary>
        /// Flattens the full tree ignoring each node's collapse state, so every node and child
        /// is included. Used by the copy action to capture the complete parsed detail regardless
        /// of what is scrolled into view or collapsed.
        /// </summary>
        public static List<TreeRow> FlattenAll(IList<TreeNode> roots)
        {
            return FlattenInternal(roots, true);
        }

        private static List<TreeRow> FlattenInternal(IList<TreeNode> roots, bool forceExpanded)
        {
            var rows = new List<TreeRow>();
            if (roots == null) return rows;
            for (int i = 0; i < roots.Count; i++)
            {
                FlattenNode(roots[i], 0, i == roots.Count - 1, rows, forceExpanded);
            }
            return rows;
        }

        private static void FlattenNode(TreeNode node, int depth, bool isLast, List<TreeRow> rows, bool forceExpanded)
        {
            if (node == null) return;
            bool expanded = forceExpanded || node.IsExpanded;
            string indent = new string(' ', 2 * (depth + 1));
            string line;
            if (node.HasChildren)
            {
                line = indent + (expanded ? "-" : "+") + node.Text;
            }
            else if (UseConnectors && depth > 0)
            {
                // Connector mode (opt-in): '├' for a mid sibling, '└' for the last sibling.
                char connector = isLast ? LastChild : MidChild;
                line = indent + connector + " " + node.Text;
            }
            else
            {
                // Default: no connectors. Reserve exactly one column (a space) for the absent
                // +/- marker so a leaf's text aligns with sibling expandable nodes' text — the
                // marker (or its blank slot) sits immediately left of the first text character.
                line = indent + " " + node.Text;
            }
            rows.Add(new TreeRow(line, node, depth));

            if (node.HasChildren && expanded)
            {
                for (int i = 0; i < node.Children.Count; i++)
                {
                    FlattenNode(node.Children[i], depth + 1, i == node.Children.Count - 1, rows, forceExpanded);
                }
            }
        }
    }

    /// <summary>
    /// A box that renders a detail tree with selection, scrolling, and expand/collapse. The
    /// tree is supplied as a list of top-level nodes (Component, Eth, IPv4, …). Expand/collapse
    /// state is persisted by node <see cref="TreeNode.Key"/> so stepping between packets keeps
    /// the same protocols open/closed.
    /// </summary>
    public sealed class DetailsBox
    {
        private readonly Box _box;
        private List<TreeNode> _roots = new List<TreeNode>();
        private List<TreeRow> _rows = new List<TreeRow>();
        private int _selected = 0;   // index into _rows
        private int _top = 0;        // first visible row index
        // Expand-state persistence keyed by TreeNode.Key.
        private readonly Dictionary<string, bool> _expandState = new Dictionary<string, bool>();

        public DetailsBox(int width, int height)
            : this(width, height, true)
        {
        }

        /// <summary>
        /// Creates a Details box. When <paramref name="showTopBorder"/> is false the box omits
        /// its own top border so it can sit flush beneath the Text box (whose menu bar becomes
        /// the shared divider).
        /// </summary>
        public DetailsBox(int width, int height, bool showTopBorder)
        {
            _box = new Box(width, height);
            _box.ShowTopBorder = showTopBorder;
            // Single-line bottom border: the Details box's bottom is the outer edge of the
            // screen while expanded, and the double-line style is reserved for the Text/Details
            // divider and the live (collapsed) bottom border.
            _box.MenuStyle = MenuBar.Cap.TerminalSingle;
            _box.MenuOptions = new List<string>();
        }

        public Box Box { get { return _box; } }
        public int ContentRows { get { return _box.ContentRows; } }
        public int RowCount { get { return _rows.Count; } }
        public int SelectedIndex { get { return _selected; } }

        public IList<string> MenuOptions
        {
            get { return _box.MenuOptions; }
            set { _box.MenuOptions = value; }
        }

        /// <summary>
        /// Resizes the underlying box in place (e.g. on a console resize), preserving the loaded
        /// tree, expand/collapse state, and selection, then re-clamps the scroll offset so the
        /// selected row stays visible within the new height.
        /// </summary>
        public void Resize(int width, int height)
        {
            _box.Resize(width, height);
            EnsureVisible();
        }

        /// <summary>
        /// Loads a new packet's detail tree. Applies persisted expand/collapse state (by Key)
        /// so protocols the user opened/closed stay that way across packets, then resets the
        /// selection to the top and rebuilds the visible rows.
        /// </summary>
        public void SetTree(IList<TreeNode> roots)
        {
            _roots = new List<TreeNode>();
            if (roots != null)
            {
                for (int i = 0; i < roots.Count; i++) _roots.Add(roots[i]);
            }
            ApplyPersistedState(_roots);
            _selected = 0;
            _top = 0;
            Rebuild();
        }

        private void ApplyPersistedState(IList<TreeNode> nodes)
        {
            if (nodes == null) return;
            for (int i = 0; i < nodes.Count; i++)
            {
                TreeNode n = nodes[i];
                if (n == null) continue;
                if (!string.IsNullOrEmpty(n.Key))
                {
                    bool state;
                    if (_expandState.TryGetValue(n.Key, out state)) n.IsExpanded = state;
                }
                ApplyPersistedState(n.Children);
            }
        }

        private void Rebuild()
        {
            _rows = TreeFlattener.Flatten(_roots);
            if (_selected >= _rows.Count) _selected = Math.Max(0, _rows.Count - 1);
            EnsureVisible();
        }

        private void EnsureVisible()
        {
            int rows = ContentRows;
            if (_selected < _top) _top = _selected;
            else if (_selected > _top + rows - 1) _top = _selected - rows + 1;
            int maxTop = Math.Max(0, _rows.Count - rows);
            if (_top > maxTop) _top = maxTop;
            if (_top < 0) _top = 0;
        }

        public void MoveUp()   { if (_selected > 0) { _selected--; EnsureVisible(); } }
        public void MoveDown() { if (_selected < _rows.Count - 1) { _selected++; EnsureVisible(); } }
        public void PageUp()   { _selected = Math.Max(0, _selected - ContentRows); EnsureVisible(); }
        public void PageDown() { _selected = Math.Min(_rows.Count - 1, _selected + ContentRows); EnsureVisible(); }

        private TreeNode SelectedNode()
        {
            if (_selected < 0 || _selected >= _rows.Count) return null;
            return _rows[_selected].Node;
        }

        private void Persist(TreeNode node)
        {
            if (node != null && !string.IsNullOrEmpty(node.Key))
                _expandState[node.Key] = node.IsExpanded;
        }

        /// <summary>Expands the selected node (if it has children). No-op on leaves.</summary>
        public void ExpandSelected()
        {
            TreeNode n = SelectedNode();
            if (n != null && n.HasChildren && !n.IsExpanded)
            {
                n.IsExpanded = true;
                Persist(n);
                Rebuild();
            }
        }

        /// <summary>
        /// Collapses the selected node. When the selected node is a leaf or already collapsed,
        /// collapses its parent instead (Wireshark behavior) and moves selection to the parent.
        /// </summary>
        public void CollapseSelected()
        {
            TreeNode n = SelectedNode();
            if (n == null) return;
            if (n.HasChildren && n.IsExpanded)
            {
                n.IsExpanded = false;
                Persist(n);
                Rebuild();
            }
            else
            {
                // Move to and collapse the parent, if any.
                int depth = _rows[_selected].Depth;
                if (depth > 0)
                {
                    for (int i = _selected - 1; i >= 0; i--)
                    {
                        if (_rows[i].Depth < depth)
                        {
                            _selected = i;
                            TreeNode p = _rows[i].Node;
                            if (p.HasChildren && p.IsExpanded)
                            {
                                p.IsExpanded = false;
                                Persist(p);
                            }
                            Rebuild();
                            break;
                        }
                    }
                }
            }
        }

        private void SetAllExpanded(IList<TreeNode> nodes, bool expanded)
        {
            if (nodes == null) return;
            for (int i = 0; i < nodes.Count; i++)
            {
                TreeNode n = nodes[i];
                if (n == null) continue;
                if (n.HasChildren)
                {
                    n.IsExpanded = expanded;
                    Persist(n);
                }
                SetAllExpanded(n.Children, expanded);
            }
        }

        public void ExpandAll()   { SetAllExpanded(_roots, true);  Rebuild(); }
        public void CollapseAll() { SetAllExpanded(_roots, false); Rebuild(); }

        /// <summary>Renders the tree into the box, highlighting the selected row.</summary>
        public string[] Render(string highlightOn, string highlightOff)
        {
            int rows = ContentRows;
            var window = new List<string>(rows);
            for (int i = 0; i < rows; i++)
            {
                int idx = _top + i;
                window.Add(idx < _rows.Count ? _rows[idx].Display : string.Empty);
            }
            int selectedRow = _selected - _top;
            if (selectedRow < 0 || selectedRow >= rows) selectedRow = -1;
            return _box.Render(window, selectedRow, highlightOn, highlightOff);
        }

        /// <summary>
        /// Returns the plain-text (ANSI-stripped) content of all currently visible rows —
        /// used by the Shift+Ctrl+C copy action to capture what the user sees in the box.
        /// </summary>
        public List<string> GetVisibleText()
        {
            int rows = ContentRows;
            var lines = new List<string>(rows);
            for (int i = 0; i < rows; i++)
            {
                int idx = _top + i;
                if (idx < _rows.Count) lines.Add(AnsiText.StripAnsi(_rows[idx].Display));
            }
            return lines;
        }

        /// <summary>
        /// Returns the plain-text (ANSI-stripped) content of the entire detail tree — every
        /// node and child, fully expanded — regardless of scroll position or collapse state.
        /// Used by the Shift+Ctrl+C copy action so the clipboard captures all parsed details,
        /// not just the rows currently in the viewport.
        /// </summary>
        public List<string> GetAllText()
        {
            var all = TreeFlattener.FlattenAll(_roots);
            var lines = new List<string>(all.Count);
            for (int i = 0; i < all.Count; i++) lines.Add(AnsiText.StripAnsi(all[i].Display));
            return lines;
        }
    }

    /// <summary>A single menu entry. Rendered as "[Hotkey]DisplayName" (Full) or "[Hotkey]" (Simple).</summary>
    public sealed class MenuItem
    {
        public string Name;        // logical id (matched by the loop's key handler)
        public string DisplayName; // shown text (may include a leading space)
        public string Hotkey;      // key label shown in brackets

        public MenuItem() { }
        public MenuItem(string name, string displayName, string hotkey)
        {
            Name = name; DisplayName = displayName; Hotkey = hotkey;
        }
    }

    /// <summary>A named menu (one per box), loadable/exportable as JSON for customization.</summary>
    public sealed class MenuDefinition
    {
        public string Box;
        public List<MenuItem> Menu;

        public MenuDefinition() { Menu = new List<MenuItem>(); }
        public MenuDefinition(string box) { Box = box; Menu = new List<MenuItem>(); }

        public MenuDefinition AddItem(string name, string displayName, string hotkey)
        {
            Menu.Add(new MenuItem(name, displayName, hotkey));
            return this;
        }
    }

    /// <summary>
    /// Renders menu definitions into the option strings a <see cref="MenuBar"/> consumes.
    /// Full mode shows "[Hotkey]DisplayName"; Simple mode (used when Full won't fit the bar)
    /// shows just "[Hotkey]". <see cref="FullFits"/> decides which mode a given width allows.
    /// </summary>
    public static class MenuRenderer
    {
        // High-contrast SGR colors so menu items stand out against the box border/rule.
        // Hotkey (in brackets) is emphasized; the label is bright but slightly softer.
        // Overridable via SetColors so a color profile can theme the menu bar later.
        private static string _hotkeySgr = "\x1b[93m";  // bright yellow (hotkey in brackets)
        private static string _labelSgr  = "\x1b[97m";  // bright white (display name)

        /// <summary>
        /// Overrides the menu item colors (raw SGR sequences, e.g. "\x1b[93m"). Pass null or
        /// empty to leave a color unchanged. Lets a color profile theme the menu bar later.
        /// </summary>
        public static void SetColors(string hotkeySgr, string labelSgr)
        {
            if (!string.IsNullOrEmpty(hotkeySgr)) _hotkeySgr = hotkeySgr;
            if (!string.IsNullOrEmpty(labelSgr)) _labelSgr = labelSgr;
        }

        public static List<string> BuildOptions(MenuDefinition def, bool full)
        {
            var list = new List<string>();
            if (def == null || def.Menu == null) return list;
            string reset = AnsiText.Reset;
            for (int i = 0; i < def.Menu.Count; i++)
            {
                MenuItem it = def.Menu[i];
                if (it == null) continue;
                string hk = it.Hotkey ?? string.Empty;
                string hotkey = _hotkeySgr + "[" + hk + "]" + reset;
                if (full)
                {
                    string name = it.DisplayName ?? string.Empty;
                    list.Add(hotkey + _labelSgr + name + reset);
                }
                else
                {
                    list.Add(hotkey);
                }
            }
            return list;
        }

        /// <summary>
        /// True when the Full-mode options fit within a menu bar of <paramref name="width"/>
        /// columns (2 cap chars + "══" rule before each option).
        /// </summary>
        public static bool FullFits(MenuDefinition def, int width)
        {
            var opts = BuildOptions(def, true);
            int used = 2; // caps
            for (int i = 0; i < opts.Count; i++) used += 2 + AnsiText.VisibleLength(opts[i]);
            return used <= width;
        }

        /// <summary>Builds Full options if they fit the width, otherwise Simple.</summary>
        public static List<string> BuildAuto(MenuDefinition def, int width)
        {
            return BuildOptions(def, FullFits(def, width));
        }
    }

    /// <summary>
    /// A centered overlay box for notifications and prompts (e.g. "Copied to clipboard",
    /// "Save capture to file"). Renders a bordered box with a title row and body lines and
    /// reports its absolute top/left so the caller can position it over the current screen.
    /// </summary>
    public static class OverlayBox
    {
        /// <summary>
        /// Builds a centered overlay. <paramref name="top"/>/<paramref name="left"/> receive the
        /// 1-based console position of the box's first row/column. Body lines are left-fitted to
        /// the inner width. The title is centered in the top border.
        /// </summary>
        public static string[] Build(int screenWidth, int screenHeight, int boxWidth, string title, IList<string> body, out int top, out int left)
        {
            if (boxWidth < 8) boxWidth = 8;
            if (boxWidth > screenWidth) boxWidth = screenWidth;
            int bodyCount = body != null ? body.Count : 0;
            int height = bodyCount + 2; // top border + body + bottom border
            if (height < 3) height = 3;
            if (height > screenHeight) height = screenHeight;

            left = Math.Max(1, (screenWidth - boxWidth) / 2 + 1);
            top = Math.Max(1, (screenHeight - height) / 2 + 1);

            var lines = new List<string>(height);
            // Top border with centered title.
            string t = title ?? string.Empty;
            if (AnsiText.VisibleLength(t) > boxWidth - 4) t = AnsiText.TakeVisiblePrefix(t, Math.Max(0, boxWidth - 4));
            int inner = boxWidth - 2;
            int titleRoom = inner - AnsiText.VisibleLength(t);
            int leftFill = Math.Max(0, titleRoom / 2);
            int rightFill = Math.Max(0, titleRoom - leftFill);
            var tb = new StringBuilder(boxWidth);
            tb.Append(BoxChars.TopLeft);
            tb.Append(new string(BoxChars.Horizontal, leftFill));
            tb.Append(t);
            tb.Append(new string(BoxChars.Horizontal, rightFill));
            tb.Append(BoxChars.TopRight);
            lines.Add(tb.ToString());

            int bodyRows = height - 2;
            for (int i = 0; i < bodyRows; i++)
            {
                string text = (body != null && i < body.Count) ? body[i] : string.Empty;
                string fit = TextJustify.Fit(text ?? string.Empty, inner, Justify.Left);
                lines.Add(BoxChars.Vertical.ToString() + fit + BoxChars.Vertical.ToString());
            }

            var bb = new StringBuilder(boxWidth);
            bb.Append(BoxChars.BottomLeft);
            bb.Append(new string(BoxChars.Horizontal, inner));
            bb.Append(BoxChars.BottomRight);
            lines.Add(bb.ToString());

            return lines.ToArray();
        }
    }
}
