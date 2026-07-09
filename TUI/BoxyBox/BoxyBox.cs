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
        /// Builds a highlighted content row: the text is stripped of its own color, fitted to
        /// the inner width, then wrapped with <paramref name="highlightOn"/> /
        /// <paramref name="highlightOff"/> so the entire row (including padding) shows the
        /// highlight background. Stripping avoids inner reset sequences punching holes in it.
        /// </summary>
        private string HighlightedContentLine(string text, string highlightOn, string highlightOff)
        {
            int inner = Width - 2;
            string plain = AnsiText.StripAnsi(text ?? string.Empty);
            string body = TextJustify.Fit(plain, inner, Justification);
            var sb = new StringBuilder(Width + 16);
            sb.Append(BoxChars.Vertical);
            sb.Append(highlightOn);
            sb.Append(body);
            sb.Append(highlightOff);
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
        /// selectedRow &lt; 0 for no highlight.
        /// </summary>
        public string[] Render(IList<string> lines, int selectedRow, string highlightOn, string highlightOff)
        {
            var result = new string[Height];
            result[0] = TopBorder();
            for (int r = 0; r < ContentRows; r++)
            {
                string text = (lines != null && r < lines.Count) ? lines[r] : string.Empty;
                if (r == selectedRow && highlightOn != null)
                {
                    result[r + 1] = HighlightedContentLine(text, highlightOn, highlightOff ?? AnsiText.Reset);
                }
                else
                {
                    result[r + 1] = ContentLine(text);
                }
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
    /// Flattens a tree into visible rows honoring each node's expanded state. Rendering rules
    /// match the TUI spec: expandable nodes show '+' (collapsed) or '-' (expanded); leaf nodes
    /// below the top level show tree connectors ('├' mid-sibling, '└' last sibling). Indent is
    /// two spaces per depth level plus a two-space left margin.
    /// </summary>
    public static class TreeFlattener
    {
        public const char MidChild  = '\u251c'; // ├
        public const char LastChild = '\u2514'; // └

        public static List<TreeRow> Flatten(IList<TreeNode> roots)
        {
            var rows = new List<TreeRow>();
            if (roots == null) return rows;
            for (int i = 0; i < roots.Count; i++)
            {
                FlattenNode(roots[i], 0, i == roots.Count - 1, rows);
            }
            return rows;
        }

        private static void FlattenNode(TreeNode node, int depth, bool isLast, List<TreeRow> rows)
        {
            if (node == null) return;
            string indent = new string(' ', 2 * (depth + 1));
            string line;
            if (node.HasChildren)
            {
                line = indent + (node.IsExpanded ? "-" : "+") + node.Text;
            }
            else if (depth == 0)
            {
                line = indent + " " + node.Text;
            }
            else
            {
                char connector = isLast ? LastChild : MidChild;
                line = indent + connector + " " + node.Text;
            }
            rows.Add(new TreeRow(line, node, depth));

            if (node.HasChildren && node.IsExpanded)
            {
                for (int i = 0; i < node.Children.Count; i++)
                {
                    FlattenNode(node.Children[i], depth + 1, i == node.Children.Count - 1, rows);
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
        {
            _box = new Box(width, height);
            _box.MenuStyle = MenuBar.Cap.Terminal;
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
    }
}
