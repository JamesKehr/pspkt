# BoxyBox

BoxyBox is a small, **project-independent** terminal UI (TUI) engine written in C#. It draws
bordered "boxes" of scrolling text and expandable detail trees to a fixed region of the
console **without ever scrolling the console itself**, using absolute cursor positioning and
full-frame repaints.

Inside pspkt it powers the [`Analysis`](https://github.com/JamesKehr/pspkt/wiki/Analysis-Mode) parsing level, but it has
no dependency on pspkt types — it can be reused anywhere a `netstandard`/.NET Framework
`Add-Type` compile is available.

- Source: `BoxyBox.cs` (single file, namespace `BoxyBox`)
- Menu definitions: `menus/*.json`
- Compiled by pspkt via `Add-Type` in `class/loader.psm1` (all repo C# is one assembly)

---

## Design principles

- **No console scroll.** Every frame is a complete rectangle written to an absolute
  `(row, col)` origin via ANSI cursor moves. Writing never advances the cursor past the
  region, so the host console never scrolls.
- **No word wrap.** Lines are truncated to the box's inner width; an ellipsis marks text
  clipped on the left (right-justified) or right (left-justified).
- **ANSI-aware measurement.** Visible width is measured ignoring SGR (color) escape
  sequences, so colored text justifies and truncates on printable columns.
- **C# for the hot path.** Formatting and framing are done in C# so the host (e.g. a
  PowerShell consumer loop) does no per-line work beyond `[Console]::Write`.

---

## Building blocks

All types live in the `BoxyBox` namespace.

### Text utilities

| Type | Responsibility |
|---|---|
| `AnsiText` | ANSI/SGR helpers: `StripAnsi`, `VisibleLength`, `ContainsAnsi`, `ApplyBackground` (wrap a string in a background color while preserving its own foreground colors — used for selection highlight), and the `Reset` constant. |
| `TextJustify` | `Fit(text, width, justify)` — pad/truncate a (possibly colored) string to an exact visible width, adding an ellipsis on the clipped side. |
| `BoxChars` | The box-drawing/menu glyph constants (single/double borders, menu caps, connectors). |

### Boxes and framing

| Type | Responsibility |
|---|---|
| `Box` | A bordered box: optional top border, N content rows, and a bottom **menu bar**. `Render(...)` returns a `string[]` frame (each line exactly `Width` visible columns). Supports a highlighted selected row and in-place `Resize(width, height)`. `ShowTopBorder=false` lets a box sit flush beneath another (shared divider). |
| `MenuBar` | Builds the bottom bar from option strings, filling with a rule and end caps. `Cap.Terminal` (`╘══╛`, double) is the outer bottom border of a standalone/collapsed box; `Cap.Mid` (`╞══╡`, double) is a divider shared with the box below; `Cap.TerminalSingle` (`└──┘`, single) is the outer bottom of a box that sits below a divider (e.g. the expanded Details box). Double-line style is reserved for dividers and collapsed/live bottoms; boxes opened beneath a divider close with the single-line cap. |
| `ScreenRegion` | A fixed rectangle on the console. `BuildFrame(lines)` turns a `string[]` into one absolute-positioned string ready for a single `[Console]::Write`. Also exposes `ClearScreen()`, `ShowCursor()`, `HideCursor()`. |

### Scrolling text

| Type | Responsibility |
|---|---|
| `TextBox` | A bounded ring of raw lines with absolute **sequence numbers** that survive front-trimming. `AppendRange`, `GetTailWindow` (live tail), `GetWindow(topSeq, rows)` (focused window), `GetLineBySeq`, `ClampSeq`. The stored lines are raw (with color); a `Box` fits them at render time. |

### Detail trees

| Type | Responsibility |
|---|---|
| `TreeNode` | A node with `Text`, a stable `Key` (for expand/collapse persistence), `IsExpanded`, and `Children`. `Add(child)` / `AddLeaf(text)`. |
| `TreeRow` | One flattened visible row: display string + originating node + depth. |
| `TreeFlattener` | `Flatten(roots)` honors each node's expanded state; `FlattenAll(roots)` ignores collapse (used for "copy everything"). Every node reserves one column for its `+`/`-` marker immediately left of its text, so a leaf's text (blank marker slot) aligns with sibling expandable nodes' text. Set `UseConnectors = true` to draw `├`/`└` tree connectors instead. |
| `DetailsBox` | Wraps a `Box` around a tree: selection, scrolling, expand/collapse (`MoveUp/Down`, `PageUp/Down`, `ExpandSelected/CollapseSelected`, `ExpandAll/CollapseAll`), per-`Key` expand-state persistence across trees, `Resize`, `GetVisibleText()` (viewport) and `GetAllText()` (whole tree). |

### Overlays and menus

| Type | Responsibility |
|---|---|
| `OverlayBox` | A centered bordered box for notifications and prompts (e.g. "Copied to clipboard", a save-path prompt). Reports its absolute top/left so the caller can position it over the current frame. |
| `MenuItem` / `MenuDefinition` | The in-memory menu model (`Name`, `DisplayName`, `Hotkey`). |
| `MenuRenderer` | Turns a `MenuDefinition` into option strings: `BuildAuto(def, width)` picks **Full** (`[Hotkey]DisplayName`) when it fits or **Simple** (`[Hotkey]`) when the bar is too narrow. Hotkeys and labels are colored for contrast (`SetColors`). |

---

## Rendering model

```
lines (string[])  ──►  Box.Render()  ──►  frame (string[])  ──►  ScreenRegion.BuildFrame()  ──►  [Console]::Write
```

1. Produce the content lines (raw, possibly colored).
2. `Box.Render(lines, selectedRow, hlOn, hlOff)` frames them: top border (optional), content
   rows fitted to the inner width with the selected row background-highlighted, and the menu
   bar.
3. `ScreenRegion.BuildFrame(frame)` prefixes each row with an absolute cursor move so the
   whole rectangle paints in place.
4. The host writes the single resulting string. No scroll, no flicker beyond the repaint.

Two boxes can be stacked by giving the top box a `Cap.Mid` menu bar (the shared divider) and
the bottom box `ShowTopBorder=false`, positioned flush beneath. An `OverlayBox` frame can be
written on top of the base frame for transient prompts/notifications.

---

## Menu JSON

Menus are data, not code, so they can be re-labelled or localized without recompiling. Each
box loads `menus/<Box>.json`; a user override may be placed at
`$HOME/.pspkt/menus/<Box>.json` (pspkt's loader checks the override first).

```json
{
  "Box": "Details",
  "Menu": [
    { "Name": "Expand",      "DisplayName": "Expand",      "Hotkey": "\u2192" },
    { "Name": "Collapse",    "DisplayName": "Collapse",    "Hotkey": "\u2190" },
    { "Name": "ExpandAll",   "DisplayName": "Expand all",  "Hotkey": "Ctrl+\u2192" },
    { "Name": "CollapseAll", "DisplayName": "Collapse all","Hotkey": "Ctrl+\u2190" }
  ]
}
```

Each item renders as `[Hotkey]DisplayName` (Full) or `[Hotkey]` (Simple). `MenuRenderer`
decides which mode fits the current width.

---

## How pspkt drives BoxyBox

The `Analysis` consumer loop lives in `function/PspktSession.psm1` (`Invoke-PspktAnalysisLoop`).
Its use of BoxyBox is a good end-to-end example:

- A full-width `TextBox` + `Box` shows one parsed packet per line, live (no console scroll).
- **Focus** (`f`) freezes scrolling and splits the screen into a focused Text box (top) and a
  `DetailsBox` (bottom), merged on a shared `Cap.Mid` divider. The selected packet's detail
  tree is parsed **just-in-time** and shown in the Details box.
- **Pause** (`p`) additionally stops ingesting new packets, then enters Focus.
- Arrow keys navigate; `Tab` switches the active box; the selected row gets a background
  highlight that preserves the parsing colors (`AnsiText.ApplyBackground`).
- **Save** (`w`) opens an `OverlayBox` prompt and writes a pcapng of the retained packets;
  **Copy** (`Shift+Ctrl+C`) copies the selected line plus the full detail tree
  (`DetailsBox.GetAllText`); both show a transient notification overlay.
- On console resize, all boxes/regions are rebuilt in place via `Box.Resize` / `DetailsBox.Resize`.

See the [Analysis Mode](https://github.com/JamesKehr/pspkt/wiki/Analysis-Mode) wiki page for the end-user view.

---

## Reusing BoxyBox elsewhere

BoxyBox depends only on `System` / `System.Text` / `System.Collections.Generic`. To reuse it:

1. Compile `BoxyBox.cs` (`Add-Type` in PowerShell, or include it in a C# project).
2. Build your content lines / `TreeNode` roots.
3. Create `Box` / `TextBox` / `DetailsBox` + `ScreenRegion` objects sized to your console.
4. In your loop: build the frame(s), `ScreenRegion.BuildFrame(...)`, and write once per tick.
5. Load menus from JSON (or build `MenuDefinition` in code) and feed `MenuRenderer.BuildAuto`.

Because there are no pspkt dependencies, the engine can back any "boxed, non-scrolling,
tree-capable" terminal view.
