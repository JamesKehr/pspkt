# Analysis Mode

`Analysis` is an **interactive, full-screen parsing level** for `Start-Pspkt`. Instead of
streaming lines that scroll off the top of the console, it paints a fixed **Text Box** of
live packets that you can freeze, select, and inspect in a Wireshark-style **Details** tree —
all in the terminal, with no console scroll.

It is powered by [BoxyBox](https://github.com/JamesKehr/pspkt/blob/main/TUI/BoxyBox/README.md), a project-independent TUI engine.

```powershell
# Start an interactive Analysis capture (Ctrl+C or 's' to stop)
pspkt -pl Analysis

# Analysis with a quick filter — only DNS to/from 1.1.1.1
pspkt -pl Analysis -DNS -i 1.1.1.1
```

> Requires an elevated shell (like every capture). Works in Windows Terminal / any
> ANSI-capable, interactive host.

---

## The two views

### Live view (Text Box)

One parsed packet per line, scrolling **inside** the box while the console stays put. Each
line is the compact summary:

```
<grp>:<comp>[<dir><edge>]: Eth: <IPvX>.<proto>: <src>.<sport> > <dst>.<dport>: <App>
```

The data-link layer is shown at Minimal level (`Eth:`); the rest is the Default parse. Your
active [color profile](./Color-Profiles.md) is preserved.

### Focus view (Text Box + Details Box)

Pressing **`f`** freezes scrolling and splits the screen: the focused Text Box on top
(~40%) and the **Details Box** on the bottom (~60%), merged on a shared divider line. The
selected packet is parsed **just-in-time** into an expandable tree. Keyboard focus starts in
the Details Box.

```
-DNS - 0xe309 1/0/0 microsoft.com. A 150.171.109.115
      Transaction ID: 0xe309
    +Flags: 0x8180 Query response, No error
      RR Count - Qry: 1, Ans: 1, Auth: 0, Adtl: 0
    -Queries
      +microsoft.com.: type A, class IN
    -Answers
      +microsoft.com.: type A, class IN, 150.171.109.115
```

Section nodes are expanded; the verbose `Flags` node and each resource-record one-liner are
collapsed by default — expand what you need. Expand/collapse state persists as you step
between packets.

---

## Keys

### Live view

| Key | Action |
|---|---|
| `f` | **Focus** — freeze scrolling, split the screen, select the middle line |
| `p` | **Pause** — stop collecting new packets *and* enter Focus (frozen snapshot) |
| `s` | **Stop** — end the capture |
| `w` | **Save pcapng** — write the retained packets to a `.pcapng` file |
| `Ctrl+C` | Stop the capture |

### Focus view

| Key | Action |
|---|---|
| `Tab` | Switch the active box (Text ⇄ Details) |
| `↑` / `↓` | Move the selection up/down one line |
| `PgUp` / `PgDn` | Move by a page |
| `→` / `←` | **Details:** expand / collapse the selected node · **Text:** left/right justify |
| `Ctrl+→` / `Ctrl+←` | **Details:** expand all / collapse all |
| `Ctrl+↑` / `Ctrl+↓` | **Details:** previous / next packet (moves the Text selection and reparses) |
| `Ctrl+PgUp` / `Ctrl+PgDn` | **Details:** page the Text Box up / down a page (moves the Text selection and reparses) without leaving the Details Box |
| `r` | **Resume** — leave Focus, clear any pause, resume live scrolling |
| `p` | **Pause** collection (stays in Focus) |
| `w` | **Save pcapng** |
| `Shift+Ctrl+C` | **Copy** the selected Text line + the full detail tree to the clipboard |
| `s` | **Stop** |

---

## Focus vs. Pause

- **Focus (`f`)** freezes *scrolling* only. Packets are still collected in the background and
  added to the buffer — resuming shows everything that arrived while you were focused.
- **Pause (`p`)** freezes *collection* — while paused, new packets are discarded (nothing is
  added to the Text Box or the detail-retention store) so you inspect a stable snapshot.
  `Pause` also enters Focus. `Resume` (`r`) clears the pause and restarts collection.

---

## Saving to pcapng

**Save** (`w`) prompts for a file path in an overlay and writes a **pcapng** of the packets
currently retained for analysis (real timestamps and per-packet component/edge/direction/drop
comments — the same format as a live `-WriteFile` capture). A `.pcapng` extension is added if
you omit it. The save is bounded to the retention window (the most recent **50,000** packets).

## Copying

**Copy** (`Shift+Ctrl+C`, Focus only) puts the selected Text line plus the **complete** detail
tree of that packet on the clipboard — every node and field, regardless of what is scrolled
into view or collapsed.

---

## Colors, layout, and resize

- The active parsing **color scheme is preserved** in both the Text Box and the Details tree.
- The selected row gets a distinct **background highlight** that keeps the foreground parsing
  colors readable (blue when its box is active, gray when it is not).
- Resizing the terminal **rebuilds the layout** in place so the boxes track the new size.
- The detail tree uses a plain two-space indent (no `├`/`└` connectors) by default.

## Capture size and runtime warnings

- **PacketSize** is automatically raised to a **1500-byte (MTU) floor** in Analysis mode so the
  just-in-time Details parse has enough payload to work with. An explicit larger `-PacketSize`
  is left as-is, and `-PacketSize 0` (full packets) is preserved.
- Because the TUI owns the screen, **warnings are shown *inside* the UI instead of being
  printed to the console**: a panel merges up from the bottom of the Text Box (joined by a
  `╞══╡` divider), sized just tall enough to fit the (yellow) warning text, stays for
  **3 seconds**, then collapses. This covers both setup warnings raised before the TUI starts
  (e.g. the PacketSize/ParsingLevel auto-bumps, which are collected and shown at first paint)
  and any warning raised while the capture runs. Suppress the auto-bump warnings at their
  source with `-NoWarning`.

---

## Menu customization

The bottom menu bars are JSON-defined, so you can re-label items or change hotkeys (including
for localization). Built-in menus live under `TUI/BoxyBox/menus/`
(`TextLive.json`, `TextFocus.json`, `Details.json`); place an override at
`"$HOME/.pspkt/menus/<Box>.json"`. Each item is `{ "Name", "DisplayName", "Hotkey" }` and
renders as `[Hotkey]DisplayName`, collapsing to `[Hotkey]` when the console is narrow.

---

## Notes

- Analysis is an interactive level; for non-interactive/redirected output use `Minimal`,
  `Default`, or `Detailed`.
- Detail retention (for the Details tree and Save) is the most recent **50,000** packets.
- See also: [Start-Pspkt](./Start-Pspkt.md) · [Display](./Display.md) ·
  [Color Profiles](./Color-Profiles.md) · [BoxyBox engine](https://github.com/JamesKehr/pspkt/blob/main/TUI/BoxyBox/README.md)
