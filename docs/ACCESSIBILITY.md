# Accessibility and keyboard

**Scope note:** this document originated as a WPF accessibility baseline. The **current Windows
desktop is Avalonia**, with WPF retained as a source fallback. Shortcut and screen-reader claims
below must be verified separately on the current Avalonia build before being presented as
comprehensive accessibility certification. The target interface uses dark/light palettes,
visible keyboard focus and appropriately named controls.

## Keyboard shortcuts

| Context | Shortcut | Action |
|---|---|---|
| Connections | `Ctrl+F` | Focus the search box and select its text |
| Connections | `Esc` | Reset search, protocol and checkbox filters |
| Events | `Ctrl+F` | Focus the search box and select its text |
| Events | `Esc` | Clear the search text |
| Events | `F5` | Refresh the event query |
| Any page | `Tab` / `Shift+Tab` | Move focus through the navigation and page controls |
| Any page | `Space` / `Enter` | Activate the focused button or list item |
| Any page | `Alt+F4` | Close the window |

## Screen-reader labels

- Main navigation: `Main navigation`; each item exposes the page title.
- Connections table: `Observed connections`; the search box and protocol filter have explicit names.
- Event timeline: `Event timeline`; time range and category filters have explicit names.
- Throughput chart: `Throughput chart`, with measured system-wide counters and timestamped
  first-observed connection markers. Longer ranges expose an explicit unavailable state.
- Status bar: monitoring, firewall, database and data-source states are plain text.

## Contrast

All normal text roles use at least WCAG AA 4.5:1 on the window, surface, alternate surface,
navigation and soft-accent backgrounds in Dark, DarkMidnight, Light and LightWarm. The muted text
roles are `#8A98A8` (Dark), `#8F9EBE` (DarkMidnight), `#5A6977` (Light) and `#6F6258` (LightWarm).
Dark structural borders use at least 3:1 against the main surfaces. `ThemeContrastTests` parses the
theme XAML and fails if a future palette change drops below these thresholds.

## Focus

Buttons, navigation items and segmented filters use a dashed accent focus rectangle. The default
system focus visual is replaced so it stays visible on both themes.

## Known limitations

- A full screen-reader walkthrough with Narrator/NVDA has not been recorded.
- Windows high-contrast mode has not been separately audited; the custom palette is used instead.
- Text scaling at 200% and multi-monitor DPI changes have not been measured.
- The tables virtualize rows, but a 10,000-row stress measurement is not recorded; real socket
  inventories are typically hundreds of rows.

These items remain for the accessibility/performance part of FND-010.
