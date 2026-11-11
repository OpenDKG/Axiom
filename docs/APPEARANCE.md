# Appearance and Axiom Glass

Axiom keeps the four original themes and adds two Axiom Glass palettes:

- Axiom Glass Dark (default for a fresh profile)
- Axiom Glass Light
- Dark
- Light
- Dark Midnight
- Light Warm

The top-bar selector and **Settings > Appearance** switch themes live. The choice is stored in
`%LOCALAPPDATA%\Axiom\theme.txt`; an existing saved choice is preserved. Unknown or unreadable
values fall back to Axiom Glass Dark.

## What the current glass work does

- Central shared palette dictionaries live in `Axiom.UI.Avalonia/Themes/AxiomPalette.axaml`; the
  Windows host merges them instead of owning four inline dictionaries.
- Reusable card, page-title, section-title and KPI styles live in
  `Axiom.UI.Avalonia/Themes/AxiomControls.axaml`.
- Glass palettes use restrained gradients, a translucent card tint, thin borders and a bright
  accent line. Dense tables keep solid surfaces.
- The shell has a larger title area, a local-first/read-only status chip, improved navigation
  spacing and a full-size Overview dashboard.
- The throughput chart takes its grid, upload, download and muted brushes from the active theme,
  so light themes no longer draw dark grid lines.

## What is not implemented yet

- Native Windows Mica/Acrylic transparency and the Auto/Full/Reduced/Off visual-effects setting
  are **not** implemented. The current glass look is composed from brushes and gradients; it does
  not request a native blur. No platform is claimed as blurred or Mica-enabled.
- Navigation still uses text labels; the planned vector icon set is not included.
- The new card and typography styling is applied to the shell, Overview and Settings. Other pages
  inherit the new palette and global control styles but keep their existing layouts.
- Motion preferences, UI density and high-contrast-specific variants are future work.

## Screenshots

- `docs/assets/screenshots/axiom-glass-dark-full.png`
- `docs/assets/screenshots/axiom-glass-light-full.png`

Both are full-window captures, not cropped dashboard sections.

## Accessibility and safety

Text and accent contrast were checked visually on the rendered surfaces; formal WCAG 2.2 AA
measurement across all six themes is still required. Theme changes do not modify firewall, DNS,
IPC, agent-hook or DKG behavior, and the UI adds no telemetry or network requests.
