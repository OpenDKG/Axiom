# Appearance, navigation names and Axiom Glass

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

## Navigation names and groups

Presentation labels only; class names, serialization, IPC contracts and persisted settings are
unchanged.

| Previously | Now |
|---|---|
| Overview | Dashboard |
| Connections | Live Connections |
| Applications | Applications |
| Events | Network Events |
| Firewall | Network Control |
| Privacy Shield | Privacy Shield (subtitle: DNS Protection) |
| Agents | Agent Protection |
| Agent Stats | Agent Activity |
| AI Analyst | AI Analyst |
| Security | Integrations |
| Settings | Settings |
| Support | Help & Support |

The sidebar groups pages as **MONITORING** (Dashboard, Live Connections, Applications, Network
Events), **PROTECTION** (Agent Protection, Agent Activity, Network Control, Privacy Shield),
**INTELLIGENCE** (AI Analyst, Integrations) and **GENERAL** (Settings, Help & Support). The
Firewall Rules editor stays inside Network Control.

## Native backdrop: what is actually used

The window is transparent with an opaque fallback; for the two Glass themes the host requests, in
this order:

1. `AcrylicBlur`
2. `Mica`
3. `Blur`
4. `None`

The achieved level is read from `ActualTransparencyLevel`; the UI reports that value instead of
assuming success.

**Verified on this machine:** Windows 10 21H2, build 19044 (x64). The window reports
`AcrylicBlur (native backdrop active)`, captured in `glass-settings-native.png`.

**Not verified:** Mica (needs Windows 11), macOS and Linux backdrops. Those are **NOT TESTED**, not
PASS. On platforms without a native material the same themes render with the simulated glass
layers and an opaque base, so the desktop never shows through unblurred.

## Visual effects preference

**Settings > Appearance > Visual effects** offers four real options; none is decorative:

| Option | Requested backdrop |
|---|---|
| Auto | Strongest supported material (AcrylicBlur, then Mica, then Blur) |
| Full | Same strong request; no downgrade |
| Reduced | `Blur` only |
| Off | `None`; glass themes keep layered surfaces over an opaque base |

The preference is stored as one word in `%LOCALAPPDATA%\Axiom\visual-effects.txt`. The status line
under the buttons shows both the preference and the backdrop the window actually reported. All four
buttons are wired to the same host service used by the window; there are no fake switches.

## Glass design

- **Shared palette** in `Axiom.UI.Avalonia/Themes/AxiomPalette.axaml`: translucent window gradients,
  glass sidebar, card gradients, gradient card borders, soft ambient glow and colour wash.
- **Axiom Glass Dark:** deep graphite-blue base, frosted charcoal/blue panels, cyan accent lines,
  indigo download colour, ambient cyan light in the upper-left.
- **Axiom Glass Light:** pearl gradient base, frosted white panels, blue-grey accents, white sheen
  and soft shadows.
- **Cards** take the gradient border and an inset top highlight in glass themes only, plus a soft
  drop shadow; the classic themes keep flat solid surfaces with no shadow.
- **Dense tables** keep solid or near-opaque surfaces for legibility; translucency is limited to the
  shell, headers and cards.
- The throughput chart takes grid, upload, download and muted brushes from the active theme, so
  light themes no longer draw dark grid lines.

The distinction is intentional and visible: the standard Dark and Light themes are conventional
flat surfaces, while Glass adds depth, translucency and light. See `glass-vs-dark.png`.

## Screenshots

Full-window captures from the running application (not mockups, not cropped dashboards):

- `docs/assets/screenshots/glass-dark-native.png` - Axiom Glass Dark, Dashboard
- `docs/assets/screenshots/glass-light-native.png` - Axiom Glass Light, Dashboard
- `docs/assets/screenshots/theme-dark.png` - standard Dark, Dashboard
- `docs/assets/screenshots/theme-light.png` - standard Light, Dashboard
- `docs/assets/screenshots/glass-settings-native.png` - Settings with the effects status line
- `docs/assets/screenshots/glass-vs-dark.png` - side-by-side comparison

The README uses `axiom-glass-dark-full.png`, which is the same capture as `glass-dark-native.png`.

## Not implemented yet

- Native Mica was not tested because no Windows 11 host was available; it is requested as a hint
  only and is never claimed.
- macOS/Linux native backdrops are not tested; the portable styles fall back to simulated glass.
- Motion preferences, UI density and a high-contrast variant are future work.
- Formal WCAG 2.2 AA measurement across all six themes is still required; contrast was checked
  visually on the rendered surfaces.
- Startup time and memory were not benchmarked for this change; the backdrop adds no timers or
  polling work.

## Accessibility and safety

Theme and effects changes do not modify firewall, DNS, IPC, agent-hook, DKG or service behaviour,
and the UI adds no telemetry or network requests. Text selection, focus, hover and list selection
behaviour are unchanged; the four classic themes remain available and preserve saved preferences.
