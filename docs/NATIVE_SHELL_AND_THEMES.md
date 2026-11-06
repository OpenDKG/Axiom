# Axiom native window shell and appearance — review notes

This Draft branch stacks on PR #97, which stacks on PR #96. Do **not** merge directly to main before validating the dependencies.

## Current implementation

- Four local-only WPF palettes: Dark (graphite), DarkMidnight (navy/violet), Light (cool/neutral) and LightWarm (ivory/terracotta). All reference the same ResourceDictionary keys. Selection persists in `%LOCALAPPDATA%\Netpetra\theme.txt`.
- The header has a theme dropdown with all four variants; the Settings view exposes the same choices.
- Custom visible caption within WPF WindowChrome with Minimize, Maximize/Restore and Close buttons; native resizable window behavior should remain available.
- Removed 900px width caps on Agents, Security and Settings; Apps gains a splitter to resize app list versus details.
- Agent cards describe OriginTrail DKG and Umanitek Guardian Agent Blackbox with measured loopback connection status, including explicit disconnected states.
- **Current glyphs OT/B are placeholders**; not licensed or approved official logos. Replace only after obtaining authentic vendor-provided assets and verifying redistribution rights. Do not bundle random image-search logos.
- Footer avoids unconditional `Powered by` or `Protected by` claims when no module is running.

## Windows test gates (not performed in this environment)

1. Build with the Windows-pinned .NET SDK; warnings are errors.
2. Test restore/maximize/snap/drag/resize on Windows 10/11, including mixed DPI monitors.
3. Verify custom title bar buttons are clickable rather than dragged by WindowChrome; keyboard Alt+F4 and Windows snap still work.
4. Confirm all four palettes render consistently in every view, text contrast in small fonts, and persisted theme survives restart.
5. Check screenshot at 1080, 1460 and 1920px widths; verify no clipped table controls and splitter can be dragged.
6. Test Agents with no node connected, DKG only, Blackbox only and both modules; never claim a disconnected or inactive module protects agents.
7. Leave external agents, junctions, their sessions and firewall rules untouched.
