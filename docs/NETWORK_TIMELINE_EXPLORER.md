# Network Timeline Explorer — UI slice (Draft)

This change is deliberately based on `fix/traffic-chart-truthful-live-interactions-20261104` (PR #96), **not** on `main`. Do not merge independently until #96 has passed Windows build/tests and is integrated.

## Included in this PR

- Functional slider over the live rolling five-minute interval; left is five minutes ago, right is now.
- A selected local time shown under the slider, with an accessible "Jump to now" button.
- Only connections first observed within ±10 seconds of the cursor appear as an application/remote-endpoint list.
- Items show application name, PID, protocol, endpoint and count of observed socket starts; details are available as tooltips.
- Session event browsing does not infer security threats, countries or per-app bytes.
- Historical range selections explicitly disable the 5-minute scrubber instead of simulating data.

## Limitations (do not hide or quietly bypass)

- This uses **session-only socket observation events** from the existing overview view model. It is *not* a persistent history browser yet.
- The IP Helper snapshot poll may miss short-lived connections. A first-observed time is not a TCP handshake timestamp.
- The event groups only represent *newly observed* connections near the selected time, not all apps that were active then.
- GeoIP flags and verified threat alerts require separate reliable data sources.
- System-wide throughput cannot be attributed to individual apps without suitable measured process telemetry.
- The time cursor is not yet linked to the chart crosshair; full synchronized zoom/pan and 1h/24h/7d/30d browsing depend on the service-side traffic history API.

## Follow-up architecture

1. Service-side sampler recording real interface-level byte deltas, with robust gaps and per-interface identity.
2. SQLite aggregation/retention, bounded UTC queries and authenticated Named Pipe read-only IPC for `traffic.query`.
3. Separate timestamped socket observation event journal and consistent event IDs for history correlation.
4. Real interactive brushed timeline with synchronized chart selection over all periods, accurate coverage limits and zoom/pan.
5. GeoIP offline lookup with attributable data source and appropriate licensing.
6. Evidence-based security alerts with risk confidence and distinct marker colors; never imply a yellow first-observed marker is a threat.

See also: `docs/TRAFFIC_AND_CONNECTION_TIMELINE.md`.

## Required verification before merge

- Build all WPF projects on Windows with the repository's pinned .NET SDK (warnings as errors).
- Test cursor far left/middle/right during active network activity; confirm ±10s observed events are accurately filtered.
- Verify no false entries when changing to historical ranges; the slider should be disabled and explain missing data.
- Check events are deduplicated across repeated connection monitor updates.
- Test resizing, scaling, dark/light themes, tooltips, keyboard slider and screen reader labels.
- Check app/endpoint list updates with changing cursor and remains bounded during high connection rates.
- Run full `dotnet test` and existing network/service regression suite.
- Leave agent configurations, junctions, sessions, MCP and firewall policy unchanged.

Status: Source changes authored. **No Windows build, integration test or interactive GUI smoke test has been executed by the authoring environment.**
