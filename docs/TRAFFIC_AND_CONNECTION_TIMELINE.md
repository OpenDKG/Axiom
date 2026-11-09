# Traffic and Connection Timeline — correctness-first roadmap

Status: UI correctness draft. This is **not** yet a full GlassWire-style history implementation.
Baseline inspected: `main`, November 4, 2026. Keep all work in reviewable draft PRs.

## Verified source limitations

- `TrafficEngine` previously showed a 60-second chart when UI selected `5m`. Its
  1h/24h/7d series were deterministic *fake* data and must not be shown as real history.
- `HistoryStore` persists observed network flow metadata and retains it up to 30 days,
  but the existing `traffic_buckets` are not populated with actual throughput.
- IP Helper owner tables supply observed socket metadata. Per-connection byte totals are read from
  Windows extended TCP statistics with collection enabled by the elevated service; UDP and flows
  shorter than one poll stay unmeasured and are shown as such.
- A yellow line is a **newly observed connection**, not a traffic spike, block or security alert.
- The service currently has no GeoIP data or complete alert stream. Never invent either.

## PR 1: Honest live visualization (this branch)

- Five-minute rolling measured bytes/second using matching active adapter counters.
- Preserve missing samples as gaps (`NaN`), not fabricated zeroes.
- No historical demo curves. Clearly label unimplemented ranges as unavailable.
- Rate readouts and a scaled Y axis; mouse hover for measured upload/download.
- Clickable, inspectable **session-only** new-connection markers with app, PID,
  protocol, endpoints, time and state. Explicitly say country/risk are unknown.
- Markers shown for longer ranges do not claim coverage beyond the UI session.
- No changes to firewall policy, agent data directories, junctions or MCP settings.

**Unverified:** This WPF/.NET 10 branch needs Windows CI build and an interactive
Windows smoke test before merging. Do not present it as fully delivered.

## Axiom-specific visual direction (not a GlassWire copy)

- A spacious, resizable dark/light chart with two distinguishable but restrained
  filled curves for **upload** and **download**. Always show actual B/s, KB/s,
  MB/s or GB/s readouts and dynamic, legible Y-axis tick labels.
- A synchronized, compact **event ribbon** under the plot: yellow for
  first-observed sockets, amber for independently assessed suspicious anomalies,
  red only for high-confidence threat indicators. Never imply that a new
  destination is malicious solely because its country is unfamiliar.
- A bottom time-brush (overview minimap) for panning/zooming real persisted
  24h/7d/30d data, with keyboard equivalents and clear UTC/local time handling.
  The active window, actual capture coverage and gaps remain visible.
- Hover over a data point: time, upload/download rates, measured duration.
  Click/keyboard-select a point: freeze the selection and reveal the processes
  and destinations observable at that time. Do not fabricate per-app byte
  totals from the system-level curve.
- Hover/click an event: a detail panel with executable name and path, PID,
  remote IP/port and protocol, first-observed timestamp, country flag **only
  when supported by offline GeoIP**, evidence/confidence and any available
  user-approved actions. Handle multiple events at the same pixel as a list.
- Small summary cards: current up/down rate, data transferred in selected
  window (only from measured counters), new destinations, unassessed
  connections and actionable alerts; display `N/A` when unsupported.
- Keep the same identity and typography as the existing Axiom WPF theme.
  Do not reuse GlassWire assets, icons, gradients or proprietary visuals.

## PR 2: Durable throughput and time windows

Use the existing service and authenticated Named Pipe. Do **not** start a second
network scanner in the UI.

1. Implement a separate service-side **system traffic sampler** at about 1s
   cadence. Track each `NetworkInterface.Id` independently; use monotonic elapsed
   time and only non-negative deltas from the same active adapter. Exclude
   loopback/tunnel by documented policy; optionally allow the user to choose
   adapters. Record counter resets, VPN/interface churn and gaps as unknown.
   Do not extrapolate to per-app bytes.
2. Add an additive SQLite migration and bounded retention. Keep genuine
   high-resolution data for short windows and aggregate older data; sample
   data must be timestamped UTC, include duration and capture quality.
   Suggested retention: per-second 1h, ten-second 24h, per-minute 7d and
   per-hour 30d, with compact rollups. Validate storage volume under real load.
3. Add read-only IPC commands for `traffic.query` with bounded range, granularity,
   max points, coverage start/end, gap counts and partial coverage metadata.
   The server determines authoritative data; the UI never invents values.
4. Suggested chart resolution:
   - `5m`: 1s buckets
   - `1h`: 10s buckets
   - `24h`: 1min buckets
   - `7d`: 10min buckets
   - `30d`: 1h buckets
5. For every bucket calculate **bytes / measured seconds**, not the total
   bytes or the count of connections. Use an explicit duration-weighted average,
   preserve gaps and avoid divide-by-zero. Show actual historical coverage when
   the service starts partway through the selected range.
6. Never silently query all historical rows on every UI refresh. Use indexed,
   bounded, cancellable, paged/range queries. Cache at a suitable TTL.
7. Record in-session real-time 1s samples while disconnected from the service
   only if explicitly labelled local/nonpersistent. When service data is
   available, prefer service authoritative timestamps.

## PR 3: First-observed event timeline and interaction

- Store **observation events** separately from the existing upserted flow
  snapshots, with timestamps, process identity, endpoints, protocol, state,
  direction and quality. Flow upsert's first/last seen alone cannot reconstruct
  every reconnect. Document snapshot blind spots.
- Implement indexed UTC range queries and deduplication; distinguish first
  ever observed destination from first observed this session and a repeated
  flow. Do not claim a complete historical event record before event capture
  was enabled.
- Show compact yellow markers with counts when crowded. Hover/click displays
  timestamp, executable name/path, PID, protocol, local/remote IP+port,
  state, and data source. Selecting marker highlights the corresponding
  connection detail and opens a fuller investigation.
- Add distinct warning/red alert markers **only when** the deterministic
  risk engine has emitted evidence-based alert records. Distinguish observed
  connection, anomaly, verified reputation match and verified firewall block.
  No foreign-country-as-malware rules.
- If multiple events share a pixel, display an accessible list with scrollable
  detail, keyboard navigation and virtualized rendering.

## PR 4: Offline GeoIP country flags (with provenance)

Suggested source: DB-IP **IP to Country Lite** offline MMDB or CSV.
License: CC BY 4.0, attribution required. Check current license and
download terms before bundling; prefer optional, verified user download
with an offline cache and visible data version/source.

- Parse IPv4 and IPv6 remote **IP addresses** robustly (including IPv6
  bracket syntax and scope IDs). Never feed endpoint strings with ports
  directly into the MMDB reader.
- Private, loopback, multicast, unspecified and link-local addresses are
  `LOCAL`/`UNKNOWN`, not a country with a flag. DNS names are not blindly
  translated to a nation. Public address with no match remains unknown.
- Display country name + validated ISO alpha-2 + local flag asset; do not
  rely on loading flag images from a remote host per connection.
- Cache lookup by IP, include data freshness and provenance. Use bounded
  resources and explain GeoIP as the **approximate location of the IP
  assignment**, not the physical location of the user or the server owner.
- Country is informative metadata, not a suspicion indicator.

## PR 5: Real security event integration

- Build or connect the deterministic risk engine and stored alerts, with
  distinct `CONFIRMED_INDICATOR_MATCH`, `SUSPICIOUS`, `LOW_OBSERVED_RISK`,
  `UNKNOWN`, `INSUFFICIENT_DATA` and evidence/confidence.
- Only show 'problems' after concrete events are actually assessed.
  Provider failure or no risk telemetry means **not assessed**, not **safe**.
- Correlate alerts to connections by stable event ID where possible, never
  assume a Windows firewall rule caused a block without enforcement evidence.
- Keep all blocking behind the native human approval gate.

## Required acceptance tests

- A controlled, measured upload/download changes both byte-rate readouts
  and the rightmost live chart while all 5 minutes are sampled.
- Adapter disappears/reappears, counters reset, the app resumes after sleep,
  and the device goes offline: plot gaps and **no giant false spike**.
- Historical ranges never show demo traffic; newly installed version shows
  partial coverage until sufficient history actually exists.
- 5m/1h/24h/7d/30d requests return correct UTC windows and bucket durations;
  query time remains bounded with a database aged to 30 days.
- Mouse hover shows rate + approximation notice; marker hover and click
  expose the same event details. Distinct connection/alert semantics remain.
- Loopback, private IP, IPv6, empty remote, unknown country and stale GeoIP
  source are handled without invented flags.
- WPF theme light/dark, DPI scaling, resized windows, keyboard focus and
  screen reader labels are tested on Windows.
- No access to `C:\\Users\\llm\\.codex`, `C:\\Users\\llm\\.config\\openchamber`,
  `C:\\Users\\llm\\.local\\share\\opencode`, their junction targets, or any
  live agent sessions/configs during implementation or testing.
