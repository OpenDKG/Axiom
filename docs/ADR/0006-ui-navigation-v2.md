# ADR 0006 — V2 eight-page navigation and gated optional modules

- **Status:** accepted
- **Date:** 2026-11-03
- **Milestone:** FND-001 UI alignment (V2)
- **Builds on:** ADR 0001–0005, Handoff V2 §G

## Context

Handoff V2 requires the navigation set `Overview | Connections | Applications | Events | Firewall |
Files | Security | Settings`. The existing shell had seven pages with different names
(`Live Connections`, `Apps`, `Firewall Rules`, `History`, `Alerts`) and no `Files` or `Security`
page.

V2 also requires that `Files` and `Security` may be feature-gated with a clear "coming later"
state, never a fake scanner, feed, agent connection or "Protected" status. The UI must keep the
standard build offline and must not start optional module processes.

## Decisions

### 1. Adopt the eight-page navigation exactly

`Overview`, `Connections`, `Applications`, `Events`, `Firewall`, `Files`, `Security`, `Settings`.
`Live Connections` becomes `Connections`, `Apps` becomes `Applications`, `Firewall Rules` becomes
`Firewall`.

**Consequence:** the page names match the product specification and the README.

### 2. Events replaces History and Alerts

`HistoryViewModel` and `AlertsViewModel` are removed. `EventsViewModel` is a unified timeline with
categories `All`, `Network`, `Blocked`, `Files`, `Agents`, `System`.

- `All` and `Network` query the real network flows stored by the service.
- `Blocked`, `Files`, `Agents` and `System` are present as filters but state that no events of that
  type exist in this build. No event is invented.

**Consequence:** one timeline instead of two overlapping pages; alert-type events arrive with
FND-007.

### 3. Files and Security are gated, explicit pages

- `Files` states that file tracking is not enabled: no folder watched, no hash, no scan, no upload,
  no quarantine.
- `Security` lists optional modules (reputation provider, Blackbox, OriginTrail DKG, community feed,
  file scanning) as `NOT CONFIGURED`/`NOT INSTALLED`/`NOT CONNECTED` and states that no optional
  process or external call is active.

**Consequence:** the pages exist for navigation completeness without claiming functionality that
does not exist.

### 4. Country is an explicit placeholder

`Connections` adds a `COUNTRY` column. No GeoIP database is loaded, so every row shows an unknown
placeholder and the footer states that no flag or country is inferred from an IP address.

**Consequence:** the column is ready for an offline, licensed GeoIP database in FND-010 without
misleading the user today.

### 5. Event markers on the throughput chart are demo-only

The chart supports vertical event markers (dashed line + triangle). The overview feeds three demo
positions, and both the legend and the note label them as demo. Real timeline markers belong to
FND-010.

**Consequence:** the visual language is ready; no event is presented as real.

## Consequences

Positive:

- Navigation and terminology match the V2 product specification.
- Gated modules are visible without fake status.
- The country column and event markers establish the UI contract for later data.

Negative / risks:

- The `Alerts` page no longer exists; alert events will be part of `Events` in FND-007.
- Only network events have data; other categories are empty by design.
- Country remains unknown until a licensed offline database is added.
- Event markers are demo until FND-010.

## Alternatives considered

| Alternative | Why not |
|---|---|
| Keep History and Alerts as separate pages | Contradicts the V2 navigation and duplicates the timeline |
| Hide Files and Security until implemented | V2 explicitly allows gated pages; hiding them weakens the product map |
| Show a demo scanner in Files/Security | Forbidden: fake scanning and protection claims |
| Infer country from the IP without a database | Unreliable and misleading; privacy risk |
| Wait for FND-010 to add markers/country | The UI contract and layout would be designed twice |
