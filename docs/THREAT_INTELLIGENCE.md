# Threat intelligence: Axiom, Blackbox and OriginTrail DKG

**Applies to:** Axiom 0.10.23 for Windows. Blackbox and OriginTrail are optional third-party integrations; their availability and retention policies may differ.

## The short version

Axiom is a **local-first firewall, network monitor and DNS policy tool**. Its firewall and DNS decisions come from Windows Firewall rules and locally loaded DNS lists/settings; they **do not depend on an online DKG lookup**. Blackbox is an optional local agent guard and a gateway for user-approved, signed threat reports. OriginTrail DKG provides an optional shared-knowledge layer with provenance and verified graph data.

**A signed report is evidence, not an automatic malware verdict.** A reported domain is not automatically promoted into a verified rule, and Axiom does not automatically turn community sightings into Windows Firewall or DNS blocks.

## Data flow and responsibility

| Stage | Owner / component | Data and action | Network required? |
|---|---|---|---|
| Observe | Axiom service / Privacy Shield / AI Analyst | Local events, blocked malware DNS requests attributable to an agent or its tool, evidence-bounded high-confidence analyst indicators | No for local observation; cloud AI requires its provider |
| Queue | Axiom service | Durable local preview queue with status, source and outcome | No |
| Approve | Axiom user | Individually choose **Share**, or **Send now** for the reviewed queue; sharing setting and reporter consent must permit submission | No until actual submission |
| Submit | Blackbox reporter, in signed-in user's session | Signs and attempts to send an approved, normalized indicator with the user's reporter identity | Yes for community delivery |
| Corroborate / curate | Third-party Blackbox / ecosystem participants | Independent reports, moderation, endorsement or promotion according to upstream rules | Usually yes |
| Synchronize | Local Blackbox dashboard and its configured DKG node | Fetch and compile verified graph knowledge; expose local dashboard status and graph view | Yes for updates; cached data can be read locally |
| Enforce | Windows Firewall / Axiom Privacy Shield / optional Blackbox guard | Apply local rules; Blackbox guard enforces its configured agent policy when reachable | Local enforcement does not require an online DKG lookup |

The **standalone Axiom DKG node** and the **DKG node configured by Blackbox** are not necessarily the same process or data store. Axiom displays their health separately. "Connected" to localhost proves only that an expected local endpoint responded with the documented status shape, **not** that it is synchronized with the network. When no standalone node answers and Blackbox reports its own DKG node reachable, the DKG card shows that node and labels it "DKG node reported by Blackbox"; a complete installation then skips Axiom's second, unused node.

## Which observations are eligible to be proposed?

- Privacy Shield list matches stay **local**. A blocked malware domain is recorded with its matched rule, source id/version, Axiom version, reason and timestamp for local provenance, but it is not proposed to the community: the same public URLhaus list on every install would look like independent corroboration. Advertising, analytics, telemetry and tracking detections are never candidates.
- The optional AI Analyst may propose structured malicious-role indicators only if they match remote endpoints already included in its evidence package and meet its severity/status restrictions. A value already present in Axiom's local malware-list block history is suppressed as list-derived. Text in observations, advice and free-form analysis is never scraped for arbitrary domains.
- A blocked DNS lookup proves an attempted lookup, **not** that malicious content was downloaded or that a completed connection occurred. A blocked lookup alone does not establish that a file was downloaded.
- Proposed items are **not automatically sent**. The user reviews and explicitly triggers submission. Turning on threat-sharing capability alone does not publish the queue.
- The reporter may reject an item under upstream policy, cooldown or consent rules. Axiom cannot guarantee acceptance or later verification.

See [AI Analyst](AI_ANALYST.md) and [Optional integrations](INTEGRATIONS.md).

### Proposed upstream provenance fields

Blackbox's current IOC report accepts type, value, context and severity; it has no field for the
list that produced a match. Axiom's request to Umanitek is to add optional machine-readable
provenance to the report schema:

- detection method (`dns-blocklist-match`, `ai-analyst`);
- source list id and pinned version/hash;
- whether the lookup was blocked or actually fetched;
- Axiom version.

A context that truthfully describes a blocked/attempted lookup is also needed. Until those fields
exist, Axiom keeps provenance local and does not invent unsupported values or send it to the
community graph.

## On-demand Check graph

Privacy Shield's blocked-domain rows have a **Graph** action. It asks the local Blackbox dashboard
(`/api/threat`) for the public, local and community tiers, one bounded request per tier with a
five-second timeout. Results are cached for ten minutes (at most 256 identifiers), only when the
user explicitly clicks; nothing runs on the per-connection or refresh path and Axiom never contacts
a DKG or external endpoint for this lookup.

The dialog shows the tier, category, sources and reporter count when the dashboard returns genuine
per-indicator evidence. It says **Unknown, not clean** when no entry exists, the dashboard does not
answer, or an entry has no source/reporter provenance. Axiom does not show VERIFIED or COMMUNITY
badges from this result, and automatic annotation stays deferred until Umanitek provides a
documented per-indicator or batch lookup with provenance.

## Local queue, retries and retention

The service persists candidates in its local threat-share store (currently `threat-share.json`, with a maximum of 500 saved entries). Failed attempts caused by network/node outages, missing CLI or unexpected reporter responses can be marked **deferred** with exponential backoff, starting at five minutes and capped at six hours. A daily reporter cap leaves items pending. **Retries are user-initiated** through **Share** or **Send now** when eligible; the existence of a backoff timestamp does *not* imply an automatic timer will transmit reports.

Axiom keeps local state according to its local retention and queue limits. This is **not** a permanent archive or proof that an upstream sighting remains available after its network TTL expires.

### Ambiguous outcomes

Some reporter runs cannot be classified: the CLI starts, then times out or exits with output Axiom does not recognise. This is recorded as **awaiting confirmation** (`Unverified`), not as a retryable failure, because the report may already have been signed and published. Such an item:

- is never retried by **Send now** or any automatic timer;
- keeps a persisted attempt key created on its first submission and reused on every retry, so attempts stay traceable;
- is shown with a **Retry** row action instead of **Share**, and the user decides after checking the graph;
- becomes **shared** only when the reporter confirms, including its `Already shared` answer.

## Shared Memory (SWM) versus Verifiable Memory (VM)

- **SWM / community sharing:** useful for exchanging time-sensitive threat observations. TTL or expiry behaviour is governed by the OriginTrail/Blackbox implementation. Do **not** assume these reports remain publicly retrievable forever.
- **VM / verifiable long-lived publication:** useful when a selected claim should remain independently discoverable with publisher provenance and evidence/verification references. The external ecosystem may express different trust levels, such as self-attestation, endorsements or consensus verification.
- A hash, publisher signature or consensus state does not itself prove a domain is malicious. Trust decisions still need a documented evidence policy, independent corroboration, expiry/revocation handling and a way to dispute mistakes.
- A publication timestamp proves when a record was published, not when an indicator was **first discovered anywhere**. "First seen by Axiom on this host", "first reported to Blackbox" and "first published in VM" are different timestamps and must be labelled separately.

**Axiom does not independently publish threat Knowledge Assets to VM, pay TRAC/gas, or guarantee that an upstream verified item contains the full history of the original reporter.** Publishing selected records to VM is a separate decision made by the relevant external publisher. Axiom does not charge users TRAC or gas fees for its threat-sharing feature. Private network activity must never be published.

## Verified graph sync and offline behaviour

Axiom reads the **local** Blackbox dashboard, including its verified-sync and public-graph endpoints. **Sync now** requests an upstream sync through Blackbox; Axiom itself does not implement a parallel DKG replication loop. An optional **Auto-sync** preference, **off by default**, requests incremental catch-up at roughly 15-minute intervals when enabled. It does not mean the node is always online or the graph is fresh.

When a dashboard read is slow, Axiom may display locally persisted authoritative sync/progress/ruleset information as **last-known state**. A stale cache is not a fresh verification, and an offline node does not mean that the graph contains no threats. Local firewall rules, stored DNS policies and previously loaded lists continue to function independently of a new graph sync.

**Important distinction:** Axiom currently displays the synchronized verified graph through the Blackbox integration; it does **not** yet use general verified/community reputation lookups as per-connection enforcement decisions. Reputation annotations do not currently change firewall rules or block connections automatically.

Other offline limits:

- If the local DNS resolver fails, saved adapter DNS may be restored or a previously configured fallback resolver may answer. **Connectivity can continue while Axiom DNS filtering is bypassed**. This is an availability trade-off, not an assurance of uninterrupted filtering.
- Agent hooks depend on a functioning local Blackbox guard. In Axiom's documented **fail-open** mode, guard failures do not block tools; Axiom displays a degraded protection state.
- Offline submission has no network destination. A queued report remains local until a permitted, user-triggered retry succeeds.
- The locally installed DKG process may be running without internet, but it cannot obtain new remote peer updates while disconnected.

## Privacy and disclosure boundary

Local history (including network metadata, blocked DNS events, AI findings and agent-guard audit records) is **not** a public dataset. Only explicitly approved, normalized indicators may be passed to the external Blackbox reporter. Axiom must not submit private network addresses, loopback or local hostnames, raw DNS browsing history, prompts, command lines, credentials, tokens, file paths, model content or session identifiers as community intelligence.

The URL sharing path discards userinfo, query strings and fragments; it also rejects private, loopback and local destinations. External optional integrations may still make network requests when enabled. The DKG node itself can communicate with peers; localhost-only Axiom status/API calls are **not** proof that the whole integration is offline or network-silent.

See [Security model](SECURITY_MODEL.md), [Privacy Shield](PRIVACY_SHIELD.md) and [Integrations](INTEGRATIONS.md).
