# Threat intelligence: Axiom, Blackbox and OriginTrail DKG

**Applies to:** Axiom 0.32.0+ for Windows. Blackbox and OriginTrail are optional third-party integrations; their availability and retention policies may differ.

## The short version

Axiom is a **local-first firewall, network monitor and DNS policy tool**. Its firewall and DNS decisions come from Windows Firewall rules and locally loaded DNS lists/settings; they **do not depend on an online DKG lookup**. Blackbox is an optional local agent guard and a gateway for user-approved, signed threat reports. OriginTrail DKG provides an optional shared-knowledge layer with provenance and verified graph data.

**A signed report is evidence, not an automatic malware verdict.** A reported domain is not automatically promoted into a verified rule, and Axiom does not automatically turn community sightings into Windows Firewall or DNS blocks.

## Data flow and responsibility

| Stage | Owner / component | Data and action | Network required? |
|---|---|---|---|
| Observe | Axiom service / Privacy Shield / AI Analyst | Local events, blocked malware DNS requests and analyst indicators tied to observed endpoints | No for local observation; cloud AI requires its provider |
| Queue | Axiom service | Durable local preview queue with status, source and outcome | No |
| Approve | Axiom user | Allow manual reporting, then use **Share** or **Send now** to review and confirm the exact indicators and the Blackbox Reporter Terms | No until actual submission |
| Submit | Blackbox reporter, in signed-in user's session | Sends the confirmed indicator type and value, severity and evidence context with the node's reporter identity and signature | Yes for community delivery |
| Corroborate / curate | Third-party Blackbox / ecosystem participants | Independent reports, moderation, endorsement or promotion according to upstream rules | Usually yes |
| Synchronize | Local Blackbox dashboard and its configured DKG node | Fetch and compile verified graph knowledge; expose local dashboard status and graph view | Yes for updates; cached data can be read locally |
| Enforce | Windows Firewall / Axiom Privacy Shield / optional Blackbox guard | Apply local rules; Blackbox guard enforces its configured agent policy when reachable | Local enforcement does not require an online DKG lookup |

The **standalone Axiom DKG node** and the **DKG node configured by Blackbox** are not necessarily the same process or data store. Axiom displays their health separately. "Connected" to localhost proves only that an expected local endpoint responded with the documented status shape, **not** that it is synchronized with the network. When no standalone node answers and Blackbox reports its own DKG node reachable, the DKG card shows that node and labels it "DKG node reported by Blackbox"; a complete installation then skips Axiom's second, unused node.

## Which observations are eligible to be proposed?

- Privacy Shield list matches stay **local**. A blocked malware domain is recorded with its matched rule, source id/version, Axiom version, reason and timestamp for local provenance, but it is not proposed to the community: the same public URLhaus list on every install would look like independent corroboration. Advertising, analytics, telemetry and tracking detections are never candidates.
- The optional AI Analyst may propose structured malicious-role indicators only if they match remote endpoints already included in its evidence package and meet its severity/status restrictions. A value already present in Axiom's local malware-list block history is suppressed as list-derived. Text in observations, advice and free-form analysis is never scraped for arbitrary domains.
- A blocked DNS lookup proves an attempted lookup. Analyst correlations and DNS blocks stay local and require independent evidence before publication.
- Community reports require evidence of a reproducible attack or curator confirmation, a supported evidence context, and an exact, normalized public indicator. Private IPs and local DNS names are excluded.
- The reporter may reject an item under upstream policy, cooldown or consent rules. Axiom cannot guarantee acceptance or later verification.

See [AI Analyst](AI_ANALYST.md) and [Optional integrations](INTEGRATIONS.md).

## Manual reporting consent

The interactive **Complete Protection** setup includes the manual-reporting permission in its existing risk acceptance checkbox. In silent setup, specify `--allow-manual-threat-sharing` alongside `--accept-risk` to grant that permission. The user can manage it later in **Agent Protection**.

Each submission still requires confirmation. The review shows the exact indicator, severity and context. Blackbox adds the node identity and signature, and publishes under its Reporter Terms. The publication can be copied under CC0, including before a later retraction. Axiom sends a closed set of normalized fields. Local evidence, prompts, file paths, logs and policy details stay outside the report.

Blackbox's own automatic sharing is a separate setting that its dashboard and other Blackbox clients can manage. Axiom shows its status in **Agent Protection** and provides an explicit action to turn it off. Axiom's manual reporter requires automatic sharing to be off and saves acceptance of the Reporter Terms separately for its own manual submissions.

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

The service persists candidates in its local threat-share store (currently `threat-share.json`, with a maximum of 500 saved entries). Known transient failures can be marked **deferred** with exponential backoff, starting at five minutes and capped at six hours. A daily reporter cap leaves items pending. **Retries are user-initiated** and require a new confirmation. Axiom's manual reporter records delivery attempts in the Blackbox ledger and leaves them out of the Blackbox retry and renewal queues.

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

Axiom reads the **local** Blackbox dashboard, including its verified-sync and public-graph endpoints. **Sync now** asks Blackbox to start its sync and reports when a job is already running. The meter shows download and compilation counts separately. **Stalled** means Blackbox reports that these counts have stopped moving. The optional **Auto-sync** preference is **off by default**. When enabled, Axiom checks live readiness before each attempt and spaces requests by at least 15 minutes.

If the dashboard cannot provide a live meter, Axiom may display locally persisted counts as **last-known state**. A signed peer snapshot is labeled **peer preview**. Local firewall rules, stored DNS policies and previously loaded lists continue to function independently of a new graph sync.

**Important distinction:** Axiom currently displays the synchronized verified graph through the Blackbox integration; it does **not** yet use general verified/community reputation lookups as per-connection enforcement decisions. Reputation annotations do not currently change firewall rules or block connections automatically.

### RAM-Only Curator-Signed Snapshot Endpoint & LAN Peer Cache

To accelerate initial Verified Graph loading without trusting arbitrary peers or touching disk, [`VerifiedGraphPeerRelay`](../src/Axiom.Presentation/VerifiedGraphPeerRelay.cs) implements a fail-closed, two-tier RAM-only bootstrap with automatic fallback to the local Blackbox/DKG node (fail-closed unless a pinned trust key — either `VerifiedGraphPeerRelay.DefaultCuratorPublicKeyDerBase64` or `AXIOM_GRAPH_TRUST_KEY` / `AXIOM_GRAPH_CURATOR_PUBKEY` — is present):

1. **Tier (a) — Curator-signed snapshot endpoint (`DefaultSnapshotUrl` / `AXIOM_GRAPH_SNAPSHOT_URL`):** Fetches a signed manifest snapshot strictly in RAM over `https://` (or loopback `http://127.0.0.1` / `localhost` DKG snapshot gateways; remote plain `http://` is rejected) with `AllowAutoRedirect = false`, validated redirect hops (max 3 hops, rejecting protocol downgrades and non-public/private IP redirects), `10 s` timeout, `7 day` snapshot freshness (`±15 minutes` future clock-skew limit), `15 minute` failure retry cooldown, and a `4 MiB` bound. Tier (a) never opens listening sockets and can be disabled entirely via `AXIOM_GRAPH_SNAPSHOT_DISABLE=1` or `AXIOM_GRAPH_SNAPSHOT_URL=off`. Built-in publisher script: `scripts/publish-verified-graph-snapshot.ps1`.
2. **Tier (b) — Opt-in LAN peer cache (`AXIOM_GRAPH_LAN=1`, `AXIOM_GRAPH_LAN_CACHE=1`, or `AXIOM_GRAPH_PEERS`):** Disabled by default (recommended off for enterprise networks). Shares only already-verified, curator-signed manifest snapshots in RAM across the user's trusted machines with a `15 minute` freshness window (`±15 minutes` clock skew) and `2 s` I/O timeout while verifying the exact same curator signature.
3. **Zero-trust verification & automatic DKG fallback:**
   - **Pinned curator trust key (fail-closed):** Self-signed or unpinned payloads are never accepted (`"never trust because a peer claimed it"`). Every snapshot must verify against the configured pinned SPKI public key, automatically falling back to DKG if missing or invalid.
   - **Strictly RAM-only & zero reflection:** Serialization and parsing run exclusively in RAM using `Utf8JsonWriter` and `Utf8JsonReader` (`MaxDepth = 8`, max `4 MiB` per payload) with no reflection, no temporary files, and immediate rejection of any unknown JSON field.
   - **Anti-rollback & manifest integrity:** Each manifest enforces `Version`, monotonic `SequenceNumber`, `CreatedUtcTicks` (max age `7 days` for Tier (a) / `15 minutes` for Tier (b), max future skew `+15 minutes`), `MinClientVersion`, canonical `PayloadSha256Hex`, binary SHA-256 `MerkleRootHex`, and ECDSA P-256 signature verification.
   - **Passive-data whitelist (no malware / code injection vector):** Every threat record (`Identifier`, `Name`, `Category`, `Severity`, `Ecosystems`, `Source`) must match strict domain/IP/64-hex/safe-token formats; control characters, path traversal (`..`, `\`), shell metacharacters, or unrecognized categories reject the entire envelope. Only public Verified Graph entries are shared; local DNS history, connections, sessions, and host files never enter the buffer.

Other offline limits:

- If the local DNS resolver fails, saved adapter DNS may be restored or a previously configured fallback resolver may answer. **Connectivity can continue while Axiom DNS filtering is bypassed**. This is an availability trade-off, not an assurance of uninterrupted filtering.
- Agent hooks depend on a functioning local Blackbox guard. In Axiom's documented **fail-open** mode, guard failures do not block tools; Axiom displays a degraded protection state.
- Offline submission has no network destination. A queued report remains local until a permitted, user-triggered retry succeeds.
- The locally installed DKG process may be running without internet, but it cannot obtain new remote peer updates while disconnected.

## Privacy and disclosure boundary

Local history (including network metadata, blocked DNS events, AI findings and agent-guard audit records) is **not** a public dataset. Only explicitly approved, normalized indicators may be passed to the external Blackbox reporter. Axiom must not submit private network addresses, loopback or local hostnames, raw DNS browsing history, prompts, command lines, credentials, tokens, file paths, model content or session identifiers as community intelligence.

The URL sharing path discards userinfo, query strings and fragments; it also rejects private, loopback and local destinations. A URL with any non-root path is rejected by default, because paths can contain account, document or session identifiers; only a domain or root URL is shareable, and no path opt-in ships yet. External optional integrations may still make network requests when enabled. The DKG node itself can communicate with peers; localhost-only Axiom status/API calls are **not** proof that the whole integration is offline or network-silent.

See [Security model](SECURITY_MODEL.md), [Privacy Shield](PRIVACY_SHIELD.md) and [Integrations](INTEGRATIONS.md).
