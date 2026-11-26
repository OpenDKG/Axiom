# Axiom Privacy Policy

**Effective date:** 2026-11-26
**Website policy:** https://opendkg.org/privacy/
**Contact:** contact@opendkg.org

## 1. Summary

Axiom is a local-first network monitor, firewall policy manager, and AI coding agent protection console affiliated with the OpenDKG open-source initiative.

- **No telemetry or user accounts:** OpenDKG and Axiom do not collect usage analytics, crash telemetry, advertising identifiers, or account profiles.
- **Local storage by default:** Network history (`axiom.db`), local settings, firewall baselines, and non-sensitive hook metadata (`agent-evidence.jsonl`) remain on your device and can be deleted at any time.
- **Network features:** Some features that connect to the network are **on by default**, including after a Complete or Light install. Section 2 lists them.

## 2. Network Features and Local Data

Core local monitoring operates without sending telemetry. Outbound network connections occur for the features below. Items 2 to 4 are active without a separate opt-in.

1. **Automatic Threat Sharing via Blackbox and OriginTrail DKG (Strict Opt-In / Sharing Off by Default)**
   - "Off by default" here applies to sharing only. A default Windows Setup still installs and starts Blackbox and a DKG node (item 4).
   - Automatic community threat sharing is **unchecked (off) by default** in both Setup and First-Run setup. You must explicitly opt in (or enable it later on the Agents page / `--enable-automatic-threat-sharing`) before Axiom publishes indicators.
   - Shared sightings contain sanitized indicators and structured threat metadata; local custom rules and local credentials are excluded.
   - Public CC0 OriginTrail DKG replicas may keep published sightings even after retraction.
   - Turning automatic sharing off keeps local Blackbox guard blocking active without publishing sightings.

2. **Release Update Checks (On by Default, Toggleable)**
   - Axiom queries GitHub Releases (`https://api.github.com/repos/OpenDKG/Axiom/releases/latest`) on startup, every 15 minutes while the app runs, and when you click *Check for updates now*. Turn the automatic check off under *Settings -> Updates -> Check for updates*.
   - No installation ID or hardware identifier is sent; GitHub receives standard HTTP transport metadata and the `Axiom/<version>` User-Agent header.

3. **Verified Graph Curated Snapshot (Read-Only Fetch / Disableable)**
   - When Threat Intelligence peer relay initialization runs, Axiom can fetch a signed curator-verified snapshot from `https://github.com/a-51-50/axiom-verified-graph/releases/download/verified-graph-latest/verified-graph-snapshot.json` (ECDSA P-256 signature verified).
   - No local telemetry or query payload is uploaded; disable anytime via `AXIOM_GRAPH_SNAPSHOT_DISABLE=1` or `AXIOM_GRAPH_SNAPSHOT_URL=off`.

4. **On by Default After a Complete or Light Install**
   - In a Windows Optional install you choose these yourself.
   - **Privacy Shield DNS:** turned on with the Strict profile and all catalogued blocklist sources. Axiom **points your network adapters' DNS at its own local resolver (`127.0.0.1`)**. Allowed DNS queries are forwarded over DNS-over-HTTPS to **both default upstreams, Cloudflare (`1.1.1.1`) and Quad9 (`9.9.9.9`)**, unless you change them. Blocklists are downloaded from their publishers and updated automatically every 24 hours.
   - **Community Feed:** Setup saves the feed as enabled, with its auto-sync setting on, using the recommended bundle. When the desktop app starts with the feed enabled, it downloads the lists in that bundle over HTTPS: a bundled offline starter list, a list from `botvrij.eu`, and a list hosted in a personal repository on GitHub. These hosts receive standard request metadata such as your IP address.
   - **DKG node and Blackbox (Complete install only):** Complete is the default mode of Windows Setup, and it installs and starts Blackbox and an OriginTrail DKG node. If Blackbox reports its own DKG node reachable, Setup does not add a second one. This causes network traffic by default: the DKG node package is downloaded from npm; the Blackbox installer is downloaded from Umanitek (`https://blackbox-w.umanitek.ai`) and run only if it matches a pinned hash (that third-party installer may download more); Blackbox's Python packages are downloaded from PyPI; Setup may install missing prerequisites with winget; and a running DKG node exchanges traffic with network peers (Axiom sets up its own node for the testnet). These hosts and peers receive standard network metadata such as your IP address. A Light install skips both. On Linux and macOS, the one-command installer defaults to Light and installs both with `--complete`. Installing them does not turn on automatic threat sharing (item 1).

5. **Opt-in External Integrations (Off by Default)**
   - **VirusTotal (`VT Check`):** Submits only the SHA-256 hash of a file you explicitly select using your own API key; files are never uploaded.
   - **AI Analyst:** Off until you set it up. No AI provider endpoint or model is configured by default. When you run it (or turn on automatic analysis), the provider you chose receives the prompt and an evidence package about current connections. The package includes application names, program paths, process IDs, local and remote addresses and ports, parent processes, signer and product details, **process command lines**, hosted Windows service names, a summary of local connection history, and details of this computer's network: **local IP addresses, subnets, gateway addresses and the DNS suffix**. The *redact paths* setting (on by default) shortens only the program path field to a file name. Command lines are passed through a pattern-based sanitiser, which cannot guarantee that they contain no paths or secrets.

6. **Local Retention and User Deletion**
   - Network flow history in `axiom.db` is kept for 30 days. The installed service stores it in its machine-wide data folder (`%ProgramData%\Axiom` on Windows), which needs administrator rights to change. Per-user files live under `%LOCALAPPDATA%\Axiom` (`$XDG_DATA_HOME/axiom` on Linux, `~/Library/Application Support/Axiom` on macOS).
   - *Settings -> Local data & privacy -> Clear local logs & cache* deletes only per-user items: the `logs`, `evidence`, `cache` and `snapshots` folders, `agent-evidence.jsonl*` and `history.db*`. It **does not remove** `axiom.db`, the firewall rule audit or the process-spawn audit.
   - These records have **no retention limit**; Axiom does not delete old entries:
     - the firewall rule audit (the `rule_audit` table in `axiom.db`), which records the Windows SID or user ID of the account that made each change;
     - the process start audit, `process-spawn-audit.jsonl` (Windows), stored in the machine-wide data folder when the service runs as a Windows service.
   - To remove all data on Windows, uninstall and choose to remove data (checkbox or `--remove-data`). Without that choice, history and settings are kept.

## 3. Third-Party Services

Optional third-party components and services (including Umanitek Blackbox, OriginTrail DKG nodes, GitHub, Cloudflare, VirusTotal, and external DNS or model providers you configure) operate under their own privacy policies and terms.

## 4. Regional Disclosures (EU, Switzerland, and United States)

### European Union and EEA (GDPR)

- **Legal bases:** Under Art. 6(1) GDPR, optional Blackbox/DKG threat sharing and opt-in integrations rely on your **consent** (Art. 6(1)(a)), which you may withdraw anytime in Axiom settings. Responding to inquiries sent to `contact@opendkg.org` relies on **legitimate interests** (Art. 6(1)(f)).
- **Rights:** Where OpenDKG holds personal data (for example, correspondence sent to `contact@opendkg.org`), you may request access, rectification, erasure, restriction, portability, or lodge a complaint with your local EU/EEA supervisory authority. Local data on your device stays under your control.

### Switzerland (revFADP / nDSG)

- Under Art. 19 of the Swiss Federal Act on Data Protection (revFADP), note that GitHub, Cloudflare, decentralized DKG peers, and optional third-party providers operate infrastructure outside Switzerland (including the EU and United States).
- You may request access to or deletion of correspondence held by OpenDKG and may contact the Swiss Federal Data Protection and Information Commissioner (FDPIC / EDÖB).

### United States (CCPA/CPRA and Federal Transparency)

- OpenDKG and Axiom do **not** sell personal information, do **not** share personal information for cross-context behavioral advertising, and do **not** track users across third-party apps or websites.
- California and other US residents may contact `contact@opendkg.org` to request access to or deletion of correspondence held by OpenDKG.

## 5. Contact

- **Email:** contact@opendkg.org
- **Web privacy policy:** https://opendkg.org/privacy/
- **Issues:** https://github.com/OpenDKG/Axiom/issues (avoid posting personal data or private paths; see [SECURITY.md](SECURITY.md))
