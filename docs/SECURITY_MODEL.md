# Axiom security and privacy model

**Applies to:** Axiom 0.10.23 for Windows. Axiom is a security tool under active development and cannot guarantee prevention of every threat.

## Trust boundaries and responsibilities

| Component | Runs where | Main authority | Important boundary |
|---|---|---|---|
| Avalonia desktop | Signed-in Windows user | UI, local display, explicit user actions | No silent elevation; no generic remote control |
| Axiom service | Local Windows host (installed Shield service: LocalSystem; portable monitoring: per-user service/process) | Observations, bounded stores and privileged Axiom rule coordinator | Service validates typed IPC; Windows Firewall does actual enforcement |
| Windows Firewall | Windows OS | Applies persistent rules | Axiom manages only its own named rules |
| Privacy Shield | Local Axiom service | Loopback DNS resolution and blocklists | DNS filtering only; it is not an inline network firewall |
| Blackbox guard/dashboard | Optional local third-party module | Agent hook decisions, audit, graph cache, reporter integration | Mode and functioning hook/guard determine protection |
| DKG node | Optional separate process | Network sync and external knowledge | May contact peers; local status does not prove sync |
| AI provider / community feed / VirusTotal | Opt-in third-party endpoints | External inference or reputation evidence | May transmit bounded data upon user's explicit configuration/action |
| Read-only MCP adapter | Local stdio process | Read-only queries through Axiom pipe | No arbitrary file, shell, process kill, OS-rule write or generic execution tool |

## Local IPC and privileged firewall writes

The Named Pipe `\\.\pipe\Axiom.Service.v1` uses an explicit DACL, caller SID verification, bounded NDJSON requests/responses and rate limits. The service rejects unsupported or unauthorized commands; its IPC is not a remote HTTP management API.

Axiom Shield requires explicit consent and an installed privileged Windows service. Only that service can add/remove Axiom-owned Windows Firewall rules (form `Axiom::{id}::{OUT|IN}`), followed by read-back and audit; it must not edit unrelated user or third-party firewall rules. An installed rule remains Windows-managed if the UI closes or the service stops. Turning Shield off deliberately removes Axiom-owned rules. The documented legacy environment overrides exist for isolated testing, **not** for normal users. See [firewall recovery](FIREWALL_RECOVERY.md).

## What is stored locally

| Data | Where / retention | External transmission |
|---|---|---|
| Network flow metadata and measured traffic history | Axiom SQLite, with versioned retention (network flow history commonly 30 days) | Not automatically shared |
| Axiom-owned firewall decisions and rule audit | Local service database/configuration | Not automatically shared |
| Privacy Shield settings and compiled DNS rules | Local installed-service data (ProgramData); portable mode may use LocalAppData | List **downloads** contact selected upstream sources |
| Blocked DNS request history | Bounded local blocked-event store (only blocked requests, with optional best-effort app identity); allowed requests are not retained as blocked history | Not published as raw browsing history |
| AI Analyst findings/settings | Bounded local findings; configured API keys DPAPI-protected for current user | Opt-in analysis may send sanitized evidence to the selected provider |
| Threat-sharing candidates/outcomes | Local `threat-share.json` preview queue, capped at 500 saved items | Only approved normalized candidates can be submitted through Blackbox |
| Agent hook evidence and Blackbox audit/profile | Separate local Blackbox/Hermes stores, managed partly by upstream components | Third-party Blackbox reporting/network sync follows its own consent and configuration |
| Reporter identity, signing key and sharing consent | Resolved local Hermes/Blackbox profile | Reporter uses signing identity for approved reports; do not publish private key |
| Optional VirusTotal/community feed keys | Windows DPAPI for current user where implemented | Requests go to selected endpoint only when configured and invoked |

Local data is **not automatically public**. "No telemetry" means Axiom does not implement its own analytics/data-sale pipeline; it does **not** mean that enabled DKG, Blackbox, AI or reputation integrations are network-silent.

Axiom's own database is not generally encrypted at rest. File ACLs, restricted service directories and DPAPI for selected credentials do **not** mean every local history file is encrypted. The local Blackbox dashboard can expose more raw audit detail than the redacted Axiom UI view; protect its endpoint and profile accordingly.

## What can leave the machine?

| Capability | Default / trigger | Typical outbound data | Notes |
|---|---|---|---|
| Core monitoring, local firewall | Local, no account needed | None required | Continues without DKG, Blackbox or internet |
| DNS resolution with Privacy Shield | User enables/configures resolver and points adapter at it | Allowed DNS questions to selected upstream resolver | Local blocked names receive NXDOMAIN; bypass/fallback can alter filtering |
| Blocklist update | User updates selected sources | HTTPS source requests | Existing local rules retained on failed source update |
| AI Analyst | Explicitly configured and invoked; automatic analysis optional and off by default | Sanitized evidence about selected process/connections | Remote provider sees the evidence; local OpenCode route may use its own provider |
| VirusTotal hash lookup | Opt-in API key and user checks hash | File SHA-256, not the file bytes | Provider can correlate lookups |
| Community feed | Configured HTTPS URL / Refresh feed | Network fetch and optional bearer token | Starter feed is bundled and offline |
| DKG/Blackbox installation and sync | User elects to install/start/enable integration | Network package downloads, DKG peer traffic and sync metadata | Localhost API reads are local, but the underlying node is networked |
| Community IOC report | Sharing consent and explicit **Share** / **Send now** | Signed, normalized threat indicator and reporter identity | No automatic timer publication; queueing alone is not transmission |
| VM publication | Not implemented directly in Axiom | None by Axiom | Any TRAC/gas-funded publishing belongs to an external, explicitly approved integration |

The normalized IOC sharing path excludes loopback, private/local/special-use destinations and drops URL userinfo, query and fragment. It is **not** authorized to publish raw prompts, network browsing histories, private IPs, command lines, files, credentials or session IDs. See [threat intelligence](THREAT_INTELLIGENCE.md).

## Offline operation and safety trade-offs

- Existing Axiom-owned Windows Firewall rules remain active under Windows, even when Axiom's UI is closed or its optional network services are down.
- Locally compiled DNS policy continues working **while the Axiom resolver is running and receiving queries**. If it stops, a saved-adapter restore or fallback DNS may restore name resolution **without filtering**. This is a deliberate connectivity failsafe.
- Cached DKG/Blackbox verified-graph data is last-known evidence. No remote refresh occurs without connectivity. `CONNECTED` (local module), `SYNCED` (graph state), `VERIFIED` (specific data) and `PROTECTED` (guard/enforcement) must not be used interchangeably.
- An unavailable Blackbox guard causes supported hooks to fail open by design. Do not claim agents are protected in this state.
- A failed reporter call can be retained as a deferred local candidate. Retry requires a later explicit sharing action; turning the internet back on does not license silent sending.

## Protection and limitations

| Threat / failure | Mitigation | Remaining limitation |
|---|---|---|
| Other-user or remote pipe invocation | DACL, SID check, bounded commands | Same-user compromise remains an important boundary |
| Unexpected firewall changes | Explicit Shield consent, Axiom-only identities, read-back and audit | Administrator/Windows policy can override; GUI status must be verified |
| DNS outage after resolver stop | Adapter snapshot, safe fallback and service restore failsafe | DNS may bypass Privacy Shield while online connectivity survives |
| Untrusted AI analysis or malicious text | Structured bounded evidence, model output treated as untrusted, no executable AI action field | Model findings can be wrong; do not auto-block |
| Threat-graph poisoning / false positives | User-reviewed IOC reporting and independent upstream curation | Signed and consensus-endorsed claims are not automatically factual |
| Leaking sensitive agent/user data | Local-first collection, sanitized indicator pipeline, explicit submission | Optional cloud/Blackbox/DKG components have their own processing/privacy terms |
| Misleading status LEDs | Distinct health/sync/hook/canary states | A hook file or localhost listener alone does not prove active protection |
| Tampered binaries / supply chain | Pinned dependencies and installer hash verification | Portable public binaries are not yet Authenticode-signed; hashes alone are not publisher identity |
| Unexpected changes to agent configuration | Marker-owned hooks, backups, user-state fingerprinting and restoration attempts | Some third-party agent hook APIs/versions remain unstable |

## Supported packaging modes

- Portable/desktop setup: may run local monitoring without a registered service; Shield setup and optional integrations involve further steps and permissions.
- Complete installation: explicitly selected Blackbox/DKG/hook installers; installation and cloud/peer communication may require network access and additional consent.
- Microsoft Store MSIX: core-only; Blackbox/DKG installers and agent hooks excluded. See [Store](STORE.md).

## Vulnerability reporting

Use [SECURITY.md](../SECURITY.md) and the repository's private GitHub security advisory workflow. Never publish real keys, user paths, database exports or private network details in a public bug report.

## Enforcement status in the Agents page

The Agents page opens with an enforcement card that separates detector health from enforcement
strength:

- **COOPERATIVE - NOT VERIFIED** is the only state this build may show. A Blackbox guard verdict,
  an installed hook file or a passing unit test does not prove that a host refused an operation.
- The card states that the managed runner and file broker are not implemented (ADR 0010) and that
  the offline policy engine exists in the library but is not wired to hooks.
- `VERIFIED BLOCKING` can only appear after a live host canary proves the deny and the absent side
  effect, or after an OS boundary is demonstrated.
