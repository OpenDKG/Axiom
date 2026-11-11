# Axiom roadmap — current development status

**Baseline:** 0.10.23, 2026-11-11. See [release notes](RELEASES/0.10.23.md) for the most recent recorded checks. This is a high-level status overview, not evidence that every integration has been end-to-end tested.

## Implemented in the current Windows build

| Capability | What exists | Verification boundary |
|---|---|---|
| Windows monitoring and history | IP Helper socket inventory, attribution, measured throughput and local retained SQLite history | Some ownership and per-process byte data remain partial |
| Windows Firewall | Axiom Shield / consented service, Axiom-owned rule creation/removal, read-back, auditing, recovery | OS policy conflicts and multi-host tests remain relevant |
| Privacy Shield | Local DNS filtering, categories, catalogued sources, explicit adapter UAC helper, DNS restore/fallback | Browser DoH, direct IP connections, VPN DNS and fallback resolver bypass filtering |
| AI Analyst | Manual analysis, optional automatic analysis, bounded evidence, structured indicators and verifier option | Model output is untrusted and not an enforcement decision |
| Agent safety | Optional Blackbox guard, supported agent hooks, protected paths, canary checks and local audit | Host-level hook loading and actual blocking require separate runtime evidence |
| Blackbox + DKG integration | Optional local installers, module probes, dashboard, verified graph view and sync | The local node can be online while graph synchronization is stale or unavailable |
| Community reporting | User-reviewed, normalized threat preview queue, signing through Blackbox, deferred failures | No automatic report publication, no automatic rule promotion |
| Avalonia Windows desktop | Current main Windows GUI; WPF fallback retained | Linux and macOS monitoring/firewall backends are not yet provided |
| Microsoft Store packaging | Core-only MSIX build path | Submission/certification and store distribution are separate |

## Planned / incomplete / needs verification

| Area | Next work |
|---|---|
| Read-only per-connection reputation | Use **cached** verified/community context as an annotation, not as a synchronous block or an OS-rule change; [issue #231](https://github.com/a-51-50/Axiom/issues/231) |
| Threat provenance | Determine whether external VM promotions retain original Axiom reporter/publisher/time evidence; upstream design and funding decision required |
| Offline fault validation | Test power loss, restart, DNS resolver failure, Blackbox guard outage and graph cache freshness independently |
| Agent integration hardening | Run each supported host with real deny canaries and version-specific tests; do not infer protection from installed hook files |
| Full performance coverage | ETW and per-process byte accuracy, stress, sleep/resume, multi-NIC/VPN and 24-hour soak |
| Cross-platform backends | Windows Avalonia GUI exists; Linux and macOS require separate service, firewall, DNS and packaging implementations |
| Release distribution | Signed Windows artifacts, independent supply-chain attestation and Microsoft Store certification |
| Documentation | Align implementation, security model, onboarding and versioned test evidence; historical baseline documents remain clearly labelled |

## DKG, community sharing and VM funding

Axiom's local firewall/DNS protection does not depend on VM publication. Approved reports can be sent through Blackbox to the community sharing system, while external curators may publish selected verified content. **Axiom currently does not implement direct paid VM publication or assume TRAC/gas fees.** Any long-lived paid publishing, provenance-retention workflow or cost sponsorship needs an explicit upstream agreement. See [threat intelligence](THREAT_INTELLIGENCE.md).

## Project ground rules

- Local-first core; no dependency on the DKG/Blackbox cloud/peer network for connection enforcement.
- Optional integrations must be opt-in and expose exactly what can leave the machine.
- Distinguish `DETECTED`, `CONNECTED`, `SYNCED`, `VERIFIED`, `BLOCKED` and `PROTECTED`; do not infer one from another.
- Evidence-backed threat labels, protection tests, signed data validation and false-positive handling.
- Preserve third-party agent user state; change only marker-owned files with backup/restore where supported.
- Each release should publish its own build/test evidence and known limitations. Older test plans remain historical records, not the current source of truth.
