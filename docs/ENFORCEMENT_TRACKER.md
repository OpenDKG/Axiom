# Enforcement handoff tracker

Status of the independent agent enforcement handoff (v2) and the #221–#231 remediation. Updated
2026-11-14. `verified` means behaviour was observed on a real host/VM; unit or mocked canary tests
alone are `addressed` until run live against a guest VM build.

## Remediation issues

| Issue | Status | Evidence |
|---|---|---|
| #221 manual sharing | verified | 0.10.17, no timer; per-item Share/Send now |
| #222 evidence-bound IOCs | verified | 0.10.18; prose never scanned; fails closed |
| #223 URL/IP sanitisation | addressed | 0.10.19 strips userinfo/query/fragment; Batch 1 (`3d2b2f7`) adds shared CDN/resolver/provenance gating |
| #224 retry taxonomy | addressed | 0.10.20 deferred/backoff; Batch 1 (`3d2b2f7`) adds explicit retract taxonomy & CC0 notice |
| #225 pinned DKG | verified | 0.10.21, lockfile, auto-update disabled |
| #226 node reuse | verified | 0.10.25 reuses Blackbox node |
| #227 endpoint identity | verified | Batch 1 (`3d2b2f7`) `DnsProcessConnectionCorrelator` adds PID + TTL + resolver correlation |
| #228 provenance | addressed | Batch 1 (`3d2b2f7`) 5-class evidence provenance (`ThreatShareEvidenceClass` / `ThreatShareProofGrade`) |
| #229 Hermes profile | verified | 0.10.23 single resolver |
| #230 docs | verified | 0.10.24 |
| #231 read-only DKG | addressed | `DkgContextAnnotator` offline cached context lookup (`Unknown != Clean`, local false-positive overrides, never enforces) |

## Enforcement stages

| Stage | Status | Evidence |
|---|---|---|
| B0 baseline/ADR | addressed | ADR 0009, Draft #247 |
| B1–B5 | see above | released 0.10.17–0.10.25, 0.2.0, 0.3.0 + Batch 1 (`3d2b2f7`) |
| E0 capability matrix | addressed | ADR 0010, Draft #255; no live host advertised as `OS_DENY_VERIFIED` without runtime proof |
| E1 policy engine | addressed | `Axiom.Core/Enforcement`, offline + deterministic, community-only advisory gate (`7e38a1c`) |
| E2 part 1 host mapping | addressed | `HostDecisionMapping`, `HostEnforcementAdapter`, `EnforcementReceiptV1` (`7e38a1c`) |
| E2 part 2 hook wiring & controller | addressed | `EnforcementController` (`enforcement.status`, `enforcement.evaluate`, `enforcement.receipts`) & disposable sentinel canary verifier (`7e38a1c`); VM integration continuing on `fix/agents/module-prerequisite-bootstrap` |
| E3 managed runner/broker | prototype / feasibility | `TrustedFileBroker` + `WindowsRunnerAndBrokerProbe` + ADR 0012; same-token host limits documented |
| E4 network policy | addressed | `AgentFirewallRulePlanner` + `AgentFirewallEnforcer` (scoped rules, community advisory refusal, dual-destination canary for `OS_DENY_VERIFIED`, rollback) |
| E5 UI status | addressed | `EnforcementSurfaceState.FromReceiptsAndStatus` distinguishes `UNAVAILABLE`, `HOST_DENY_SENT - NOT VERIFIED`, `HOST_DENY_VERIFIED (CANARY)`, `OS_BOUNDARY_VERIFIED` |

## Non-negotiable claims

- No host or OS rule is claimed as `HOST_DENY_VERIFIED` / `OS_DENY_VERIFIED` without runtime proof; hooks without proven deny verification are surfaced as `COOPERATIVE - NOT VERIFIED`.
- DKG reputation is not an input to the policy engine and cannot create a block.
- Managed runner/broker (`E3`) remains a feasibility prototype (`TrustedFileBroker` / `WindowsRunnerAndBrokerProbe`); full E4 OS boundary enforcement requires elevated Windows VM proof (see [validation/OS_ENFORCEMENT_AND_OFFLINE_RUNBOOK.md](validation/OS_ENFORCEMENT_AND_OFFLINE_RUNBOOK.md)).
- Live canary rules: temporary protected directory, explicitly loaded hook, captured payload and
  absent side effect, `MANUAL REQUIRED` when it cannot be automated.
