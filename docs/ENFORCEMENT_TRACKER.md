# Enforcement handoff tracker

Status of the independent agent enforcement handoff (v2) and the #221–#231 remediation. Updated
2026-11-11. `verified` means behaviour was observed on a real host; unit tests alone are `addressed`.

## Remediation issues

| Issue | Status | Evidence |
|---|---|---|
| #221 manual sharing | verified | 0.10.17, no timer; per-item Share/Send now |
| #222 evidence-bound IOCs | verified | 0.10.18; prose never scanned; fails closed |
| #223 URL/IP sanitisation | addressed | 0.10.19 strips userinfo/query/fragment; domain-only default still in Draft #249 |
| #224 retry taxonomy | addressed | 0.10.20 deferred/backoff; ambiguous outcome in Draft #254 |
| #225 pinned DKG | verified | 0.10.21, lockfile, auto-update disabled |
| #226 node reuse | verified | 0.10.25 reuses Blackbox node |
| #227 endpoint identity | verified | 0.10.22 schema; Draft #253 adds owning-process check, live-tested |
| #228 provenance | verified | 0.2.0 list-only stays local |
| #229 Hermes profile | verified | 0.10.23 single resolver |
| #230 docs | verified | 0.10.24 |
| #231 read-only DKG | deferred | user-triggered Check graph only; automatic annotations await Umanitek per-indicator lookup |

## Enforcement stages

| Stage | Status | Evidence |
|---|---|---|
| B0 baseline/ADR | addressed | ADR 0009, Draft #247 |
| B1–B5 | see above | released 0.10.17–0.10.25, 0.2.0, 0.3.0 |
| E0 capability matrix | addressed | ADR 0010, Draft #255; no host is `Host deny verified` |
| E1 policy engine | addressed | `Axiom.Core/Enforcement`, Draft #252, offline + deterministic |
| E2 part 1 host mapping | addressed | `HostDecisionMapping`, Draft #256; deny shapes preserved |
| E2 part 2 hook wiring | **not started** | requires live canary and opt-in; blocked by evidence gate |
| E3 managed runner/broker | deferred | feasibility questions in ADR 0010; not claimed |
| E4 network policy | **not started** | requires live firewall test with disposable Axiom-owned rule |
| E5 UI status | addressed (basic) | Agents page cooperative badge, Draft #258; decisions list and recovery pending |

## Non-negotiable claims

- No host has `Host deny verified`; the UI shows `COOPERATIVE - NOT VERIFIED`.
- DKG reputation is not an input to the policy engine and cannot create a block.
- Managed runner, broker and OS boundary are not implemented.
- Live canary rules: temporary protected directory, explicitly loaded hook, captured payload and
  absent side effect, `MANUAL REQUIRED` when it cannot be automated.
