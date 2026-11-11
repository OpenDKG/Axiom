# ADR 0009 - Agent enforcement baseline and G0/G1 gap register

- **Status:** proposed (Draft PR, no behavior change)
- **Date:** 2026-11-11
- **Baseline:** `main` at `4414474`, Axiom `0.3.0`
- **Related:** handoff "Independent Agent Enforcement Layer v2"; issues #221-#231

## Context

The v2 handoff asks for a separate, opt-in agent enforcement layer on top of the existing
Blackbox-assisted hooks, while first remediating the external-review issues and making DKG
lookups advisory-only. Its review snapshot is `c8e71c9` / Axiom `0.10.15` (2026-11-10), where
issues #221-#231 were open.

That snapshot is stale. This ADR records what is actually in `main` before any enforcement code is
written, separates confirmed behavior from unverified assumptions, and lists the gaps that still
block a truthful enforcement layer. It changes no runtime behavior.

## Repository and issue inventory

- `main` at `4414474` (after the 0.3.0 release and CI changes); no open pull requests.
- Issues #221-#230 are **closed** with releases:
  - #221 manual Share / no timer: 0.10.17, PR #233
  - #222 structured evidence-bound indicators: 0.10.18, PR #234
  - #223 URL/IP sanitisation: 0.10.19, PR #235
  - #224 deferred retry / cap preserved: 0.10.20, PR #236
  - #225 pinned DKG 10.1.0 and disabled auto-update: 0.10.21, PR #237
  - #227 schema/network validation for module probes: 0.10.22, PR #238
  - #229 one resolved Hermes/Blackbox profile: 0.10.23, PR #239
  - #230 documentation drift and Start-button copy: 0.10.24, PR #241 (docs PR #240)
  - #226 reuse Blackbox's DKG node and skip the second node: 0.10.25, PR #242
  - #228 list-only matches stay local, local provenance, AI suppression: 0.2.0, PR #244
- #231 remains open. A limited user-triggered **Check graph** action shipped in 0.3.0 (PR #246):
  local Blackbox `/api/threat`, bounded requests and cache, explicit Unknown, no badges, no
  automatic annotations.
- Open epics/platform issues: #116, #119, #120, #150, #151, #175.

## Verified current behavior

| Area | Current behavior | Evidence |
|---|---|---|
| Threat-share publication | Individually approved Share or Send now; no timer; cap leaves items pending | `AgentsPageViewModel`, 0.10.17 |
| AI indicators | Structured `indicators`; evidence-bound; prose never scanned | `ThreatShareIocExtractor`, 0.10.18 |
| AI provenance failure | Fails closed: no queue when local block-history lookup is unavailable | `AiAnalystPageViewModel`, 0.3.0 |
| List-only matches | Never published; stored locally with source/version/Axiom version/reason/timestamp | `PrivacyShieldController`, `PrivacyShieldBlockedEvent`, 0.2.0 |
| URL normalisation | Userinfo, query and fragment removed; private/special hosts rejected | `ThreatShareVocabulary`, 0.10.19 |
| Reporter failures | Deferred with attempts/backoff; explicit refusal Rejected; cap preserved | 0.10.20 |
| Module status | DKG requires documented identity and known network id; Blackbox requires graph-status fields | `OptionalModuleProbe`, 0.10.22 |
| DKG install | Pinned 10.1.0, embedded lockfile, `npm ci`, auto-update disabled | `OptionalModuleInstaller`, 0.10.21 |
| DKG node ownership | Complete install reuses Blackbox's reachable node; standalone skipped | `SetupInstaller`, 0.10.25 |
| Hermes profile | One resolver for reporter, consent, mode, local state and uninstall | `BlackboxPaths`, 0.10.23 |
| Check graph | User-triggered, local-only, 5 s/10 min/256 cache, Unknown not clean, no badges | `BlackboxGraphLookup`, 0.3.0 |
| Enforcement layer | Not implemented. Hooks remain cooperative and fail open; no deterministic policy engine or managed broker | `AgentHookScript`, `docs/SECURITY_MODEL.md` |

Build and tests at baseline: `dotnet build Axiom.sln -c Release` 0 warnings/0 errors;
`dotnet test Axiom.sln -c Release` 574 passed. These are unit/integration tests; no live host
deny test or OS-boundary proof is included.

## Gap register (handoff acceptance is stricter than the closed issues)

These are real gaps against the v2 acceptance criteria. They are **not** regressions of the closed
issues; they need separate, scoped work.

### G0 gaps

1. **#223 URL paths remain shareable by default.** The sanitizer removes credentials/query/fragment
   and rejects private hosts, but keeps the URL path. The handoff asks for domain-only by default,
   with explicit narrow opt-in for URL paths. The AI extractor can therefore queue a path that may
   contain account or document identifiers.
2. **#227 endpoint identity is schema-level, not process-level.** The probe validates response
   shape and network id, but does not prove the listening process is the expected Blackbox/DKG
   executable. A local squatter that reproduces the schema is still accepted. The handoff asks for
   owning-process/instance metadata where feasible and says UNKNOWN when unverifiable.
3. **#221 consent migration.** Auto-send was removed, which is safe, but there is no separate
   `auto_publish` preference with a conservative migration for legacy profiles. The current default
   is manual-only, so no unreviewed report is sent; a future auto-publish feature needs an explicit
   off-by-default setting and disclosure.

### G1 gaps

4. **#224 ambiguous submission outcome.** A timeout after the reporter may have signed/published is
   recorded as Deferred. A manual retry can duplicate a report because there is no persisted
   idempotency key/reconciliation, and the CLI only reports `Already shared` when it answers.
   The handoff explicitly forbids blind retries after an ambiguous outcome.
5. **#231 per-indicator evidence.** Check graph is honest but usually Unknown because Blackbox
   `/api/threat` returns no per-IOC entries for ordinary domains on this host. Automatic badges
   remain deferred until Umanitek provides a documented per-indicator/batch lookup with tier,
   source, reporters and provenance (UAL/timestamp).
6. **#229 runtime proof.** The resolver and local layout are verified on this host, but there is no
   automated check across env overrides, missing profiles or multiple homes. The current behavior
   is read-only discovery; no migration is attempted.

### Enforcement-layer gaps

- No shared typed request/verdict contract, deterministic policy engine or offline rule precedence.
- No host capability matrix separating `Configured`, `Loaded`, `Guard available`, `Guard failed`,
  `Host deny sent`, `Host deny verified`, `OS/broker enforced`.
- No live-host deny evidence for any supported host. Codex remains unverified.
- No managed runner, restricted token/AppContainer boundary or trusted file broker.
- No selective fail-closed mode for managed protected operations.
- UI does not separate detector health from enforcement strength.

## Decisions

1. **B0 (this ADR) changes no behavior.** Enforcement work starts only after the G0 gaps above have
   scoped fixes or explicit, truthful limitation states.
2. **No kernel driver, TLS interception, root CA, blanket file ACL deny, or user-file ownership
   change.** Strong isolation is deferred until an opt-in restricted runner/broker is proven and
   documented.
3. **Detection is not enforcement.** Blackbox guard verdicts, DKG annotations and Check graph results
   must never produce a green `VERIFIED BLOCKING` label without live host/OS evidence.
4. **DKG lookups stay advisory.** They cannot mutate firewall or DNS policy. No network call on the
   per-connection hot path; use a bounded local cache.
5. **Publishing remains manual.** No new DKG report is signed or sent in development or tests. Any
   future auto-publish is a separate opt-in with permanent-publication disclosure.
6. **User data is immutable in this workstream.** No cleanup of agent history, profiles, databases,
   keys or hooks; hook installs keep merge/backup and reparse-point protections.
7. **Draft PRs only.** Each workstream gets a scoped branch and Draft PR with tests and rollback;
   no automatic merge or external publication.

## Proposed delivery order

| Stage | Scope | Gate |
|---|---|---|
| B0 | This baseline/gap register, issue-to-PR tracker | Reviewed; no behavior change |
| B2 | Domain-only URL sharing with explicit path opt-in or rejection; tests | No URL path enters the queue by default |
| B3 | Endpoint owner/instance identity where feasible; UNKNOWN otherwise | Fake schema listener cannot receive settings |
| B4 | Persisted idempotency/reconciliation for ambiguous reporter outcomes | No duplicate signed report on retry |
| E0 | Enforcement ADR: host capability matrix, restricted-runner/broker feasibility | Proof plan, not claims |
| E1 | Typed contracts + deterministic policy engine with mocked inputs | Offline unit tests, no default behavior change |
| E2 | OpenCode/OpenChamber and Claude wiring; preserve Blackbox deny shapes | Live host deny evidence before any verified label |
| E3 | Managed runner/broker feasibility and only then implementation | OS boundary demonstrated, or deferred |
| E4 | Network policy reusing Axiom-owned firewall rules | Read-back verified, reversible |
| E5 | Enforcement UI/audit and truthful state model | No detection/enforcement conflation |

B2/B3 are the next G0 work. E0/E1 can proceed in parallel with mocked inputs. #231 remains a
G2 feature and does not block offline policy evaluation.

## Test and evidence inventory

- Existing automated coverage: threat-share model/extractor tests, service queue tests, module
  probe tests, DKG install/version tests, Blackbox path tests, Check graph lookup tests.
- Not run/available in this baseline: real-host deny canary, OS-boundary isolation, managed broker,
  DKG per-IOC verified/community lookup, multi-profile #229 matrix.
- Live host state during this inventory: desktop 0.3.0, service 0.2.0 running, Privacy Shield
  adapter `127.0.0.1, 192.168.0.1`. No report was submitted and no protection setting was changed.

## Rollback and safety

- This ADR is documentation only; reverting the PR restores no runtime state.
- Future enforcement changes must ship disabled by default with an explicit opt-in, a recovery path
  and tests for service restart, corrupted policy, timeout and interrupted approval.
- No signed/public report may be produced during tests; fixtures use synthetic indicators and
  temporary profiles.

## Follow-up issues to create with the corresponding Draft PRs

- G0: enforce domain-only sharing by default and reject/opt-in URL paths (#223 follow-up).
- G0: endpoint owning-process/instance identity for module probes (#227 follow-up).
- G1: ambiguous reporter-outcome idempotency/reconciliation (#224 follow-up).
- G2: per-indicator/batch local lookup request to Umanitek (#231).
- E0/E1: policy engine and host capability matrix (new).
