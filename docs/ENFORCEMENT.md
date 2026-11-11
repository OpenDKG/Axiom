# Axiom agent enforcement policy engine

**Status:** implemented as a library only (stage E1 of the independent enforcement handoff). It is
**not wired** to any agent hook, host adapter, UI page, Windows Firewall rule or DKG lookup. Nothing
in the running application calls it yet.

## What this slice contains

| Piece | Type | Purpose |
|---|---|---|
| Typed request | `AgentActionRequest` | Identifiers, action kind, target/process, parent request, host timestamp |
| Typed verdict | `AgentActionVerdict` | Decision, rule, reason code, available strength, approval flag |
| Capabilities | `EnforcementCapabilities` | Strongest control that actually exists on the host |
| Guard signal | `BlackboxGuardSignal` | Optional Blackbox `block` verdict, with an explicit "unavailable" state |
| Policy | `EnforcementPolicy`, `AgentEnforcementPolicy`, `EnforcementRule`, `ProtectedResource` | Offline user-owned rules |
| Evaluator | `EnforcementPolicyEvaluator` | Deterministic decision, first-match rules, idempotent retries |
| Audit | `EnforcementAuditLog`, `EnforcementAuditEvent`, `EnforcementAuditRedactor` | Bounded, hashed local records |
| Tests | `tests/Axiom.Core.Tests/EnforcementPolicyEvaluatorTests.cs` | Precedence, identity, guard, boundary, idempotency, redaction |

## Precedence

The evaluator applies this order, matching the handoff specification:

1. Malformed request → `Unavailable` (`ENF-INVALID-REQUEST`). No rule is consulted.
2. Protected resource handled by a real boundary (`OsBoundary`, `TrustedBroker`, or a proven
   `HostHook`) → `Block`, even when an allow rule matches.
3. Protected resource with no boundary → `Ask` in protect-selected/ask modes, otherwise `Audit`.
   It is never reported as a verified block.
4. Explicit Blackbox `block` → `Block`, overriding allow rules.
5. First matching user rule → `Allow`, `Ask` or `Block`.
6. No matching rule → `Audit` (monitor), or `Ask` in ask mode.

An agent identity that is not listed in the policy inherits no rules, so it cannot reuse another
agent's allow decision.

## Invariants

- **Determinism:** the evaluator reads no clock, network or file system. The verdict timestamp is
  copied from the request, so identical inputs give identical verdicts.
- **Idempotency:** a repeated `RequestId` returns the first verdict; a retried hook event cannot
  flip a decision. The cache is bounded to 1024 entries.
- **Observation is not enforcement:** a `Block` with `AvailableStrength = Observation` has
  `CanEnforce = false`. Callers must not render `VERIFIED BLOCKING` from it.
- **A guard is a detector, not a boundary:** `HostHook` only counts when the host has been proven to
  honour deny responses.
- **DKG reputation is not an input:** the engine has no reputation parameter, so a community or
  verified DKG sighting can never silently become a block or an allow.
- **No secrets in audit:** agent identifiers and targets are stored as SHA-256 prefixes.

## Bounds

| Bound | Value |
|---|---|
| Rules per policy | 512 |
| Identifier length | 128 characters |
| Target / process path | 4096 characters |
| Remembered verdicts | 1024 |
| Audit entries (default) | 512 |

## Not implemented here

- No hook, plugin or host-adapter wiring; the current hooks keep their existing fail-open behaviour.
- No host capability matrix, live host deny test or `VERIFIED BLOCKING` state.
- No managed runner, restricted token, AppContainer boundary or file broker.
- No DKG annotation, Check graph call, firewall rule or DNS change.
- No UI, no persistence of user choices, no migration of existing settings.
- No per-agent network policy; Axiom Shield remains the enforcement authority for its own rules.

These are stages E0/E2/E3/E4/E5 of the handoff and remain separate, scoped Draft PRs.
