# Axiom agent enforcement policy engine (Stage E1 specification)

**Status:** Core E1 policy engine implemented in `Axiom.Core/Enforcement` and unit tested (`EnforcementPolicyEvaluatorTests.cs`). Subsequent stages (`E2` host adapter & receipts, `E3` broker prototype, `E4` `AgentFirewallEnforcer`, `E5` UI status surfacing) are wired in later commits and tracked with their live-VM verification status in [ENFORCEMENT_TRACKER.md](ENFORCEMENT_TRACKER.md) and [validation/RELEASE_READINESS_MATRIX.md](validation/RELEASE_READINESS_MATRIX.md).

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

## Boundaries outside Stage E1

Stage E1 (`Axiom.Core/Enforcement`) intentionally excludes host wiring, OS enforcement, DKG lookups, and UI rendering so the pure evaluator stays deterministic and offline. Those responsibilities belong to separate components tracked in [ENFORCEMENT_TRACKER.md](ENFORCEMENT_TRACKER.md):

- Host adapter mapping, `EnforcementController`, and sentinel canary verification (`E2`).
- Managed runner / broker feasibility probes (`E3`, prototype only).
- Per-agent scoped firewall rules and dual-destination canary verification (`E4`, `AgentFirewallEnforcer`).
- UI truth-surface status states (`E5`, `EnforcementSurfaceState`) and live Windows VM runtime validation (`docs/validation/RELEASE_READINESS_MATRIX.md`).
