# Enforcement E2-B — Offline Decision Controller & EnforcementReceiptV1 Bridge

**Status:** E2-B controller, authenticated local pipe commands (`enforcement.status`, `enforcement.evaluate`, `enforcement.receipts`), host adapter (`HostEnforcementAdapter`), and tamper-evident `EnforcementReceiptV1` (`axiom.enforcement.receipt.v1`) journal are implemented and tested. Enforcement stays off by default unless a user-owned policy file enables it.

## Architecture Summary

1. **`Axiom.Core.Enforcement.EnforcementReceiptV1` & `EnforcementReceiptJournal` (`src/Axiom.Core/Enforcement/EnforcementReceipt.cs`)**
   - Implements the Handoff v2.0 §4.3 schema (`axiom.enforcement.receipt.v1`) with bounded capacity (`512` entries), idempotency by `EventId`, and SHA-256 hash chaining (`PreviousHash` / `IntegrityHash`).
   - Redacts targets and paths via `EnforcementAuditRedactor.Hash` into `IndicatorRef`; raw file paths, prompts, credentials, and tool arguments never enter the receipt store.
   - Enforces the anti-overclaim invariant programmatically: `HOST_DENY_VERIFIED` and `OS_DENY_VERIFIED` are permitted **only** when `ObservedSideEffect == Absent` and `VerifiedBy` is non-empty; otherwise the receipt is downgraded to `UNVERIFIED`.
   - Community-only and IOC sightings (`BlackboxGuardSignal.CommunityOnly = true`) remain advisory (`ENF-COMMUNITY-ADVISORY`, `AUDIT_ONLY`) unless an explicit local policy rule blocks them.

2. **`Axiom.Service.EnforcementController` (`src/Axiom.Service/EnforcementController.cs`)**
   - Reads the opt-in user-owned policy from `%LOCALAPPDATA%\Axiom\enforcement-policy.json` (missing or `enabled: false` stays disabled).
   - Evaluates bounded requests using deterministic `EnforcementPolicyEvaluator` and rejects mismatched `RequestId` replays (`ENF-REPLAY-MISMATCH`) or missing caller SIDs (`ENF-UNAUTHENTICATED`).
   - Records an `EnforcementReceiptV1` entry for every evaluation (`DETECTED`, `AUDIT_ONLY`, `DENY_REQUESTED`, `HOST_DENY_SENT`, `GUARD_UNAVAILABLE`, `FAILED_OPEN`) and exposes `enforcement.receipts` as a read-only IPC query.

3. **`Axiom.Core.Enforcement.HostEnforcementAdapter` (`src/Axiom.Core/Enforcement/HostEnforcementAdapter.cs`)**
   - Maps host pre-action events through `HostDecisionMapping`, queries `enforcement.evaluate` over the same-user local named pipe (`PipeEnforcementDecisionTransport`), and returns a native deny payload only when `CanEnforce` is true.
   - `VerifyDisposableCanaryAsync` executes a disposable sentinel probe and emits `HOST_DENY_VERIFIED` strictly when both a deny payload was returned and the sentinel state remained untouched (`ObservedSideEffect.Absent`).

4. **`Axiom.Presentation.EnforcementSurfaceState` (`src/Axiom.Presentation/EnforcementSurface.cs`)**
   - `FromReceiptsAndStatus(...)` distinguishes `UNAVAILABLE - NOT PROTECTED`, `HOST_DENY_SENT - NOT VERIFIED` (`COOPERATIVE`), `HOST_DENY_VERIFIED (CANARY)`, and `OS_BOUNDARY_VERIFIED` without ever promoting unverified hook returns to `VERIFIED BLOCKING`.
