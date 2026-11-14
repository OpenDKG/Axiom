# ADR 0012 - Stage E3 Managed Runner and Trusted File Broker Feasibility

- **Status:** prototype evaluated (opt-in library & probe implemented; live third-party CLI confinement remains gated)
- **Date:** 2026-11-14
- **Related:** Issue #323, ADR 0010, Handoff v2.0 §4.3 / §7

## Context

Same-user cooperative hooks (`OpenCode`, `Claude Code`, `Codex`) execute under the user's primary Windows security token. While host hooks can refuse tool calls cleanly (`HOST_DENY_VERIFIED` via disposable sentinel canary), a bypassed runtime executing directly with the same token cannot be stopped solely by modifying ACLs on user files without violating Axiom's non-negotiable safety constraints (no blanket ACL rewrites, no `SYSTEM` ownership swaps, no TLS MITM, no custom kernel drivers).

## Prototype Design Implemented

1. **`Axiom.Core.Enforcement.TrustedFileBroker`**
   - Mediates explicit broker-routed file reads through `EnforcementPolicyEvaluator` at `EnforcementStrength.TrustedBroker`.
   - Rejects UNC, `\\?\`, and `\\.\` device namespaces prior to any filesystem call (`DeniedUnsafePath`).
   - Walks every path ancestor through `hasReparsePointInChain` to reject junctions and symlinks (`DeniedReparseOrSymlink`).
   - Captures pre-read and post-read file identity stamps to detect concurrent TOCTOU replacements (`DeniedToctouMismatch`).
   - Emits redacted `EnforcementReceiptV1` receipts into `EnforcementReceiptJournal`.

2. **`Axiom.Infrastructure.Windows.Enforcement.WindowsRunnerAndBrokerProbe`**
   - Implements Windows ancestor reparse-point inspection (`HasReparsePointInAncestry`) failing closed on suspicious or inaccessible path segments.
   - Probes standard Win32 Job Object creation (`CreateJobObjectW` / `CloseHandle`) without requiring administrator elevation.

## Measured Feasibility & Compatibility Limits

| Primitive | Measured Status on Windows | Why Not Default for Arbitrary Hosts |
|---|---|---|
| Canonical + reparse-point + TOCTOU file broker | Works deterministically in-process | Covers only accesses routed through the Axiom broker |
| Win32 Job Object (`CreateJobObjectW`) | Available unprivileged | Bounds process lifetime/child cleanup (`KILL_ON_JOB_CLOSE`), not arbitrary same-user file reads |
| AppContainer / Restricted Token | Requires dedicated low-privilege principal and launcher opt-in | Arbitrary third-party Electron/Node/Python runtimes (`OpenCode`, `OpenChamber`, existing IDEs) require per-host launcher migration and filesystem capability grants; blanket enablement risks breaking user dev workflows |

## Decision

- Keep default live host protection claims scoped cleanly to `HOST_DENY_VERIFIED` (host hook + disposable canary proof) and `OS_DENY_VERIFIED` (Stage E4 scoped Windows Firewall rules + dual-destination canary proof).
- Retain `TrustedFileBroker` as an opt-in prototype for explicitly brokered workspaces and future managed-runner integrations. Never market same-user cooperative hooks as OS filesystem isolation.
