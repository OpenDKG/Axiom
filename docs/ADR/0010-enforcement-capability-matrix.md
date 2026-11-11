# ADR 0010 - Host capability matrix and enforcement boundaries

- **Status:** proposed (documentation only, no runtime change)
- **Date:** 2026-11-11
- **Related:** handoff "Independent Agent Enforcement Layer v2", ADR 0009 (baseline and gap register, Draft PR #247), issues #221-#231

## Context

The enforcement layer must never present a detector signal, a hook file or a unit test as proof that
an agent was blocked. This ADR fixes the vocabulary, records what is actually verified on the tested
host, and states which Windows isolation path is required before a strong boundary can be claimed.

## Capability states

Every host and every enforcement channel is described with one of these states. A UI badge may only
use the state backed by evidence for the running host.

| State | Meaning | Evidence required |
|---|---|---|
| Not installed | No hook/plugin entry for the host | Configuration inspection |
| Configured | Axiom managed entries exist | File content check |
| Loaded | The host actually loaded the entry | Host log or runtime probe |
| Guard available | The Blackbox guard imported and answered | Guard call result |
| Guard failed | Import or call failed | Error record |
| Audit-only | Axiom records the call but cannot deny | Host contract |
| Host deny sent | Axiom returned a deny payload | Response captured |
| Host deny verified | The host refused the tool call and the side effect did not happen | Live canary with side-effect evidence |
| OS/broker enforced | An OS boundary refused direct access | Isolation prototype evidence |

`Host deny sent` is not `Host deny verified`. No code or documentation may collapse them.

## Tested host matrix

Tested host: Windows 10 21H2, build 19044, Axiom 0.11.0 development build.

| Host | Provisioning | Deny contract | Live deny verified | Current honest state |
|---|---|---|---|---|
| OpenCode / OpenChamber | Managed plugin and bridge | Shared hook payload (`hookSpecificOutput.permissionDecision = deny`) | **No** | Configured; guard call proven in unit tests only |
| Claude Code | Merged user hooks | Same shared payload | **No** | Configured; payload shape unit-tested |
| Codex | Managed entries exist | `{"decision":"block","reason":...}` | **No** (README records execution failures) | Unverified |
| Cursor | Adapter exists | Shared payload, host semantics not confirmed | **No** | Configured, unverified |
| GitHub Copilot CLI | Adapter exists | Shared payload, not confirmed | **No** | Configured, unverified |
| Gemini CLI | Adapter exists | Shared payload, not confirmed | **No** | Configured, unverified |
| Windsurf Cascade | Adapter exists | Shared payload, not confirmed | **No** | Configured, unverified |
| Cline | Adapter exists | Shared payload, not confirmed | **No** | Configured, unverified |
| ZCode | Adapter exists | Shared payload, not confirmed | **No** | Configured, unverified |
| DeepSeek Harness | Adapter exists | Shared payload, not confirmed | **No** | Configured, unverified |
| Antigravity | Adapter exists | Shared payload, not confirmed | **No** | Configured, unverified |

No row claims `Host deny verified` or `OS/broker enforced`. This is the current truth, not a
regression.

## Required live deny test (manual until automated)

1. Create a temporary protected directory with a harmless sentinel file.
2. Start a supported host with the Axiom hook explicitly loaded and a policy that denies that path.
3. Ask the agent to read the sentinel through a file tool.
4. Capture: host event id, the exact deny payload Axiom returned, the host's refusal, and the absence
   of the sentinel content in tool output.
5. Record the host version and the policy revision.

If any step cannot be automated, mark the result `MANUAL REQUIRED`, never `PASS`.

## Managed runner / broker feasibility

A same-token agent cannot be confined reliably by adding ACLs to files, and the handoff forbids
blanket deny entries, ownership changes to `SYSTEM`, kernel drivers and TLS interception. The only
acceptable strong boundary is an opt-in managed runner plus a trusted broker.

Candidate Windows primitives:

| Primitive | Covers | Does not cover |
|---|---|---|
| Restricted token (`CreateRestrictedToken`) | Removing privileges/SIDs from a child | Direct file access by the same user outside the runner |
| AppContainer with capability SIDs | File/registry/network isolation for the container | Apps that cannot run in a container, elevated agents |
| Separate low-privilege identity | Files ACL'd away from the agent identity | Agents launched outside that identity |
| Job object | Lifetime, memory, child limits | File or network denial |

Open questions that must be answered by a prototype before E3 is implemented:

1. Which primitive actually denies a read of a user file by the agent without changing that file's ACL?
2. How are child processes created by the agent constrained and identified?
3. How does the broker authenticate the caller and re-check the path immediately before opening it
   (TOCTOU)?
4. What happens for unsupported applications, elevated agents and tools that spawn their own runtime?
5. Can the runner be installed and removed without touching existing agent history, keys or hooks?

Until a prototype answers these with measurements, the enforcement layer remains **cooperative host
protection**. The broker is not implemented and is not promised by the app.

## Decisions

1. No `VERIFIED BLOCKING`, Mica-equivalent or OS-boundary claim without live evidence; absence of
   evidence maps to `Unverified`/`Degraded`.
2. Detection (Blackbox guard), policy (offline engine) and enforcement (host, broker, firewall) stay
   separate layers with separate status.
3. DKG reputation remains advisory and is not an input to the policy engine (`docs/ENFORCEMENT.md`
   on Draft PR #252).
4. No kernel driver, TLS interception, root CA, blanket ACL deny or user-file ownership change.
5. User hooks, agent data and settings remain byte-equivalent except Axiom's own managed entries.
6. A failed or missing guard never produces a green state; fail-closed applies only to explicitly
   managed protected operations with a boundary that can honour it.
