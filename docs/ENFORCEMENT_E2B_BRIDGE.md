# Enforcement E2-B — offline decision controller

**Status:** E2-B bridge core. The controller, the authenticated `enforcement.status` /
`enforcement.evaluate` pipe commands and a C# host adapter exist and are tested. No live host plugin
calls the pipe yet, so installed agents keep their current behaviour. Enforcement stays off unless a
valid policy file enables it.

**Base:** `77cc50ac50ea3db04a9206e30756a68e27fdd09d`

## What this slice adds

`Axiom.Service/EnforcementController.cs`:

- Loads an opt-in policy file from
  `%LOCALAPPDATA%\Axiom\enforcement-policy.json`.
- Validates it with the existing `EnforcementPolicyValidator`.
- Evaluates bounded requests with the existing deterministic `EnforcementPolicyEvaluator`; the
  evaluator is not rewritten.
- Returns an honest verdict: decision, rule id, reason code, available strength, approval flag,
  `CanEnforce`, optional Blackbox signal id, evaluation time and policy revision.
- Keeps a bounded replay guard: a request id reused for a different agent/kind/target/process or
  policy revision is rejected instead of inheriting the first verdict.
- Reads no network, no DKG and no clock during evaluation; the only clock read is when a caller
  omits `UtcTime`.

`Axiom.Contracts/Ipc/EnforcementDtos.cs` and `IpcProtocol` add two commands on the existing local
named pipe, with the same SID DACL and request-size cap as every other command:

- `enforcement.status` — enabled state, policy revision, agent/rule/resource counts and an error.
- `enforcement.evaluate` — one bounded request; returns `EnforcementVerdictDto`.

`Axiom.Core/Enforcement/HostEnforcementAdapter.cs` maps a real host pre-action event to the canonical
request through `HostDecisionMapping`, sends it with `PipeEnforcementDecisionTransport` and returns a
host-specific deny payload only when the verdict is a block with `CanEnforce = true`. An
observation-strength block returns no deny, so an unverified host cannot be presented as blocked.
`HostDecisionMapping` gains a decision-based overload; the existing verdict overload delegates to it.

## Policy file

The file is user-owned and off by default. Missing file = disabled, not an error.

```json
{
  "enabled": true,
  "policy": {
    "version": "lab-1",
    "agents": [
      {
        "agentId": "opencode",
        "mode": "monitor",
        "rules": [
          { "ruleId": "allow-lab", "effect": "allow", "kind": "readFile", "targetScope": "C:\\lab\\allowed" },
          { "ruleId": "block-secret", "effect": "block", "kind": "readFile", "targetScope": "C:\\lab\\secret" }
        ]
      }
    ],
    "protectedResources": []
  }
}
```

`enabled: false`, an empty file, malformed JSON or validation problems keep enforcement off and expose
the error through `EnforcementStatusDto.Error`.

## Decision semantics

| Situation | Decision | Reason code |
|---|---|---|
| No policy file, or `enabled: false` | `unavailable` | `ENF-DISABLED` |
| Invalid policy | `unavailable` | `ENF-POLICY-INVALID` |
| Missing caller identity | `unavailable` | `ENF-UNAUTHENTICATED` |
| Malformed or oversized request | `unavailable` | `ENF-INVALID-REQUEST` |
| Request id reused for a different action/revision | `unavailable` | `ENF-REPLAY-MISMATCH` |
| Policy allow rule | `allow` | `ENF-RULE-ALLOW` |
| Policy block rule | `block` | `ENF-RULE-BLOCK` |
| Blackbox block | `block` | `ENF-GUARD-BLOCK` |
| No matching rule, monitor mode | `audit` | `ENF-NO-RULE-MONITOR` |

`AvailableStrength` is `observation` unless the caller proves that this exact host and version honours
a deny (`hostSupportsDeny`). A block at observation strength has `CanEnforce = false` and must never
be shown as verified blocking.

## Bounds

| Field | Limit |
|---|---|
| Request id, agent id, session id, parent id, guard signal id | 128 characters |
| Target, process path | 4096 characters |
| Remembered request ids | 1024 |
| Rules | existing policy validator limit (512) |

## Threat model notes

- The controller is intended to sit behind the existing same-user named pipe ACL. It is not an HTTP
  endpoint and exposes no generic execution command.
- It is a cooperative boundary: a compromised same-user agent can bypass a voluntary hook. No file,
  process or network isolation is claimed.
- The policy file is read-only to the controller. It does not create, migrate or repair user state.
- Blackbox is an optional detector. A guard block is a signal; it is not proof that a host refused the
  action.

## Not in this slice

- Live OpenCode/OpenChamber, Claude Code or Codex plugin that calls `enforcement.evaluate` and turns
  a verdict into a host deny. The C# adapter is ready; the host-side bridge is the next PR.
- `Ask` approval UX and a real pause/approve path.
- Per-host/version capability evidence and the live status service.
- OS boundary, managed runner or file broker.

## Verification

```text
dotnet build tests/Axiom.Service.Tests/Axiom.Service.Tests.csproj -c Release
  Build succeeded. 0 warnings, 0 errors

dotnet test tests/Axiom.Core.Tests/Axiom.Core.Tests.csproj -c Release --no-build
  134 passed, 0 failed, 0 skipped

dotnet test tests/Axiom.Service.Tests/Axiom.Service.Tests.csproj -c Release --no-build
  81 passed, 0 failed, 0 skipped
```

New tests cover disabled/missing policy, missing caller identity, allow and block rules, observation
strength, guard override, invalid kind, oversized target, replay mismatch, idempotent repeats, status
counts, malformed policy and `enabled: false`, plus adapter mapping of allow, observation, Codex and
Claude deny payloads and the canonical request fields.

## Rollback

Revert the commit. No user file is written by the controller; deleting an optional policy file also
returns the system to `DISABLED`.
