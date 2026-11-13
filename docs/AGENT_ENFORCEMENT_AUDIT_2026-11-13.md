# Agent enforcement audit — 2026-11-13

**Status:** audit only. No runtime code, agent profile, hook file, firewall rule or DNS setting was
changed while producing this document. All host reads were read-only.

**Base:** `77cc50ac50ea3db04a9206e30756a68e27fdd09d` (`main`, Axiom 0.17.0)

## Environment

| Item | Value |
|---|---|
| Host OS | Windows 10 IoT Enterprise LTSC 19044 |
| .NET SDK | 10.0.403 |
| OpenCode | 2.2.5 (`...\@openchamberelectron\resources\opencode-cli\opencode.exe`) |
| OpenChamber | 2.6.1 |
| Codex CLI | 0.167.0-alpha.4.1 (`...\OpenAI\Codex\bin\9e1da79431da526b\codex.exe`) |
| Codex sandbox runner | 0.166.0-alpha.6 |
| Blackbox plugin | 1.0.0, `requires_hermes >= 0.21.7` |
| Node | v24.14.1 |
| Claude Code | not installed / not on PATH |
| Gemini CLI | not installed / not on PATH |
| Antigravity | hook configured, host version not captured |

## Baseline build and tests

```text
dotnet build Axiom.sln -c Release
  Build succeeded. 0 Warning(s), 0 Error(s)

dotnet test tests/Axiom.Core.Tests       -c Release --no-build
  Passed! 128 passed, 0 failed, 0 skipped

dotnet test tests/Axiom.Presentation.Tests -c Release --no-build
  Passed! 81 passed, 0 failed, 0 skipped
```

These are baseline results, not host-deny evidence. Unit tests cannot prove that a host honoured a
deny.

## Installed hook state (observed, not modified)

| Host | Installed hook | Observed evidence |
|---|---|---|
| OpenCode / OpenChamber | V2 directory plugin `~/.config/opencode/plugins/axiom-blackbox/index.ts`; V1 fallback `~/.config/opencode/plugins/axiom-blackbox.ts` | `HOOK_LOADED` x3, `GUARD_ALLOWED` x510, `GUARD_FAILED` x1 |
| Codex | `~/.codex/hooks.json`: `PreToolUse`, `SessionStart`, `UserPromptSubmit`, `PostToolUse`, `Stop` all invoke `axiom-codex-hook.py --bridge-version 2` | no `framework=codex` rows in the evidence log |
| Antigravity | `~/.gemini/config/hooks.json` `PreToolUse` matcher `*` invokes `axiom-antigravity-hook.py` | `GUARD_ALLOWED` x31 |
| Claude Code | installer exists in Axiom, host not installed | none |
| Gemini, Cursor, Copilot, Windsurf, Cline, ZCode, DeepSeek | installers exist, hosts not installed | none |

Axiom's installers preserved user files: several `*.axiom-backup-*` copies exist next to the Codex
and OpenCode hook files. This audit did not add, remove or rewrite any of them.

## Runtime decision path today

```text
Host pre-action event
  -> host-specific plugin/hook (OpenCode V1/V2, Codex, Antigravity, ...)
  -> Python bridge (axiom-guard-bridge.py / axiom-codex-hook.py / axiom-antigravity-hook.py)
  -> plugins.blackbox.guard.hooks.on_pre_tool_call
  -> {action: "block", message} or allow
  -> host-specific deny payload, or allow
  -> local JSONL evidence at %LOCALAPPDATA%\Axiom\agent-evidence.jsonl
```

Axiom's own decision layer is **not** in this path:

- `EnforcementPolicyEvaluator` is referenced only by its own file and tests.
- `HostDecisionMapping` is referenced only by its own file and tests.
- `EnforcementSurfaceState.Current` is a static `COOPERATIVE - NOT VERIFIED`.

So today the decision is Blackbox's, not Axiom's. The offline Axiom policy engine is library code that
no hook calls.

## Capability matrix

`deny_contract_documented` below means the *Axiom-side* payload shape is documented in code. It does
**not** mean the host version accepts it.

| Host | Version | Installed | Hook configured | Hook loaded | Pre-action observed | Guard callable | Deny contract documented | Deny sent | Host honoured deny | Side effect absent | Verified at | Policy revision | Evidence |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| OpenCode | 2.2.5 | yes | yes (V1 + V2) | yes | yes | yes | partial: throws `Error` from `execute.before`; host API not documented | only synthetic `axiom-test` row | **no** | **no** | never | none | AUD-01 |
| OpenChamber | 2.6.1 | yes (host UI) | same OpenCode adapter | yes | yes | yes | same | same | **no** | **no** | never | none | AUD-01 |
| Codex | 0.167.0-alpha.4.1 | yes | yes (`hooks.json`) | not observed | not observed | not observed | Axiom emits `{"decision":"block","reason":...}`; host support unverified | no | **no** | **no** | never | none | AUD-02 |
| Claude Code | not installed | no | installer only | no | no | no | `hookSpecificOutput.permissionDecision=deny`; host support unverified | no | **no** | **no** | never | none | AUD-03 |
| Antigravity | not captured | yes | yes | yes (31 calls) | yes | yes | Axiom emits `{"decision":"deny","reason":...}`; host support unverified | no | **no** | **no** | never | none | AUD-04 |
| Gemini CLI | not installed | no | installer only | no | no | no | unverified | no | **no** | **no** | never | none | AUD-05 |
| Cursor, Copilot, Windsurf, Cline, ZCode, DeepSeek | not installed | no | installers exist | no | no | no | unverified | no | **no** | **no** | never | none | AUD-06 |

No host is `HOST DENY VERIFIED`. No host is `OS BOUNDARY VERIFIED`.

## Evidence log summary

`%LOCALAPPDATA%\Axiom\agent-evidence.jsonl`, 546 rows at audit time:

| Framework | Event | Count |
|---|---|---|
| opencode | GUARD_ALLOWED | 510 |
| antigravity | GUARD_ALLOWED | 31 |
| opencode | HOOK_LOADED | 3 |
| opencode | GUARD_FAILED | 1 |
| axiom-test | GUARD_BLOCKED | 1 |

The single `GUARD_BLOCKED` row is from a synthetic `axiom-test`, not from a real host action. There
are no `codex` rows, so the configured Codex hooks have no observed runtime evidence on this host.

The log records framework, event type, tool name, decision, guard status, duration, session and call
ID. It does not record file paths or command text.

## Findings

1. **No live host-deny canary exists.** The UI label `COOPERATIVE - NOT VERIFIED` is accurate.
2. **Axiom's policy engine is not wired.** `EnforcementPolicyEvaluator` and `HostDecisionMapping`
   have no production callers. Any claim that Axiom policy blocks a call today would be false.
3. **Deny semantics are assumed per host.** Codex and Claude/Antigravity shapes differ; the OpenCode
   adapter throws an `Error`. None of these has been tested against the installed host version, and
   Codex is an alpha build.
4. **Failure handling is fail-open.** OpenCode's bridge has an 8 s `spawnSync` timeout and returns on
   spawn/parse failure; the Codex hook catches exceptions and exits allow; Antigravity does the same.
   A guard outage therefore does not deny.
5. **Target identity is heuristic.** Tool names are mapped by fixed sets; shell scripts, patches,
   MCP wrappers, sub-agents and delegated tools are not resolved to a canonical target. Path case,
   junctions, symlinks, UNC paths and TOCTOU are not validated before a decision.
6. **Ask is not implemented.** There is no authenticated pause/approve path; `Ask` cannot be
   presented as enforcement.
7. **No capability/evidence service exists.** There is no per-host/version/action verification store,
   no policy revision in the hook request, and no automatic degradation after a host upgrade.
8. **OpenCode has no real block evidence.** Only allow decisions were recorded, plus one synthetic
   test block. Whether `execute.before` throwing actually prevents the tool is unproven.
9. **Codex hooks are configured but unused in evidence.** Either the host did not load them, the
   event did not fire, or the hook silently failed before recording. This must be tested, not assumed.
10. **Host version gating is absent.** An alpha Codex build and OpenCode 2.2.5 are treated the same
    as any future version.

## What is explicitly not claimed

- No file, tool, shell or network denial through any host.
- No independent isolation boundary, managed runner or file broker.
- No per-agent network policy beyond the existing Axiom Shield firewall path.
- No protection when Blackbox is unavailable, slow or crashing.
- No protection against a compromised same-user agent that bypasses the voluntary hook.

## Recommended next steps

1. **E2-B:** authenticated, bounded, local decision bridge that calls the existing
   `EnforcementPolicyEvaluator`, is off by default, and returns a host-specific verdict. Keep
   Blackbox as an optional detector input, not the decision owner.
2. **E2-C:** live canaries in a disposable VM/profile for OpenCode/OpenChamber, Claude Code and Codex
   (Codex may remain `UNSUPPORTED` if its installed version cannot deny). Record deny payload, host
   refusal and absent side effect per host/action/version.
3. **E5:** replace the static surface with a capability/evidence service and per-host status; do not
   ship a green shield from one canary.
4. **E3:** managed runner/broker feasibility only after the hook layer is truthful, with an
   OS-boundary test, not a label change.

## Safety statement

This audit read existing files and logs only. It did not install, remove or rewrite hooks, profiles,
agent settings, MCP servers, models, sessions, firewall rules, DNS settings or databases. No test
payload was executed on this host. Live canaries belong in the disposable lab VM, with synthetic
files and no real credentials or projects.
