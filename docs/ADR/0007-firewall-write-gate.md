# ADR 0007 — Gated Windows Firewall writes (FND-006)

- **Status:** accepted
- **Date:** 2026-11-03
- **Milestone:** FND-006 (code complete; VM verification pending)
- **Builds on:** ADR 0001–0006

## Context

FND-006 is the first write phase. It must create and remove real Windows Firewall rules for one
application, verify the OS result, keep other programs untouched and provide a safe rollback. The
handoff requires an isolated Windows VM and explicit approval before any rule is applied.

The development host is a production workstation. No VM is available to the agent, and applying a
block rule here is forbidden. The implementation therefore separates code that can be verified
(read-only COM, validation, storage, coordinator with a fake adapter) from code that requires a VM
(real apply/remove and network behaviour).

## Decisions

### 1. Documented COM API with late binding on a dedicated STA thread

`INetFwPolicy2`/`INetFwRule` are used through `Type.GetTypeFromProgID` and `dynamic`. A dedicated
`StaComExecutor` thread creates and uses every COM object; the thread-pool never touches COM
apartment state. This avoids shipping interop assemblies and keeps the COM lifecycle in one place.

### 2. Exact owned names only; no wildcard deletion

Every rule is named `Netrigil::{rule-id:D}::{OUT|IN}`. Apply updates only that exact name; remove
finds the exact name for the id and direction. There is no code path that deletes by prefix, group or
wildcard, and no code path that changes another product's rule.

### 3. Two-variable write gate

Writes are refused unless both environment variables are present on the service process:

```text
NETRIGIL_ENABLE_FIREWALL_WRITES=1
NETRIGIL_FIREWALL_WRITE_CONFIRM=yes
```

The gate is checked in the adapter, in the pipe command handler and in the UI capability query. A
normal install starts with the gate closed; `FirewallWrites=false` disables the block/remove buttons.

### 4. Coordinator with audit

`FirewallRuleCoordinator` serialises changes with a semaphore and runs:

```text
validate -> store pending + audit -> adapter apply -> adapter read-back
        -> store applied/verified + audit  (or failed + audit)
```

SQLite schema v2 adds `firewall_rules` (spec JSON, state, last verified, last error) and `rule_audit`
(actor SID, time, action, result, new spec, error). The actor is the verified pipe client SID.

### 5. Deterministic identity in Contracts

`RuleIdentity.ForApp(path, direction)` derives a stable UUID from the normalized path and direction.
It lives in `Contracts` so the UI can request the same id the service uses; block, re-block and
unblock therefore target the same OS rule.

### 6. Read-only page first, write actions second

The Firewall page reads capability and owned rules through `rules.query`. Block outbound/inbound is
on the Applications page; remove is on the Firewall page. All write actions require
`FirewallWrites=true`, show a confirmation dialog and report the verified result.

### 7. No real rule applied on the development host

Tests use a fake adapter for the coordinator and only read COM state on the host. The real apply and
remove methods were not executed. The definition of done for FND-006 (a real test app blocked while
another program still connects) remains **NOT RUN** until an isolated VM is available.

## Consequences

Positive:

- The full write path exists and is gated, audited and deterministic.
- Read-only COM, validation, storage and coordinator logic are tested (107 tests).
- A normal build cannot create or remove a rule by accident.

Negative / risks:

- Real enforcement is unverified; COM property mapping, profile behaviour and read-back may differ
  from the fake adapter.
- The gate is an environment-variable switch, not a signed installer setting; FND-009 must replace
  it with a proper installation-time opt-in.
- The service runs as the current user in console mode; a real service account and its COM rights
  are unverified.
- The UI blocks an entire executable path, not a port/CIDR scope (FND-008).
- External rules and Group Policy can still win; the page reports only owned rules.

## Alternatives considered

| Alternative | Why not |
|---|---|
| Apply a rule on the workstation to test | Forbidden by the handoff; risks the host's connectivity |
| `netsh`/PowerShell shell calls | Not the documented COM contract; harder to validate and audit |
| Wildcard removal by prefix | Could delete another product's rule if the prefix were reused |
| No write gate | A normal build could change firewall state accidentally |
| In-memory rule state only | Loses audit and desired/applied reconciliation |
| Skip FND-006 entirely | Leaves the product as a monitor only |

## VM verification checklist

1. Snapshot the VM and confirm network access.
2. Build and start the service with both gate variables set; confirm `capabilities` reports
   `firewallWrites=true`.
3. Apply an outbound block for a test executable; confirm the exact `Netrigil::{id}::OUT` rule.
4. Confirm the test app cannot connect and a second app still can.
5. Remove the rule; confirm the test app connects again and no other rule changed.
6. Restart the service and the UI; confirm the state reconciles.
7. Record `Get-NetFirewallRule -Name 'Netrigil::*'` before/after and attach the output.
