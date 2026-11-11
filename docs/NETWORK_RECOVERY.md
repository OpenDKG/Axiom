# Network recovery

Axiom saves a small, machine-wide recovery baseline **before** it changes DNS or Windows Firewall
state. Restoring that baseline is the supported fallback when a protection change leaves a machine
without working name resolution. Axiom never resets the Windows Firewall, never removes a rule it
cannot prove it owns, and never invents DNS servers.

## Where the baseline lives

| Item | Value |
| --- | --- |
| Snapshot | `%ProgramData%\Axiom\network-recovery.txt` |
| Writer | The elevated Axiom Windows service (or the explicit administrator command) |
| Reader | The service, and the administrator recovery command |
| Contents | Adapter ids, IPv4/IPv6 DNS mode and servers, Axiom rule identities, protection intent |

The snapshot is written once. A second capture keeps the existing valid baseline instead of
overwriting it with state that may already have been changed. A corrupt or unreadable file is
**not** replaced automatically: capture reports it and leaves it for the operator.

Capture also refuses a missing baseline when Privacy Shield is enabled and the adapters already
point only at the loopback resolver. Recording that state would make the outage look like the
baseline; stop Privacy Shield before resetting the baseline.

The previous per-user file `%LOCALAPPDATA%\Axiom\network-recovery.txt` is legacy. It is not read
by the service and is not deleted automatically.

## Snapshot format

The file is deliberately plain text so an administrator can read it without the app. It is also
strictly validated: a fixed header, a SHA-256 checksum over the whole body, no unknown entries, no
duplicates, and a per-family rule that automatic DNS has no static servers and static DNS has at
least one valid server of the right family.

```text
axiom-network-recovery=2
captured=2026-11-11T20:00:00.0000000+00:00
protection=active
adapter|11111111-1111-1111-1111-111111111111|Ethernet|Intel(R) Ethernet|static|192.168.0.1;1.1.1.1|auto|
rule|22222222-2222-2222-2222-222222222222|OUT|Axiom
checksum=<sha-256 of the preceding lines>
```

* `auto` means Windows receives DNS automatically (DHCP); restore clears the static override for
  that family with `Set-DnsClientServerAddress -ResetServerAddresses`.
* `static` means the captured addresses are authoritative; restore sets exactly those addresses for
  that family.
* A rule is stored as managed id + direction + the observed OS ownership group. The rule name is
  derived as `Axiom::{id}::{OUT|IN}`.

Do not edit the file by hand. The checksum and parser will refuse it, and the recovery command has
no option to accept unvalidated DNS or rule names.

## Ownership rules

Capture accepts a firewall rule only when **both** conditions hold:

1. Its OS name parses exactly as `Axiom::{managed-rule-id}::{OUT|IN}` (the legacy `Netpetra::`
   prefix maps to the same identity), and the id/direction match the stored managed rule.
2. The OS metadata still carries Axiom ownership evidence: the group is `Axiom` (or legacy
   `Netpetra`), or the description starts with `Axiom`/`Netpetra`.

The `Axiom::` prefix alone is not enough. Before removing a captured rule, restore re-reads the
exact rule and repeats the metadata check. If the metadata changed, the rule is skipped and a
`rule.not_owned` problem is reported; it is never removed. Removal is limited to the captured
id **and direction**, so a later rule in the other direction is untouched.

## Desktop flow

* The service captures the baseline during its startup, before the local pipe server starts.
* The desktop asks the service for an idempotent capture at launch as a fallback.
* **Settings → Restore network settings** sends `networkRecovery.restore` over the authenticated
  local pipe. The request carries no adapter, DNS or rule values; the service reads only the
  validated machine snapshot.
* The result distinguishes success, already-satisfied, partial failure, corrupt snapshot, missing
  snapshot, not authorized, service unavailable, incompatible service and busy. UI text never says
  "restored" unless the service read back every changed adapter and rule.

Capture and restore are serialised in the service. Repeated restore is idempotent: an already
restored adapter is left alone, and an already absent rule counts as verified absence. An
interrupted restore keeps the snapshot, so the next attempt can safely retry.

## IPC compatibility

The envelope stays at protocol version 1. The two commands are additive and are advertised in
`capabilities`:

```text
networkRecovery.capture
networkRecovery.restore
```

A newer desktop against an older service receives `not_supported`/`unknown_command` and shows an
"update or reinstall" message instead of a false success. An older desktop is unaffected. Both
commands reject any request payload: state cannot be supplied by the caller.

## Watchdog

The watchdog runs **inside the service**, never in the desktop. It only acts when the snapshot is
valid and adapters point at the loopback resolver:

* Resolver running → intentional active state (even if the desktop is closed) → no action.
* Resolver wanted but stopped, loopback DNS present → restart the resolver once.
* Resolver still stopped, or intentionally disabled while loopback DNS remains → restore **DNS
  only**. Firewall rules and protection intent are not touched, so the watchdog cannot disable an
  intentionally active protection.

The desktop no longer contains the old rollback timer, so closing it cannot trigger a rollback.

## Emergency recovery when the service or desktop cannot run

Use an elevated PowerShell, stop the Axiom service first, then run the service binary:

```powershell
& "C:\Program Files\Axiom\Service\Axiom.Service.exe" --recover-network
```

This is a dry run: it prints the captured adapters and Axiom rule identities and changes nothing.
Apply only after reviewing the plan:

```powershell
& "C:\Program Files\Axiom\Service\Axiom.Service.exe" --recover-network --apply
```

The command refuses to run when the service process is still running, refuses a missing/corrupt
snapshot, requires administrator rights for `--apply`, and accepts no names or addresses on the
command line. It restores only what the validated snapshot contains and verifies the result.

Exit codes:

| Code | Meaning |
| --- | --- |
| 0 | Restore completed and was verified |
| 1 | Dry-run plan only |
| 2 | No snapshot |
| 3 | Snapshot corrupt or unreadable; refused |
| 4 | `--apply` without administrator rights |
| 5 | Restore partial or failed; review the output |
| 6 | Axiom service still running |

## Verification

After a restore, confirm the result from an elevated prompt:

```powershell
Get-DnsClientServerAddress -AddressFamily IPv4,IPv6 |
  Select-Object InterfaceAlias, AddressFamily, ServerAddresses

Get-NetFirewallRule -Name 'Axiom::*' |
  Select-Object Name, DisplayName, Direction, Action, Enabled, Group
```

Only Axiom-owned rules should be affected, and only the captured directions. Other products' rules
are outside this check and are never touched.

## Rollback of this feature

There is no schema migration and no change to the Windows Firewall policy. To roll back the code:

1. Stop the Axiom service.
2. Deploy the previous build (the old build simply ignores `%ProgramData%\Axiom\network-recovery.txt`).
3. Start the service again.

The snapshot file is inert data. Never delete firewall rules by prefix as a rollback step, and do
not delete the history database; it is the audit record, not enforcement state.
