# Firewall recovery

Axiom owns only rules whose name follows `Axiom::{managed-rule-id}::{OUT|IN}` and whose OS metadata
still proves ownership. Recovery never resets the Windows Firewall and never deletes another
product's rules. Service-backed capture, DNS recovery, the snapshot format and the emergency
command are documented in [NETWORK_RECOVERY.md](NETWORK_RECOVERY.md).

## Identify owned rules

```powershell
Get-NetFirewallRule -Name 'Axiom::*' |
  Select-Object Name, DisplayName, Direction, Action, Enabled, Profile, Group
```

A rule name has the form `Axiom::{rule-id}::{OUT|IN}`. The same id and direction identify the
rule in the local database (`firewall_rules`). The group or description is the second ownership
signal recovery checks; do not edit it on an Axiom rule you want recovery to manage.

## Remove one owned rule

```powershell
Remove-NetFirewallRule -Name 'Axiom::11111111-1111-1111-1111-111111111111::OUT'
```

This requires an elevated PowerShell session. Do not use wildcard removal against a prefix that
could match another product; check the list first.

## Remove all owned rules (recovery only)

```powershell
Get-NetFirewallRule -Name 'Axiom::*' | Remove-NetFirewallRule
```

Run this only after reviewing the list. It still targets only names with the Axiom prefix.

## Service stopped or unavailable

Applied Windows Firewall rules remain in force when the service or UI stops. Axiom does not
remove rules on exit. The UI shows `Service unavailable`; use the commands above if the service
cannot be started. For the saved DNS/Axiom-rule baseline, use the elevated
`--recover-network --apply` command described in [NETWORK_RECOVERY.md](NETWORK_RECOVERY.md).

## Firewall page configuration

The Firewall page now has two configuration layers:

- **Rule defaults** are per-user scope preferences (profiles, protocol, remote ports and addresses).
  They are always editable and are applied to new block rules created from Applications.
- **Create or update an owned rule** is a direct rule editor. Its fields can be prepared while the
  write path is read-only, but **Apply rule** remains disabled until the service write gate is open.

The page intentionally never creates, changes or removes a non-Axiom rule. The owned-rule table
lists only names with the `Axiom::` prefix and offers targeted removal when writes are enabled.

## Write gate

Writes require the Axiom Shield to be on: the Firewall page installs and starts the Axiom Windows
service once (administrator approval) and persists consent in
`%ProgramData%\Axiom\protection.json`. Only the non-interactive service can then create or remove
`Axiom::` rules. The interactive desktop process never writes, even with consent.

The legacy test override still exists for an isolated VM: set both variables on the service process.

```text
AXIOM_ENABLE_FIREWALL_WRITES=1
AXIOM_FIREWALL_WRITE_CONFIRM=yes
```

Turn the shield off in the app (or remove the service) to return to read-only behaviour. Turning it
off removes every Axiom-owned rule.

## Do not

- Do not run `netsh advfirewall reset` or disable the Windows Firewall service.
- Do not delete rules by display name or group without checking that they are owned by Axiom.
- Do not delete the local database as a recovery step; it is the audit record, not the enforcement
  state.

## Verification after recovery

```powershell
Get-NetFirewallRule -Name 'Axiom::*'
```

An empty result means no Axiom-owned rule remains. Other rules are outside this check.
