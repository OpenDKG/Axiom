# Firewall recovery

Axiom owns only rules whose name starts with `Netpetra::`. Recovery never resets the Windows
Firewall and never deletes another product's rules.

## Identify owned rules

```powershell
Get-NetFirewallRule -Name 'Netpetra::*' |
  Select-Object Name, DisplayName, Direction, Action, Enabled, Profile
```

A rule name has the form `Netpetra::{rule-id}::{OUT|IN}`. The same id and direction identify the
rule in the local database (`firewall_rules`).

## Remove one owned rule

```powershell
Remove-NetFirewallRule -Name 'Netpetra::11111111-1111-1111-1111-111111111111::OUT'
```

This requires an elevated PowerShell session. Do not use wildcard removal against a prefix that
could match another product; check the list first.

## Remove all owned rules (recovery only)

```powershell
Get-NetFirewallRule -Name 'Netpetra::*' | Remove-NetFirewallRule
```

Run this only after reviewing the list. It still targets only names with the Axiom prefix.

## Service stopped or unavailable

Applied Windows Firewall rules remain in force when the service or UI stops. Axiom does not
remove rules on exit. The UI shows `Service unavailable`; use the commands above if the service
cannot be started.

## Write gate

The service refuses write commands unless both variables are set on the service process:

```text
NETPETRA_ENABLE_FIREWALL_WRITES=1
NETPETRA_FIREWALL_WRITE_CONFIRM=yes
```

Unset them (or restart the service without them) to return to read-only behaviour.

## Do not

- Do not run `netsh advfirewall reset` or disable the Windows Firewall service.
- Do not delete rules by display name or group without checking that they are owned by Axiom.
- Do not delete the local database as a recovery step; it is the audit record, not the enforcement
  state.

## Verification after recovery

```powershell
Get-NetFirewallRule -Name 'Netpetra::*'
```

An empty result means no Axiom-owned rule remains. Other rules are outside this check.
