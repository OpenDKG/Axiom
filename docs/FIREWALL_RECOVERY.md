# Firewall recovery

Netrigil owns only rules whose name starts with `Netrigil::`. Recovery never resets the Windows
Firewall and never deletes another product's rules.

## Identify owned rules

```powershell
Get-NetFirewallRule -Name 'Netrigil::*' |
  Select-Object Name, DisplayName, Direction, Action, Enabled, Profile
```

A rule name has the form `Netrigil::{rule-id}::{OUT|IN}`. The same id and direction identify the
rule in the local database (`firewall_rules`).

## Remove one owned rule

```powershell
Remove-NetFirewallRule -Name 'Netrigil::11111111-1111-1111-1111-111111111111::OUT'
```

This requires an elevated PowerShell session. Do not use wildcard removal against a prefix that
could match another product; check the list first.

## Remove all owned rules (recovery only)

```powershell
Get-NetFirewallRule -Name 'Netrigil::*' | Remove-NetFirewallRule
```

Run this only after reviewing the list. It still targets only names with the Netrigil prefix.

## Service stopped or unavailable

Applied Windows Firewall rules remain in force when the service or UI stops. Netrigil does not
remove rules on exit. The UI shows `Service unavailable`; use the commands above if the service
cannot be started.

## Write gate

The service refuses write commands unless both variables are set on the service process:

```text
NETRIGIL_ENABLE_FIREWALL_WRITES=1
NETRIGIL_FIREWALL_WRITE_CONFIRM=yes
```

Unset them (or restart the service without them) to return to read-only behaviour.

## Do not

- Do not run `netsh advfirewall reset` or disable the Windows Firewall service.
- Do not delete rules by display name or group without checking that they are owned by Netrigil.
- Do not delete the local database as a recovery step; it is the audit record, not the enforcement
  state.

## Verification after recovery

```powershell
Get-NetFirewallRule -Name 'Netrigil::*'
```

An empty result means no Netrigil-owned rule remains. Other rules are outside this check.
