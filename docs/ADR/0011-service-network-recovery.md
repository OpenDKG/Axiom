# ADR 0011: Service-owned network recovery

Status: Proposed

## Context

The first recovery slice captured DNS in the desktop process and tried to capture Axiom firewall
rules with a PowerShell read. Both are wrong for a privileged operation:

* `Get-NetFirewallRule` returns **Access is denied** without elevation, so the rule list was always
  empty in a normal session.
* Restoring adapter DNS with `Set-DnsClientServerAddress` also needs elevation.
* The snapshot lived in `%LOCALAPPDATA%`, was per user, and could be overwritten by a later capture
  of already-modified state.
* The rollback watchdog ran in the desktop. Closing the app stopped it, and a timer that removed
  rules could turn an intentional protection into an outage.
* Ownership was decided from the `Axiom::` name prefix alone, which is not enough evidence to
  delete a firewall rule.

## Decision

1. The elevated Axiom service owns capture and restore.
2. Capture runs before the service starts the local pipe server and is idempotent: a valid existing
   baseline is kept; a corrupt one is reported and never replaced.
3. The snapshot moves to `%ProgramData%\Axiom\network-recovery.txt`. It has a strict versioned
   format, a SHA-256 checksum, per-family DHCP/static modes, and validation that rejects unknown,
   duplicate or out-of-range entries. Missing, corrupt and valid-empty are distinct states.
4. Two additive IPC commands are added: `networkRecovery.capture` and `networkRecovery.restore`.
   They accept no payload. The envelope protocol version stays 1; command support is negotiated
   through `capabilities`, so a newer desktop with an older service gets a clear incompatible
   result instead of a broken protocol.
5. A rule is captured only with strict name identity **and** OS ownership metadata (group or
   description). Restore re-reads that evidence immediately before removing the exact rule id and
   direction. It never removes by prefix, display name or wildcard.
6. Restore is authorised by the existing authenticated pipe SID check **and** the service-host
   condition for writes. The emergency command additionally requires an elevated administrator and
   the explicit `--apply` flag.
7. The watchdog moves into the service and is driven by persisted resolver intent and live resolver
   state, not the desktop lifecycle. A running resolver means the loopback DNS is intentional. A
   stopped resolver is restarted once; only a continued failure rolls back DNS, and that path never
   touches firewall rules.
8. The desktop only sends typed commands and renders truthful results. It has no in-process
   privileged recovery path and no rollback timer.

## Alternatives considered

* **Run PowerShell as administrator from the desktop on each restore.** Rejected: a UAC prompt per
  recovery, and the desktop would hold the privileged write path the write-gate design avoids.
* **Store the snapshot per user in LocalAppData.** Rejected: the service and an administrator
  recovery command must read it; machine state belongs in ProgramData with the existing hardening.
* **Bump the IPC protocol version.** Rejected: it would make an older service reject every request
  from a newer desktop. Additive commands are capability-negotiated.
* **Trust the `Axiom::` prefix for removal.** Rejected: prefix alone is spoofable and does not prove
  ownership. Strict identity plus OS metadata is required.
* **Keep the desktop watchdog but gate it on the app being open.** Rejected: the requirement is the
  opposite — closing the desktop must not disable an active protection.

## Consequences

* Network recovery requires the installed service. A bundled, interactive service cannot perform
  privileged writes and reports `NotAuthorized` truthfully.
* The machine-wide snapshot is shared by the allowed interactive account. It contains no secrets,
  only adapter ids, DNS addresses and Axiom rule identities.
* The legacy per-user snapshot is ignored, not deleted.
* Privacy Shield keeps its separate DNS backup and failsafe; this snapshot is an additional layer,
  not a replacement for that path.
* There is no automatic baseline reset. Replacing a baseline is a deliberate operator action
  (remove the file only after accepting the loss), which keeps a corrupt or suspicious file from
  being silently replaced.
