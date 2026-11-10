# Axiom for macOS — acceptance test report

Environment: macOS Sequoia 15.8.3 (x86_64), QEMU/KVM VM, SIP disabled, `systemextensionsctl developer on`,
ad hoc signed `Axiom.app` 0.10.6 built from branch `buba/macos-desktop` (published on Linux, signed in the VM
with `scripts/macos/deploy-to-vm.sh`). All steps were driven through the app's own UI; checks were made over SSH.
Dates are 2026-11-10 (VM local time, PST) / 2026-11-11 (UTC+4).

| # | Check | Result | Evidence |
|---|---|---|---|
| A | Install the background service from the app (administrator prompt) | PASS | Daemon `com.axiom.service` installed and running about 3 s after the password; desktop log `[daemon] state=Running endpoint=/var/run/axiom/axiom.sock`. |
| B | Activate the network filter from the app and approve it | PASS | `systemextensionsctl list` → `com.axiom.firewall.filter … [activated enabled]`; `axiomd.log` "AxiomFilter connected to the flow-event socket"; screenshot `screenshots/macos/first-run.png`. |
| C | Connections page shows live flows | PASS | Live rows including `curl` (`/usr/bin/curl`) while it ran; `screenshots/macos/connections.png`. |
| D | Block an app from Connections | PASS | Block outbound on `curl` → `curl` exit 7 (connect timeout) while `python3` urllib to the same host returned 200; `screenshots/macos/connections-block.png`. |
| E | Unblock from the Firewall page | PASS | Rule removed on the Firewall page → `curl` 200 again. |
| F | Privacy Shield on/off from the app | PASS | Tick "Enable Privacy Shield resolver" + Apply → `networksetup -getdnsservers Ethernet` = `127.0.0.1`, `dig @127.0.0.1 doubleclick.net` → NXDOMAIN, `dig example.com` → 2 addresses. Disable → "There aren't any DNS Servers set on Ethernet." (and on "Built-in Serial Port (1)"), `example.com` resolves, `axiomd.log`: `restore 'Ethernet' -> automatic: ok`, `restore finished: changed=True stillRedirected=False unknown=False`. No false "DNS is not answering" alert. `screenshots/macos/privacy-shield.png`. |
| G | Screenshot of every page, no broken text | PASS | `screenshots/macos/{overview,connections,apps,firewall,privacy-shield,security,agents,agent-stats,events,ai-analyst,settings,support,about,menu-bar}.png`; reviewed for Windows-only wording, glyph boxes and overlaps (fixes listed below). |
| H | Menu-bar icon, quit/relaunch, single instance | PASS | Status-bar shield icon present; menu shows service/filter state, Open Axiom (restores a closed window), "Install Background Service…"/"Turn On Network Filter…" (still offered while both are running, see limitations), Show problem notifications, Quit Axiom (process exits, daemon keeps running). `osascript -e 'quit app "Axiom"'` → 0 processes; `open` → 1 process; `open` again (window closed or behind Terminal) → still 1 process (same pid) and the window comes to front. |

## Fixes made during F–H

- DNS restore after disable could log `restore check …: unreadable` and leave system DNS at 127.0.0.1 (seen once when the daemon was running from a replaced bundle). The configurator now retries reads, restores services listed in the backup even when unreadable, and keeps the backup until the state is known. The dev deploy script did not actually restart the daemon (escaped `&&` in the remote command); fixed.
- No false "Privacy Shield DNS is not answering" alert during a normal disable on macOS (8 s grace while the daemon restores DNS).
- macOS wording for system DNS on Privacy Shield and Support (no "UAC/adapter helper" text), Applications/Firewall write prompts no longer mention an "isolated test VM" off Windows.
- Axiom's own daemon (`Axiom.app/Contents/Resources/service/axiomd`) is no longer listed as a new outbound application waiting for Block/Allow.

## Known limitations

- Tested only in an Intel (x86_64) VM; Apple silicon (`osx-arm64`) is built but untested.
- Ad hoc signed with SIP off and developer mode on; Developer ID signing, provisioning profiles and notarization need an Apple Developer team with the Network Extension capability.
- The menu-bar menu keeps offering "Install Background Service…" and "Turn On Network Filter…" while both already run (harmless re-run; cosmetic).
- ICMP is not filterable (the content filter sees TCP/UDP socket flows only).
- Enabling, disabling or upgrading the filter drops TCP connections that were established while it was active (macOS behaviour).
- Blocked TCP connections fail with a connect timeout, not a reset.
- Privacy Shield redirects every enabled network service, including ones without an active interface; all are restored on disable.
- Agent protection config paths are assumed to be the same as the Windows equivalents under `~`; they were not individually verified on macOS.
- The optional DKG and Blackbox installers are PowerShell-only and not available on macOS (the Agents page shows them as not running).
