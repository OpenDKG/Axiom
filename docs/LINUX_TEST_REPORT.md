# Linux port — test report (phase P1, branch `buba/linux`)

Host: Ubuntu 24.04, kernel 7.0.0-42-generic, systemd 255, systemd-resolved owns
`/etc/resolv.conf`, NetworkManager running, nftables v1.0.9 present. .NET SDK 10 at `~/.dotnet`.
All `dotnet` commands ran through `~/vms/macos-dev/build-lock` with
`-c Release -m:2 -nr:false -p:UseSharedCompilation=false`. Run as uid 1000 unless stated.

## Gates

| # | Gate | Result | Evidence |
|---|---|---|---|
| 1 | `dotnet build Axiom.sln -c Release -p:EnableWindowsTargeting=true` | PASS | `0 Warning(s)`, `0 Error(s)`, `Build succeeded.` (`TreatWarningsAsErrors` on; Windows TFMs compiled via `EnableWindowsTargeting`) |
| 2a | `Axiom.Infrastructure.MacOS.Tests` | PASS | `Passed! - Failed: 0, Passed: 155, Skipped: 0, Total: 155, Duration: 388 ms` — unchanged count after the Unix extraction |
| 2b | `Axiom.Desktop.Avalonia.MacOS.Tests` | PASS | `Passed! - Failed: 0, Passed: 35, Total: 35` |
| 2c | `Axiom.Infrastructure.Unix.Tests` (new) | PASS | `Passed! - Failed: 0, Passed: 22, Total: 22` — PeerAuthorization ranges (macOS/Linux), InstallOwner, UnixFileStat GNU+BSD dialects, ProtectedImageLayout audit, UnixServicePaths, ManagedRuleStore |
| 2d | `Axiom.Infrastructure.Linux.Tests` (new) | PASS | `Passed! - Failed: 0, Passed: 26, Total: 26` — /proc table parsing (v4, v6, v4-mapped), fd→inode join on a fake /proc tree, live /proc self-socket, scanner cache, DNS backend detection matrix, resolved/NetworkManager/resolv.conf backends with redirect+restore round trips, recovery adapter mapping + validation, systemd unit text, sd_notify over a real datagram socket, installer dry-run / refusal / full flow with fake `stat`+`systemctl` / non-root image refusal, firewall stub, doctor |
| 2e | Other net10.0 suites | PASS / pre-existing | Contracts 142/142, McpServer 33/33, Persistence 19/19, Presentation 90/90, UI.Avalonia 40/40. `Axiom.Core.Tests` 117/128 — the **same 11** Windows-path tests fail on the pristine `7a48bdf` worktree on this host (`RuleSpecValidatorTests.*`, `ProtectionTests.*`, `ProtectionPathFamilyTests.*` use `C:\…` paths); `MACOS_TEST_REPORT.md` already lists them as pre-existing. `Axiom.Infrastructure.Windows.Tests`, `Axiom.Service.Tests`, `Axiom.UI.Tests` are `net10.0-windows` only and cannot run here |
| 3 | `dotnet publish src/Axiom.Service -f net10.0 -r linux-x64 -c Release --self-contained` | PASS | `Axiom.Service -> …/axiom-publish/`, `axiomd: ELF 64-bit LSB pie executable, x86-64`; `git checkout -- '*.lock.json'` afterwards (publish rewrites the RID section of every lock file; no package was added) |
| 4 | `sudo -n` root install | DRY-RUN ONLY | `sudo -n axiomd --install-service --dry-run` → exit 0, printed the plan with "root available" (sudo was *not* blocked by the approval guard). A real install was deliberately not run on this workstation: it would register a system service whose enforcement is a stub; the installer logic is proven by the unit tests in 2d (copy + chown + stat audit + stop-wait + hash + unit + enable) and by the non-root dry-run below |

## Local run (non-root, env overrides)

```
$ export AXIOM_DATA_ROOT=$TMPDIR/axiom-run/data AXIOM_RUNTIME_DIR=$TMPDIR/axiom-run/run
$ $TMPDIR/axiom-publish/axiomd &        # uid 1000, pid 1007724
$ ls -la $AXIOM_RUNTIME_DIR
srw-rw-rw- 1 buba buba 0 Nov 12 06:42 axiom.sock
$ ls -la $AXIOM_DATA_ROOT
-rw------- 1 buba buba 277 network-recovery.txt      # service-owned recovery snapshot, 0600
```

`network-recovery.txt` captured by the Linux DNS recovery adapter:

```
axiom-network-recovery=2
protection=inactive
adapter|7cacd1c3-2c90-5771-9647-415cc6148b3f|eno2|SystemdResolved: systemd-resolved link|static|192.168.70.1|auto|
checksum=72c845c4…
```

`AXIOM_IPC_SOCKET=$AXIOM_RUNTIME_DIR/axiom.sock scripts/linux/axipc.py serviceHealth`:

```
"ok": true, "result": { "status": "running", "sourceName": "/proc socket tables",
  "pollIntervalSeconds": 1, "connectionCount": 186, "processCount": 11,
  "limitations": [ "The daemon is not root: only its own user's processes can be attributed; other sockets show pid 0.",
                   "Connections come from /proc/net/{tcp,tcp6,udp,udp6}; the kernel tables have no per-socket byte counters, …", … ] }
```

`axipc.py capabilities` → `"ok": true`, 22 commands (`serviceHealth`, `capabilities`, `snapshot`,
`rules.query`, `privacy.*`, `protection.*`, `threatshare.*`, `networkRecovery.capture/restore`, …),
`"monitoring": true`; the firewall capability block reports `Unavailable` ("firewall enforcement
is not available on Linux in this build (nftables engine pending)").

`axipc.py snapshot` → 186 connections from /proc, 49 attributed to the daemon's own uid, e.g.
`{'appDisplayName': 'chrome', 'processId': 1705, 'protocol': 'tcp', 'localEndpoint': '127.0.0.1:9222',
'state': 'Listen', 'direction': 'inbound', 'parentChain': 'systemd(1598) > systemd(1)'}`.

`axiomd --doctor` (unprivileged) → exit 1 with the expected findings:

```
WARN systemd unit: /etc/systemd/system/axiomd.service is missing; run `sudo axiomd --install-service`.
WARN protected image: /usr/libexec/axiom does not exist.
WARN axiom.sock: …/axiom-run/run/axiom.sock is uid=1000 gid=1000 mode=666, expected root 0666.
SKIP data directory: /var/lib/axiom modes are checked as root.
PASS dns backend: SystemdResolved; eno2: 192.168.70.1
PASS privacy shield dns: not redirected; no backup.
SKIP ipc owner: /var/lib/axiom/protection.json is readable as root.
WARN enforcement: firewall enforcement is not available in this build (nftables engine pending); nft nftables v1.0.9 (Old Doc Yak #3).
```

`axiomd --install-service --dry-run` (non-root) → exit 0, prints the copy/stop/verify/unit plan and
the full `axiomd.service` text; nothing on disk changed.

`kill -TERM <pid>` → daemon exited within 4 s, `axiom.sock` removed, data directory intact.

## Not proven here

- Real root install / `systemctl` lifecycle (`Type=notify` readiness end-to-end) — unit-tested only.
- Privacy Shield DNS redirect against the live resolver (would change this workstation's DNS) —
  backends are proven with fake `resolvectl`/`nmcli` output and a real temp `resolv.conf`.
- Root attribution of other users' sockets (`CAP_SYS_PTRACE`/`CAP_DAC_READ_SEARCH` path).
- Enforcement — intentionally absent until the nftables engine lands.

# Phase P3 — root end-to-end on this box (2026-11-12, branch `buba/linux`)

Same host. The daemon was published with `dotnet publish src/Axiom.Service -f net10.0 -r linux-x64 -c Release
--self-contained -o build/linux/axiomd` and installed with `sudo -n build/linux/axiomd/axiomd --install-service`
("IPC write commands are allowed for uid 1000 (installing user), root and members of the axiom, sudo or wheel
groups. Installed and started axiomd.service from /usr/libexec/axiom"). Baseline recorded first:
`resolvectl status` (eno2: `DNS Servers: 192.168.70.1`, no DNS Domain line), `/etc/resolv.conf` →
`../run/systemd/resolve/stub-resolv.conf` (`nameserver 127.0.0.53`). All IPC calls as uid 1000 through
`scripts/linux/axipc.py` unless stated. Three defects were found and fixed during the run (rows 8, 13, 14);
the fixed image was installed in row 11 and everything after it ran on the fixed daemon.

| # | Step | Result | Evidence |
|---|---|---|---|
| 1 | `systemctl status axiomd`, `Type=notify` | PASS | `Active: active (running)`, `Loaded: … enabled`, `Type=notify NotifyAccess=main`, `Main PID … /usr/libexec/axiom/axiomd` + child `/usr/sbin/nft monitor trace`. Journal: `Starting axiomd.service…` → `IPC socket listening on /run/axiom/axiom.sock` → `Started axiomd.service` (READY=1 reached after the socket listens) → `Published table inet axiom generation 1 (0 applied, 0 rejected)`. |
| 2 | `sudo -n /usr/libexec/axiom/axiomd --doctor` | PASS | 9 × `PASS` (`systemd unit`, `service state: active (enabled)`, `protected image: 240 entries root-owned and read-only`, `axiom.sock: root 0666 (peer uid checked with SO_PEERCRED)`, `data directory: /var/lib/axiom root 0700`, `dns backend: SystemdResolved; eno2: 192.168.70.1`, `privacy shield dns: not redirected; no backup`, `ipc owner: uid 1000 may write`, `enforcement: nftables v1.0.9 (Old Doc Yak #3); table inet axiom generation 1 is in force`), `Result: all checks passed.`, rc=0. |
| 3 | `serviceHealth` + `capabilities` | PASS | `"status":"running"`, `sourceName "/proc socket tables"`, 172 connections / 24 processes, limitations: no byte counters, sub-poll connections missed, UDP peers unknown, *"Blocked attempts come from the nftables trace of Axiom's block rules (TCP reset / UDP drop); allowed flows are not traced."* `capabilities` before `protection.enable`: 22 commands, `firewallWrites:false` (write gate closed, as on Windows/macOS). After `protection.enable {"defaultPolicy":"ask"}` → `writeGateOpen:true`, journal `Axiom Shield enabled by uid:1000; policy ask`; `capabilities` lists `rule.apply`, `rule.remove`, `rule.verify`, `firewallWrites:true`. `rules.query.capability.status` = `available`. |
| 4a | `rule.apply` Block `/usr/bin/curl` | PASS | `{"success":true,"state":"applied","osRuleName":"Axiom::11111111-…-000000000001::OUT"}`; `nft list table inet axiom` → `comment "axiom generation 2"`, 3 rules `socket cgroupv2 level 2 "axiom.slice/a-f0da955d46aa49e3"` (tcp `reject with tcp reset`, udp `drop`, other `drop`, each `meta nftrace set 1`, comment `axiom:<id>:n`); `/sys/fs/cgroup/axiom.slice/a-f0da955d46aa49e3` created. `rules.query` → `filterEnforcement {generation:2, appliedRuleCount:1, rejectedRules:[]}`, rule state `applied`; `rule.verify` → `presentInOs:true, matchesSpec:true, effectiveAction:"block"`, note `table inet axiom generation 2, 3 nft rule(s), 0 packet(s) matched.` |
| 4b | `curl -m 8 https://example.com` → rc=7 | PASS with caveat | A bare `curl -m 8 https://example.com` returned **200** three times: it connects within ~20 ms of exec, before the 1 s attribution pass (exec-time race, documented in `LINUX_ENFORCEMENT.md` §4 and `LINUX_ARCHITECTURE.md` §10). Herding itself works: a running curl was in `cgroup.procs` of the app cgroup within 1 s (`cg=0::/axiom.slice/a-f0da955d46aa49e3`). Proof with one curl pid that is alive longer than a second: `curl --limit-rate 400k 'https://speed.cloudflare.com/__down?bytes=1500000' 'https://example.com/'` → first URL `http=200` (socket created before herding stays open), second URL **`curl: (7) Failed to connect to example.com port 443 after 0 ms`**, `exit=7`, `rc=7` — immediate reset, not a timeout; `nft` counter `packets 2 bytes 120`; `rule.verify` → `2 packet(s) matched`. |
| 4c | Block flow event over IPC | PASS | `snapshot` right after the reset: two entries `{"appPath":"/usr/bin/curl","processId":0,"protocol":"tcp","localEndpoint":"192.168.70.4:54806","remoteEndpoint":"104.20.23.154:443","state":"Blocked","ruleStatus":"blockedByOwnedRule","quality":"observed"}` (v4 + v6-fallback attempts; pid 0 because the rejected SYN's socket is gone before the trace is parsed). Independent `sudo -n nft monitor trace` capture at the same time: `trace id b4668614 inet axiom axiom_out packet: oif "eno2" ip saddr 192.168.70.4 ip daddr 104.20.23.154 … tcp dport 443 tcp flags == syn` + `rule … reject with tcp reset comment "axiom:…:1" (verdict drop)`. Journal shows no placement line for curl by design: only moves out of `system.slice/*.service` and failures are "reportable". |
| 5 | Rejected rule (hostname in `remoteAddresses`) | PASS (validator) | `rule.apply {…,"remoteAddresses":["example.com"]}` → `{"success":false,"state":"failed","errorCode":"rule.invalid","errorMessage":"rule.addresses.invalid: 'example.com' is not an IP address or CIDR range."}` — rejected by the shared `RuleSpecValidator` before the engine, so it never reaches `filterEnforcement.rejectedRules` (the engine-level rejection path — a live pid that cannot be moved — is covered by the unit tests). |
| 6 | `rule.remove` | PASS | `{"success":true,"state":"desired"}`; `curl https://example.com` → `http=200`; table `comment "axiom generation 3"`, 0 `cgroupv2` rules; `ls /sys/fs/cgroup/axiom.slice/` → 0 app cgroups (released). |
| 7 | Read-only caller | PASS | `sudo -n -u nobody …` → `Connection reset by peer`: uid 65534 is outside the Linux account range (1000…, nobody excluded) and is refused at accept, by design. Created `axtest` (`useradd -M -s /usr/sbin/nologin`, uid 1001, no groups): `serviceHealth` → `"ok":true,"status":"running"`; `rule.apply` → `"code":"unauthorized","message":"This command changes machine-wide settings and is only allowed for root, the user who installed Axiom (uid 1000) and members of the axiom, sudo or wheel groups; uid 1001 may only read."`; `privacy.configure` → `unauthorized`; journal `Denied 'rule.apply' for uid:1001: write commands are not allowed for this caller.` `userdel axtest` afterwards (`id: 'axtest': no such user`). |
| 8 | Privacy Shield on (P1 unit) | FAIL → fixed | First attempt on the P1 unit: `privacy.configure {"enabled":true}` → `state:"Disabled"`, `privacy.status.lastError = "Configuration failed; previous disabled configuration was kept. Permission denied"`: the unit's `CapabilityBoundingSet` lacked `CAP_NET_BIND_SERVICE`, so even root could not bind 127.0.0.1:53. Fixed in `SystemdUnit` (+ test), re-installed in row 11. |
| 8' | Privacy Shield on/off (fixed unit) | PASS | `privacy.configure {"enabled":true}` → `{'state':'Active','enabled':True,'running':True,'bindAddress':'127.0.0.1, ::1','upstream':'192.168.70.1:53','ruleCount':24}`; journal `Privacy Shield DNS: redirect (SystemdResolved): links=eno2`; `resolvectl status eno2` → `DNS Servers: 127.0.0.1`; `/etc/resolv.conf` unchanged (stub 127.0.0.53, resolved forwards to the shield); `resolvectl query doubleclick.net` → `Name 'doubleclick.net' not found`; `resolvectl query example.com` → `2606:4700:10::ac42:93f3 …`; `curl https://example.com` → 200; doctor `PASS dns backend: SystemdResolved; eno2: 127.0.0.1`, `PASS privacy shield dns: redirected to 127.0.0.1 on eno2; backup present.`; `privacy.status` → `queries 30, allowed 26, blocked 4`. `privacy.configure {"enabled":false}` → `state:"Disabled", running:False`; `resolvectl status eno2` → `DNS Servers: 192.168.70.1`. |
| 9 | `networkRecovery.capture` / `restore` with the shield on | PASS | `capture` → `{"status":"alreadyCaptured","capturedUtc":"…05:25:42Z","adapterCount":1,"ruleCount":0,"persisted":true}` (baseline from service start); `restore` → `{"status":"succeeded","adaptersRestored":1,"adaptersVerified":1,"verified":true,"problems":[]}`, journal `Network recovery restore by uid:1000: 1 adapter(s), 0 rule(s), verified True`; `resolvectl status eno2` → `192.168.70.1` while the shield still reports `Active` (recovery overrides the redirect without touching shield settings, as on macOS). |
| 10 | `systemctl restart axiomd` with a block rule | PASS | Rule 2 applied, `sudo -n systemctl restart axiomd` → `Stopping… Stopped… Started…`, journal `Published table inet axiom generation 5 (1 applied, 0 rejected)`, 3 `cgroupv2` rules back; herded curl → `https://example.com/ http=000 exit=7`, `rc=7`; `rule.verify` → `effectiveAction:"block"`, `2 packet(s) matched`. |
| 11 | Upgrade in place (`--install-service` over a running daemon, rule present) | PASS | New publish (`Axiom.Infrastructure.Linux.dll` b58071b0… vs installed 52983688…; the `axiomd` apphost itself hashes identical, the installer's `FilesMatch` check compares that file — silent on success, so there is no journal line for it). `sudo -n build/linux/axiomd/axiomd --install-service` → `Installed and started axiomd.service from /usr/libexec/axiom`, rc=0; `Stopped` → `Started`, new `MainPID`, `CapabilityBoundingSet` now includes `cap_net_bind_service`; journal `IPC endpoint … (uid 0 or uid >= 1000, checked with SO_PEERCRED)` (was the macOS `uid >= 501 … getpeereid` text), `Published table inet axiom generation 6 (1 applied, 0 rejected)`; herded curl → `exit=7` again; installed dll hash = new hash. Journal from the new pid: **0** "Got notification message … only permitted for main PID" lines (the old daemon logged two every 30 s). |
| 12 | `--uninstall-service` | PASS | `sudo -n /usr/libexec/axiom/axiomd --uninstall-service` → `Removed /usr/libexec/axiom.` `Stopped and removed axiomd.service.` rc=0. After: `systemctl is-active` → `inactive` / `not-found`, unit file gone, `/usr/libexec/axiom` gone, `nft list table inet axiom` → `Error: No such file or directory`, `/sys/fs/cgroup/axiom.slice` gone, `/run/axiom` gone, no `axiomd`/`nft monitor` process. `/var/lib/axiom` (`drwx------ root`) is **kept**, like the macOS uninstaller keeps its data root: rules, protection consent, history and the DNS backup survive a reinstall; `rm -rf /var/lib/axiom` is the operator's explicit step. `curl https://example.com` → 200, `resolvectl query example.com` resolves. |
| 13 | DNS diff vs baseline | FAIL → fixed | `diff` of `resolvectl status` before/after showed one residual line on eno2: `DNS Domain: ~.` (servers were correct). Cause: `ResolvedDnsBackend.SetDns` ran `resolvectl domain eno2` with *no* domain argument to restore an empty domain list, which only prints; `resolvectl domain eno2 ''` clears. Fixed in `LinuxDnsBackends.cs` (+ test). Box cleaned with `sudo -n resolvectl domain eno2 ''` → `diff` empty (`IDENTICAL-TO-BASELINE`); `/etc/resolv.conf` identical throughout. |
| 14 | Journal noise | FAIL → fixed | `strace -f` on the daemon: `resolvectl dns` / `resolvectl domain` children `sendmsg(… "/run/systemd/notify", "EXIT_STATUS=0")` — they inherit `$NOTIFY_SOCKET`; with `NotifyAccess=main` systemd logs `Got notification message from PID …, but reception only permitted for main PID` for every probe (2 lines / 30 s). Fixed by removing `NOTIFY_SOCKET` from the child environment in `ToolProcess`, `NftRunner`, `NftTraceMonitor`; verified in row 11. |

## Gates after P3

`dotnet build Axiom.sln -c Release -p:EnableWindowsTargeting=true` → `Build succeeded. 0 Warning(s) 0 Error(s)`.
Contracts 142/142, Core 117/128 (the same 11 pre-existing Windows-path failures as P1 and the pristine
`7a48bdf`), McpServer 33/33, Persistence 19/19, Presentation 90/90, UI.Avalonia 40/40,
Infrastructure.MacOS 155/155, Desktop.Avalonia.MacOS 35/35, Infrastructure.Unix 22/22,
Infrastructure.Linux 27/27, Infrastructure.Linux.Nft 54/54.

## Blocked by the host guard (not retried, not worked around)

- A combined command containing `sudo -n cat /var/lib/axiom/protection.json; sudo -n ls -la /var/lib/axiom`
  was held for approval ("sudo with combined-flag privilege escalation"); the data-directory contents were
  therefore not inspected directly (the doctor's `data directory: /var/lib/axiom root 0700` check covers the modes).
- The first uninstall command was held for the same reason because it contained `sudo -n ls -la /var/lib/axiom`;
  it was re-issued without that sub-command (row 12).

## Not proven here

- The exec-time race (row 4b) means a short-lived process can get one connection out; eBPF `cgroup/connect4` (P2b) closes it.
- NetworkManager-only and plain `/etc/resolv.conf` hosts (this box runs systemd-resolved); the other two backends are unit-tested only.
- Inbound rules and remote-address/port rule shapes on the live kernel (unit-tested; the e2e used an outbound app-only block).
- Fedora/SELinux, firewalld coexistence, kernels without `nft_socket`.
- Desktop app, packaging, polkit: not built (see P4 below).

# Phase P4 — desktop host on this box (2026-11-12, branch `buba/linux`)

Same host, GNOME 46 on X11 (`DISPLAY=:1`, AppIndicator extension present so a StatusNotifierWatcher exists),
`axiomd.service` installed from `build/linux/axiomd`. Desktop published with `dotnet publish
src/Axiom.Desktop.Avalonia.Linux -r linux-x64 -c Release --self-contained -o build/linux/Axiom.next` and the daemon
tree copied to `build/linux/Axiom.next/axiomd/`. Driven with `xdotool` clicks and `scrot`; every screenshot was
inspected before it was kept (`docs/screenshots/linux/*.png`: no glyph boxes, no clipped layout). Rows marked
*(first run, re-verified)* were proven by the first walkthrough on the pre-`f85bdba` bundle and proven again on the
final bundle; rows marked *(first run)* come from that walkthrough's log and were not repeated.

| # | Step | Result | Evidence |
|---|---|---|---|
| 1 | Launch, daemon detection, tray probe | PASS (first run, re-verified) | `desktop.log`: `[startup] Axiom 0.13.0.0 pid=… base=…/build/linux/Axiom.next/`, `[tray] StatusNotifierWatcher present; creating tray icon`, `[daemon] state=Running unit=active endpoint=/var/run/axiom/axiom.sock`. The 10:21 launch, before the AppIndicator extension was active, logged `[tray] no StatusNotifierWatcher on the session bus; no tray, close = quit` — both branches of `StatusNotifierProbe` seen live. |
| 2 | Every page renders (dashboard, connections, applications, events, network control, privacy shield, agent protection, agent activity, AI analyst, integrations, settings, help, first-run, light theme) | PASS (first run) | `docs/screenshots/linux/*.png` (16 files). Settings shows `Milestone: Avalonia UI · Linux port`, `Protocol: IPC contract v1 (service connected)`, `Storage: /var/lib/axiom/axiom.db (daemon)`, `OS: Linux 7.0.0 · Ubuntu 24.04.5 LTS`. |
| 3 | Block rule from the UI (`curl`), then remove | PASS (first run) | `nft list table inet axiom` → `comment "axiom generation 9"`, `socket cgroupv2 level 2 "axiom.slice/a-f0da955d46aa49e3" … reject with tcp reset comment "axiom:f070ab4f-…"`; herded curl: second connect reset, `rc=7`; after Unblock from the Remembered Shield decisions row: `after-remove:200`. `network-control-rule.png`. |
| 4 | Privacy Shield on/off from the UI | PASS (first run) | After Enable: `resolvectl status eno2` → `DNS Servers: 127.0.0.1`, resolver answers (`104.20.23.154`), `ss -ulpn` shows `127.0.0.1:53` next to the resolved stubs; `privacy-shield-enabled.png`. After Disable: `192.168.70.1`, `diff` against the baseline empty (`RESOLVED BASELINE RESTORED`, the `DNS Domain: ~.` residue seen once came from the pre-fix daemon image and was cleared with `resolvectl domain eno2 ''`). |
| 5 | Process actions | PASS (first run) | End-process on a root-owned pid refused by policy: `[process] pid 12 not ended: RootOwned`, `pid 1 not ended: InitProcess` (no signal sent). |
| 6 | AI analyst key persisted through the protector | PASS (first run, re-verified) | Saved dummy key `test-key-123` → `~/.local/share/Axiom/ai-analyst.json` holds only `"apiKeyProtected": "ss1:…"`; `~/.local/state/axiom/secret-protection-key` 0600 in a 0700 directory (no `secret-tool` on this box, so the file store was used). Relaunch on the final bundle: the field shows the placeholder `stored with keyring`, hint `API key is stored with the Secret Service keyring (file fallback under ~/.local/state/axiom); it is never shown or logged.` The key text never appeared in the UI, the settings file or `desktop.log`. |
| 7 | Windows firewall profiles hidden | PASS (re-verified) | Network Control page and the `New owned rule` editor after relaunch: checkboxes are `Enabled` only; no `Domain`/`Private`/`Public`; `PROFILES` column of the owned-rules table is present but empty. |
| 8 | Single instance | FAIL on the first bundle → fixed in `f85bdba` → PASS (re-verified) | First run: second launch logged `Another Axiom instance is running; show signal delivered=True` and then `[fatal] System.InvalidOperationException: Cannot perform requested operation because the Dispatcher shut down` (lock taken inside `App`). After moving the lock into `Main`: second launch of `build/linux/Axiom.next/Axiom` prints the `show signal delivered=True` line, `second rc=0`, no fatal, first pid still running and its window raised. |
| 9 | Autostart toggle | PASS (re-verified) | First run: ticking *Start at login* wrote `~/.config/autostart/com.axiom.firewall.desktop` (`Exec="…/build/linux/Axiom/Axiom" --autostart`, `X-GNOME-Autostart-enabled=true`). Relaunch from `Axiom.next`: Settings shows the box ticked with `Autostart: path is stale; repair` + an enabled *Repair startup entry* button; unticking → `ls ~/.config/autostart/` empty, `Autostart: off`, repair button disabled. |
| 10 | Disable protection from the UI | PASS | *Disable protection* → confirmation `Disable Axiom Shield — Turn protection off and remove every Axiom-owned nftables firewall rule?` → badge `OFF`, `Protection is off. Axiom only observes.`, nftables section `READ-ONLY`. |
| 11 | Install path through pkexec | PASS | `sudo -n /usr/libexec/axiom/axiomd --uninstall-service` (`Removed /usr/libexec/axiom. Stopped and removed axiomd.service.`), app relaunched → `[daemon] state=NotInstalled unit=inactive …` and the startup offer `Install the Axiom background service … polkit will ask for an administrator password once.` *Install* with a bundle that lacked `axiomd/`: message `The Axiom daemon was not found at …/Axiom.next/axiomd/axiomd. Reinstall Axiom.` (graceful). With the daemon tree copied in: `pkexec …/Axiom.next/axiomd/axiomd --install-service` + `polkit-agent-helper-1 buba` running, GNOME Shell dialog `Authentication Required — Authentication is needed to run '…/axiomd --install-service' as the super user` (`polkit-install.png`; generic text because the policy's `exec.path` is `/usr/libexec/axiom/axiomd` and the policy is not installed on this box). *Cancel* clicked, nobody typed a password → `[daemon] install: Administrator approval was cancelled.` and the message `Background service not installed — Administrator approval was cancelled.`; no `pkexec` left. Daemon reinstalled afterwards with `sudo -n build/linux/axiomd/axiomd --install-service` (`active`, `enabled`, installed `Axiom.Infrastructure.Linux.dll` hash = publish hash `2da3b118…`). |
| 12 | Not exercised | — | Tray menu clicks (GNOME's AppIndicator menu is not reachable with `xdotool`; the menu items are unit-tested), portal theme change at runtime (light theme was selected from the palette, `settings-light.png`), restart/shutdown actions, `secret-tool` keyring path. |

## Gates after P4

`dotnet build Axiom.sln -c Release -p:EnableWindowsTargeting=true` → `Build succeeded. 0 Warning(s) 0 Error(s)`.
Contracts 142/142, Core 117/128 (the same 11 pre-existing Windows-path failures as P1/P3 and the pristine
`7a48bdf`), McpServer 33/33, Persistence 19/19, Presentation 90/90, UI.Avalonia 40/40, Infrastructure.MacOS
155/155, Desktop.Avalonia.MacOS 35/35, Infrastructure.Unix 22/22, Infrastructure.Linux 27/27,
Infrastructure.Linux.Nft 54/54, Desktop.Avalonia.Linux 49/49. `git checkout -- '*.lock.json'` afterwards.

## P2b: connect-time BPF layer (branch `buba/linux-enforce`, 2026-11-12)

Same host (Ubuntu 24.04.5, kernel 7.0.0-42-generic, cgroup2fs, `bpftool` 7.x at `/usr/sbin/bpftool`,
`/sys/kernel/btf/vmlinux` present, `unprivileged_bpf_disabled=2`, `bpftool cgroup tree` shows systemd's
`sd_fw_egress`/`sd_devices` programs attached `multi` on ~15 service cgroups and snap's `cgroup_device` ones).

| # | Step | Result | Evidence |
|---|---|---|---|
| 1 | Toolchain probe `which clang llvm-strip bpftool; ls /sys/kernel/btf/vmlinux; dpkg -l \| grep -E 'libbpf\|clang'` | **BLOCKED** | `bpftool` and the BTF file exist; `clang` and `llvm-strip` are absent (`find / -name clang*` → only `libclang-cpp18`/`libclang1-18` libraries), `libbpf1` runtime only — no `/usr/include/bpf/bpf_helpers.h`. Per the brief nothing was installed; needs `apt install clang libbpf-dev`. |
| 2 | Design + sources | done, uncompiled | `docs/LINUX_EBPF.md`; `src/Axiom.Infrastructure.Linux/Bpf/native/{axiom_bpf.h,axiom_connect.bpf.c,axiom-bpf-events.c,Makefile}`. `make check-tools` reports the missing pieces before touching anything. |
| 3 | .NET engine + wiring | done | `Bpf/{BpfLayout,BpfVerdictPlanner,BpfCapabilityProbe,BpfEngine,BpfEventMonitor}.cs`, `Nft/IVerdictLayer.cs`; adapter `VerdictLayer` + `ResyncLayerAsync`, supervisor layer lifecycle, `LinuxEnforcement.CreateBpfEngine`, DI + `NftEnforcementWorker`, doctor check `bpf layer`, `snapshot.limitations`, unit caps `CAP_BPF CAP_PERFMON` + `ReadWritePaths /sys/fs/bpf`, csproj ships `bpf/*` when built. |
| 4 | Unit tests | PASS | `Axiom.Infrastructure.Linux.Nft.Tests` 67/67 (13 new in `BpfLayerTests`: byte layout, stat parsing, planner coverage/merging/never-widening, probe order, event parsing + flow pair with `bpf-N` ids, engine load/attach/sync/delete/unpin over a fake `bpftool`, attach-failure rollback, no-objects/non-root paths, adapter sync after publish + inactive-layer reason, supervisor start/stop ordering, unit caps, doctor WARN-never-FAIL). `Axiom.Infrastructure.Linux.Tests` 27/27. |
| 5 | Part A e2e (`scripts/linux/bpf/e2e.sh`: load/pin/attach, curl inode entry, bare curl rc=7, event, delete → 200, detach/unpin clean) | **not run** | Needs the compiled object (row 1). Script written and syntax-checked; nothing BPF-related was created on the box. |
| 6 | Part B daemon path (`--daemon`: install in place, `rule.apply` block curl → bare curl rc=7, `snapshot` `bpf-` flow, journal `BPF layer attached`) | **not run** | Same blocker. The daemon on the box is unchanged (P4 image, active, no rules, shield off). Expected behaviour of the new image without the objects: journal `BPF layer inactive: BPF object not shipped: /usr/libexec/axiom/bpf/axiom_connect.bpf.o (…)`, nft-only. |

## Box state after P4 (owner's instruction: daemon stays installed)

`axiomd.service` active + enabled from the newest image, `table inet axiom` holds only the loopback accept rules
(0 `cgroupv2` rules), no `/sys/fs/cgroup/axiom.slice`, protection off (`firewallWrites: false`), Privacy Shield
disabled, `resolvectl status eno2` → `DNS Servers: 192.168.70.1` and no `DNS Domain` line, `/etc/resolv.conf`
unchanged (stub). Removed: the test key (`apiKeyProtected` cleared, `secret-protection-key` deleted),
`~/.config/autostart/com.axiom.firewall.desktop`, the `axiom-desktop.lock/.sock` runtime files, every Axiom
desktop process. Kept on purpose: `/var/lib/axiom`, `packaging/linux/com.axiom.firewall.policy` (not installed
system-wide), `build/linux/*`.
