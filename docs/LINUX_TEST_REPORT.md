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

## Security parity with the macOS review + BPF proof (2026-11-12, branch `buba/linux` after merging `buba/macos` 2436b3d and `buba/linux-enforce` ecc1330)

Same box (Ubuntu 24.04.5, kernel 7.0.0-42-generic, systemd 255, nft 1.0.9, clang 18.1, libbpf-dev 1.3, bpftool 7.7.0,
`/sys/kernel/btf/vmlinux` present). Baseline before the run: `axiomd.service` active from the P4 image, no rules,
shield off (`writeGateOpen:false`), Privacy Shield disabled, `resolvectl status eno2` → `DNS Servers: 192.168.70.1`,
no `axiom_*` BPF program, `/sys/fs/bpf` empty of ours. Daemon rebuilt from this branch
(`dotnet publish src/Axiom.Service -f net10.0 -r linux-x64 -c Release --self-contained -o build/linux/axiomd`, the
csproj ships `bpf/*` because `Bpf/native/out` exists) and installed in place with `sudo -n build/linux/axiomd/axiomd --install-service`.

| # | Step | Result | Evidence |
|---|---|---|---|
| S1 | Second uid, public reads | PASS | throwaway account `sudo -n useradd -M -s /usr/sbin/nologin axtest` (uid 1001, not in `sudo`/`wheel`/`axiom`); `sudo -n -u axtest python3 -I axipc.py serviceHealth` → `ok` keys `status, uptimeSeconds, sourceName, pollIntervalSeconds, lastCaptureUtc, connectionCount, processCount, limitations`; `capabilities` → `ok` keys `protocolVersion, commands, monitoring, firewallWrites, milestone` |
| S2 | Second uid, private reads + writes | PASS | `snapshot`, `history.query`, `diagnostics.export` → `error unauthorized – This command discloses machine-wide activity and is only allowed for root, the user who installed …`; `privacy.configure`, `rule.apply` → `error unauthorized – This command changes machine-wide settings …`. Journal: `Denied 'snapshot' for uid:1001: private read commands are not allowed for this caller.` (one line per command). `sudo -n userdel axtest` afterwards (no host-guard block) |
| S3 | Installing uid (1000) | PASS | `serviceHealth`, `capabilities`, `snapshot`, `rules.query`, `history.query` all `ok`; `protection.enable {"defaultPolicy":"ask"}` → `writeGateOpen:true` |
| S4 | `LinuxSocketIpcTests` with `AXIOM_TEST_SECOND_USER=axtest` | PASS | `Passed! – Failed: 0, Passed: 2` (installing uid full access; second uid public-only + `unauthorized` over the real `SO_PEERCRED` socket) |
| S5 | `rule.apply` Block `/usr/bin/curl` (`createdBy` is required in the payload) | PASS | `{"success":true,"state":"applied","osRuleName":"Axiom::0f8fad5b-…::OUT"}`; journal `BPF verdicts generation 16: 1 exe, 1 cgroup entries; 0 rule(s) left to nftables.` |
| S6 | Bare `curl -m 8 https://example.com` immediately after | PASS | `curl: (7) Failed to connect to example.com port 443 after 0 ms` **rc=7 in 8 ms** (the BPF layer closes the exec race); `curl --limit-rate 400k` → rc=7, 8 ms |
| S7 | `rule.verify` | PASS | `presentInOs:true, matchesSpec:true, effectiveAction:"block", enforcementVerified:true`, notes `table inet axiom generation 16, 3 nft rule(s), 0 packet(s) matched.` (0 packets because BPF refused the connect before any packet) |
| S8 | `rules.query` enforcement report | PASS | `filterEnforcement {state:"verified", connected:true, publishedGeneration:16, ackedGeneration:16, lastSeenUtc, lastAckUtc, appliedRuleCount:1, rejectedRules:[]}`; `limitations: ["Attribution is a 1 s loop: … The BPF layer closes this window for unscoped outbound block rules."]` |
| S9 | `sudo -n nft delete table inet axiom` | PASS | 4 s later `rules.query` → `{state:"degraded", connected:false, publishedGeneration:16, ackedGeneration:null}`; bare curl still rc=7 (BPF maps); journal `table inet axiom disappeared (generation 16 was published); enforcement degraded; republishing.` → `Republished table inet axiom generation 17; enforcement verified.`; report back to `verified … 17/17`, rule still `applied` |
| S10 | Hostname rule (`remoteAddresses:["example.com"]`) | PASS | `{"success":false,"state":"failed","errorCode":"rule.invalid","errorMessage":"rule.addresses.invalid: 'example.com' is not an IP address or CIDR range."}` |
| S11 | `rule.remove` | PASS | `state:"desired"`; bare curl → `200 rc=0`; journal `BPF verdicts generation 18: 0 exe, 0 cgroup entries`; report `verified 18/18, appliedRuleCount:0` |
| S12 | Journal BPF lines | PASS | `BPF layer attached: connect4/connect6/sendmsg4/sendmsg6 at /sys/fs/cgroup (multi), pinned at /sys/fs/bpf/axiom.`; `sudo -n bpftool cgroup tree /sys/fs/cgroup` → 4 `axiom_*` programs `multi` at `/sys/fs/cgroup`. First install attempt logged `BPF layer inactive: bpftool prog loadall failed: libbpf: failed to mkdir /sys/fs/bpf/axiom/axiom_connect4: -EROFS` → unit fixed (`ProtectKernelTunables=no` + hand-written `ReadOnlyPaths`), reinstalled, attached |
| S13 | `--doctor` | PASS | all 12 checks PASS incl. `log directory: /var/log/axiom root 0700, no file logs (journal only).`, `ipc owner: uid 1000 may write; admin groups allowed.`, `enforcement: … table inet axiom generation 14 is in force.`, `bpf layer: bpftool v7.7.0; 4 programs pinned at /sys/fs/bpf/axiom (connect4/connect6/sendmsg4/sendmsg6 at the cgroup root).`; `stat /var/log/axiom` → `root:root 700` |
| S14 | Privacy Shield on/off | PASS | on → `state:"Active", upstream:"192.168.70.1:53"`, `resolvectl` → `DNS Servers: 127.0.0.1`, curl 200; off → `state:"Disabled"`, `DNS Servers: 192.168.70.1` (baseline), `/etc/resolv.conf` stub unchanged |
| S15 | `protection.disable` | PASS | `enabled:false, writeGateOpen:false`; end state: 0 `socket cgroupv2` rules in `table inet axiom`, `axiom.slice` holds no app cgroup, the daemon's 4 BPF programs stay attached (daemon stays installed per owner's instruction) |
| S16 | `scripts/linux/bpf/e2e.sh` part A (bpftool only) | PASS | first run (before the daemon had BPF): verifier rejected `axiom_connect4` (`invalid bpf_context access off=8`) → per-family fix → PASS. Re-run with the live daemon attached: `our prog ids: 1771 1772 1773 1774` → exe verdict for `/usr/bin/curl` (dev 8:2 ino 51643045) → bare curl `000 rc=7` → 8 block events from `axiom-bpf-events` (`{"verdict":"block","source":"exe","hook":"connect","family":2/10,"proto":6/17,"dport":443,…}`) → delete entry → `200 rc=0` → `/sys/fs/bpf/axiom-e2e removed`, none of our ids loaded/attached, only the daemon's own 4 remain. `## RESULT: PASS` |

Not exercised: a second *admin* uid (no spare `sudo`-group account; the pure table is covered by `LinuxPeerAuthorizationTests`), Pending-state UI banner on a real desktop (text covered by `FilterEnforcementSummaryTests`), BPF on another kernel.

## P5: packaging (`.deb`), 2026-11-12, branch `buba/linux` after `ab1c976`

Box: Ubuntu 24.04, GNOME 46 X11 `DISPLAY=:1`, kernel 7.0.0-42, systemd 255, dpkg 1.22.6, fakeroot, no lintian.
Before: `axiomd.service` active from the P3 dev image (`Axiom.Infrastructure.Linux.dll` sha256 `963b9087…`),
protection off, 0 managed rules, Privacy Shield disabled, `resolvectl status` eno2 → `DNS Servers: 192.168.70.1`,
`/etc/resolv.conf` → `nameserver 127.0.0.53` (recorded to a file and diffed at the end).

| # | Step | Result | Evidence |
|---|---|---|---|
| P-0 | `scripts/linux/package.sh deb` (clang present: BPF objects rebuilt; publish both; stage; shlibdeps; fakeroot dpkg-deb) | PASS | `build/linux/axiom_0.13.2_amd64.deb` 62 874 284 bytes, control archive with `postinst`/`prerm`/`postrm`, 504 entries, `Installed-Size: 193480`; `dpkg -c` shows `/opt/axiom/Axiom`, `/opt/axiom/axiomd/axiomd`, `/opt/axiom/axiomd/bpf/{axiom_connect.bpf.o,axiom-bpf-events}`, desktop entry, 8 hicolor icons, polkit action, `usr/share/doc/axiom/{copyright,README.md}`, everything `root/root`. `Depends: libbpf1 (>= 1:0.0.9), libc6 (>= 2.34), libfontconfig1 (>= 2.12.6), libgcc-s1 (>= 3.0), libstdc++6 (>= 6), libicu76 \| libicu74 \| …, nftables, polkitd \| policykit-1, pkexec \| policykit-1, systemd`; `Recommends: linux-tools-common \| bpftool, libsecret-1-0, gnome-shell-extension-appindicator \| plasma-workspace`. `ls build/linux/Axiom/axiomd/axiomd` → present (publish target) |
| P-1 | `sudo -n dpkg -i build/linux/axiom_0.13.2_amd64.deb` over the running dev daemon | PASS | `Setting up axiom (0.13.2)… Installed and started axiomd.service from /usr/libexec/axiom (/etc/systemd/system/axiomd.service).` + hicolor/desktop-file/gnome-menus triggers; `systemctl is-active axiomd` → `active`; image dll sha256 now `de43b936…` (replaced in place); `/usr/libexec/axiom/bpf` has both objects; `dpkg -L axiom \| wc -l` → 504; `dpkg -s` → `install ok installed` |
| P-2 | `sudo -n /opt/axiom/axiomd/axiomd --doctor` | PASS | 11/11 PASS incl. `protected image: /usr/libexec/axiom: 234 entries root-owned and read-only`, `enforcement: … table inet axiom generation 19 is in force`, `bpf layer: bpftool v7.7.0; 4 programs pinned at /sys/fs/bpf/axiom`; `Result: all checks passed.` |
| P-3 | polkit action visible | FAIL → fixed → PASS | first build: `pkaction --action-id com.axiom.firewall.install` → `No action with action id`; cause: the shipped policy's XML comment contained `--` (`xml.dom.minidom` → `not well-formed (invalid token): line 6, column 58`), polkitd drops the file silently. Comment rewritten, `package.sh` validates the policy; after the rebuilt package was installed: `pkaction \| grep axiom` → `com.axiom.firewall.install` |
| P-4 | Launch from the desktop: `gtk-launch com.axiom.firewall` on `DISPLAY=:1` (bells off first) | PASS | process `/opt/axiom/Axiom` pid 1208031; window `Axiom — Free Open-Source Network & AI Agent Security`; `desktop.log`: `[startup] Axiom 0.13.2.0 … base=/opt/axiom/`, `[tray] StatusNotifierWatcher present`, `[daemon] state=Running unit=active`; 0 `pkexec`/`polkit-agent-helper` processes, no install dialog; `docs/screenshots/linux/packaged-launch.png` (vision-checked: Dashboard, "Protection: off", no dialog); `ls /usr/share/icons/hicolor/*/apps/com.axiom*` → 8 files; closed with `xdotool windowclose` (to tray) + `kill <pid>` |
| P-5 | Rule flow through the packaged daemon (`scripts/linux/axipc.py`) | PASS | `protection.enable {"defaultPolicy":"ask"}` → `writeGateOpen:true`; `rule.apply` block `/usr/bin/curl` (GUID id, `createdBy:"uid:1000"`) → `state:"applied"`; bare `curl https://example.com` → `000 rc=7`; `rule.remove` → `state:"desired"`; curl → `200 rc=0`; `protection.disable` → `enabled:false`; `rules.query` → `managedRuleCount:0`. (A non-GUID `managedRuleId` is refused with `invalid_request`.) |
| P-6 | `sudo -n apt-get remove -y axiom` | PASS | `Removed /usr/libexec/axiom. Stopped and removed axiomd.service.`; `is-active` → `inactive`; unit file, `/usr/libexec/axiom`, `/opt/axiom`, desktop entry, policy all gone; `bpftool cgroup tree \| grep -c axiom_` → 0; `nft list tables` → no axiom; `/var/lib/axiom` kept; `dpkg -s` → `deinstall ok config-files`; DNS `192.168.70.1` |
| P-7 | `sudo -n dpkg -P axiom` | PASS | `Purging configuration files for axiom (0.13.2)…`; `/var/lib/axiom` gone, `/var/log/axiom` gone, `/run/axiom` gone; package unknown to dpkg |
| P-8 | Reinstall (box keeps a packaged daemon) | PASS | `dpkg -i` → `Installed and started axiomd.service`; `active`; `pkaction` lists `com.axiom.firewall.install`; `--doctor` → `Result: all checks passed.`; protection `enabled:false`, shield `Disabled`, `managedRuleCount:0`; `resolvectl status` Link 2 block identical to the recorded baseline, `/etc/resolv.conf` unchanged |
| P-9 | `scripts/linux/package.sh rpm --skip-publish` (nfpm 2.49.0, sha256 verified against the release `checksums.txt`) | PASS (build only) | `build/linux/axiom-0.13.2-1.x86_64.rpm` 76 256 524 bytes; not installed (no RPM host; `rpm` not on this box) |

Held by the host guard (not retried in that form): a one-liner combining `kill` with a `pgrep` expansion; the app was
closed with `xdotool windowclose` and `kill <explicit pid>` in a separate command instead.

Gate after P5: `dotnet build Axiom.sln -c Release -p:EnableWindowsTargeting=true` → `0 Warning(s) 0 Error(s)`;
Infrastructure.Linux 32/32, Infrastructure.Linux.Nft 82/82, Infrastructure.Unix 32/32, Desktop.Avalonia.Linux 51/51
(+2: startup-offer rule, package prefix); `bash -n` on every maintainer script (shellcheck and lintian not installed);
`git checkout -- '*.lock.json'`.

## Gates after the security parity + BPF merge

`dotnet build Axiom.sln -c Release -p:EnableWindowsTargeting=true` → `0 Warning(s) 0 Error(s)`. `Axiom.Portable.slnx` build → `0 Warning(s) 0 Error(s)`; test: Contracts 142/142, Core 117/128
(the same 11 pre-existing Windows-path failures as every earlier gate and as pristine `buba/macos` on this host),
Desktop.Avalonia.MacOS 35/35, Infrastructure.Linux 32/32 (+5: socket IPC classes, log permissions, doctor),
Infrastructure.Unix 32/32 (+10: Linux peer-authorization table), Infrastructure.MacOS 199/199, McpServer 33/33,
Persistence 21/21, Presentation 93/93, UI.Avalonia 42/42. Separately: Infrastructure.Linux.Nft 82/82 (+15:
lifecycle readback/pending/degraded/unavailable, BPF layer), Desktop.Avalonia.Linux 49/49, Service.Tests 66/78
(the same 12 pre-existing failures as `buba/macos` 2436b3d on this host, e.g. `FirewallRuleCoordinatorTests.Apply_failure_stores_failed_state_and_error`).
`git checkout -- '*.lock.json'` afterwards; `dotnet build-server shutdown`.

## Box state after the security parity + BPF run (owner's instruction: daemon stays installed)

`axiomd.service` active + enabled from the image built here (with `bpf/*` shipped), `table inet axiom` holds only the
loopback accept rules (0 `cgroupv2` rules), no app cgroup under `axiom.slice`, protection off (`writeGateOpen:false`),
Privacy Shield disabled, `resolvectl status eno2` → `DNS Servers: 192.168.70.1`, `/etc/resolv.conf` stub unchanged.
The daemon's own four `axiom_*` programs stay attached at `/sys/fs/cgroup` and pinned at `/sys/fs/bpf/axiom` (they are
part of the running daemon; `--uninstall-service` detaches and removes them). `/sys/fs/bpf/axiom-e2e` gone; `axtest`
user removed; `build/linux/axiomd` kept.

## Box state after P4 (superseded by the section above)

`axiomd.service` active + enabled from the newest image, `table inet axiom` holds only the loopback accept rules
(0 `cgroupv2` rules), no `/sys/fs/cgroup/axiom.slice`, protection off (`firewallWrites: false`), Privacy Shield
disabled, `resolvectl status eno2` → `DNS Servers: 192.168.70.1` and no `DNS Domain` line, `/etc/resolv.conf`
unchanged (stub). Removed: the test key (`apiKeyProtected` cleared, `secret-protection-key` deleted),
`~/.config/autostart/com.axiom.firewall.desktop`, the `axiom-desktop.lock/.sock` runtime files, every Axiom
desktop process. Kept on purpose: `/var/lib/axiom`, `packaging/linux/com.axiom.firewall.policy` (not installed
system-wide), `build/linux/*`.

## Windows runner

`Axiom.Infrastructure.Linux.Tests`, `Axiom.Infrastructure.Linux.Nft.Tests`, `Axiom.Infrastructure.Unix.Tests` and
`Axiom.Desktop.Avalonia.Linux.Tests` exercise Linux/Unix-only runtime behaviour (`/` path expectations,
`File.SetUnixFileMode`, `pkexec` wording, Doctor WARN vs SKIP, `desktop.lock` cleanup) and went red on the Windows 11
VM run (`docs/WINDOWS_REGRESSION_2026-11-12.md`: 4 + 1 + 2 + 5 failures) without any Windows code being involved.
Each csproj now sets `<IsTestProject Condition="$([MSBuild]::IsOSPlatform('Windows'))">false</IsTestProject>` (same
pattern as the macOS test projects merged from `buba/macos`): the projects still compile on every OS, but
`dotnet test Axiom.sln` on a Windows runner no longer executes them (verified on Linux by inverting the condition to
`IsOSPlatform('Linux')`: the assemblies disappear from the solution test run). The `MacBundleLayoutTests` path fix
and the deterministic `Firewall_page_requeries_enforcement_when_stale` come in with the `buba/macos` merge. Not
re-run on the Windows VM in this pass.

## PR #276 review (LNX-1, LNX-2): red run, fix, fault matrix, live evidence (2026-11-12)

Host: Ubuntu 24.04.5 LTS, x86_64, kernel `7.0.0-42-generic`, `nftables v1.0.9 (Old Doc Yak #3)`, `bpftool v7.7.0`
(`libbpf v1.7`), systemd 255. Branch `buba/linux`: red tests `4ff73d5` on `62b6406`; fixes `983ef21` (LNX-1),
`bd33548` (LNX-2), `f2063fa` (hardening + fault matrix), `d8949e9` (CA1873). Author-run; not CI.

### Red run (tests at `4ff73d5`, fix absent)

`dotnet test tests/Axiom.Infrastructure.Linux.Nft.Tests -c Release` in a detached worktree of `4ff73d5`:
`Failed!  - Failed: 7, Passed: 83, Skipped: 0, Total: 90`. Failing:
`BpfEffectiveStateTests.Remove_whose_bpf_map_delete_failed_must_not_report_a_verified_removal` ("a removal with a
stale BPF entry must not be reported as verified"), `…Partial_bpf_map_update_failure_leaves_the_rule_pending_not_applied`,
`NftEnforcementSupervisorTests.{Attribution,Watcher,Events,Trace}_loop_fault_still_tears_down*` (the events and
trace variants hit the 5 s guard: the loop fault never ended the run), `…Teardown_step_failure_does_not_skip_the_other_steps_and_is_reported`.

### Green gate (at `d8949e9`)

`dotnet build Axiom.sln -c Release -p:EnableWindowsTargeting=true` → `0 Warning(s) 0 Error(s)`.
Infrastructure.Linux.Nft **106/106** (82 before + 8 red tests + 16 fault matrix; stable over 4 runs),
Infrastructure.Linux 32/32, Infrastructure.Unix 32/32, Desktop.Avalonia.Linux 51/51; macOS unchanged:
Infrastructure.MacOS 199/199, Desktop.Avalonia.MacOS 35/35. `dotnet build-server shutdown`; `git checkout -- '*.lock.json'`.

### Fault matrix (unit, `LinuxFaultMatrixTests` + `BpfEffectiveStateTests` + supervisor tests)

| Fault | Expected | Result |
|---|---|---|
| unscoped outbound block | nft rule + exe and cgroup verdicts, `Verified` | PASS |
| `bpftool map delete` fails persistently | remove `Success=false`, `Pending`, `bpf.delete_failed`; 3 passes; only `axiom_*` detached; `Degraded`; watcher re-attaches; retry verified | PASS |
| delete **and** detach fail | `bpf.stale_entry`, "may still be blocked", engine `degraded:`, verify not verified | PASS |
| transient update failure (1×) | repaired by the read-back pass, `Applied` | PASS |
| persistent partial update | `Pending` `bpf.update_failed`, report `Pending`; retry after recovery → `Applied`, no duplicates | PASS |
| unknown key in a pinned map | deleted by reconciliation | PASS |
| EPERM on map writes | `Pending`, message carries "Operation not permitted", limitation "BPF map sync failed" | PASS |
| bpftool vanishes at runtime | failed result (exit 127), not an exception; not verified | PASS |
| bpftool missing at start | layer inactive, rules `Applied` by nft, "BPF layer inactive … nftables alone" | PASS |
| map pin missing | not mistaken for a deleted key; removal `Pending` | PASS |
| programs detached by another tool | `bpf.neutralised`, `Degraded`, watcher re-attaches | PASS |
| scoped / inbound vs unscoped | `nft-only: <reason>` vs `BPF-backed`; coverage statement in limitations | PASS |
| fault in each loop (attribution, watcher, trace, events) | teardown of layer, table, cgroups; fault logged then rethrown | PASS |
| teardown: BPF stop throws / hangs / nft delete fails | other steps still run; errors aggregated; hang bounded | PASS |
| 3 rapid stop/start cycles | 4 attachments while running, 0 after; no pins; no `axiom.slice/*` | PASS |
| crash (no teardown) + new instance | old programs detached (4 not 8), orphan cgroup released, journal lines | PASS |
| every test | pre-seeded third-party program id 7 attached and never addressed; every nft call only `inet axiom`, no `flush ruleset` | PASS |

### Live, packaged daemon (`scripts/linux/package.sh deb` → `build/linux/axiom_0.13.2_amd64.deb`, 62 889 452 bytes)

Baseline: `axiomd` active (0.13.2 package), no rules, protection off, Privacy Shield `Disabled`, `Link 2 (eno2):
192.168.70.1`, `/etc/resolv.conf` → `nameserver 127.0.0.53`; tables `ip filter, ip6 filter, ip nat, ip6 nat, inet axiom`;
4 `axiom_*` programs at `/sys/fs/cgroup`.

| # | Step | Result | Evidence |
|---|---|---|---|
| L-0 | third-party table before publish: `nft add table inet zz_thirdparty` + output chain prio 10 + `tcp dport 9 counter comment "axiom-test thirdparty"` | — | listing sha256 `bf34380d…9119` |
| L-1 | upgrade: `sudo -n dpkg -i build/linux/axiom_0.13.2_amd64.deb` | PASS | `Installed and started axiomd.service from /usr/libexec/axiom`; `/usr/libexec/axiom/Axiom.Infrastructure.Linux.dll` sha256 `bbe0fc74…f9a8` = build; journal: old instance `BPF layer detached and /sys/fs/bpf/axiom removed.` + `Removed table inet axiom …`; new: `BPF verdicts generation 2: … (read back verified).` |
| L-2 | `protection.enable {"defaultPolicy":"ask"}`, `rule.apply` block `/usr/bin/curl` | PASS | `state:"applied"`; bare `curl -sS -m 8 https://example.com` → `Failed to connect … after 8 ms`, `000 rc=7`; `bpftool -j map dump pinned …/axiom_exe_verdicts` → key `08 00 00 00 02 00 00 00 a5 02 14 03 …` (dev 8:2 ino 51643045), value action 2, generation 3 |
| L-3 | fault: `sudo -n mv /sys/fs/bpf/axiom/maps/axiom_exe_verdicts …/held_exe_verdicts`, then `rule.remove` | PASS | `success:false`, `state:"pending"`, `errorCode:"bpf.delete_failed"`, `verifiedUtc:null`, message `… could not be deleted after 3 pass(es) (… map pin /sys/fs/bpf/axiom/maps/axiom_exe_verdicts is missing …); the daemon detached its own BPF programs …`; journal 23:26:35 `pass 1 left 1 stale … retrying in 250 ms`, `pass 2 … 500 ms`, `neutralising: detaching Axiom's programs …`; curl → `200` (nothing stale enforces) |
| L-4 | restore/reconcile | PASS | the neutralisation removed the pin tree (incl. the renamed pin), so there was nothing to rename back; 23:26:37 `BPF layer is neutralised; re-attaching …`, `BPF layer attached …`, `BPF verdicts generation 4: 0 exe, 0 cgroup entries … (read back verified)`, `BPF layer re-attached; enforcement verified.`; retry `rule.remove` → `success:true`, `state:"desired"`, `verifiedUtc` set; `rule.verify` → `presentInOs:false`; curl `200` |
| L-5 | re-apply, then `sudo -n systemctl kill -s KILL axiomd` | PASS | `Main process exited, code=killed, status=9/KILL`; `Scheduled restart job, restart counter is at 1`; new pid: `Startup reconciliation: table inet axiom generation 6 (replaced by the first publish); 1 axiom.slice cgroup(s) from a previous daemon (1 still ruled, 0 removed: )`, `BPF layer: reconciled orphaned state from a previous daemon: pinned axiom_connect4, … pins /sys/fs/bpf/axiom`, `Published … generation 7 … enforcement verified`; `bpftool -j cgroup show /sys/fs/cgroup` → **4** programs (`axiom_connect4/6`, `axiom_sendmsg4/6`), not 8; curl rc=7 |
| L-6 | `sudo -n systemctl stop axiomd` | PASS | `inactive`; `nft list tables` → no `inet axiom`, `inet zz_thirdparty` present; `bpftool cgroup show /sys/fs/cgroup` → empty; `/sys/fs/cgroup/axiom.slice` absent; `test -e /sys/fs/bpf/axiom` → rc 1; journal `BPF layer detached …`, `Removed table inet axiom and the Axiom cgroups …`; `zz_thirdparty` listing sha256 identical (`bf34380d…9119`) |
| L-7 | `sudo -n systemctl start axiomd` | PASS | `Published table inet axiom generation 8 (1 applied …)`, `BPF verdicts generation 8: 1 exe, 1 cgroup entries … (read back verified)`; curl rc=7 |
| L-8 | IPv6 | structural only | no IPv6 default route on this box (`ip -6 route show default` empty), so `curl -6` fails regardless (`rc=7 after 0 ms`) and proves nothing; the generated rules are `meta l4proto … socket cgroupv2 level 2 "axiom.slice/a-…"` in an `inet` table (no `ip`/`ip6` qualifier, so both families match), loopback accepts exist for `::1`, and `connect6`/`sendmsg6` are attached. Live v6 traffic: **untested** |
| L-9 | cleanup | PASS | `rule.remove` → `desired`, verified; `protection.disable` → `enabled:false`; `rules.query` → `managedRuleCount:0`; Privacy Shield `Disabled`; `nft delete table inet zz_thirdparty`; tables back to the baseline set; no `axiom.slice/a-*`; `Link 2 (eno2): 192.168.70.1`, resolv.conf unchanged; `axiomd` active |

Not done here: uninstall/purge/rollback of this build (the box keeps the packaged daemon by instruction; P-6/P-7 above
cover remove/purge of the same packaging), RPM install, other distributions.

## Fedora 45 RPM (2026-11-13, branch `buba/linux` at `5ffc5ba` + packaging fix `a1b65f8`)

VM: Fedora Cloud Base Generic 45-1.4 (image sha256 verified against `Fedora-Cloud-45-1.4-x86_64-CHECKSUM`), QEMU/KVM
2.5 GB, 2 vCPU, root on btrfs (`/dev/vda3[/root]`). Kernel `7.2.11-300.fc45.x86_64`, `getenforce` → `Enforcing`
(targeted), `firewalld` active (zone `public`, nftables backend, `table inet firewalld`), nftables 1.1.6, libbpf
1.7.0-2.fc45, rpm 6.1.0, dnf5, `/sys/kernel/btf/vmlinux` present; polkit and bpftool not preinstalled. Each run
starts from the `clean` qcow2 snapshot (firewalld installed, nothing else). Package built on the Ubuntu box with
`scripts/linux/package.sh rpm` (full publish, then `--skip-publish` after the fix); IPC via `scripts/linux/axipc.py`
as user `axiom` (wheel) unless noted.

| # | Step | Result | Evidence |
|---|---|---|---|
| F-1 | `dnf install ./axiom-0.13.2-1.x86_64.rpm` built at `5ffc5ba` (`Requires: openssl-libs`) | **FAIL** (fixed) | deps resolved (polkit, libX*, bpftool weak), then `>>> Non-critical error in %post scriptlet` / `No usable version of libssl was found` / `Aborted (core dumped) "$AXIOM_BUNDLED_DAEMON" --install-service` / `%post(axiom-0.13.2-1.x86_64) scriptlet failed, exit status 134`; dnf rc 1, `axiomd.service could not be found`. Cause: Fedora 45 `openssl-libs-4.0.3` ships `libssl.so.4`; the .NET shim probes `libssl.so.3/1.1/1.0.x/10` only |
| F-2 | fix `a1b65f8`: require `libssl.so.3()(64bit)`, `libcrypto.so.3()(64bit)`, `libbpf.so.1()(64bit)`; `dnf install --setopt=install_weak_deps=False ./axiom-…rpm` from `clean` | PASS | dnf pulls `openssl3-libs 1:3.5.9-1.fc45` + polkit + X11 libs (16 packages); `%post`: `Installed and started axiomd.service from /usr/libexec/axiom (/etc/systemd/system/axiomd.service).`; `Complete!`, rc 0; `systemctl is-active axiomd` → `active` |
| F-3 | `axiomd --doctor` without bpftool | PASS (1 WARN, expected) | all PASS (unit, image 234 entries root-owned, sock, data/log dirs, `dns backend: SystemdResolved; enp0s3: 10.0.2.3`, `table inet axiom generation 1 is in force`) + `WARN bpf layer: bpftool is not available; the connect-time layer is off`; journal `BPF layer inactive: bpftool is not available (apt install linux-tools-common …)` (Debian hint on Fedora: cosmetic) Fixed in `3bc48fb`: the hint now follows `/etc/os-release` (`dnf install bpftool` on Fedora) |
| F-4 | SELinux | PASS | `ausearch -m avc,user_avc,selinux_err -ts boot` → `<no matches>` after every step (F-2…F-12); `ps -eZ` → `system_u:system_r:unconfined_service_t:s0 axiomd`; `/usr/libexec/axiom/axiomd` `bin_t`, unit `systemd_unit_file_t`, `/opt/axiom` `usr_t`, `/var/lib/axiom` `var_lib_t`, `/run/axiom/axiom.sock` `var_run_t`; `restorecon -Rnv` on all of them → nothing to change. No scriptlet change needed |
| F-5 | polkit | PASS | `pkaction \| grep axiom` → `com.axiom.firewall.install` |
| F-6 | nft-only: `protection.enable`, `rule.apply` block `/usr/bin/curl` | PASS (as designed) | `state:"applied"`; `rule.verify` (root) `enforcementVerified:true`, `nftables alone enforces this rule (~1 s exec window)`; bare `curl -m 8 https://example.com` → rc 0 (connects inside the 1 s herding window, documented limitation); curl that reads its config from stdin after 2 s → **rc 7**, `4 packet(s) matched`; `rule.remove` → curl `200`; `protection.disable` (root) → `enabled:false` |
| F-7 | `dnf install bpftool` (7.7.0-3.fc45), restart | PASS | `BPF layer attached: connect4/connect6/sendmsg4/sendmsg6 at /sys/fs/cgroup (multi), pinned at /sys/fs/bpf/axiom.`; `--doctor` → `PASS bpf layer: bpftool v7.7.0; 4 programs pinned …`, `Result: all checks passed.`; `bpftool cgroup tree` → 4 `axiom_*` |
| F-8 | BPF verdict for `/usr/bin/curl` | **FAIL** (open, C#) | `rule.verify` claims `BPF-backed: connect-time verdict for this rule in the maps (generation 7, read back verified)`, yet bare `curl -m 8` → rc 0. Map key `{dev_major:0, dev_minor:35, ino:3056}` = `stat -L -c '%Hd %Ld %i' /usr/bin/curl` → `0 35 3056`, but `findmnt -T /usr/bin/curl` MAJ:MIN → `0:33` (btrfs superblock `s_dev`, which `axiom_connect.bpf.c` reads via `inode->i_sb->s_dev`). On btrfs subvolumes `st_dev` ≠ `s_dev`, so the exe map never matches. nftables still blocks long-lived processes (rc 7). **Fixed** by `3bc48fb`, see F-13…F-16 |
| F-9 | `firewall-cmd --reload` with a block rule active (both runs) | PASS | `success`; tables before/after and +8 s: `table inet axiom`, `table inet firewalld` — firewalld does not touch Axiom's table; long-lived curl still rc 7; `rule.verify` still `enforcementVerified:true`; no republish needed (nothing in the journal) |
| F-10 | `systemctl stop axiomd` / start | PASS | `inactive`; `nft list tables` → only `table inet firewalld`; `bpftool cgroup tree` → 0 `axiom_*`; no `/sys/fs/cgroup/axiom.slice`, no `/sys/fs/bpf/axiom`; start → `active` |
| F-11 | upgrade `rpm -Uvh --replacepkgs` | PASS (with `--nosignature`) | without it rpm 6 refuses: `package axiom-0.13.2-1.x86_64 does not verify: no signature`, rc 2; with `--nosignature`: `%post` reinstalls the image, `%preun/%postun` of the old instance do nothing (`$1`=1), journal `BPF layer detached …` → `Started axiomd.service` → `BPF layer attached …`, `active`, doctor all PASS; `dnf reinstall ./axiom-…rpm` likewise |
| F-12 | `dnf remove -y axiom` | PASS | `%preun`: `Removed /usr/libexec/axiom.` / `Stopped and removed axiomd.service.`; gone: unit, `/usr/libexec/axiom`, `/opt/axiom`, polkit action, `/run/axiom`, `/sys/fs/bpf/axiom`, `axiom.slice`, `table inet axiom`, `axiom_*` programs, `axiom*` units; tables → `table inet firewalld`; **left (by design, RPM has no purge):** `/var/lib/axiom` (`axiom.db filter network-recovery.txt protection.json threat-share.json`) and empty `/var/log/axiom`; DNS unchanged (`enp0s3: 10.0.2.3`) |

### btrfs exe key fix (F-8), 2026-11-13, branch `buba/linux`: red `66f0e76`, fix `3bc48fb`

Design: dev of the key from `/proc/self/mountinfo` field 3 (superblock `s_dev`) of the mount holding
`realpath(appPath)`, ino from `stat`; unprovable keys → rule uncovered (nft-only), never "BPF-backed"
(docs/LINUX_EBPF.md §2.1).

| # | Step | Result | Evidence |
|---|---|---|---|
| F-13 | red run at `66f0e76` (tests + API stubs) | FAIL as intended | `Failed! - Failed: 16, Passed: 107, Total: 123` (Nft suite); key test: `Planner_keys_a_btrfs_exe_by_the_superblock_dev_from_mountinfo_not_the_subvolume_st_dev` → `Assert.Equal() Failure: Strings differ … Expected: "0000000021000000f00b000000000000"` (0:33 ino 3056; the stat-based planner wrote 0:35) |
| F-14 | gate at `3bc48fb` | PASS | `dotnet build Axiom.sln -c Release -p:EnableWindowsTargeting=true` 0 warnings / 0 errors; Linux.Nft 123/123 (106 + 17 new), Linux 32, Unix 32, Desktop.Linux 51, Infra.MacOS 214, Desktop.MacOS 35 |
| F-15 | Fedora 45 VM (`clean` snapshot, btrfs `/dev/vda3[/root]`, kernel 7.2.11, SELinux Enforcing): `dnf install -y ./axiom-0.13.2-1.x86_64.rpm` (bpftool 7.7.0-3.fc45 pulled as weak dep, BPF attached on first start) | PASS | `findmnt -T /usr/bin/curl` → `0:33 btrfs /dev/vda3[/root]`, `stat -L -c '%Hd %Ld %i'` → `0 35 3056`; doctor `PASS bpf exe key: /usr/bin/env: key dev 0:33 ino 3102, source mountinfo superblock dev (btrfs at /, /dev/vda3). stat st_dev 0:35 is a btrfs subvolume device and is NOT used.`, `Result: all checks passed.`; `rule.apply` block `/usr/bin/curl` → journal `BPF exe key: exe /usr/bin/curl dev 0:33 ino 3056 proto 0x7 (dev 0:33 from mountinfo (btrfs at / [root /root]; stat 0:35 is the btrfs subvolume device)).`; `bpftool map dump … axiom_exe_verdicts` → `dev_major 0, dev_minor 33, ino 3056, action 2`; **bare `curl -m 8 https://example.com` → `Failed to connect … after 10 ms`, rc 7** (was rc 0 in F-8); `axiom_stats` blocked counter 8; `rule.verify` `BPF-backed … (generation 2, read back verified)`, `enforcementVerified:true`; `rule.remove` → curl 200; `protection.disable` ok; `ausearch -m avc,user_avc,selinux_err -ts boot` → `<no matches>`; `dnf remove -y axiom` → `Removed /usr/libexec/axiom.` / `Stopped and removed axiomd.service.`, `inactive`; VM powered off |
| F-16 | Ubuntu 24.04 host (ext4), packaged `.deb` from `3bc48fb` via `dpkg -i`; baseline: axiomd active, 0 rules, protection off, shield off, `eno2: 192.168.70.1` | PASS | doctor `PASS bpf exe key: /usr/bin/env: key dev 8:2 ino 51660111, source mountinfo superblock dev (ext4 at /, /dev/sda2).`; `rule.apply` block `/usr/bin/curl` → journal `BPF exe key: exe /usr/bin/curl dev 8:2 ino 51643045 proto 0x7 (dev 8:2 from mountinfo (ext4 at /; stat agrees)).` (`findmnt` `8:2 ext4`, `stat` `8 2 51643045`); bare `curl -m 8 https://example.com` → `Failed to connect … after 0 ms`, rc 7; `rule.remove` → 200; `protection.disable`; left as found (active, 0 rules, protection/shield off, DNS `192.168.70.1`), daemon is now the `3bc48fb` build |

Ubuntu regression after touching `scripts/linux/package.sh`: `package.sh deb --skip-publish` → `Depends` identical to the
previous build; `sudo -n dpkg -i build/linux/axiom_0.13.2_amd64.deb` on the evidence box → `Installed and started
axiomd.service`, doctor `all checks passed`, protection off, 0 owned rules, Privacy Shield not redirected, `eno2:
192.168.70.1`.

Not run on Fedora: the desktop app (Cloud image has no session), Wayland/GNOME, a real version-to-version upgrade
(only `--replacepkgs`), NetworkManager-managed DNS / Privacy Shield, IPv6, RHEL/openSUSE.

## PR #276 round 3 (2026-11-14, branch `buba/linux`, tested head `b06adb8`; merge `6c52ee9` + `89c53b4`)

Author-run on project machines, **not GitHub-hosted CI**. Commits: red `9dc4ec4` (10 failing) → `1c71a01`
(#290 doctor live state, restart-while-pending, per-rule coverage); UI red `4599e8b` (does not compile
without the API) → `5a3f3ad`; red `794e226` (3 failing) → `c60fc36` (btrfs → nft-only, re-resolve
replaced executables); `4d14f80` `scripts/linux/canary.sh` (apply result read from `result`, in
`0c65629`); red `0c65629` (`LiveStateAndCoverageTests.Externally_detached_programs_are_noticed_by_verify_and_re_attached_by_the_watch_tick`,
`Failed! - Failed: 1, Passed: 134, Total: 135`) → `b06adb8`. Design and tables: `LINUX_EBPF.md` §2.1, §11.

### Gate at `b06adb8` (Ubuntu 24.04.5, kernel 7.0.0-42-generic, .NET SDK 10.0.403)

`scripts/ci/run-all.sh` (from `buba/macos` `79ac636`) through `~/vms/macos-dev/build-lock`, `-c Release -m:2
-nr:false -p:UseSharedCompilation=false -p:EnableWindowsTargeting=true`:

| Suite | Result |
|---|---|
| `dotnet build Axiom.sln` / `Axiom.Portable.slnx` | 0 Warning(s) 0 Error(s) / 0 Warning(s) 0 Error(s) |
| Infrastructure.Linux.Nft | 135/135 |
| Infrastructure.Linux | 32/32 |
| Infrastructure.Unix | 32/32 |
| Desktop.Avalonia.Linux | 51/51 |
| UI.Avalonia (incl. `ConnectTimeCoverageWordingTests`) | 57/57 |
| Infrastructure.MacOS / Desktop.Avalonia.MacOS | 214/214 / 35/35 |
| Contracts / McpServer / Persistence / Presentation | 142/142 / 33/33 / 21/21 / 93/93 |
| Core | 117/128, 11 failed (Windows paths: `ProtectionPathFamilyTests.Detector_applies_a_decision_to_the_next_versioned_path`, `ProtectionTests.{Agent_executable_detection_is_name_and_path_based, Every_non_loopback_range_passes_rule_validation, Pending_detector_marks_agents_and_respects_the_limit}`, `RuleSpecValidatorTests.{A_complete_spec_is_valid, Parent_segment_is_rejected, Unc_and_extended_paths_are_rejected_for_now ×2, Valid_cidr_and_port_scope_is_accepted, Valid_udp_port_range_is_accepted, Wildcard_address_alone_is_accepted}`) |
| Service | 67/79, 12 failed (`FirewallRuleCoordinatorTests` ×7, `NetworkRecoveryCommandTests` ×4, `PrivacyShieldTests.Settings_write_failure_restores_the_previous_resolver`) |
| Infrastructure.Windows | 45/68, 23 failed (`IpHelperConnectionSourceTests` ×4, `PipeSecurityTests` ×1, `PipeServerTests` ×13, `WindowsFirewallPolicyAdapterTests` ×5) |
| UI.Tests (WPF) | not runnable on Linux: test host aborted, `Microsoft.WindowsDesktop.App` framework absent |

Core/Service/Infrastructure.Windows failing sets compared **by name** with the base `9241bd6` run the
same way in a detached worktree: 46 names each, `diff` empty (identical). Skipped tests: none.

### Gate after merging `buba/macos` `accef91` → `6c52ee9`, `89c53b4`

`git merge --no-ff accef91` had no textual conflicts, but the build failed at `6c52ee9`:
`DaemonLogFile.cs(80,40): error CS0103: The name 'MacDataDirectoryPermissions' does not exist` (the macOS
commit used the pre-extraction name; this branch has `UnixDataDirectoryPermissions`, same 0644 constant).
Fixed in `89c53b4` (source + `DaemonLogFileTests`). Gate at `89c53b4`, same flags: `Axiom.sln` 0/0,
`Axiom.Portable.slnx` 0/0; Linux.Nft 135/135, Linux 32/32, Unix 32/32, Desktop.Avalonia.Linux 51/51,
Infrastructure.MacOS 221/221 (214 + 7 new macOS tests), Desktop.Avalonia.MacOS 35/35, UI.Avalonia 57/57;
Service 67/79 with the same 12 failing names as `b06adb8`/`9241bd6`. (A first merge of the then-head
`1891a49` was discarded unpublished when `buba/macos` was amended to `accef91`.)

### Fedora 45 VM, `b06adb8` RPM (`clean` snapshot, btrfs root, SELinux Enforcing, kernel 7.2.11-300.fc45)

`scripts/linux/package.sh all` at `b06adb8` → `axiom-0.16.0-1.x86_64.rpm` (sha256 `1f22d9f5…34dd`),
`axiom_0.16.0_amd64.deb` (`b394d3ee…da1d`). Author scratch scripts `vm-boundary.sh`, `vm-b3.sh`,
`vm-detach.sh` (outputs quoted below) + `scripts/linux/canary.sh`.

| # | Step | Result | Evidence |
|---|---|---|---|
| R3-F1 | `sudo dnf install -y ./axiom-0.16.0-1.x86_64.rpm bpftool` | PASS | `Complete!`, dnf rc 0, `active`, `axiom-0.16.0-1.x86_64`, `bpftool-7.7.0-3.fc45` |
| R3-F2 | `sudo /usr/libexec/axiom/axiomd --doctor` | PASS | `PASS live enforcement: capability available, enforcement verified`; `PASS bpf layer: bpftool v7.7.0; live layer active, generation 1, maps read back verified; 0 rule(s) connect-time proven, 0 rule(s) nft-only (not race-free); 4/4 program pins`; `SKIP bpf exe key: /usr/bin/env: exe key ambiguous on btrfs subvolumes: dev 0:33 ino 3102 …`; `Result: all checks passed.` |
| R3-F3 | btrfs subvolumes subA/subB (ino 257 both, `st_dev` 0:68/0:69, superblock 0:33), rule on `subA/tool` | PASS (downgraded) | `state=applied`, `connectTimeBlockingProven=False`, `coverageReason=exe key not provable … exe key ambiguous on btrfs subvolumes …`; `rule.verify` `enforcementVerified=True nftRuleReadBack=True connectTimeBlockingProven=False`; journal `BPF exe key: rule … left to nftables`; fresh connects slipped subA 20/20, subB 20/20 |
| R3-F4 | hand-written pre-fix key `{0:33, 257}` | collision proven | subA 0/10, **unrelated subB 0/10** slipped, system python3 5/5; deleted → subB 5/5 |
| R3-F5 | subC/subD, ino 257, different executables (sha256 `8f9b3657…` / `13d0b4f7…`) | collision proven | with key: subC 0/10, **different exe subD 0/10**; deleted → subD 5/5 |
| R3-F6 | overlayfs merged dir | PASS (nft-only) | `connectTimeBlockingProven=False`, `… is on overlay at /srv/axov/merged …`; 20/20 slipped |
| R3-F7 | `canary.sh unscoped --count 50` | as designed (btrfs → nft-only) | `connectTimeBlockingProven=False` for both; curl v4 49/50, v6 50/50, python v4 49/50, v6 49/50 slipped |
| R3-F8 | `canary.sh scoped --count 50` | as designed | curl v4 50/50, v6 49/50, python v4 49/50, v6 50/50 slipped |
| R3-F9 | externally detached programs (tmpfs copy, `st_dev` = mountinfo 0:73) | PASS | proven=True, 0/20 slipped → `bpftool cgroup detach` ×4 → attached 0, `rule.verify` immediately `connectTimeBlockingProven=False coverageReason=the BPF layer is neutralised (degraded: only 0 of 4 Axiom BPF programs are attached (detached by another tool) …)`; doctor `WARN bpf layer: … live layer neutralised …`, `Result: 1 problem(s).`; 10/10 slipped; **re-attached after 2.8 s** (4 programs, proven=True, `ConnectTimeLayer.state=active`, `pendingRemovals: []`), 0/20 slipped; journal `BPF layer is neutralised; re-attaching …` / `BPF layer re-attached; enforcement verified.` |
| R3-F10 | SELinux / end state | PASS | `ausearch -m avc,user_avc,selinux_err -ts boot` → `<no matches>`; `canary.sh --cleanup` → `topology and /opt/axiom-canary removed`, `ip netns list` empty; doctor `Result: all checks passed.`; VM shut down from inside, qemu exited |

### Ubuntu host, `b06adb8` .deb

| # | Step | Result | Evidence |
|---|---|---|---|
| R3-H1 | `sudo -n dpkg -i build/linux/axiom_0.16.0_amd64.deb` | PASS | `active`; `/usr/libexec/axiom/Axiom.Infrastructure.Linux.dll` sha256 `8bf2a4ae3a91f3b0…` = build |
| R3-H2 | `sudo scripts/linux/canary.sh unscoped --count 50 --keep-topology` (ext4, BPF attached) | PASS | both rules `applied connectTimeBlockingProven=True`; curl v4 0/50, v6 0/50, python v4 0/50, v6 0/50 slipped (50/50 blocked each) |
| R3-H3 | earlier runs at `c60fc36` (same host) | — | scoped: curl 50/50 v4, 50/50 v6, python 50/50 v4, 49/50 v6 slipped; programs detached (nft only): curl 50/50, 50/50, python 49/50, 49/50 (the pre-`b06adb8` daemon still claimed coverage); mount-ns bind mount 0/20, hard link 0/20; `rename(2)` replacement: proven=False at once, ~7 s slip window until the watch tick re-resolved |
| R3-H4 | externally detached programs (tmpfs copy) | PASS | same sequence as R3-F9: proven=False at once, doctor WARN + `1 problem(s)`, 10/10 slipped, re-attached after 7.2 s, 0/20 |
| R3-H5 | `axiomd --doctor` | PASS | `PASS live enforcement …`, `PASS bpf layer: … live layer active, generation 37, maps read back verified …`, `PASS bpf exe key: /usr/bin/env: key dev 8:2 ino 51660111 …`, `Result: all checks passed.` |
| R3-H6 | `sudo scripts/linux/canary.sh --cleanup`; final state | PASS | netns none, `axc0` does not exist, `/opt/axiom-canary` gone; `axiomd` active, 0 owned rules, protection off, Privacy Shield `Disabled`, `Link 2 (eno2): 192.168.70.1`, 4 `axiom_*` programs attached |

Not covered by this round: live repro of #290 with a failing-bpftool wrapper + restart (unit-tested only),
the desktop UI wording on a live session (unit-tested), Debian, Wayland/KDE, NetworkManager-only DNS,
`resolv.conf` rollback, offline install, upgrade/uninstall with active rules, interrupted install, arm64,
package signing.

## btrfs subvolume id in the BPF exe key (2026-11-14, branch `buba/linux`): red `7a75471`, fix `788c709`

Author-run evidence on project machines (not GitHub-hosted CI). `scripts/linux/package.sh all` at
`788c709` → `axiom-0.17.0-1.x86_64.rpm` (sha256 `acf439bd4c6a8a6c…`), `axiom_0.17.0_amd64.deb`
(`710d78b0f9b09685…`). BPF object built with clang 18 / libbpf 1.3 (`make -C …/Bpf/native` via
`package.sh`). Scratch scripts: `vm-btrfs.sh`, `host-neutralise.sh` (outputs quoted below).

### Unit tests (red → green)

| # | Step | Result | Evidence |
|---|---|---|---|
| R4-U1 | `dotnet test tests/Axiom.Infrastructure.Linux.Nft.Tests` at `7a75471` (stubs only) | red as intended | `Failed: 13, Passed: 134` — layout ABI 2, subvolume-keyed plan, same ino in two subvolumes, non-btrfs subvol 0, unprovable subvolume, unconfirmed kernel, mismatch, self-check record, engine self-check pass/mismatch, ABI 1 object refused, doctor `live enforcement` on a neutralised layer, plus the 24-byte hex of an existing engine test |
| R4-U2 | same at `788c709` | PASS | `Passed: 148` (Nft), `Passed: 32` (Linux) |
| R4-U3 | host `sudo bpftool -d prog loadall out/axiom_connect.bpf.o /sys/fs/bpf/axiomtest …` (ext4, kernel 7.0) | PASS | `relo #7: <type_exists> struct btrfs_inode___axiom … no matching targets found … patched insn #117 imm 1 -> 0`; verifier accepted; `map show` `bytes_key 24`; scratch pins removed |

### Gate at `788c709` (`~/vms/macos-dev/build-lock`-serialised `scripts/ci/run-all.sh`, `-c Release`)

| # | Step | Result | Evidence |
|---|---|---|---|
| R4-G1 | builds | PASS | `build Axiom.sln rc=0 0 Warning(s) 0 Error(s)`, `build Axiom.Portable.slnx rc=0 0 Warning(s) 0 Error(s)` |
| R4-G2 | test projects | PASS | Linux.Nft 148/148, Linux 32/32, Unix 32/32, Desktop.Avalonia.Linux 51/51, Infrastructure.MacOS 221/221, Desktop.Avalonia.MacOS 35/35, UI.Avalonia 57/57, Contracts 142/142, McpServer 33/33, Persistence 21/21, Presentation 93/93; UI.Tests (WPF) 0 results on Linux |
| R4-G3 | Windows-only failures vs base `0fc7822` (detached worktree, same host) | identical | Core 11, Service 12, Infrastructure.Windows 23 = 46 names each; `diff` of the sorted names is empty |

### Fedora 45 VM (`clean` snapshot, btrfs root, SELinux Enforcing, kernel 7.2.11-300.fc45), RPM `788c709`

| # | Step | Result | Evidence |
|---|---|---|---|
| R4-F1 | `sudo dnf install -y ./axiom-0.17.0-1.x86_64.rpm bpftool` | PASS | `Complete!`, `active`, `axiom-0.17.0-1.x86_64`, `bpftool-7.7.0-3.fc45` |
| R4-F2 | journal | PASS | `BPF exe key self-check verified: kernel and user space agree for /usr/libexec/axiom/axiomd: dev 0:33 ino 34192 subvol 256 (btrfs); btrfs subvolume read relocated (CO-RE).`; `axiom_selfcheck` dump `tgid 0 hits 1 dev 0:33 ino 34192 subvol 256 flags 3` |
| R4-F3 | `sudo /usr/libexec/axiom/axiomd --doctor` | PASS | `PASS bpf exe key: /usr/bin/env: key dev 0:33 ino 3102 subvol 256, source mountinfo superblock dev (btrfs at /, /dev/vda3) + btrfs subvolume id 256 (statx STATX_SUBVOL (BTRFS_IOC_INO_LOOKUP agrees)); stat st_dev 0:35 is a btrfs subvolume device and is NOT used. Kernel self-check verified: …`; `Result: all checks passed.` |
| R4-F4 | `python3 -I btrfs-subvol.py …` (statx vs ioctl) | PASS | curl 256/256, axiomd 256/256, `/home/axiom` 258/258, `subA/tool` 260/260, `subB/tool` 261/261, `/boot/loader` 257/257 — all `agree` |
| R4-F5 | subA/subB: `subA/tool` = python3 copy, `subB/tool` = copy + marker (sha256 `8f9b3657…` / `b23fe00f…`), both ino 257, `st_dev` 0:68 / 0:69, superblock 0:33; rule on `subA/tool` | PASS | `connectTimeBlockingProven=True`, map key `dev 0:33 ino 257 subvol 260`; fresh connects slipped: A **0/10**, unrelated B **10/10**, system python3 5/5 |
| R4-F6 | reverse: rule on `subB/tool` | PASS | key `dev 0:33 ino 257 subvol 261`; B **0/10**, A **10/10** |
| R4-F7 | `unshare -m` + `mount --bind subA/tool /tmp/axns-tool` | PASS | `bind-mounted A in a new mount ns: slipped 0/10` |
| R4-F8 | `subA/tool` replaced via `rename(2)` | PASS (window reported) | `rule.verify` at once `connectTimeBlockingProven=False`, `the executable at this path was replaced (new inode) …`; 9 s later proven=True, key `ino 258 subvol 260`, 0/10 |
| R4-F9 | overlayfs merged dir | PASS (nft-only) | `connectTimeBlockingProven=False`, `… is on overlay at /srv/axov/merged …` |
| R4-F10 | `canary.sh unscoped --count 50` (btrfs root) | PASS | both rules `connectTimeBlockingProven=True`; curl v4 **0/50**, v6 **0/50**, python v4 **0/50**, v6 **0/50** slipped (`b06adb8`: 49/50, 50/50, 49/50, 49/50) |
| R4-F11 | verifier / SELinux / end state | PASS | 4 `axiom_*` programs attached; 0 verifier/loadall errors in the journal; `ausearch -m avc,user_avc,selinux_err -ts boot` → `<no matches>`; `canary.sh --cleanup` → `topology and /opt/axiom-canary removed`; owned rules 0; VM powered off (qemu exited) |

### Ubuntu host (24.04.5, ext4, kernel 7.0.0-42-generic), `.deb` `788c709`

| # | Step | Result | Evidence |
|---|---|---|---|
| R4-H1 | `sudo -n dpkg -i build/linux/axiom_0.17.0_amd64.deb` | PASS | `active`; journal `BPF exe key self-check verified: … axiomd: dev 8:2 ino 4194354 subvol 0; no btrfs BTF at load: btrfs subvolume ids are not read.` |
| R4-H2 | `axiomd --doctor` | PASS | `PASS bpf exe key: /usr/bin/env: key dev 8:2 ino 51660111 subvol 0, source mountinfo superblock dev (ext4 at /, /dev/sda2) (subvol 0: not btrfs). Kernel self-check verified: …`; `Result: all checks passed.` |
| R4-H3 | `sudo scripts/linux/canary.sh unscoped --count 50 --keep-topology` | PASS | proven=True ×2; curl v4 0/50, v6 0/50, python v4 0/50, v6 0/50 slipped |
| R4-H4 | neutralised layer (`mv …/axiom_exe_verdicts held_…`, rule removed → delete fails) → doctor | PASS | `WARN live enforcement: … but the connect-time BPF layer is neutralised (degraded: detached after 1 stale map entry could not be deleted (generation 44); …)`, `WARN bpf layer: … neutralised …`, `Result: 2 problem(s).`; the same report also said `table inet axiom is missing (another tool may have flushed the ruleset)` — a wrong reason, the table was present (see R5-*); after `systemctl restart axiomd`: all PASS |
| R4-H5 | `sudo scripts/linux/canary.sh --cleanup`; final state | PASS | `topology and /opt/axiom-canary removed`, no netns; `axiomd` active, 0 owned rules, protection off, Privacy Shield `Disabled`, `Link 2 (eno2): 192.168.70.1`, 4 `axiom_*` programs attached |

## "table inet axiom is missing" while the BPF layer is neutralised (2026-11-14, branch `buba/linux`): red `d2de9c0`, fix `70c7ee8`

Question from R4-H4: can `table inet axiom` disappear (or be reported missing) while axiomd runs, and was
enforcement lost? Answer: no table was lost; the capability reason named the table for every Degraded
state, including the BPF-only degradations (neutralised layer, pending BPF removal). The same probe found
a real gap: `nft flush table inet axiom` left the table and its generation comment, and the daemon
reported `verified` with 0 rules. Ubuntu 24.04 host, kernel 7.0.0-42, nft 1.0.9, ufw + Docker active
(iptables-nft tables only; neither touched `table inet axiom` in any sample). Repro script (root):
`tablerepro/repro.py` in the session scratch: rule on `/opt/axiom-canary/curl` (canary topology kept),
then every ~110 ms for 30 s `nft -j list table inet axiom` (rc, rule count), `rules.query` capability
status/reason, and a fresh `curl --connect-timeout 1 http://10.231.0.2:18080/` (rc 0 = slip).

### Unit tests (red → green)

| ID | Command | Result | Evidence |
|---|---|---|---|
| R5-U1 | `dotnet test tests/Axiom.Infrastructure.Linux.Nft.Tests` at `d2de9c0` | red as intended | `Failed: 4, Passed: 149` — `Neutralised_layer_with_the_table_present_never_reports_the_table_missing` (reason contained "missing"), `One_watch_tick_restores_a_deleted_table_and_reattaches_a_neutralised_layer_without_touching_other_tables`, `External_table_delete_is_degraded_with_the_reason_never_read_back_and_restored_within_one_tick` (wording), `Flushed_table_that_keeps_its_generation_comment_is_detected_as_modified_and_republished` (`Expected: Degraded, Actual: Available`) |
| R5-U2 | same at `70c7ee8` | PASS | `Passed: 153` (Nft); `Table_without_owned_rules_is_not_reported_modified_and_never_republished_in_a_loop` guards the comment check; the re-attach path issues no `delete table inet axiom` |

### Gate at `70c7ee8` (`flock …/.build.lock`-serialised `scripts/ci/run-all.sh`, `-c Release`)

| ID | Check | Result | Evidence |
|---|---|---|---|
| R5-G1 | builds | PASS | `build Axiom.sln rc=0 0 Warning(s) 0 Error(s)`, `build Axiom.Portable.slnx rc=0 0 Warning(s) 0 Error(s)` |
| R5-G2 | test projects | PASS | Linux.Nft 153/153, Linux 32/32, Unix 32/32, Desktop.Avalonia.Linux 51/51, Infrastructure.MacOS 221/221, Desktop.Avalonia.MacOS 35/35, UI.Avalonia 57/57, Contracts 142/142, McpServer 33/33, Persistence 21/21, Presentation 93/93 |
| R5-G3 | Windows-only failures vs `788c709` | identical | Core 11, Service 12, Infrastructure.Windows 23 = 46 names; `diff` of the sorted names is empty |

### Live, Ubuntu host

| ID | Step | Result | Evidence |
|---|---|---|---|
| R5-H1 | `.deb` at `fb8f04f` (installed `Axiom.Infrastructure.Linux.dll` = build), `bpftool cgroup detach /sys/fs/cgroup <hook> id <n>` ×4 | table never absent | 267 samples / 30 s: table absent **0**, ≥ 7 rules every sample, reason never "missing", `available/verified` with `Connect-time BPF layer degraded: only 0 of 4 …`; canary slips 25/267, last at 2.8 s (re-attached by the watch tick) |
| R5-H2 | `fb8f04f`, R4-H4 neutralisation (`mv …/axiom_exe_verdicts held_…`, remove a second rule → delete fails) | **reproduced the wrong reason** | 257 samples: table absent **0**, ≥ 7 rules; 18 samples `degraded/degraded` with `table inet axiom is missing (another tool may have flushed the ruleset) …` (0.0–1.9 s); canary 18/18 slipped in that window (nft-only), 0 after the re-attach |
| R5-H3 | `fb8f04f`, `nft delete table inet axiom` / `nft flush ruleset` (iptables-nft tables restored at once with `iptables-restore`) | detected, restored | absent 96 samples (0–9.5 s) / 98 (0–9.7 s), Degraded throughout, journal `table inet axiom disappeared … republishing.` → `Republished … verified`; canary 0 slips (BPF attached) |
| R5-H4 | `fb8f04f`, `nft flush table inet axiom` | **gap** | 300 samples: 0 nft rules, `available/verified` for the whole 30 s; nothing logged |
| R5-H5 | `.deb` at `70c7ee8` (`dpkg -i`, installed dll sha256 `8c5cc6dc…` = build) — detach ×4 | PASS | 227 samples, table absent 0, reason never "missing"; slips 38/227, last at 5.0 s; journal `only 0 of 4 Axiom programs are attached …` → `BPF layer re-attached; enforcement verified.` |
| R5-H6 | `70c7ee8`, map-fault neutralisation | PASS | 254 samples, table absent 0, ≥ 7 rules; 33 `degraded` samples with `table inet axiom is present (generation 64) and nftables enforces the stored rules; enforcement is degraded by the connect-time BPF layer: 1 rule removal(s) …`; slips 32/254 until the re-attach (last 4.1 s) |
| R5-H7 | `70c7ee8`, `nft delete table inet axiom` | PASS | absent 45 samples (0–4.4 s), reason `nft table inet axiom missing (removed externally: another tool deleted it or flushed the ruleset); …`; journal `table inet axiom disappeared (generation 64 was published; removed externally); enforcement degraded; republishing.` → `Republished table inet axiom generation 65; enforcement verified.`; canary 0/258 |
| R5-H8 | `70c7ee8`, `nft flush table inet axiom` | PASS | 0 rules for 4.6 s, `degraded` with `nft table inet axiom modified externally: generation 65 is present but 3 of 3 owned rule(s) are missing …`; journal `… was modified externally (3 of 3 owned rule(s) missing); … republishing.` → generation 66 verified; canary 0/268 |
| R5-H9 | `70c7ee8`, `nft flush ruleset` (+ iptables restore) | PASS | absent 48 samples (0–4.7 s), same missing reason, generation 67 verified; canary 0/268; iptables rules 71/116 before and after |
| R5-H10 | `70c7ee8`, `rule.verify` around an external delete | PASS | before `nftRuleReadBack True enforcementVerified True`; right after `presentInOs False nftRuleReadBack False enforcementVerified False` (`connectTimeBlockingProven True`: the BPF layer is still attached); table back after ~4.0 s, all True |
| R5-H11 | R4-H4 script again at `70c7ee8` | PASS | `WARN live enforcement: … table inet axiom is present (generation 70) and nftables enforces the stored rules; enforcement is degraded by the connect-time BPF layer: 1 rule removal(s) …`; no "missing"; after restart all PASS |

## New `main` baseline `16229f4` through the macOS branch `c62ad14` (2026-11-14, branch `buba/linux`): merge `db876a7`, tests `740ea7c`, merge fix `a507b64`

Author-run on project machines (Ubuntu 24.04 host, kernel 7.0.0-42-generic, .NET SDK 10.0.403); not GitHub CI.
The merge brings upstream's `enforcement.status` / `enforcement.evaluate` / `enforcement.receipts` and their
classification in the shared dispatcher (`status` and `receipts` private read, `evaluate` write, none public).
The Linux daemon registers no enforcement controller, so an authorized caller gets upstream's `not_supported`.

### Merge and unit tests

| ID | Check | Result | Evidence |
|---|---|---|---|
| M16-U1 | `git merge --no-ff --signoff c62ad14` into `3dd31a4` | clean | no textual conflict; merge commit `db876a7` |
| M16-U2 | first gate at `740ea7c` | **red, fixed** | `build Axiom.sln rc=1 0 Warning(s) 1 Error(s)`: `EnforcementIpcAuthorizationTests.cs(6,34): error CS0234: The type or namespace name 'Ipc' does not exist in the namespace 'Axiom.Infrastructure.MacOS'` (the merged macOS test imports the namespace that this branch extracted into `Axiom.Infrastructure.Unix.Ipc`). `a507b64` drops the stale `using`; no test change |
| M16-U3 | `LinuxEnforcementCommandAuthorizationTests` (Unix.Tests, 15 cases) | PASS | per command: never `PublicRead`; uid 0 and the install owner permitted, another uid not, under `UnixAccountRange.Linux`; without an install record only root. Unix.Tests 32 → 47 |
| M16-U4 | `LinuxEnforcementIpcAuthorizationTests` (Linux.Tests, 5 cases, real Unix socket, `LinuxServicePaths`) | PASS | second uid: `unauthorized` for the three commands, handler call count 0, the evaluate target path is neither echoed nor logged, `Denied 'enforcement.status' for uid:1001: private read` / `… 'enforcement.evaluate' for uid:1001: write` logged; uid 0 and owner on a daemon without enforcement handlers: `not_supported`. Linux.Tests 32 → 37 |
| M16-U5 | opt-in test with a real second account and SO_PEERCRED: `AXIOM_TEST_SECOND_USER=axr3test dotnet test tests/Axiom.Infrastructure.Linux.Tests -c Release` | PASS | `Passed … RealSecondUidGetsUnauthorizedForEnforcementCommandsOverSoPeerCred`; whole project with the account present `Passed: 37` in 3 of 3 further runs. In the very first run with the freshly created account the older opt-in test `LinuxSocketIpcTests.SecondUidGetsPublicHealthOnlyOverSoPeerCred` failed once (message not captured); it passed in the 4 runs that followed and the failure was not reproduced |

### Gate at `a507b64` (`~/vms/macos-dev/build-lock scripts/ci/run-all.sh <out>`, `-c Release`)

| ID | Check | Result | Evidence |
|---|---|---|---|
| M16-G1 | builds | PASS | `build Axiom.sln rc=0 0 Warning(s) 0 Error(s)`, `build Axiom.Portable.slnx rc=0 0 Warning(s) 0 Error(s)` |
| M16-G2 | test projects | PASS | Linux.Nft 153/153, Linux 37/37, Unix 47/47, Desktop.Avalonia.Linux 51/51, Infrastructure.MacOS 248/248, Desktop.Avalonia.MacOS 35/35, UI.Avalonia 57/57 in each of 3 runs, Contracts 143/143, McpServer 33/33, Persistence 21/21, Presentation 117/117 |
| M16-G3 | Windows-only failures on Linux, by name, against pristine `main` `16229f4` on the same host | no test that passes on `main` fails here | Core 12 failed of 151: the same 12 names. Infrastructure.Windows 25 failed of 70 (`main`: 27): the same names minus `DnsProxyTests.Proxy_blocks_a_matching_domain_without_contacting_upstream` and `DnsProxyTests.Proxy_blocks_matching_domains_over_tcp`, which pass here (DNS proxy behind the platform seam). Service 15 failed of 96 (`main`: 15 of 87): `PrivacyShieldTests.Failed_reconfiguration_keeps_previous_resolver_and_persisted_settings` passes here; `FirewallRuleCoordinatorTests.Apply_pending_is_stored_as_pending_not_applied` fails here and does not exist on `main` (a test added by the macOS branch in the test class whose other cases already fail on a Linux host; it fails the same way on `c62ad14`). `Axiom.UI.Tests` (WPF) aborts on Linux on both |

### Live second-user check on the installed daemon (`.deb` built at `a507b64`)

`scripts/linux/package.sh deb` → `build/linux/axiom_0.17.0_amd64.deb` (sha256 `689f507d…e6b8ab66`), `sudo -n dpkg -i`;
installed `Axiom.Service.Hosting.dll` sha256 `c6bbe6dd…` = build. Socket `/run/axiom/axiom.sock` `root:root 666`
(authorization is per connection by peer uid, not by socket mode). Client: `scripts/linux/axipc.py`
(`python3 -I`), one request per connection; evaluate payload
`{"requestId":"req-live-1","agentId":"opencode","kind":"readFile","target":"/home/buba/.ssh/canary-not-a-real-file"}`.
Second user: `sudo -n useradd -m axr3test` (uid 1001, only its own group, no password, `not allowed to run sudo`),
client run with `sudo -n -u axr3test`, then `sudo -n userdel -r axr3test` (`getent passwd axr3test` exit 2, home gone).

| ID | Caller | Command | Result | Raw reply (id removed; health result shortened) |
|---|---|---|---|---|
| M16-L1 | owner uid 1000 | `serviceHealth` | ok | `{"ok":true,"result":{"status":"running","connectionCount":268,"processCount":27,…` |
| M16-L2 | owner | `snapshot` | ok | `"ok":true,"result":{"capturedUtc":"2026-11-14T14:36:26…","connections":[…` |
| M16-L3 | owner | `enforcement.status` | `not_supported` | `{"ok":false,"result":null,"error":{"code":"not_supported","message":"Agent enforcement is not available in this build."},"currentRevision":null}` |
| M16-L4 | owner | `enforcement.receipts` | `not_supported` | `…"code":"not_supported","message":"Agent enforcement receipts are not available in this build."…` |
| M16-L5 | owner | `enforcement.evaluate` | `not_supported` | `…"code":"not_supported","message":"Agent enforcement is not available in this build."…` |
| M16-L6 | root (`sudo -n`) | `serviceHealth`, `snapshot` | ok | as M16-L1 / M16-L2 |
| M16-L7 | root | `enforcement.status`, `.receipts`, `.evaluate` | `not_supported` ×3 | the same three replies as M16-L3..L5 |
| M16-L8 | `axr3test` uid 1001 | `serviceHealth` | ok, redacted | `{"ok":true,"result":{"status":"running","connectionCount":0,"processCount":0,"limitations":["private fields redacted: this caller may read service health but not machine-wide activity"]},"error":null,"currentRevision":null}` |
| M16-L9 | `axr3test` | `snapshot` | `unauthorized` | `…"code":"unauthorized","message":"This command discloses machine-wide activity and is only allowed for root, the user who installed Axiom (uid 1000) and members of the axiom, sudo or wheel groups; uid 1001 may only read public service health."…` |
| M16-L10 | `axr3test` | `enforcement.status` | `unauthorized` | the same private-read message as M16-L9, `"result":null` |
| M16-L11 | `axr3test` | `enforcement.receipts` | `unauthorized` | the same private-read message, `"result":null` |
| M16-L12 | `axr3test` | `enforcement.evaluate` | `unauthorized` | `…"code":"unauthorized","message":"This command changes machine-wide settings and is only allowed for root, the user who installed Axiom (uid 1000) and members of the axiom, sudo or wheel groups; uid 1001 may only read public service health."…` |

As the messages say, members of the `axiom`, `sudo` or `wheel` groups are treated like the installing user by the
existing Linux policy; that also applies to the three enforcement commands. Not covered by this run: a second
user who is a member of one of those groups.

### Live sanity of the merged build

| ID | Step | Result | Evidence |
|---|---|---|---|
| M16-S1 | `sudo -n /usr/libexec/axiom/axiomd --doctor` | PASS | exit 0, `Result: all checks passed.`, no WARN / FAIL line; `PASS bpf layer: bpftool v7.7.0; live layer active, generation 78, maps read back verified; … 4/4 program pins at /sys/fs/bpf/axiom.` |
| M16-S2 | `sudo -n bpftool cgroup show /sys/fs/cgroup` | 4 attached | `axiom_connect4`, `axiom_connect6`, `axiom_sendmsg4`, `axiom_sendmsg6` (ids 2545–2548, `multi`) |
| M16-S3 | `sudo -n scripts/linux/canary.sh unscoped` | 0 slips | both rules `applied connectTimeBlockingProven=True`; `canary unscoped curl ipv4: slipped 0/50 blocked 50/50`, `curl ipv6: 0/50`, `python ipv4: 0/50`, `python ipv6: 0/50` |
| M16-S4 | `sudo -n scripts/linux/canary.sh --cleanup`; host state | clean | `canary: topology and /opt/axiom-canary removed`; no netns, no `axc0`; `axiomd` active; `protection.status` `enabled false`, `ownedRuleCount 0`; `privacy.status` `Disabled`; `rules.query` `managedRuleCount 0`; `resolvectl status` identical to before the install (eno2 DNS 192.168.70.1) |

Not verified by this round: Debian, Wayland / KDE, the rollback / upgrade / uninstall matrix, arm64, package
signing, Fedora at this head (the last Fedora VM run is `788c709`).

## Upstream `main` `e904bf8` (v0.68.0) merged (2026-11-16, merge `5d756ab`)

Pinned `main` = `e904bf8a6c1615608cce5a121b0050f5988b6594` (v0.68.0). The range since the previous base `25bfcc1`
(v0.64.0) is 9 commits / 9 files: the agent command-guard rules (`src/Axiom.Contracts/Blackbox/AgentCommandGuard.cs`,
a Python helper string, plus its tests), release notes and the version bump. The merge had no conflicts. Nothing in
the range touches IPC, platform seams, file paths or Windows APIs, so no port change was needed.

Tested head: `5d756ab` (the merge commit; this section is the only later change).

### Windows 11 VM (author-run, SDK 10.0.403, fresh `NUGET_PACKAGES` per tree)

| Check | `main` `e904bf8` | branch `5d756ab` |
|---|---|---|
| `dotnet restore Axiom.Portable.slnx --locked-mode` | exit 0 | exit 0 |
| `dotnet restore Axiom.sln --locked-mode` | exit 0 | exit 0 |
| per-project `--locked-mode` restore | 21/21 PASS | 33/33 PASS |
| clean restore (`--no-http-cache`, empty package folder) | 88 packages | 88 packages |
| `dotnet build Axiom.sln -c Release` | 0 warnings / 0 errors | 0 warnings / 0 errors |

Lock files: all locked restores pass on Windows, so none was regenerated or committed. A `--force-evaluate` run on
Windows, kept out of the branch, changes only the in-repo project version ranges (`[0.54.0, )` -> `[0.68.0, )`);
pristine `main` drifts the same way. No package version, content hash or target-framework/RID section changes, and
no NuGet package version differs from `main`.

Windows suites (`dotnet test --no-build`, interactive scheduled task), failing tests by name versus `main`:

| Suite | `main` passed/total (failed) | branch passed/total (failed, skipped) | failing only on branch | failing only on `main` |
|---|---|---|---|---|
| Axiom.Contracts.Tests | 164/164 (0) | 173/173 (0) | none | none |
| Axiom.Core.Tests | 184/184 (0) | 184/184 (0) | none | none |
| Axiom.Infrastructure.Windows.Tests | 86/86 (0) | 152/153 (1) | `WindowsFirewallPolicyAdapterTests.Capabilities_are_available` (known RCW flake `InvalidComObjectException`; `WindowsFirewallPolicyAdapterTests` re-run rate: branch 2/16 (1 in the full suite + 1/15 re-runs; `Capabilities_are_available`, `Owned_rules_all_follow_the_naming_contract`), `main` 0/16, unexplained) | none |
| Axiom.McpServer.Tests | 34/34 (0) | 34/34 (0) | none | none |
| Axiom.Persistence.Tests | 21/21 (0) | 21/21 (0) | none | none |
| Axiom.Presentation.Tests | 287/287 (0) | 301/302 (0, 1 skipped) | none | none |
| Axiom.Service.Tests | 101/101 (0) | 120/120 (0) | none | none |
| Axiom.UI.Avalonia.Tests | 62/62 (0) | 82/82 (0) | none | none |
| Axiom.UI.Tests | 194/198 (4) | 194/198 (4) | none | none |

On `main` and the branch the same 4 `AgentHookScriptTests` fail (no `python` on the VM). Branch tests skipped on Windows are the macOS-only ones (`MacBundleLayoutTests`, POSIX venv/provisioning gates); the Unix/Linux/macOS test projects are excluded from `dotnet test` on Windows by their `IsTestProject` condition.

### This host (Ubuntu, Release, `HOME`/`XDG_*` redirected to a scratch dir, `~/.hermes/config.yaml` SHA-256 unchanged)

| Suite | `main` passed/total (failed) | branch passed/total (failed, skipped) | failing only on branch | failing only on `main` |
|---|---|---|---|---|
| Axiom.Contracts.Tests | 164/164 (0) | 173/173 (0) | none | none |
| Axiom.Core.Tests | 170/184 (14) | 170/184 (14) | none | none |
| Axiom.Desktop.Avalonia.Linux.Tests | not in tree | 51/51 (0) | none | none |
| Axiom.Desktop.Avalonia.MacOS.Tests | not in tree | 35/35 (0) | none | none |
| Axiom.Infrastructure.Linux.Nft.Tests | not in tree | 182/182 (0) | none | none |
| Axiom.Infrastructure.Linux.Tests | not in tree | 37/37 (0) | none | none |
| Axiom.Infrastructure.MacOS.Tests | not in tree | 248/248 (0) | none | none |
| Axiom.Infrastructure.Unix.Tests | not in tree | 47/47 (0) | none | none |
| Axiom.McpServer.Tests | 34/34 (0) | 34/34 (0) | none | none |
| Axiom.Persistence.Tests | 21/21 (0) | 21/21 (0) | none | none |
| Axiom.Presentation.Tests | 280/287 (7) | 295/302 (7) | none | none |
| Axiom.Service.Tests | 86/101 (15) | 105/120 (15) | `FirewallRuleCoordinatorTests.Apply_pending_is_stored_as_pending_not_applied` | `PrivacyShieldTests.Failed_reconfiguration_keeps_previous_resolver_and_persisted_settings` |
| Axiom.UI.Avalonia.Tests | 62/62 (0) | 82/82 (0) | none | none |

Builds: `Axiom.Portable.slnx`, `Axiom.Service` (`-p:EnableWindowsTargeting=true`), the port's desktop and test projects, Release: 0 warnings / 0 errors. Linux-side `--locked-mode` restore: both solutions and every project with a lock file give the same result as pristine `main`; on Linux `Axiom.Desktop` (NU1102 `System.CodeDom`) and `Axiom.Setup` (NU1004 RIDs) fail on `main` too (Windows-only WPF projects). The Service.Tests difference is the same as at the previous base: `FirewallRuleCoordinatorTests.Apply_pending_is_stored_as_pending_not_applied` is a port test, `PrivacyShieldTests.Failed_reconfiguration_keeps_previous_resolver_and_persisted_settings` fails on `main` only on this host. The other Core/Presentation/Service failures on this host are Windows-only tests and fail identically on `main`.

Not tested in this round: the installed service/daemon (no runtime or service differential), Privacy Shield on
Windows, a second-user IPC run, packaging, Fedora/Debian, the `.deb`/`.rpm` upgrade paths, the live nft/eBPF canary at this head.

## v1.1.0 merge candidate (branch `buba/linux-recon80`, 2026-11-17)

Author-run on a project machine, not CI. Pinned upstream: main v1.1.0 `da1987a1896275f0127eb8fe176c1a780471ebe9`,
merged (no rebase) as `44cdb26`. Packages built from `44cdb26`; host gate on `b01a0a8` (later commits
`d231e11` tests only, `b01a0a8`/`1c7e9dd` lock files only; locked restore re-checked on `1c7e9dd`).
SDK 10.0.403.

### Host (Ubuntu host, kernel 7.0, HOME/XDG_* redirected to a scratch dir; `~/.hermes/config.yaml` sha256 unchanged)

- Linux locked restore with `--force` (re-evaluates; without it a no-op restore hid NU1004): Axiom.Portable.slnx,
  Axiom.Service, Desktop.Avalonia.Linux, Linux test projects: all rc=0.
- Release build with `EnableWindowsTargeting`: Axiom.Portable.slnx, Service, Desktop.Avalonia.Linux and the two
  Linux test projects: 0 warnings, 0 errors.

| suite | head | pristine da1987a, same script |
|---|---|---|
| Infrastructure.Linux.Tests | 115/115 | n/a |
| Infrastructure.Linux.Nft.Tests | 203/203 | n/a |
| Infrastructure.Unix.Tests | 47/47 | n/a |
| Contracts.Tests | 180/180 | 169/170 |
| Core.Tests | 190/190 | 170/184 |
| Persistence.Tests | 21/21 | 21/21 |
| McpServer.Tests | 34/34 | 34/34 |
| Presentation.Tests | 335/335 | 307/315 |
| UI.Avalonia.Tests | 110/110 | 65/66 |
| Desktop.Avalonia.Linux.Tests | 51/51 | n/a |
| Service.Tests | 97/105 | 86/101 |
| Infrastructure.MacOS.Tests | 249/249 | n/a |
| Desktop.Avalonia.MacOS.Tests | 35/35 | n/a |

The 8 Service.Tests failures on head (AgentFirewallEnforcer canary x3, NetworkRecoveryCommand x4,
PrivacyShield settings-write restore x1) all fail on pristine da1987a by the same names; no test fails on
head only.

### Packages

- `axiom-firewall_1.1.0+linux.rc1_amd64.deb` (`package.sh all --local linux.rc1`), 62834136 bytes,
  sha256 `e5f48dfa7f98a24b560c3dd3f8fce220c7dfabbb0df1bad5e18a2e66d4822b1c`, Version `1.1.0+linux.rc1`.
- `axiom-firewall-1.1.0+linux.rc1-1.x86_64.rpm`, 76261444 bytes,
  sha256 `1f107d23e969d3f1f00191e4b085567611cc9ad85d3816905f7797786529c6d1`.
- Unsigned development candidates, not a release.

### Ubuntu 24.04.5 VM (disposable overlays; kernel 6.8.0-147-generic, bpftool v7.4.0, systemd 255.4-1ubuntu8.18)

- Upgrade 0.97.0 -> 1.1.0+linux.rc1 with an applied block rule: blocked program 111 attempts before and 2505
  after the upgrade action, 0 slipped; allowed control 173 ok, 0 failed. Rule kept, data dir kept, doctor
  13 PASS / 0 WARN / 0 FAIL, 4 Axiom BPF programs attached.
- 2x `systemctl restart`, 2x SIGKILL with the probe loop: 0 slipped in each run (392-530 attempts after each
  action); control 34-44 ok, 0 failed; 4 programs attached at the end.
- Rule removal: blocked program connects again (10/10).
- Second local user (throwaway uid 1001): `protection.status`, `rules.query`, `snapshot`, `rule.apply`,
  `protection.disable` all refused (`unauthorized`, journal "Denied ... for uid:1001"); `serviceHealth`
  answered. The install user (uid 1000) is allowed.
- Fresh install on a clean overlay: doctor all PASS, 4 programs; block canary 20/20 refused, 0 slipped; allowed
  control 20/20; after unblock 10/10 connect.
- GUI under Xvfb in the guest: header lamp SHIELD ON with the daemon running; with axiomd stopped the Simple
  home reads STATUS UNKNOWN / "Protection status is unknown" and the lamp UNKNOWN.
- Remove + purge (both overlays): no `inet axiom` table, no Axiom BPF programs, no pins, no unit, data and
  image dirs gone, resolv.conf on the systemd stub.

### Fedora 45 VM (snapshot `clean`, kernel 7.2.11-300.fc45, systemd 262, SELinux Enforcing, btrfs)

- `dnf install ./axiom-firewall-1.1.0+linux.rc1-1.x86_64.rpm` rc=0 (pulled bpftool 7.7.0 as weak dep); doctor
  13 PASS; 4 programs; block canary 20/20 refused, control 20/20; after unblock 10/10.
- 0 AVC/USER_AVC/SELINUX_ERR records since boot; axiomd runs as `unconfined_service_t`.

### Open findings / not tested

- Simple home shows "AI AGENT GUARD READY" on Linux; per #441 Linux agent protection must read unsupported /
  not verified. Not fixed in this round.
- Integrations page has no Trader Shield entry at all (no toggle, but no "unavailable" label either).
- Upgrade test did not compare data-file hashes (the snapshot step failed on a permission error); only the
  file listing and the kept rule were checked.
- Not tested: Windows build/tests of this tree (lock files' Windows sections are provisional), DNS
  fail-safe/Privacy Shield, reboot, arm64, Mini mode, RPM upgrade/erase.

## Addendum 2026-11-18: UI truthfulness fixes, VM look (author-run, not CI)

Tested SHA `ed47c9a` (fixes 7461f1f, 81244c0, e6820fc, b1ad705 + Windows-regenerated lock files on top of the
v1.1.0 merge). Package `axiom-firewall_1.1.0+linux.rc2_amd64.deb`, 62,839,096 bytes, sha256
`661615905f4bfd0005b9383defe38a034d63ebf79fad75a196f7b43ff098d9f9` (unsigned dev candidate).

Fresh disposable Ubuntu 24.04.5 overlay (6.8.0-147):
- Install rc=0, doctor 13 PASS / 0 WARN / 0 FAIL, 4 Axiom BPF programs attached.
- Block canary (copy of curl blocked, system python3 as allowed control, veth target): before the rule 0/10
  refused; with the rule 20/20 refused while python3 connected 20/20; after one `systemctl restart`
  20/20 refused. Probe loop across the restart: 634 fresh execs after the action, 0 slipped; control 50/50.
  After unblock 0/10 refused, 10/10 connected. Doctor after the smoke 13 PASS.
- Purge: no unit, no `inet axiom` table, 0 Axiom BPF programs, data and image dirs gone.

GUI under Xvfb (1600x1000), what the screen showed:
- Simple home, daemon running: AI AGENT GUARD **NOT VERIFIED**, "Unsupported on Linux for now: Blackbox host
  hooks are not verified here, so AI agents are not protected". Same text with the daemon stopped (firewall tile
  UNKNOWN, heading "Protection status is unknown", lamp UNKNOWN) and after restart. Never READY.
- Network Control, verified rule on curl: "Axiom Shield ON", "nftables firewall · Axiom-owned rules SHIELD ON",
  "Filter: connected · generation 6 verified ... 1 connect-time proven"; footer "Protection: ON · 1 rule(s)".
- Daemon stopped: "Axiom Shield UNKNOWN", "Protection status unknown: the local service did not answer.",
  firewall section READ-ONLY / Unknown, no filter or "verified" line, no pending rows; lamp UNKNOWN. The owned-rules
  table still lists the last read ("1 owned rules read at 21:09:07", row curl "Applied") under the note "The local
  service did not answer, so the filter state is unknown."
- 10 s after the daemon was started again: page back to Shield ON with "generation 7 verified"; at the same
  moment the header and footer still read "not acknowledged rules generation 7" / "1 rule(s) · blocks not
  verified" (one poll behind).
- Rule removed: page "0 owned rules", count 0, footer "Protection: ON · 0 rule(s)". No stale "1 rule(s)".
- Fix 3 (macOS own-path prompts) does not apply to Linux; not checked here.

## Addendum 2026-11-18 (2): daemon-stopped UI fixes, VM look (author-run, not CI)

Tested SHA `07d2daf` (UI fixes e05c7d9, f63c2e6, 37f93fd, 9772ef1 plus test-only commits). Package
`axiom-firewall_1.1.0+linux.rc3_amd64.deb`, 62,835,072 bytes, sha256
`c0715ef609eca7420bee403f3b2e24cdf80a8145824f15ce742c305b25cf00d5` (unsigned dev candidate).

Fresh disposable Ubuntu 24.04.5 overlay (6.8.0-147):
- Install rc=0, doctor 13 PASS / 0 WARN / 0 FAIL, 4 Axiom BPF programs attached.
- Block canary: before the rule 0/10 refused; with the rule 20/20 refused while python3 connected 20/20;
  one `systemctl restart` with the probe loop: 586 fresh execs after the action, 0 slipped, control 46/46;
  after it 20/20 refused. After unblock 0/10 refused, 10/10 connected. Doctor after 13 PASS.
- Purge: no unit, no `inet axiom` table, 0 Axiom BPF programs, data and image dirs gone.

GUI under Xvfb (1600x1000), one applied verified rule on the curl copy. What the screen showed:
- Daemon up, Network Control: header "Protection active: Axiom rules apply; firewall writes enabled. No
  telemetry."; "Axiom Shield ON", button "Disable protection"; "Filter: connected · generation 5 verified ...
  1 connect-time proven"; "1 owned rules read at ...", row "Applied"; footer "Protection: ON · 1 rule(s)", lamp
  SHIELD ON. Simple home: SHIELD ACTIVE, FIREWALL SHIELD ON, AI AGENT GUARD NOT VERIFIED.
- Daemon stopped, settled (Network Control, 6 s and more after the stop): header "Protection status unknown: the
  local service did not answer. Monitor unavailable: Service unavailable: The service did not respond in time.
  (service_unavailable)"; badge UNKNOWN, "Protection status unknown: the local service did not answer.";
  button "Check protection"; firewall section READ-ONLY, "Unknown / unknown"; count "—"; "1 owned rule(s) shown
  as last known (last read 04:39:06); their state is unknown until the local service answers.", row state
  "Unknown (la…" (column truncated), Unblock disabled; footer "Protection: unknown · the local service did not
  answer", lamp UNKNOWN. Matches.
- Simple home stopped, 10 s: "STATUS UNKNOWN · Protection status is unknown", button "Check Firewall", tile
  FIREWALL SHIELD UNKNOWN, footer "Protection: unknown · the local service did not answer", lamp UNKNOWN. Matches.
- "Check protection" pressed while stopped: no dialog, screen unchanged, nothing sent. Matches.
- Back: 1 s after start every surface said unknown (header "Protection status unknown: waiting for the local
  service.", page UNKNOWN, footer "Protection: unknown", lamp UNKNOWN); 3 s and 10 s after start all surfaces
  verified together (header "Protection active ...", page ON with a new generation verified, footer
  "Protection: ON · 1 rule(s)", lamp SHIELD ON). Matches in that run.

Does not match (recorded, not patched):
- One run 2 s after start: page "Axiom Shield ON", "generation 6 verified", footer "Protection: ON · 1 rule(s)",
  lamp SHIELD ON, while the header still read "Protection status unknown: the local service is offline." and
  the footer "IPC: service offline" (header one poll behind the page).
- For a few seconds after the stop the old state stays up: Network Control 6 s after a stop (page opened 3 s
  before it) still showed Shield ON, "generation 8 verified", "Disable protection", footer "Protection: ON ·
  1 rule(s)", lamp SHIELD ON, under a header "Monitor unavailable: Service unavailable ..."; Simple home 3 s and
  6 s after a stop still showed "SHIELD ACTIVE · Firewall Shield is protecting your apps", tile ON, "Turn Shield
  Off", footer "Monitoring: unavailable ... Protection: ON · 1 rule(s)", lamp SHIELD ON.
- Opening Network Control after the daemon stopped (no earlier read in that page) shows no rows and "No
  Axiom-owned rules were found on this host." under the unknown note, count "—".
- Simple home 2 s and 10 s after start: "NOT VERIFIED · Shield is on, blocking is not verified ... has not
  acknowledged rules generation N", footer "Protection: ON · 1 rule(s) · blocks not verified", amber lamp.
  Header and footer agree, but it had not turned verified at 10 s (Network Control verified within 3 s).
- Switching to Simple mode left the content area blank until Home was clicked in the side bar.

## Addendum 2026-11-18 (3): shared "service unreachable" signal, VM look (author-run, not CI)

Tested SHA `88510ce`. Package `axiom-firewall_1.1.0+linux.rc4_amd64.deb`, 62,822,552 bytes, sha256
`6be98ba48f0e7aecd5dbeef8ec8a1b231f6694fc9340a23b524ac5599775a252` (unsigned dev candidate).

Fresh disposable Ubuntu 24.04.5 overlay (6.8.0-147):
- Install rc=0, doctor 13 PASS / 0 WARN / 0 FAIL, 4 Axiom BPF programs attached.
- Block canary: before the rule 0/10 refused; with the rule 20/20 refused while python3 connected 20/20;
  one `systemctl restart` with the probe loop: 561 fresh execs after the action, 0 slipped, control 46/46;
  after it 20/20 refused. After unblock 0/10 refused, 10/10 connected. Doctor after 13 PASS.
- Purge: no unit, no `inet axiom` table, 0 Axiom BPF programs, data and image dirs gone.

GUI under Xvfb (1600x1000), one applied verified rule. Timed screenshots (offset = seconds after
`systemctl stop|start` returned); texts read by OCR per surface and checked by eye on montages.

| Moment | Header | Page | Footer / lamp | |
|---|---|---|---|---|
| NC up | Protection active: Axiom rules apply | Shield ON, row Applied | Protection: ON · 1 rule(s) / SHIELD ON | agree |
| NC stop +1, +2 s | Protection active | Shield ON, row Applied | ON / SHIELD ON | agree (old state) |
| NC stop +3 … +10 s | Protection status unknown: the local service did not answer | UNKNOWN, Check protection, row "Unknown (la…", Unblock greyed, count — | Protection: unknown · the local service did not answer / UNKNOWN | agree |
| NC start +1 s | unknown | UNKNOWN | unknown / UNKNOWN | agree |
| NC start +2 … +10 s | Protection active: Axiom rules apply | Shield ON, verified, row Applied | ON / SHIELD ON | agree |
| Simple stop +1, +2 s | – | SHIELD ACTIVE, Turn Shield Off | ON / SHIELD ON | agree (old state) |
| Simple stop +3 … +10 s | – | STATUS UNKNOWN · Protection status is unknown, Check Firewall, tile UNKNOWN | unknown / UNKNOWN | agree |
| Simple start +1 … +5 s | – | NOT VERIFIED · Shield is on, blocking is not verified (generation 9) | ON · blocks not verified / SHIELD ON | agree |
| Simple start +7, +10 s | – | SHIELD ACTIVE | ON / SHIELD ON | agree |
| Agents page stop +1 s | unknown | – | unknown / UNKNOWN | agree |

Measured delay stop -> all unknown: 1 to 3 s (Agents page 1 s; Network Control and Simple home between
2 and 3 s, all surfaces in the same frame). No sampled frame showed one surface ON/verified and another
unknown.

- Network Control opened with the daemon down in a freshly started app (no earlier read): "Axiom-owned
  rules could not be read: the local service did not answer. Whether any exist is unknown until it
  answers.", empty table, count "—". Matches. Opened while down after an earlier read: last-known row
  "Unknown (la…", Unblock greyed, note "Service unavailable: The service did not respond in time."
- "Check protection" pressed while down: no dialog, screen unchanged at 3 s and 6 s.
- Crash cycles: 10 stop/start cycles about 10 s apart with the app open, alternating Agent Protection and
  Network Control; cycle 5's start was refused by systemd's start limit (5 starts/min, harness pace), so 9
  real restarts, plus 2 more after `reset-failed` on a second app instance. App process alive throughout;
  `desktop.log` and stdout: 0 fatal/unhandled/exception lines.

Not as expected (recorded, not patched):
- Simple home reached verified 5 to 7 s after start (NOT VERIFIED until then, header and footer agreeing)
  while Network Control in its own restart was verified at 2 s. In another restart (page opened while
  down) Network Control also stayed "generation 10 pending acknowledgement" with the red banner "nftables
  has not acknowledged rules generation 10 yet (table read back with another generation)" until between
  5 and 10 s, so the lag looks tied to the filter acknowledgement, not to the page.
- In that restart, +1 s: header "Monitor unavailable: Service unavailable: The monitoring worker has not
  produced a snapshot yet." (no protection state) while the page showed Shield ON pending and the footer
  "Protection: ON · 1 rule(s) · blocks not verified". Nothing claimed verified; from +2 s the header read
  "Protection active: Axiom rules not verified as enforced …" in agreement.
- Mini mode was not looked at on Linux.

## Addendum 2026-11-18 (4): Linux Core Preview 1 package `1.3.0+linux.preview1` (author-run, not CI)

Tested commit: `625efb32aa2ab6b9cbeb376fb76c29de564f781c` (branch `buba/linux-recon80`, upstream v1.3.0 merged).
Package: `axiom-firewall_1.3.0+linux.preview1_amd64.deb`, 62836660 bytes,
sha256 `ed31c7a59e4237688a87732e15b89ce895f6483e151b8dffa3dd0986cd295f90`
(`scripts/linux/package.sh deb --local linux.preview1`; tree clean afterwards, publish lock-file churn reverted).
VM: disposable overlay of the minimal Ubuntu cloud image, Ubuntu 24.04.5 LTS, kernel 6.8.0-147-generic,
bpftool v7.4.0, systemd-resolved, 3 GB RAM. The release-notes commands were run as written, as the install user.

| # | Check | Result | Evidence |
|---|---|---|---|
| R1 | `echo "<sha>  <deb>" \| sha256sum -c` | PASS | `…deb: OK`, rc 0 |
| R2 | `sudo apt install ./<deb>` as documented | FAIL, then PASS | First run rc 100: the image's package lists were stale (404 on security.ubuntu.com). After `sudo apt update`: rc 0. Recommends (`gnome-shell-extension-appindicator \| plasma-workspace`) pulled 680 new packages incl. gnome-shell, gdm3, network-manager (NM left links unmanaged); `--no-install-recommends` would install 26 |
| R3 | `systemctl status axiomd`, `sudo /usr/libexec/axiom/axiomd --doctor`, `sudo nft list table inet axiom` | PASS | active (enabled); doctor rc 0, 13 PASS / 0 WARN / 0 FAIL / 0 SKIP; table present (generation 1); 4 Axiom BPF programs attached |
| R4 | Canary block (copied curl vs python3, netns target) | PASS | before rule 0/10 refused; blocked 30/30 refused, control 30/30 connected; `connectTimeBlockingProven: true` |
| R5 | `systemctl restart axiomd` under 3 probe loops | PASS | 620 probes after the action, 0 slipped (113 before, 0 slipped); control 49 ok / 0 failed; new pid at 295 ms, attached programs 4 → 8 → 4 (make-before-break); 20/20 refused afterwards |
| R6 | Release-notes block commands with `/usr/bin/curl` blocked | PASS | `curl exit 7` 5/5, `python3 connected` 5/5; after removal `curl exit 0` 5/5 |
| R7 | Unblock | PASS | 0/10 refused, control 10/10; doctor 13/0/0 |
| R8 | Second local user (`axtest`, uid 1001) | PASS | `protection.status`, `snapshot`, `history.query`, `diagnostics.export` → `unauthorized` (private read); `rule.apply`, `privacy.configure`, `protection.disable` → `unauthorized` (write); only `serviceHealth` answered; journal `Denied '<cmd>' for uid:1001 …` per command; user deleted |
| R9 | Privacy Shield on/off | PASS | on: `state Active`, DoH `1.1.1.1`/`9.9.9.9`, `resolvectl dns` global + enp0s2 → 127.0.0.1, `doubleclick.net` not found, `example.com` resolves, status `blocked 6`; doctor `PASS privacy shield dns: redirected … backup present`. off: snapshot of resolv.conf + `resolvectl dns/domain/status` byte-identical to before (hash `c546dd8ef330`) |
| R10 | `--recover-network` (first Linux run), shield on | PASS | while running: dry run rc 1 (plan), `--apply` rc 6 "The Axiom service is running … Nothing was changed."; `systemctl stop` restored DNS exactly; dry run rc 1 "Dry run: no change was made."; `--apply` rc 0 "Result: Succeeded; verified: yes … Recovery completed and was verified."; names + `curl https://example.com` 200; after start the shield came back Active, off restored DNS exactly; doctor 13/0/0 |
| R11 | `apt-get remove` with Privacy Shield on | PASS | rc 0; DNS identical to pre-shield; names resolve, HTTPS 200; unit, nft table, BPF programs/pins, `axiom.slice`, `/usr/libexec/axiom`, `/usr/lib/axiom-firewall`, launcher, polkit, desktop file, doc dir gone; kept `/var/lib/axiom` (8 files, 0600 root) and empty `/var/log/axiom`; dpkg state `rc` |
| R12 | `apt-get purge` | PASS | rc 0; nothing left (incl. `/var/lib/axiom`, `/var/log/axiom`); DNS identical to pre-shield |
| R13 | Upgrade from `1.1.0+linux.rc4` with a block rule under the probe loop | PASS | fresh overlay; rc4 rule refused 20/20; `apt-get install --reinstall` of the new deb under 3 probe loops: 3455 probes after the action, 0 slipped (123 before, 0); control 230 ok / 0 failed; old pid stopped at +18.8 s, new pid at +20.6 s, attached programs 4 → 8 → 4; IPC `pending` at +21.0 s, `verified` again at +21.7 s; doctor WARN only while stopped ("/sys/fs/bpf/axiom remains"); after: same rule id present (first `rules.query` read showed state `pending`), refused 20/20, data file names kept (+`threat-share.json`), doctor 13/0/0; purge afterwards left nothing |
| G1 | App start (Xvfb, user session, no tray host) | PASS | "Set up Axiom" dialog, "Skip for now"; toast "Axiom protection needs attention — Enforcement is NOT protecting this host. Blackbox guard or required protection state is unavailable; actions are unprotected. Open Agent Protection to review." |
| G2 | Network Control stop/start series | PASS with delay | stop: +1 s still ON/verified with the rule Applied, +3 s header/page/row/footer all UNKNOWN ("Unknown (la…", "The local service did not answer, so the filter state is unknown."); start: +1…+5 s "not verified … has not acknowledged rules generation 9" + red "Network filter problem" banner, footer "blocks not verified"; +10 s verified |
| G3 | Agents page, LOCAL MODULES | as expected | Blackbox and OriginTrail DKG "NOT RUNNING", buttons "Install" (no "Repair" shown). "Start local modules" → "Neither local module answered. Install or Repair each card, then try Start local modules again."; "Install" (Blackbox) → "Guided module installation is not available on Linux yet. Install the module manually, then click Check again." Nothing claims protection ("No agents connected", OFFLINE) |
| G4 | Simple home tile | PASS | "AI AGENT GUARD — NOT VERIFIED — Unsupported on Linux for now: Blackbox host hooks are not verified here, so AI agents are not protected" |
| G5 | In-app rule apply/remove | PASS | "New owned rule" → path → "Apply rule" → dialog "Create or update the Axiom-owned block rule for: … Only this rule is changed. Other nftables firewall rules are not touched. Continue only on an isolated test VM." (Cancel / Apply rule) → "Rule applied and verified at 08:21:56."; curl copy refused 5/5. Row "Unblock" → dialog "Remove the Axiom outbound block rule for: … This restores network access and records an allow decision. …" (Cancel / Unblock) → rule gone, 5/5 connect |
| G6 | Unblock on a rule created over IPC (test harness id) | FAIL (recorded) | twice: dialog confirmed, "Remembered Shield decisions: curl Allowed" appears, rule stays Applied, 5/5 still refused. The row action sends `protection.decide Allow` by app path (deterministic `RuleIdentity.ForApp` id), so a rule with another id for that path is not removed |
| G7 | 6 daemon stop/start cycles, 15 s apart, app open | PASS | app pid alive after every cycle; `NRestarts=0`; app stdout and `desktop.log`: 0 fatal/unhandled/exception lines |
| G8 | Simple mode | known issue | blank page after switching (footer follows: UNKNOWN by +3 s, SHIELD ON after start) |

Not tested here: Ubuntu Desktop image (only the minimal cloud image), Wayland, reboot, NetworkManager and
resolv.conf DNS backends, the app's own Privacy Shield toggle and "Block" on a live connection, Mini mode,
arm64, other distributions. Windows CI for this commit was not checked in this run.
Scripts: `v13-rel/rel-vm.sh`, `rel-guest.sh`, `gui.sh` (scratch, not committed).
