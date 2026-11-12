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
