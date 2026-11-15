# AXIOM 1.0 — Phase 8: Cross-Platform Validation Gates (macOS & Linux)

> **Release Policy:** Windows is the primary `1.0` target. Large platform reference PRs (`#274` macOS, `#276` Linux) must **not** be merged into `main` solely to claim cross-platform coverage. Each platform advances only after passing its independent native runner and security validation gates.

---

## 1. Current Portable & Cross-Platform Posture Observed in Repo

| Track | Branch / Workflow / Reference | Observed State | Blocking Issues & Structural Gaps |
|---|---|---|---|
| **Portable Core (`Axiom.Portable.slnx`)** | `Axiom.Contracts`, `Axiom.Core`, `Axiom.McpServer`, `Axiom.Persistence`, `Axiom.Presentation`, `Axiom.UI.Avalonia` (+ 6 test projects) | Compiles and passes tests on Windows; `.github/workflows/macos-port.yml` defines portable test execution and `/tmp/axiom-ci` short-socket `TMPDIR` workaround. | **Shared CI/Portability Blocker (`#280`):** `dotnet restore Axiom.Portable.slnx --locked-mode` fails with **`NU1004`** even cleanly against `Axiom.Contracts`, `Axiom.Core`, `Axiom.Persistence`, and `Axiom.Presentation` because their committed `packages.lock.json` files include `net10.0/win-x64`. |
| **macOS Port** | PR **`#274`** (`feature/macos-port`), PR **`#325`** (`feature/macos-s1a-ipc-dispatcher`), `.github/workflows/macos-port.yml` (`workflow_dispatch`, `macos-15-intel`..`macos-13`) | Smaller architectural splits such as `#325` decouple portable IPC dispatching and write gates into `Axiom.Core`; `.github/workflows/macos-port.yml` runs `swift` filter unit tests plus macOS infrastructure/desktop/portable suites. | **`#280`** blocks locked restore on macOS; **`#281`** fails `Antigravity_protection_writes_hooks_without_utf8_bom_and_repairs_existing_bom` on macOS because `StorageSafety.IsReparsePointInPath` treats macOS `/var` -> `/private/var` temp symlink as a reparse point. |
| **Linux Port** | PR **`#276`** (`feature/linux-port`, parent `#150` — currently `CONFLICTING` with `main`) | Implements `systemd` daemon (`axiomd`), `nftables` + connect-time eBPF concepts, and Avalonia Linux host on feature branch outside `main`. | **`#290`:** `axiomd --doctor` can falsely report `PASS bpf layer` / `all checks passed` while the running BPF layer is `degraded` and stale `/sys/fs/bpf/axiom` pins remain (`pendingRemovals`). **`#175`:** Per-executable eBPF/cgroup enforcement must prove fail-closed behavior natively. PR needs rebase onto `main`. |

---

## 2. Independent Acceptance Gates Required Before Tagging a Cross-Platform Release

Every platform (macOS and Linux) must separately pass all 9 checks on a native host/VM before shipping:

1. **Clean Locked Dependency Restore & Build (`#280`):** `dotnet restore Axiom.Portable.slnx --locked-mode` and native solution build succeed with `0` lockfile edits and `0` warnings.
2. **Portable Test Pass Without Platform Skips (`#281`):** All portable tests pass on native macOS/Linux (or platform-specific Windows-only behavior is explicitly documented).
3. **Native Package Install, Upgrade & Uninstall:** `.pkg`/`.dmg`/app bundle (macOS) or `.deb`/`.rpm`/tarball + `systemd` unit (Linux) installs, preserves user/reporter state on upgrade, and removes service + owned rules cleanly on uninstall.
4. **Daemon Lifecycle & Privileged Boundary:** `launchd` / `systemd` service starts with least privilege, handles restart/crash recovery cleanly, and separates UI permissions from daemon root/admin actions.
5. **Local IPC Authorization:** Unix domain socket DACL / peer-UID/PID verification refuses unauthorized cross-user clients (`#325` contract).
6. **Native Network Enforcement & Canary Proof:** Network Extension (`NEFilterDataProvider` on macOS) or `nftables` + cgroup eBPF (`#175`, `#290` on Linux) passes the Phase 4 dual-destination canary (`OS_DENY_VERIFIED`) and clean rollback; health/doctor commands read live daemon capability instead of stale pins (`#290`).
7. **Host Hook & Guard Integration:** Cooperative host hooks work with real OS paths and temp-path symlinks cleanly; fail-open vs fail-closed boundary is accurately surfaced in UI/CLI.
8. **DNS Filtering & Recovery:** Privacy Shield resolver binds safely and restores OS DNS cleanly (`scutil`/networksetup on macOS; `systemd-resolved`/`resolv.conf` on Linux) after stop or crash.
9. **Offline Operation Continuity:** Ruleset caching, DKG-offline continuity, and threat-sharing safety match Phase 5 & Phase 6 invariants with platform-native paths.
