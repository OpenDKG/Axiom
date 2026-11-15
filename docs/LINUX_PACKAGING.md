# Axiom on Linux: packaging (`.deb`, `.rpm`)

Branch `buba/linux`, P5 of the Linux port (docs/LINUX_PORT_REPORT.md). A user installs Axiom
without a terminal: the package ships the desktop app with the daemon bundled, installs the
polkit action, the desktop entry and the icon, and registers `axiomd` as a systemd unit through
the daemon's own `--install-service` path. Proven on Ubuntu 24.04 (GNOME X11, kernel 7.0):
docs/LINUX_TEST_REPORT.md rows P-1…P-8.

## Package name

The package is `axiom-firewall` (`.deb` and `.rpm`). Builds up to 0.17 were named `axiom`, which is
also the name of an unrelated computer algebra system in the Debian and Ubuntu archives (version
`20170501`). With the old name apt listed the archive's `20170501` as the upgrade candidate for the
firewall, and on the Ubuntu 24.04 evidence box `unattended-upgrade` installed that family's add-on
packages (`axiom-graphics`, `axiom-hypertex`, `axiom-doc`, ...), which left apt reporting unmet
dependencies. The bound `axiom (<< 1000)` matches an old 0.x build of ours and never the archive package.

- `.deb`: `Conflicts`/`Replaces: axiom (<< 1000)`, so `dpkg -i`/`apt install` removes the old build in
  favour of the new one and `/var/lib/axiom` carries over. dpkg leaves the old package in the
  "config-files" state with its postrm, whose purge branch deletes `/var/lib/axiom`; the new postinst
  replaces that script with a no-op (only when it carries our marker lines), so a later
  `dpkg --purge axiom` drops the record and nothing else.
- `.rpm`: `Conflicts: axiom < 1000` only. rpm would run the old package's erase scriptlets after the
  new `%post` and remove the service again, so there is no `Obsoletes`: `dnf remove axiom` first
  (`/var/lib/axiom` stays), then install `axiom-firewall`. Not tested on Fedora. Paths, the unit name
`axiomd.service` and the desktop id `com.axiom.firewall` are unchanged.

## 1. Build

```sh
scripts/linux/package.sh [deb|rpm|all] [--arch x64|arm64] [--skip-publish] [--no-bpf] [--snapshot]
```

| Step | What happens | Tool |
|---|---|---|
| 1 | `make -C src/Axiom.Infrastructure.Linux/Bpf/native` when `clang` is present; otherwise an existing `out/` is reused or the package ships without the eBPF layer (nft-only, said in the log) | clang, bpftool, libbpf-dev |
| 2 | `dotnet publish src/Axiom.Service -f net10.0 -r linux-<arch> --self-contained` → `build/linux/axiomd` (the Service csproj ships `bpf/*` when the objects exist) | .NET 10 SDK |
| 3 | `dotnet publish src/Axiom.Desktop.Avalonia.Linux -r linux-<arch> --self-contained -p:AxiomDaemonPublishDir=build/linux/axiomd` → `build/linux/Axiom`; the project's `PublishBundledDaemon` target copies the daemon tree into `build/linux/Axiom/axiomd/` (§2) | |
| 4 | Stage `build/linux/root` (§3), drop `*.pdb`, the bundle's reference copies of the packaging files and `libcoreclrtraceptprovider.so` (would pull in liblttng-ust), normalise modes (dirs 0755, files 0644, `Axiom`, `axiomd`, `axiom-bpf-events`, `*.so`, `createdump` 0755), validate the polkit XML and the desktop entry | python3, desktop-file-validate (optional) |
| 5 | `Depends` = `dpkg-shlibdeps` over every dynamic ELF in `/opt/axiom` (`-l` for the private runtime libraries) + the libraries the runtime and Avalonia `dlopen` (ICU, OpenSSL, zlib, X11, fontconfig, freetype) + the hard-coded service deps (§4); `Installed-Size`, `md5sums`, maintainer scripts (`bash -n` checked) | dpkg-dev |
| 6 | `fakeroot dpkg-deb --build -Zxz` (falls back to `dpkg-deb --root-owner-group`); `lintian` when installed | dpkg-deb, fakeroot |
| 7 | `rpm`/`all`: `nfpm package -p rpm` from `packaging/linux/nfpm.yaml.in` rendered over the same root (§7) | nfpm |

Environment: `DOTNET`, `DOTNET_WRAPPER` (e.g. a flock wrapper for shared build hosts),
`AXIOM_DOTNET_ARGS` (default `-m:2 -nr:false -p:UseSharedCompilation=false`). A RID publish adds
sections to `packages.lock.json`; discard with `git checkout -- '*.lock.json'`. `build/` is
gitignored.

Version: `<Version>` from `Directory.Build.props` (0.13.2). `--snapshot` appends
`~git<yyyymmdd>.<sha>` so a draft sorts *before* the release it precedes (Debian `~` ordering);
the RPM gets the same string with `~` replaced by `_`.

Artifacts: `build/linux/axiom-firewall_<version>_amd64.deb` (63 MB, xz) and
`build/linux/axiom-firewall-<version>-1.x86_64.rpm` (76 MB). Installed size 193 MB (self-contained .NET
runtime twice: window and daemon are separate processes with separate trust boundaries).

## 2. Desktop publish bundles the daemon

`src/Axiom.Desktop.Avalonia.Linux/Axiom.Desktop.Avalonia.Linux.csproj` target
`PublishBundledDaemon` (`AfterTargets="Publish"`, Linux RIDs only):

- source `$(AxiomDaemonPublishDir)` (default `build/linux/axiomd/`); when it holds no `axiomd`
  the target restores and publishes `Axiom.Service` into it for the same RID/configuration
  (`MSBuild` task, fresh restore session), so a plain `dotnet publish -r linux-x64` of the desktop
  project is self-sufficient;
- copies the tree to `$(PublishDir)axiomd/` (what `LinuxDaemonLayout.BundledDaemonPath` and
  `axiomd --install-service` expect; P4 did this by hand);
- `-p:AxiomBundleDaemon=false` skips it; a missing tree is a build error, never a silent bundle
  without a daemon ("The Axiom daemon was not found at … Reinstall Axiom." in P4).

Proof: `ls build/linux/Axiom/axiomd/axiomd` after step 3, and the same file under
`/opt/axiom/axiomd/axiomd` in `dpkg -c`.

## 3. Layout

| Path | Content | Mode |
|---|---|---|
| `/opt/axiom/Axiom` + runtime | desktop app (self-contained publish) | 0755 / 0644 |
| `/opt/axiom/axiomd/` | daemon publish tree incl. `bpf/axiom_connect.bpf.o`, `bpf/axiom-bpf-events`; **install source only**, never executed from here by systemd | 0755 dir, `axiomd` 0755 |
| `/usr/share/applications/com.axiom.firewall.desktop` | `Exec=/opt/axiom/Axiom`, `Icon=com.axiom.firewall`, `StartupWMClass=com.axiom.firewall` | 0644 |
| `/usr/share/icons/hicolor/{16,24,32,48,64,128,256,512}x…/apps/com.axiom.firewall.png` | from `src/Axiom.UI.Avalonia/Assets/axiom-icon.png` (1024², committed resizes under `packaging/linux/icons`) | 0644 |
| `/usr/share/polkit-1/actions/com.axiom.firewall.policy` | action `com.axiom.firewall.install`, `exec.path=/usr/libexec/axiom/axiomd` | 0644 |
| `/usr/share/doc/axiom-firewall/{copyright,README.md,LINUX_PACKAGING.md}` | DEP-5 copyright (GPL-3.0-or-later) | 0644 |

Created by `axiomd --install-service` at configure time (not package-owned files, so dpkg never
overwrites or diffs them): `/usr/libexec/axiom` (root-owned read-only copy of `/opt/axiom/axiomd`,
audited), `/etc/systemd/system/axiomd.service`, `/var/lib/axiom` 0700, `/var/log/axiom` 0700,
`/run/axiom` (RuntimeDirectory).

## 4. Control fields

```
Package: axiom-firewall   Version: 0.13.2          Architecture: amd64
Section: net              Priority: optional       Homepage: https://github.com/a-51-50/Axiom
Depends: <dpkg-shlibdeps: libbpf1 (>= 1:0.0.9), libc6 (>= 2.34), libfontconfig1 (>= 2.12.6),
         libgcc-s1 (>= 3.0), libstdc++6 (>= 6)>,
         libicu76 | libicu74 | libicu72 | libicu70, libssl3t64 | libssl3, zlib1g,
         libx11-6, libxext6, libxrender1, libxi6, libxcursor1, libxrandr2, libice6, libsm6, libfreetype6,
         nftables, polkitd | policykit-1, pkexec | policykit-1, systemd
Recommends: linux-tools-common | bpftool, libsecret-1-0, gnome-shell-extension-appindicator | plasma-workspace
```

- **bpftool is a Recommends, not a Depends.** Ubuntu has no `bpftool` package: `linux-tools-common`
  ships the `/usr/sbin/bpftool` wrapper (`dpkg -S /usr/sbin/bpftool` → `linux-tools-common`) that
  execs `/usr/lib/linux-tools/<running kernel>/bpftool` from `linux-tools-<kernel>`; on a custom
  kernel (this box: 7.0.0-42-generic with the matching tools dir, while the archive's
  `linux-tools-generic` is 6.8) a hard dependency could be unsatisfiable or point at the wrong
  kernel. Debian/Fedora have a real `bpftool` package (alternative). Without it the daemon
  degrades to nft-only and says so in `capabilities`, `snapshot.limitations` and `--doctor`.
- `libbpf1` is a real Depends: the shipped `axiom-bpf-events` helper links `libbpf.so.1`
  (dpkg-shlibdeps found it). `--no-bpf` builds drop both.
- `polkitd` + `pkexec` are the Ubuntu 24.04 / Debian 12 names (`dpkg -S /usr/bin/pkexec` →
  `pkexec`); `policykit-1` is the alternative on older releases.
- ICU/OpenSSL/X11/fontconfig are `dlopen`ed by the .NET runtime and Avalonia, invisible to
  shlibdeps, hence the hand-written list with ICU alternatives for Ubuntu 22.04–26.04 and
  Debian 12/13. `libfontconfig1` appears versioned via shlibdeps (libSkiaSharp links it).
- `gnome-shell-extension-appindicator | plasma-workspace`: a StatusNotifier host for the
  optional tray; stock GNOME without it runs window-only (§11 of LINUX_ARCHITECTURE.md).

## 5. Maintainer scripts (`packaging/linux/debian/`)

| Script | When | Action |
|---|---|---|
| `postinst configure` | first install and every upgrade | `/opt/axiom/axiomd/axiomd --install-service`: stage `/opt/axiom/axiomd` → `/usr/libexec/axiom` (chown 0:0, 0755/0644, verified with `stat`), `systemctl stop` of a running daemon (its shutdown restores Privacy Shield DNS), replace the image, write the unit, `daemon-reload`, `enable --now` with retries. Idempotent. Skipped with a notice when systemd is not running (chroot/image build). A failing install fails the configure step, so the user sees the error instead of a half-registered service |
| `prerm remove\|deconfigure` | package removal | `/usr/libexec/axiom/axiomd --uninstall-service` (bundle copy as fallback): `disable --now`, unit file, `table inet axiom` + `axiom.slice`, DNS backup restore, `/usr/libexec/axiom`; then stale `/sys/fs/bpf/axiom` pins are detached/removed if the daemon died before it could (belt and braces, only Axiom's pin directory) |
| `prerm upgrade` | upgrade | nothing: the old daemon keeps running from `/usr/libexec/axiom` while dpkg swaps `/opt/axiom`; the new postinst replaces it |
| `postrm remove` | after removal | unit file / `/usr/libexec/axiom` / `/run/axiom` if a prerm could not run (idempotent) |
| `postrm purge` | `dpkg -P` / `apt purge` | additionally `rm -rf /var/lib/axiom /var/log/axiom` (rules, settings, history, DNS backup). Never on upgrade. Per-user state (`~/.local/state/axiom`, `~/.local/share/Axiom`) is not touched |

Nothing in the scripts touches a path Axiom did not create. Upgrades in place over an older
package *or* a dev install (`sudo build/linux/axiomd/axiomd --install-service`) work the same way:
the image under `/usr/libexec/axiom` is replaced and the unit restarted (P-1 proved it over the
P3 dev image: `Axiom.Infrastructure.Linux.dll` hash changed, service active, `--doctor` all PASS).

## 6. Desktop behaviour when installed by the package

`LinuxDaemonLayout.IsPackageManaged` is true when the executable runs under `/opt/axiom`.
`LinuxProtectionSetup.ShouldOfferInstallAtStartup(state, declined, packageManaged)` then never
offers the pkexec install at startup: the package registered the daemon, a missing or inactive
unit means the package is damaged or mid-removal (logged as `package-managed install (/opt/axiom);
no startup install offer, unit=…`). The Shield page's manual Install/Upgrade remains available.
First launch from the app grid right after `dpkg -i`: `[daemon] state=Running unit=active`, no
dialog (`docs/screenshots/linux/packaged-launch.png`).

Because the polkit action is installed and `exec.path` matches `/usr/libexec/axiom/axiomd`, a
later manual upgrade through pkexec shows the Axiom message instead of the generic prompt
(P4's finding). The action file shipped before this branch was **not well-formed XML** (a `--`
inside the comment); polkitd drops such a file silently and `pkaction` lists nothing. Fixed, and
`package.sh` now refuses to stage a policy that does not parse.

## 7. RPM

Built with [nfpm](https://nfpm.goreleaser.com) (static Go binary, official goreleaser release,
SHA-256 checked against the release's `checksums.txt`; v2.49.0 on the evidence box) from the same
staged root: `packaging/linux/nfpm.yaml.in` carries the control mapping
(`depends: nftables, polkit, systemd, libicu, libssl.so.3()(64bit), libcrypto.so.3()(64bit), libbpf.so.1()(64bit), fontconfig, libX11…`,
`recommends: bpftool, libsecret`, `license: GPL-3.0-or-later`) and
`packaging/linux/rpm/{postinstall,preremove,postremove}` translate the Debian semantics to RPM's
numeric `$1` (`%post` 1/2 = install/upgrade → `--install-service`; `%preun` 0 = erase →
`--uninstall-service` + pins; `%postun` 0 = erase → leftovers; upgrades do nothing). RPM has no
purge: `/var/lib/axiom` stays after erase.

**Status: installed, upgraded and removed on Fedora 45** (Cloud Base 45-1.4, kernel 7.2.11-300.fc45, SELinux
Enforcing, firewalld active, nftables 1.1.6, rpm 6.1.0, dnf5; LINUX_TEST_REPORT.md F-1…F-12). No other RPM
distribution (RHEL/Alma 9–10, openSUSE) has been run.

### 7.1 Fedora dependency mapping

| Need | Debian/Ubuntu (`control.in` + `DLOPEN_DEPENDS`) | RPM (`nfpm.yaml.in`) | Fedora 45 provider |
|---|---|---|---|
| OpenSSL 3 (dlopened by the .NET crypto shim) | `libssl3t64 \| libssl3` | `libssl.so.3()(64bit)`, `libcrypto.so.3()(64bit)` | `openssl3-libs` (Fedora 45's `openssl-libs` is OpenSSL **4**, `libssl.so.4`) |
| ICU | `libicu76 \| … \| libicu70` | `libicu` | `libicu` 78 |
| libbpf for `bpf/axiom-bpf-events` | `libbpf1` (shlibdeps) | `libbpf.so.1()(64bit)` (omitted with `--no-bpf`) | `libbpf` 1.7 (preinstalled) |
| polkit / pkexec | `polkitd \| policykit-1`, `pkexec \| policykit-1` | `polkit` (ships pkexec) | `polkit` 127 |
| nftables / systemd | same names | same names | `nftables` 1.1.6, systemd |
| X11/fontconfig (desktop) | `libx11-6`, … | `libX11`, `libXext`, …, `fontconfig` | same |
| bpftool (Recommends) | `linux-tools-common \| bpftool` | `bpftool` | `bpftool` 7.7.0 (weak dep: installed by default by dnf) |

Requiring the soname rather than `openssl-libs` is the fix for F-2: with `openssl-libs` the rpm installed and
`%post` aborted (`No usable version of libssl was found`, exit 134). The capability form is also what Fedora
≤ 44 / RHEL 9–10 (`openssl-libs` 3.x) and openSUSE (`libopenssl3`) provide, so no per-distro branch is needed.

### 7.2 Signatures

The rpm is unsigned. dnf installs it from the command line with a warning (`skipped OpenPGP checks for 1 package
from repository: @commandline`); bare `rpm -U` on rpm 6 (`%_pkgverify_level all`) refuses it
(`package axiom-0.13.2-1.x86_64 does not verify: no signature`) unless `--nosignature` is passed. Signing
(`rpmsign`) stays a release-process item (§8).

### 7.3 SELinux (Enforcing, targeted policy)

No custom policy module and no `restorecon` in the scriptlets are needed: files the installer creates inherit
the correct type from the parent directory, and `restorecon -Rnv` over every Axiom path reports nothing to change.
Observed labels (type part = `matchpathcon`; only the SELinux *user* differs, `unconfined_u` for files created by
the scriptlet, which `restorecon` without `-F` does not touch and the policy does not use):

| Path | Label |
|---|---|
| `/usr/libexec/axiom`, `/usr/libexec/axiom/axiomd`, `bpf/*` | `unconfined_u:object_r:bin_t:s0` |
| `/etc/systemd/system/axiomd.service` | `unconfined_u:object_r:systemd_unit_file_t:s0` |
| `/opt/axiom`, `/opt/axiom/axiomd/axiomd` | `system_u:object_r:usr_t:s0` (rpm-installed) |
| `/var/lib/axiom` | `unconfined_u:object_r:var_lib_t:s0` |
| `/run/axiom`, `/run/axiom/axiom.sock` | `system_u:object_r:var_run_t:s0` |
| polkit action | `system_u:object_r:usr_t:s0` |

`axiomd` runs as `system_u:system_r:unconfined_service_t:s0` (the generic domain for a service binary labelled
`bin_t` without its own policy), so nftables, bpftool, cgroup and BPF-pin operations are not confined.
`ausearch -m avc,user_avc,selinux_err -ts boot` stayed `<no matches>` across install, IPC, rules, BPF attach,
firewalld reload, stop/start, upgrade and removal. A confining policy module is future work, not a requirement.

### 7.4 firewalld

firewalld (nftables backend) owns `table inet firewalld`; Axiom owns `table inet axiom`. They coexist: a
`firewall-cmd --reload` with an Axiom block rule active leaves `table inet axiom` in place (firewalld only replaces
its own table), the rule keeps blocking and `rule.verify` stays `enforcementVerified:true`; Axiom's stop/uninstall
never touched `table inet firewalld`. Both chains see the packet; a drop in either wins (Axiom only adds drops).

### 7.5 Known gaps found on Fedora

- **BPF exe verdicts never matched on btrfs** (Fedora's default root FS; F-8): the key used `stat`'s subvolume
  `st_dev` (`0:35`) instead of the superblock `s_dev` (`0:33`) the BPF program reads. Fixed in `3bc48fb` (device from
  `/proc/self/mountinfo`; LINUX_EBPF.md §2.1, F-15: bare `curl` rc 7 on Fedora 45).
- The "bpftool is not available" hint (journal + doctor) follows `/etc/os-release`: Fedora/RHEL `dnf install
  bpftool`, Ubuntu `apt install linux-tools-common linux-tools-$(uname -r)`, Debian `apt install bpftool`, SUSE
  `zypper install bpftool` (was the Ubuntu text everywhere).
- RPM has no purge: `/var/lib/axiom` (rules, settings, history DB) and an empty `/var/log/axiom` stay after
  `dnf remove`.

## 8. Not done

- Lintian was not run (not installed on the box; `package.sh` runs it when present).
- No `changelog.Debian.gz`; Debian-archive compliance (dh-based source package) is not a goal
  for the GitHub release asset.
- arm64 packages are untested (`--arch arm64` cross-publishes .NET but the `axiom-bpf-events`
  helper is compiled for the build host; the BPF object itself is CO-RE).
- AppImage/Flatpak: not planned (Flatpak cannot host the root daemon).
- Signing of the `.deb` (`dpkg-sig`/apt repository) and the `.rpm` (`rpmsign`) is a release
  process decision, like Windows code signing.
