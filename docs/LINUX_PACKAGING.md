# Axiom on Linux: packaging (`.deb`, `.rpm`)

Branch `buba/linux`, P5 of the Linux port (docs/LINUX_PORT_REPORT.md). A user installs Axiom
without a terminal: the package ships the desktop app with the daemon bundled, installs the
polkit action, the desktop entry and the icon, and registers `axiomd` as a systemd unit through
the daemon's own `--install-service` path. Proven on Ubuntu 24.04 (GNOME X11, kernel 7.0):
docs/LINUX_TEST_REPORT.md rows P-1…P-8.

## Package name and migration

The package is `axiom-firewall` for both DEB and RPM. `axiom` is an unrelated computer algebra
system in the Debian/Ubuntu archives (20170501) and in Fedora; builds up to 0.17 used that name,
which let apt/unattended-upgrade treat the archive package as an upgrade. Paths, `axiomd.service`
and the desktop id `com.axiom.firewall` are unchanged.

- `.deb`: `Conflicts`/`Replaces: axiom (<< 1000)` matches only our 0.x builds. `dpkg -i` replaces
  the old package and keeps `/var/lib/axiom`; the old package is left in the config-files state,
  so `postinst` disarms its purge branch (only when the script carries our marker lines), and a
  later `dpkg --purge axiom` drops the record only. The old script is located with `dpkg-query
  --control-path`, never by spelling out dpkg's private directory; rewriting a replaced package's
  control file at all is the legacy-migration mechanism, and retiring it is an owner decision.
- The payload moved from `/opt/axiom` to `/usr/lib/axiom-firewall` (Debian Policy 9.1.1 forbids
  `/opt`); `/usr/bin/axiom-firewall` is the stable launcher. An upgrade from a `/opt` build is a
  normal in-place `dpkg -i`: dpkg removes the obsolete `/opt` files, `/var/lib/axiom` (rules,
  settings, history, credentials, DNS backup) and the service image `/usr/libexec/axiom` are not
  package-owned and are replaced by the new `postinst`, and the old unit keeps running until that
  postinst stops it. No data or unit is dropped.
- `.rpm`: `Conflicts: axiom < 1000` without `Obsoletes`; rpm would run the old erase scriptlets
  after the new `%post` and remove the service again. Remove an old `axiom` build first
  (`/var/lib/axiom` stays), then install `axiom-firewall`. Not tested on Fedora.


## 1. Build

```sh
scripts/linux/package.sh [deb|rpm|all] [--arch x64|arm64] [--skip-publish] [--no-bpf] [--snapshot]
                          [--local <suffix>]
```

| Step | What happens | Tool |
|---|---|---|
| 1 | `make -C src/Axiom.Infrastructure.Linux/Bpf/native` when `clang` is present; otherwise an existing `out/` is reused or the package ships without the eBPF layer (nft-only, said in the log) | clang, bpftool, libbpf-dev |
| 2 | `dotnet publish src/Axiom.Service -f net10.0 -r linux-<arch> --self-contained` → `build/linux/axiomd` (the Service csproj ships `bpf/*` when the objects exist) | .NET 10 SDK |
| 3 | `dotnet publish src/Axiom.Desktop.Avalonia.Linux -r linux-<arch> --self-contained -p:AxiomDaemonPublishDir=build/linux/axiomd` → `build/linux/Axiom`; the project's `PublishBundledDaemon` target copies the daemon tree into `build/linux/Axiom/axiomd/` (§2) | |
| 4 | Stage `build/linux/root` (§3), drop `*.pdb`, the bundle's reference copies of the packaging files and `libcoreclrtraceptprovider.so` (would pull in liblttng-ust), normalise modes (dirs 0755, files 0644, shared libraries 0644, `Axiom`, `axiomd`, `axiom-bpf-events`, `createdump`, `bpf-pins.sh` 0755), strip the five native objects lintian reports (never `*.bpf.o`), install the `/usr/bin/axiom-firewall` symlink and the lintian override file, validate the polkit XML and the desktop entry | python3, desktop-file-validate (optional) |
| 5 | `Depends` = `dpkg-shlibdeps` over every dynamic ELF in `/usr/lib/axiom-firewall` (`-l` for the private runtime libraries) + the libraries the runtime and Avalonia `dlopen` (ICU, OpenSSL, zlib, X11, fontconfig, freetype) + the hard-coded service deps (§4); `Installed-Size`, `md5sums`, maintainer scripts (`bash -n` checked) | dpkg-dev |
| 6 | `fakeroot dpkg-deb --build -Zxz` (falls back to `dpkg-deb --root-owner-group`); `lintian` when installed | dpkg-deb, fakeroot |
| 7 | `--local <suffix>` appends `+<suffix>` to the package version only (e.g. `0.59.0+linux.1`): a local, upgradable test build; the app still reports the upstream `0.59.0` | |
| 7 | `rpm`/`all`: `nfpm package -p rpm` from `packaging/linux/nfpm.yaml.in` rendered over the same root (§7) | nfpm |

Environment: `DOTNET`, `DOTNET_WRAPPER` (e.g. a flock wrapper for shared build hosts),
`AXIOM_DOTNET_ARGS` (default `-m:2 -nr:false -p:UseSharedCompilation=false`). A RID publish adds
sections to `packages.lock.json`; discard with `git checkout -- '*.lock.json'`. `build/` is
gitignored.

Version: `<Version>` from `Directory.Build.props` (0.59.0). `--snapshot` appends
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
`/usr/lib/axiom-firewall/axiomd/axiomd` in `dpkg -c`.

## 3. Layout

| Path | Content | Mode |
|---|---|---|
| `/usr/lib/axiom-firewall/Axiom` + runtime | desktop app (self-contained publish) | 0755 / shared libraries 0644 |
| `/usr/lib/axiom-firewall/axiomd/` | daemon publish tree incl. `bpf/axiom_connect.bpf.o`, `bpf/axiom-bpf-events`; **install source only**, never executed from here by systemd | 0755 dir, `axiomd` 0755 |
| `/usr/lib/axiom-firewall/bpf-pins.sh` | sourced by `prerm` (BPF pin cleanup) | 0755 |
| `/usr/bin/axiom-firewall` | symlink → `/usr/lib/axiom-firewall/Axiom`, the launcher `Exec=` uses | symlink |
| `/usr/share/applications/com.axiom.firewall.desktop` | `Exec=/usr/bin/axiom-firewall`, `Icon=com.axiom.firewall`, `StartupWMClass=com.axiom.firewall` | 0644 |
| `/usr/share/icons/hicolor/{16,24,32,48,64,128,256,512}x…/apps/com.axiom.firewall.png` | from `src/Axiom.UI.Avalonia/Assets/axiom-icon.png` (1024², committed resizes under `packaging/linux/icons`) | 0644 |
| `/usr/share/polkit-1/actions/com.axiom.firewall.policy` | action `com.axiom.firewall.install`, `exec.path=/usr/libexec/axiom/axiomd` | 0644 |
| `/usr/share/doc/axiom-firewall/{copyright,README.md,LINUX_PACKAGING.md,changelog.gz}` | DEP-5 copyright (GPL-3.0-or-later) | 0644 |

Created by `axiomd --install-service` at configure time (not package-owned files, so dpkg never
overwrites or diffs them): `/usr/libexec/axiom` (root-owned read-only copy of `/usr/lib/axiom-firewall/axiomd`,
audited), `/etc/systemd/system/axiomd.service`, `/var/lib/axiom` 0700, `/var/log/axiom` 0700,
`/run/axiom` (RuntimeDirectory).

## 4. Control fields

```
Package: axiom-firewall   Version: 0.59.0          Architecture: amd64
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
| `postinst configure` | first install and every upgrade | `/usr/lib/axiom-firewall/axiomd/axiomd --install-service`: stage `/usr/lib/axiom-firewall/axiomd` → `/usr/libexec/axiom` (chown 0:0, 0755/0644, verified with `stat`), `systemctl stop` of a running daemon (its shutdown restores Privacy Shield DNS) **confirmed with `is-active` before the image is replaced** — an unconfirmed or still-active stop fails the install and keeps the old image/unit, replace the image, write the unit, `daemon-reload`, `enable --now` with retries. Idempotent. Skipped with a notice when systemd is not running (chroot/image build). A failing install fails the configure step, so the user sees the error instead of a half-registered service |
| `prerm remove\|deconfigure` | package removal | `/usr/libexec/axiom/axiomd --uninstall-service` (bundle copy as fallback): `disable --now`, unit file, `table inet axiom` + `axiom.slice`, DNS backup restore, `/usr/libexec/axiom`; then stale `/sys/fs/bpf/axiom` pins are detached and removed **only after `bpftool -j cgroup show` proves no Axiom program is attached**. The list is parsed as JSON: bpftool's blank stdout or `[]` means no attachment, and every other successful answer must be an array of objects with a non-zero uint32 `id` and a decoded string `name`. Missing/unreadable bpftool or awk, malformed JSON (non-array, non-object element, missing/duplicate/wrong-typed field, invalid id, bad escape, trailing data), a failed detach that still shows an attachment, or an unconfirmed `systemctl` stop keeps the pins/unit/image for recovery and fails the removal (belt and braces, only Axiom's pin directory). Parsing uses POSIX awk from the base system (`mawk` is Priority: required on Debian/Ubuntu, `gawk` is in Fedora's core group); python/jq are not used and a missing awk fails safe |
| `prerm upgrade` | upgrade | nothing: the old daemon keeps running from `/usr/libexec/axiom` while dpkg swaps the payload directory; the new postinst replaces it |
| `postrm remove` | after removal | unit file / `/usr/libexec/axiom` / `/run/axiom` if a prerm could not run (idempotent). The leftover unit is deleted **only after the stop is confirmed** (`systemctl disable --now` plus a readable `is-active` of `inactive`/`failed`); a still-active, timeout/unknown or unavailable systemctl keeps the unit/image/run directory and fails the removal |
| `postrm purge` | `dpkg -P` / `apt purge` | additionally `rm -rf /var/lib/axiom /var/log/axiom` (rules, settings, history, DNS backup) **after the same stop confirmation**; an unconfirmed stop keeps the data/logs too. Never on upgrade. Per-user state (`~/.local/state/axiom`, `~/.local/share/Axiom`) is not touched |

Nothing in the scripts touches a path Axiom did not create. Upgrades in place over an older
package *or* a dev install (`sudo build/linux/axiomd/axiomd --install-service`) work the same way:
the image under `/usr/libexec/axiom` is replaced and the unit restarted (P-1 proved it over the
P3 dev image: `Axiom.Infrastructure.Linux.dll` hash changed, service active, `--doctor` all PASS).

## 6. Desktop behaviour when installed by the package

`LinuxDaemonLayout.IsPackageManaged` is true when the executable runs under `/usr/lib/axiom-firewall` (the `/usr/bin/axiom-firewall` symlink resolves there, so a normal launch is package-managed too).
`LinuxProtectionSetup.ShouldOfferInstallAtStartup(state, declined, packageManaged)` then never
offers the pkexec install at startup: the package registered the daemon, a missing or inactive
unit means the package is damaged or mid-removal (logged as `package-managed install (/usr/lib/axiom-firewall);
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
`--uninstall-service` + pins; `%postun` 0 = erase → leftovers, unit/image kept and erase failed
when the stop is unconfirmed; upgrades do nothing). RPM has no purge: `/var/lib/axiom` stays after erase.

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
| `/usr/lib/axiom-firewall` | `system_u:object_r:usr_t:s0` (rpm-installed) |
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

- A Debian **source** package (`debian/rules`, d/rules, d/changelog as a dh package) is still not a
  goal for the GitHub release asset; the build is a binary package assembled by `package.sh`.
- arm64 packages are untested (`--arch arm64` cross-publishes .NET but the `axiom-bpf-events`
  helper is compiled for the build host; the BPF object itself is CO-RE).
- AppImage/Flatpak: not planned (Flatpak cannot host the root daemon).
- Signing of the `.deb` (`dpkg-sig`/apt repository) and the `.rpm` (`rpmsign`) is a release
  process decision, like Windows code signing.
- The RPM path follows the same payload move, but no RPM was built or tested in this pass.

## 9. Lintian and local test versions

`package.sh` shows lintian output when lintian is installed; it does not make lintian a build
dependency. The local Ubuntu 24.04 pass on the 0.59.0 artifact reported 508 errors / 3 warnings,
almost all of them the `/opt` placement (466 `dir-or-file-in-opt`) plus `.NET` self-contained
natives (30 `shared-library-is-executable`, 5 `unstripped-binary-or-object`, 5
`embedded-library`, 1 `binary-from-other-architecture`) and four maintainer-script/doc issues
(`no-changelog`, `maintainer-script-calls-systemctl`, `script-not-executable`,
`uses-dpkg-database-directly`). The current packaging fixes what is a packaging decision:

- payload under `/usr/lib/axiom-firewall` + `/usr/bin` launcher (no `/opt`);
- shared libraries 0644, scripts and apphosts 0755;
- `strip --strip-unneeded` on the five unstripped ELF natives (never the BPF object, its BTF is
  what CO-RE needs);
- `changelog.gz` generated from the package version;
- `postrm` stops through `deb-systemd-invoke`/`deb-systemd-helper` and keeps the `is-active`
  read-back, so a quiet helper failure still keeps the unit/image instead of deleting them;
- `postinst` finds the replaced package's `postrm` with `dpkg-query`, not `/var/lib/dpkg`.

Three tags remain true statements about the upstream artifacts and get **per-file** overrides in
`packaging/linux/debian/lintian-overrides` (no package-wide suppression): the BPF object's
`EM_BPF` machine, and the freetype/libjpeg/libpng/zlib copies in SkiaSharp and the runtime's
compression shim. Each line names the file and why a system library is not a drop-in. A lintian
run on a new artifact is evidence for review, not a release approval.

An artifact built from an unreleased commit should carry `--local <suffix>`, e.g.
`0.59.0+linux.1`: dpkg sorts it after `0.59.0` so it upgrades the locally tested 0.59.0 artifact,
while the app and the upstream version stay `0.59.0`. Do not push such an artifact as a release.
