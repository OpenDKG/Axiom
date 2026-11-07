# Axiom — DPI and Release Cutover Checklist

Status: the 0.6.0 cutover installed the Avalonia host over the 0.5.3 WPF install on the test
workstation. DPI and rollback evidence are still outstanding.
Applies to: `main` after the Avalonia cutover.

## 1. DPI evidence (125% / 150% / 200%)

True DPI evidence requires the Windows display scale to change and the session to sign out and back
in. It cannot be produced by resizing the window on a 96 DPI desktop.

For each scale (125%, 150%, 200%):

1. Set **Settings → Display → Scale** and sign out/in.
2. Start the Release Avalonia host in service mode:
   `Axiom.Desktop.exe --service`.
3. Capture `1460×900` and `1080×720` for every page:
   Overview, Connections, Applications, Events, Firewall, Privacy Shield, Security, Agents,
   AI Analyst, Support, Settings.
4. Capture the dialogs: first-run onboarding, reputation, community feed, agent-hook choice,
   Blackbox settings, DKG log, confirm/uninstall, file/folder pickers.
5. Check:
   - all eleven navigation items reachable and readable;
   - KPI cards do not overlap and remain readable;
   - table headers and the rightmost column are not clipped;
   - dialogs fit on screen and their action buttons remain reachable;
   - custom title bar buttons and the native resize border still work;
   - no text is cut off in Security, Agents or Privacy Shield long descriptions.
6. Record OS build, GPU/driver, scale, window size, timestamp and the exact executable hash.
7. Keep screenshots out of Git; they contain live local process data.

Exit condition: all three scales pass, or each failure is filed with a page, screenshot and exact
control that clips.

## 2. Controlled performance run

Use a fixed workload, resolution, mode and idle period:

1. Same machine, 1460×900, service mode, no debugger, 30 minutes idle after a 2-minute warm-up.
2. Record desktop and service working set, private bytes, handle count and CPU over the steady period.
3. Repeat for WPF 0.5.3 on the same workload.
4. Do not use a single sample or a busy desktop as a regression result.

## 3. Hosted portable CI

`.github/workflows/portable.yml` runs locked restore/build/test for `Axiom.Portable.slnx` on Ubuntu
and macOS. It must pass on the host before the next release.

The workflow is not in the repository yet because the local GitHub token lacks the `workflow`
scope. Add it with a scoped token or a maintainer-approved path.

## 4. Installer and cutover gates

- [x] Avalonia Release build: 0 warnings, 0 errors.
- [x] `dotnet test Axiom.sln`: 375/375 passed.
- [ ] `Axiom.Portable.slnx` locked restore/build/test passes on hosted Ubuntu and macOS.
- [x] Self-contained package starts on a Windows 10 19044 host without the SDK.
- [x] Installer installs the Avalonia `Axiom.Desktop.exe` and starts the bundled service.
- [ ] Installer uninstall removes the app, service and shortcuts without touching user data.
- [x] Upgrade from 0.5.3 replaces the WPF executable and keeps the install directory/user data.
- [ ] Service install/uninstall and firewall write gate verified on an isolated VM.
- [ ] Code signing, hashes and release notes prepared.
- [ ] Rollback to the WPF 0.5.3 package tested.
- [x] Explicit maintainer decision that Avalonia is primary (`0.6.0`).
