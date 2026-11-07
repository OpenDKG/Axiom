# Axiom — DPI and Release Cutover Checklist

Status: execution requires a display-scaling change and a separate release approval.
Applies to: `feature/avalonia-windows-first`, Windows 10 19044 test host.

## 1. DPI evidence (125% / 150% / 200%)

True DPI evidence requires the Windows display scale to change and the session to sign out and back
in. It cannot be produced by resizing the window on a 96 DPI desktop.

For each scale (125%, 150%, 200%):

1. Set **Settings → Display → Scale** and sign out/in.
2. Start the Release Avalonia host in service mode:
   `Axiom.Desktop.Avalonia.Windows.exe --service`.
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
and macOS. It must pass on the host before cutover.

The branch push requires a GitHub token with the `workflow` scope because the workflow file is new.
The current keyring token has `gist`, `read:org` and `repo` only; use an authorized token or add the
workflow through a maintainer-approved path.

## 4. Installer and cutover gates

Do not call this a release until every gate is signed off:

- [ ] Avalonia Release build: 0 warnings, 0 errors.
- [ ] `dotnet test Axiom.sln`: all tests pass.
- [ ] `Axiom.Portable.slnx` locked restore/build/test passes on hosted Ubuntu and macOS.
- [ ] Self-contained package starts on a clean Windows 10 19044 VM without the SDK.
- [ ] Installer installs/uninstalls the Avalonia host, service, shortcuts and per-user data correctly.
- [ ] Upgrade from 0.5.3 keeps user data and does not duplicate services or startup entries.
- [ ] Service install/uninstall and firewall write gate verified on an isolated VM.
- [ ] Code signing, hashes and release notes prepared.
- [ ] Rollback to the WPF 0.5.3 package tested.
- [ ] Explicit maintainer approval for the cutover; 0.5.3 remains the published release until then.
