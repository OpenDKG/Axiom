# Cross-platform status — 17 November 2026

This is a status note, not a merge decision. Axiom's Windows work does not imply macOS or Linux
parity. Both ports are open and blocked on review and platform CI, not on Windows defects.

## macOS

| Item | State | What blocks it |
| --- | --- | --- |
| #274 macOS port (Avalonia app, launchd daemon, Network Extension filter) | Open reference branch `feature/macos-port`, head `4f8c226`; Windows CI passed on the updated reference | Nothing from the branch is merged without explicit maintainer approval; it lands as dependency-ordered slices, and the security-sensitive slices need a macOS reviewer |
| #388 separate filter host + activation/installer fixes | Open, 14 commits stacked on #274 (`4f8c226`), not on `main` | Depends on #274 staying open; merge #274 first |
| #325 portable IPC dispatcher and write gate (S1a) | Open; Windows evidence is author-run on the Windows VM, not CI | The macOS split needs the pinned `main` rebased and a macOS CI run before it can be treated as validated |

The Network Extension filter cannot be exercised from the Windows lab. Signing and notarization for
macOS are not set up.

## Linux

| Item | State | What blocks it |
| --- | --- | --- |
| #276 Linux port (systemd daemon, nftables + eBPF, Avalonia host) | Open draft stacked on #274; a reconciled branch `recon/linux-main-0.73.0` at `2c908fa` was independently reviewed and approved as a **bounded Ubuntu 24.04 x86_64 local candidate** | Not merged; no release artifact published from it; it is based on an older `main` and needs the same review gate as macOS |
| #150 Linux desktop handoff | Open enhancement with the implementation handoff | Tracks the port; acceptance still needs Linux CI and an installer/release decision |
| #175 per-executable firewall enforcement | Branch contains a real eBPF/cgroup backend, re-based on `main` 0.5.2 | Needs the Linux review and a run on a kernel with the required BPF features; nftables alone fails closed by design |
| #290 `axiomd --doctor` false green | Fixed on `feature/linux-port` (#276): the doctor asks the running daemon over IPC instead of counting pin files | The fix rides with #276; it is not on `main` |

## Common blockers

1. **No platform CI.** The only self-hosted runner is Windows. macOS and Linux changes are validated
   by author runs, which the project does not treat as equivalent to CI.
2. **Review capacity.** Security-sensitive slices (filter host, BPF attach/detach, privileged IPC)
   need a platform reviewer before merge.
3. **Artifacts and signing.** No macOS notarization or Linux package is published from these
   branches; Windows signing is still pending (see RELEASE_VALIDATION_2026-11-17.md).
4. **Base drift.** Both ports are based on older `main` commits and need periodic reconciliation;
   the Linux branch already has a reconciled 0.73.0 line.

Until those change, Windows remains the supported platform and the Windows release notes do not
claim cross-platform coverage.
