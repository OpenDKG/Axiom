# Axiom Linux integration — Linux PR CI gate (execution record)

Date: 2026-11-17 (UTC). Author: build agent (single builder; no DKG/parallel workers).

Status legend: **done** = committed + verified locally, **partial** = verified with a named gap,
**blocked** = needs a decision or permission, **todo** = not started.

Re-measure every SHA below before resuming; upstream `main` moved twice in the last 24 h.

## 1. Authority and current state (measured 2026-11-17 21:2xZ–21:5xZ)

- Operator authorization for this session: execute, commit and push focused source/test/CI
  branches; no merge, force-push, tag, sign, release, deploy or repository-permission change.
- Maintainer handoff under execution: **issue #441**, body directive "v1.1.0 execution plan —
  Windows stable + Linux first supported build", plus the newer owner comment of
  2026-11-17T22:06:53Z
  (`https://github.com/a-51-50/Axiom/issues/441#issuecomment-6962366890`).
  That comment moves port leadership to @dreddster, asks for a **Linux CI Draft in parallel**
  ("locked restore, Release builds, native tests and a DEB packaging smoke test as the relevant
  slices land"), and keeps @brxtrac on Linux extraction/provenance. Work below is limited to that
  CI item, which both versions assign to @brxtrac.
- Windows integration target remains **v1.1.0**, `da1987a1896275f0127eb8fe176c1a780471ebe9`
  (PR #440). No later Windows behaviour is chased here.
- Upstream `main` is now **v1.3.0**, `26f1047acb63e40cb9073130dde943b3b10e0adf`: later module and
  dashboard releases only; it still contains no Linux files.
- S1a **#325** head `a1ad18b673f45cba639ea6c4c5f4cb920532a60c`, open Draft, Windows CI **SUCCESS**
  (run [44171425940](https://github.com/a-51-50/Axiom/actions/runs/44171425940), 2026-11-17T23:28Z).
  Not merged; still the prerequisite for S1b/L1.
- S1b branch `feature/macos-s1b-service-seams` head `0330e4a00fd36d42db192d1f185bff06644f28ea`;
  no PR yet.
- Linux reconciliation `feature/linux-recon-0.97.0` head
  `07d2daf707eb016ef188ef61221786ed2c1c96ef`, based on `da1987a` (v1.1.0), 59 commits, DCO
  attestation `37fa3b14` in ancestry. Reference only, not a standalone merge candidate.
- Older clean reference `recon/linux-main-0.73.0` `2c908faf…` and the preserved artifact
  `axiom-firewall_0.73.0+linux.7_amd64.deb` (SHA-256 `a2ccc826…`) are untouched.

## 2. Finding that fixes the CI placement

The PR-triggered gate cannot sit on current `main`: the shared portable suites there still assert
Windows path semantics, so they fail on Ubuntu. Measured on `26f1047a` in a clean Ubuntu 24.04
worktree (`/tmp/opencode/axiom-integration-1.1-20261117/wt-linux-ci`, SDK 10.0.403):

| Measurement | Result |
|---|---|
| `dotnet restore Axiom.Portable.slnx --locked-mode` | ok |
| `dotnet build Axiom.Portable.slnx -c Release` | ok, 0 warnings / 0 errors |
| `dotnet test` (6 projects) | **770 passed, 24 failed, 794 total** — every failure is a Windows-path assertion |

Examples: `RuleSpecValidatorTests` (`C:\…` absolute-path checks), `ProtectionProvisionerTests`
(`C:\lab\…` config paths), `ShieldProcessFilterTests` (`Program Files` exclusion, `Path.Combine`
separators). These are shared projects; adapting them is part of the Linux port, already present on
`feature/linux-recon-0.97.0` (§4), and touching them needs Windows CI per the owner's rule.

Consequence: the Linux gate is green only on the Linux stack, so this commit is stacked on the
reconciled tree rather than on `main`. Retarget it when the first focused Linux slice lands; until
then it is a stacked Draft and is not claimed as a main-line required check.

## 3. What this commit adds

- `.github/workflows/linux-ci.yml`: PR-triggered Ubuntu 24.04 job (ephemeral GitHub-hosted runner,
  `contents: read`, no secrets, no privileged nft/BPF/DNS mutation, no package install):
  - .NET SDK from `global.json`, Python 3.12 for agent-hook runtime tests;
  - locked restore + Release build of `Axiom.Portable.slnx` (warnings as errors);
  - full portable test run with TRX reports and a strict gate: any failed test, zero passing
    tests, or a suite that executed nothing fails the job; skips are reported in the job summary
    (`shortcut:` comment in the workflow records that skip counts become fatal per suite once the
    Linux projects are stable);
  - the two Linux suites outside `Axiom.Portable.slnx` — `Axiom.Desktop.Avalonia.Linux.Tests` (51)
    and `Axiom.Infrastructure.Linux.Nft.Tests` (203) — are restored locked, built Release and
    tested explicitly; adding them to the portable solution would break the macOS portable job;
  - deterministic BPF compile (`clang`/`llvm`/`libbpf-dev`/`bpftool`, objects hashed and uploaded);
  - DEB build smoke with `scripts/linux/package.sh deb --arch x64 --local ci`, then package
    identity and payload inspection (no install, no service start) and SHA256SUMS;
  - TRX, BPF hashes, DEB control and package uploaded as `linux-ci-evidence`;
  - Linux-only steps are file-gated and the summary states what ran, so a skip is not read as green.
    The two Linux test projects are the exception: they must exist (the job fails with a clear
    message otherwise), so retargeting the gate to `main` before L1 lands requires adding them.
- This record.

## 4. Local evidence (Ubuntu 24.04.5 host, SDK 10.0.403, 2026-11-17 21:3xZ)

Run at `07d2daf7` in `wt-linux-src`, and re-run 2026-11-18 in `wt-linux-ci` with the exact commands
from the workflow (PowerShell not used). The 2026-11-18 run restored, built and tested all three
sets and executed the workflow's "Summarize and gate" script verbatim: **13 suites, 1615 executed,
1615 passed, 0 failed, 0 skipped**, gate exit 0 (logs in
`/tmp/opencode/axiom-integration-1.1-20261117/ci-followup-20261118/`).

| Step | Result |
|---|---|
| locked restore, portable solution | ok |
| Release build, portable solution | ok, 0 warnings / 0 errors |
| portable tests (11 assemblies incl. Service.Hosting, Unix, Linux, Avalonia, macOS desktop) | **1361 executed / 1361 passed / 0 failed / 0 skipped** |
| Linux desktop tests (explicit, `Axiom.Desktop.Avalonia.Linux.Tests`) | **51 executed / 51 passed / 0 failed / 0 skipped** |
| Linux nft/BPF tests (explicit, `Axiom.Infrastructure.Linux.Nft.Tests`) | **203 executed / 203 passed / 0 failed / 0 skipped** |
| BPF compile (`make -C src/Axiom.Infrastructure.Linux/Bpf/native`) | ok; `axiom_connect.bpf.o` 115536 B, `axiom-bpf-events` 16856 B |
| DEB smoke | ok, see §5 |

`python3 -c "yaml.safe_load(...)"` parses the workflow; the job has 12 steps and the expected
three triggers. Linux GUI, systemd start/stop, nft/eBPF enforcement and DNS were **not** exercised
here — that remains VM evidence, not CI evidence.

## 5. DEB smoke result

`scripts/linux/package.sh deb --arch x64 --local ci` (log
`/tmp/opencode/axiom-integration-1.1-20261117/package-build.log`, exit 0) produced
`axiom-firewall_1.1.0+ci_amd64.deb`, 62,836,024 B, SHA-256
`d091d97cead927247ea6eb2364dfdbcb4555c3b977659cc8f6045ca04ba2abd6`, installed size 192,712 KB.

The workflow's inspection assertions all hold against it: `Package=axiom-firewall`,
`Architecture=amd64`, `Version=1.1.0+ci`; payload `usr/lib/axiom-firewall/Axiom` and
`axiomd/axiomd` executable; `usr/bin/axiom-firewall` symlink; polkit action, desktop entry and
`bpf-pins.sh` present. This is a build/inspection smoke only: the package was not installed, no
service was started, no firewall or DNS state was touched.

## 6. Dependency status after this phase

```
main v1.1.0 da1987a ─┬─ S1a #325 a1ad18b  (Draft, Windows CI green, not merged)
                     ├─ S1b 0330e4a       (branch only, no PR)
                     └─ Linux recon 07d2daf ── this CI commit (stacked Draft)
L1 unix IPC → L2 daemon → L3 nft → L4 eBPF → L5 DNS → L6 desktop → L7 packaging
```

- **Blocked:** S1a merge (owner/@dreddster); S1b PR; all L-slices until prerequisites merge.
- **Independent review:** this CI change is non-security and needs no native security reviewer;
  privileged slices still require a qualified non-author Linux reviewer, not claimed here.
- **Not done / not claimed:** Windows CI on this branch (the stack changes shared files and needs
  the existing Windows CI when PR'd), DCO checker pass (repo has no DCO workflow), release,
  signing, Linux production support or AI-parity claims.

## 7. First CI run attempt is blocked by the repository owner's runner billing

Push and PR: branch `ci/linux-pr-validation` head
`efe5bf6ad1281ee28ad485359d42f5e6898cc4c0`, Draft PR
[#443](https://github.com/a-51-50/Axiom/pull/443), base `feature/linux-recon-0.97.0`.

Run [44224988929](https://github.com/a-51-50/Axiom/actions/runs/44224988929) was created by the
`pull_request` event (so the workflow parsed and the job was recognised), then the job completed as
`failure` in one second with **zero steps** and this check-run annotation:

> The job was not started because recent account payments have failed or your spending limit needs
> to be increased. Please check the 'Billing & plans' section in your settings

Nothing in the workflow or the repository caused this: no step executed, and the same billing block
is on the repository owner's account (the Windows CI keeps working only because it runs on the
self-hosted runner). Consequences, stated plainly:

- **Blocked:** any GitHub-hosted Linux run, including this gate, until the owner fixes billing or
  points the job at an approved Linux runner. No hosted-run green is claimed.
- **Evidence that stands:** the local Ubuntu 24.04.5 run of the exact commands in §4/§5
  (1361/1361 tests, BPF compile, DEB build + inspection) and the workflow YAML parse.
- **Not a code failure:** do not treat run 44224988929 as a red build; it never started.

## 8. Next bounded steps

1. Owner decides whether the CI gate stays stacked on the Linux tree or is retargeted to the first
   clean L1 slice; no other change is needed for it to run.
2. S1a merge → S1b Draft → L1 extraction (Unix IPC, kernel peer credentials, explicit access
   classes) from the reconciled tree, preserving original authorship and DCO provenance.
3. Re-run this workflow on the exact L1 PR head and link the run in #441.
