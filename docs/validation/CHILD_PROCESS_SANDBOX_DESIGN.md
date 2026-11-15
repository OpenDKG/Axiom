# F-19 — Agent process containment design (2026-11-15)

Status: design decision, no code yet. Supersedes the "child-process sandbox" wording in the
backlog, which assumed a generic mechanism that Windows does not provide.

## What the PoC proved

In the lab VM, `SetProcessMitigationPolicy(ProcessChildProcessPolicy, NoChildProcessCreation)` on a
process blocks every later `CreateProcess` from that process:

- `Start-Process notepad` → "The process creation has been blocked."
- ElectroRAT dropper `2a3b92f6…` → blocked; control run without the policy dropped
  `C:\ProgramData\3101f8f780\gbudn.exe`.

A Job Object with `ActiveProcessLimit=1` did **not** block the child in this environment (tested
twice), so it is not a usable primitive.

## Why a generic sandbox cannot be built from the guard hook

- The policy applies to the **calling process** (`SetProcessMitigationPolicy`), or to a new process
  through creation-time mitigation attributes — there is **no documented creation-time attribute
  for "no child processes"** on current Windows.
- A launcher that sets the policy on itself cannot then start the target (that is the child the
  policy blocks).
- The OpenCode guard is a pre-tool hook inside the agent process; it does not create the shell that
  runs `bash` commands, so it cannot apply the policy to that shell.
- Applying the policy to the agent itself would break every legitimate tool.

Conclusion: a universal "run any command, but it may not spawn children" is not achievable without
cooperating code in the process that runs the command.

## What is achievable and worth building

### A. Containment for Axiom-owned runners (where the policy can be applied)

If Axiom starts the process that executes a tool command (its own runner or a future sandbox host),
that runner can enable `NoChildProcessCreation` **before** handing control to a single command.
This is useful only for commands that legitimately need no children; the runner needs an allowlist
and a fallback ("cannot sandbox, run normally/ask").

### B. Process-creation audit and response (detection, not prevention)

Axiom Service can subscribe to process-creation events (ETW `Microsoft-Windows-Kernel-Process` or a
WMI `Win32_ProcessStartTrace` watcher), match the parent chain against known agent processes, and:

- record "agent spawned <path>" as a protected event and a graph finding;
- alert in the UI;
- optionally terminate on a policy match (dangerous; needs an explicit setting).

This closes the visibility gap seen with ElectroRAT: a direct child of an agent tool would at least
be recorded, unlike today.

### C. Per-process egress control (the highest-value control)

Axiom already owns firewall rules. A WFP filter keyed to the agent/tool process (app ID or process
path) can block outbound traffic for processes spawned by the agent, except an allowlist. Even if a
dropper runs, its C2 cannot connect. This works for IP-based C2, which the DNS shield cannot see.

### D. Execution gate (already partly present)

The guard blocks remote-download-and-execute shapes. A next step is to require a hash allowlist
before executing binaries from `Downloads`, `Temp`, or the workspace, and to record a finding when
a downloaded file is executed.

## Recommended scope for the F-19 release

Ship **B + C** first; they are implementable in Axiom's own service and provide real protection for
the ElectroRAT scenario. Add **A** only for Axiom-owned runners and with an allowlist. Do not market
any of this as a kernel sandbox; report it as `HostHook`/`Audit` plus per-process egress.

## Test plan (after the owner installs a build)

1. Live: start an agent tool command that spawns `notepad`; expect a recorded process event.
2. Live: spawn a process that attempts an outbound connection; expect the WFP block when the
   egress policy is enabled.
3. Re-run the ElectroRAT dropper inside the VM with the policy on; expect no C2 connection and a
   recorded spawn event (drop may still occur).
4. Negative controls: `git status`, `dotnet build`, plain HTTPS GET must still work.

## Lab integrity note

During the 0.34.0 verification the installed bridge in the VM was replaced with the generated
0.34.0 bridge; the original 0.30.0 copy is at `C:\Lab\bridge-backup-030.py`. Before the next live
verification round, the owner should install the current release so the VM returns to a known
build.
