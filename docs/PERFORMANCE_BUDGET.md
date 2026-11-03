# Performance budget and measurements

The numbers below are measurements from the development host, not guarantees. Re-run
`scripts\measure-performance.ps1` on the target machine before making a release claim.

## Targets (from the product specification)

| Metric | Target |
|---|---|
| Service idle CPU | around < 1% total |
| Service working set | < 150–200 MB |
| UI working set while open | target below 200 MB additional |
| Chart rendering | at most 1–4 Hz, not per event |
| SQLite writes | batched every 1–5 s |
| Event queue | bounded, with a visible loss counter |
| No-UI mode | no WPF/GPU process; service keeps monitoring |

## Method

- Host: Windows 10 IoT Enterprise LTSC 2021, 10.0.19044, x64.
- Build: `Release`, self-contained UI, service in console mode.
- Warm-up: 10 s after the UI connected to the service.
- Sampling: 60 s, one sample every 2 s.
- CPU: process `TotalProcessorTime` delta divided by wall time and logical processor count, so the
  value is a share of the whole machine.
- Memory: process working set, peak over the samples.
- Command: `.\scripts\measure-performance.ps1 -Seconds 60 -IntervalSeconds 2`.
- Raw CSV: `artifacts\performance\netpetra-<timestamp>.csv` (gitignored).

## Measured (2026-11-03)

| Process | Average CPU | Peak working set |
|---|---|---|
| `Netpetra.Service` (console, polling 1 s, SQLite writer) | **0.35%** | **78.6 MB** |
| `Netpetra.Desktop` (UI, service mode, ~300 sockets) | **0.47%** | **229.2 MB** |

Interpretation:

- The service is comfortably inside the CPU and memory targets for this workload.
- The UI CPU is low, but its working set is about 29 MB above the 200 MB target. The baseline is
  dominated by the WPF/.NET runtime and the self-contained deployment; row count is small. This is
  recorded as an open optimization item, not hidden.
- Measurements include only the read-only inventory and the local history writer. ETW byte
  accounting is not implemented, so its cost is not included.

## Not measured

- ETW collection and event-loss overhead (FND-004, requires elevation).
- 10,000-row table stress and frame time.
- 24-hour soak, sleep/resume, VPN/WSL and multi-monitor DPI.
- Firewall rule writes (FND-006, requires a VM).
- GPU usage; the UI uses WPF rendering only.

## Reproduce

```powershell
.\scripts\publish-standalone.ps1
.\scripts\measure-performance.ps1
```

The script starts only the processes it measures and stops them afterwards. It does not require
administrator rights, change firewall rules or make network requests.
