# Test matrix — Axiom (FND-005)

Date: 2026-11-06. Host: Windows 10 IoT Enterprise LTSC 2021, 10.0.19044, x64.
SDK: 10.0.403. Configuration: `Release`.

## 1. Automated checks (executed)

| Command | Result |
|---|---|
| `dotnet restore Axiom.sln --locked-mode` | passed (also after standalone publish) |
| `dotnet build Axiom.sln -c Release --no-restore` | **0 warning(s), 0 error(s)** |
| `dotnet test Axiom.sln -c Release --no-build` | **363/363 passed** |
| `dotnet publish src\Axiom.Desktop -p:PublishProfile=win-x64-selfcontained` | passed, 70.1 MB single EXE |

| Test project | Count | Notes |
|---|---|---|
| Core | 66 | deterministic rule identity, spec and CIDR/port validation |
| Contracts | 50 | IPC contract, limits, optional-module probe, bounded history, local file hashing, VirusTotal and community feed |
| Persistence | 14 | schema v2, history, firewall state and audit |
| Infrastructure.Windows | 40 | IP Helper, pipe, COM read-only adapter |
| Service | 16 | coordinator with a fake adapter, Privacy Shield rollback and persistence |
| MCP server | 33 | endpoint parsing, private IPv4/IPv6, indicator type, invalid-input handling, truthful unavailable states |
| UI | 137 | view models, settings stores, lifecycle hook contracts, Codex trust hashes, session readers, OpenCode lifecycle generation, ZCode/DeepSeek hook generation, firewall defaults and display status |

### History coverage

- `Initialize_creates_schema_version_two` — schema version 2.
- `Upsert_and_query_round_trip_utc_timestamps` — UTC round-trip.
- `Repeated_upsert_updates_last_seen_without_duplicating` — upsert semantics.
- `Search_matches_app_path_remote_and_pid` — parameterized search.
- `Time_window_and_paging_are_applied` — range, limit/offset, total.
- `Retention_removes_old_flows_and_orphan_apps` — 30 days.
- `Corrupt_database_is_moved_aside_and_recreated` — `.corrupt-*` + recreate.

### IPC coverage

- DACL allow/deny, SID rejection, `unknown_command`, `not_supported`, oversized request.
- **Snapshot larger than 256 KiB** (3000 rows) delivered through the 4 MiB response limit.
- Buffered line reader (16 KiB) — no byte-by-byte reads.

### Firewall coverage (FND-006)

- COM read-only: capability `Available`, owned-rule listing and unknown-rule verification against
  the real Windows Firewall on this host.
- Write gate: `UpsertOwnedRuleAsync` throws `NotSupportedException` without both gate variables; a
  test confirms no rule is created.
- Coordinator with a fake adapter: success stores `Applied` + 2 audit rows; failure stores `Failed`
  with the error; invalid spec never calls the adapter; remove deletes state + audit; verify reads
  the adapter state.
- `rules.query` over the pipe returns capability, owned rules and `WritesEnabled=false` by default.
- `rule.apply` is rejected with `not_supported` when the gate is closed.
- CIDR/IP and port scope validation: IPv4/IPv6 addresses, prefix bounds, wildcard-only semantics, the 32-address cap, TCP/UDP-only ports, 1–65535 single ports and ascending ranges.

### Optional module coverage (FND-011/012 status)

- DKG: loopback `/api/status` success is `CONNECTED` with version/peer/role; refusal is `NOT RUNNING`.
- Blackbox: loopback dashboard response is `CONNECTED`; missing graph status is still reported as running.
- A non-loopback endpoint returns `UNAVAILABLE` without sending a request.
- The probe never installs, starts or controls a module.
- The activity strip uses a 30-sample bounded history; a test confirms the oldest sample is dropped.
- Local file scan: known SHA-256 value and oversized-file skip are tested; hashes never leave the process.
- VirusTotal client: hash-only URL, `x-apikey` header, stats parsing, 404 and invalid-hash rejection are tested.
- Community feed: HTTPS-only URL, bearer header, valid SHA-256 entries and invalid-entry filtering are tested.

### MCP foundation coverage (PR A)

- MCP over stdio: `initialize` and `tools/list` were executed against the built server; nine
  read-only tools were advertised.
- `tools/call` for `axiom_get_threat_alerts`, `axiom_get_reputation`, `axiom_get_status` and
  `axiom_list_connections` returned structured JSON. With the service stopped, status and
  connections returned `UNAVAILABLE`; the process did not crash and stdout stayed JSON-RPC only.
- A raw JSON-RPC harness was run against a temporary console service (separate
  `AXIOM_DATA_DIR`, stopped afterwards): status, current connections, history and report returned
  real observations with limitations attached.
- Unit tests cover endpoint host/port parsing (IPv4 and bracketed IPv6), private/loopback/ULA
  classification, SHA-256 indicator inference, invalid date rejection, missing-selector rejection,
  and truthful `UNAVAILABLE` alert/reputation responses.
- **NOT RUN:** a real MCP client (OpenCode/another agent), a full model-driven investigation, or any
  action against a live protected host. No MCP client configuration was written.

## 2. End-to-end checks (executed)

Service in console mode + published standalone UI with `--service`.

| # | Check | Result | Evidence |
|---|---|---|---|
| E01 | Service creates the database and writes flows | ✅ 1.1 MB after ~1 min | `svc-h*.log` |
| E02 | Events shows real rows | ✅ 1000 of 3607 flows | `fnd005-history.png` |
| E03 | Search and ranges work | ✅ tests + manual | — |
| E04 | Service stop → UI `Service unavailable` | ✅ | `fnd003-service-offline.png` |
| E05 | Service restart → history survives | ✅ 4229 flows after restart | `fnd005-history-after-restart.png` |
| E06 | Reconnect without restarting the UI | ✅ | `fnd003-service-recovered.png` |
| E07 | Standalone EXE (no SDK) | ✅ | all screenshots |
| E08 | CSV export | ⚠️ code + escaping; dialog not automated | — |
| E09 | Navigation exposes Overview, Connections, Applications, Events, Agents, Firewall, Security, Privacy Shield, AI Analyst, Support and Settings; Agents sits above Firewall | PASS | `agents-nav.png`, `agents-page.png`, `security-no-agents.png` |
| E10 | The redundant Files tab is absent; the working local SHA-256 scan remains on Security and background tracking is explicitly disabled | PASS | `security-local-scan.png` |
| E11 | Connections shows the unknown country placeholder | ✅ | `fnd006-connections.png` |
| E12 | Overview 5m chart shows `LIVE COUNTERS` from timestamped system-wide interface samples; longer ranges show an explicit unavailable state; markers use first-seen time | ✅ | `traffic-live2.png` |
| E13 | Firewall page reads capability `Available`, 0 owned rules and write path `disabled` | ✅ no rule changed | `axiom-firewall.png` |
| E14 | Gate-open service: Applications block buttons enabled, Firewall shows `TEST VM` and write path enabled; no click | ✅ 0 owned rules after | `axiom-applications-writes-enabled.png`, `axiom-firewall-writes-enabled.png` |
| E15 | Advanced scope panel: protocol, ports, CIDR/addresses and profile checkboxes; block buttons disabled with the gate closed | ✅ no rule written | `axiom-applications-scope-expanded.png` |
| E16 | Security page probes a mock DKG node on loopback and shows `CONNECTED` with version/peer/role; Blackbox stays `NOT RUNNING`; no module started | ✅ loopback-only | `axiom-security-connected.png` |
| E17 | Security page shows Install for a non-connected module, Restart Axiom, and the last-30-checks activity strip; installer not clicked | ✅ no installer run | `axiom-security-install-activity.png` |
| E19 | Uninstall button visible for an installed Blackbox; cleanup is scoped to its folder/shortcut/`.hermes\blackbox`/scheduled task | ✅ no uninstall clicked | `axiom-uninstall-button.png` |
| E20 | Audit and Block buttons visible next to installed Blackbox; switching wrote `plugins.entries.blackbox.mode` and restored audit | ✅ config only | `axiom-audit-block-buttons.png` |

## 3. FND-005 definition of done

| Requirement | Status |
|---|---|
| Migrations | ✅ schema v1 + checksum |
| Batch writes | ✅ every 2 s, not per poll |
| Aggregations | ⚠️ flow queries; `traffic_buckets` prepared (FND-004) |
| Retention | ✅ 30 days, hourly check |
| Query/paging | ✅ UTC range, search, limit/offset, total |
| CSV | ✅ UTF-8 BOM + escaping (dialog manual) |
| Reboot/restart persistence | ✅ service restart; reboot not tested |
| Timezone | ✅ UTC in storage, local in UI |
| 64-bit counters | ⚠️ columns exist; bytes not measured until FND-004 |
| Cleanup | ✅ retention + orphan apps |
| Corrupt DB recovery | ✅ tested |

## 4. FND-006 firewall (code complete; VM verification pending)

| Requirement | Status |
|---|---|
| COM adapter with STA executor | ✅ read-only paths tested |
| Exact `Axiom::{id}::{OUT|IN}` names, no wildcard | ✅ |
| Two-variable write gate | ✅ tested refusal |
| Coordinator pending/applied/failed + audit | ✅ fake adapter tests |
| UI block/unblock/remove | ✅ code; disabled unless `WritesEnabled=true` |
| Real block of a test app (T08/T09) | ❌ NOT RUN — requires an isolated VM |
| Zero rule changes on this host | ✅ 0 owned rules before/after |

## 5. FND-004 (ETW) — blocked

`logman create trace -p Microsoft-Windows-Kernel-Network` returns **Access is denied**; the process
is UAC-filtered (`BUILTIN\Administrators` is deny-only) and has no `SeSystemProfilePrivilege`.
Therefore:

- No ETW collector is implemented; there are no per-process byte claims.
- The 5m chart uses timestamped system-wide interface counters (`LIVE COUNTERS`); longer ranges
  show an explicit unavailable state, never simulated history.
- Per-process verification moves to an elevated session or a VM.

## 6. Scenario matrix (§13)

| ID | Scenario | Status |
|---|---|---|
| T01 | TCP IPv4 | ✅ |
| T02 | TCP IPv6 | ⚠️ read; no controlled IPv6 test |
| T03 | UDP/QUIC | ⚠️ endpoints; remote/direction unknown |
| T04 | 1000 short connections | ❌ |
| T05 | Loopback LLM | ✅ |
| T06 | GPU + throughput | ❌ |
| T07 | VPN/NIC | ❌ |
| T08/T09 | Firewall block | ⚠️ write path exists; real block NOT RUN (VM) |
| T10 | EXE replaced | ⚠️ path only, no hash |
| T11 | GPO conflict | ⚠️ read-only listing; conflict not tested |
| T12 | Service killed / UI closed | ✅ |
| T13 | Restart/reboot | ✅ service restart; reboot ❌ |
| T14 | Uninstall | ❌ FND-009 |
| T15 | Unprivileged IPC | ✅ ACL/SID (real second account ❌) |
| T16 | Large/malformed IPC | ✅ limits + 1.5 MB snapshot test |
| T17 | 5157 audit | ❌ FND-007 |
| T18 | DoH | ❌ FND-010 |
| T19 | Windows update/DNS | ⚠️ no rule applied on this host |
| T20 | Sleep/resume | ❌ |

## 7. Not run (explicit)

- Real Windows Firewall block/allow behaviour and external-rule conflicts (T08/T09/T11) — requires
  an isolated VM and the explicit write gate.
- ETW/bytes (FND-004) — no privileges.
- Windows service installation, service account, ProgramData ACL (FND-009).
- A real second Windows user.
- Windows 11, 24 h soak, stress, reboot.
- CSV dialog through UI automation.
- Installer/signing.

## 8. Reproduction

```powershell
dotnet restore Axiom.sln --locked-mode
dotnet build Axiom.sln -c Release --no-restore
dotnet test Axiom.sln -c Release --no-build
.\scripts\run-service.ps1
```
