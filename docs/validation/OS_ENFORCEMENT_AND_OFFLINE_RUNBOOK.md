# AXIOM 1.0 — Phases 4 & 5: OS Enforcement & Offline Continuity Validation Runbook

> **Principle:** A firewall API return code is `DenyRequested` (`HOST_DENY_SENT` / `DENY_REQUESTED`), **never** `OS_DENY_VERIFIED`. `OS_DENY_VERIFIED` requires an independent dual-destination network probe showing blocked traffic failed while a permitted control destination succeeded, followed by rule rollback verification.

---

## 1. Architecture & Truthful State Mapping Observed in Code

| Component | Source Implementation | Enforced State Transitions |
|---|---|---|
| **Scoped Agent Firewall Enforcer (`E4`)** | `src/Axiom.Service/AgentFirewallEnforcer.cs`, `src/Axiom.Core/Enforcement/AgentNetworkControl.cs` | `ApplyScopedBlockAsync` refuses community/public-feed origins without user consent (`AuditOnly`). After `FirewallRuleCoordinator.ApplyAsync`, read-back verification (`PresentInOs && MatchesSpec && EffectiveAction == Block`) emits **`DenyRequested`**. Only `VerifyDualDestinationCanaryAsync` (`BlockedEndpointDenied && PermittedControlEndpointSucceeded && OsRuleReadbackVerified`) emits **`OsDenyVerified`** with `ObservedSideEffect.Absent`. `RollbackTrackedRulesAsync` deletes tracked rules and verifies `!verify.PresentInOs`. |
| **Offline Blackbox & DKG Continuity** | `src/Axiom.Presentation/BlackboxLocalState.cs` | Independently separates `GuardAvailable`, `RulesetAvailable`, `SyncStale` (>6h), `DkgOffline`, `RulesetCorrupted`, `CuratorManifestStale`, and `KillListRefused`. Corrupted/missing `ruleset.json` explicitly reports degraded/unprotected state; never fakes healthy protection when dashboard (`9700`) or DKG (`7879`) stops. |
| **Privacy Shield DNS Fail-Safe** | `src/Axiom.Service/PrivacyDnsFailSafe.cs`, `src/Axiom.Infrastructure.Windows/Network/WindowsDnsRecoveryAdapter.cs` | Captures per-adapter IPv4/IPv6 DNS mode (`NameServer` registry override vs automatic DHCP). Stopping the resolver/service restores saved DNS or resets to DHCP so the host is never stranded offline. Service-crash recovery re-checks adapter state on startup. |

---

## 2. Reproducible VM Execution Protocol (`scripts/validate-vm-enforcement.ps1`)

> **WARNING:** Never run live firewall or adapter DNS mutation tests (`-ExecuteInIsolatedVm`) on a daily-driver host. Run the mutating checks only inside a disposable, elevated Windows 10/11 VM snapshot.

### Phase 4 Checks (WFP / Windows Firewall)
1. **Apply Scoped Rule & Verify Read-Back:** Apply an Axiom-owned outbound block rule scoped to a disposable test binary (e.g., temporary copy of `curl.exe` or PowerShell test helper) targeting disposable TEST-NET/loopback-alias IPv4 + IPv6 test listeners on local isolated ports. Verify via `Get-NetFirewallRule` + `Get-NetFirewallAddressFilter` + `Get-NetFirewallApplicationFilter`.
2. **Dual-Destination Proof:** Confirm traffic from that binary to the blocked IPv4/IPv6 endpoint fails (`BlockedEndpointDenied`), while traffic from the same binary to a non-blocked permitted control endpoint succeeds (`PermittedControlEndpointSucceeded`).
3. **Bypass / Lifecycle Probes:**
   - Restart the test executable (verify rule still enforces by normalized image path).
   - Replace/copy the executable to an alternate path (confirm honest boundary: per-path Windows Firewall rule does **not** follow a renamed/moved binary unless scoped or re-evaluated).
   - Restart `Axiom.Service` and verify Axiom-owned rules survive recovery and clean removal works.
4. **Rollback Proof:** Remove only the Axiom test rule and verify connectivity to the previously blocked endpoint recovers cleanly.

### Phase 5 Scenarios (Offline & Failure Recovery Verification Matrix)

| # | Scenario | Method (VM) | Required Honest Result |
|---|---|---|---|
| 1 | Internet disconnected after sync | Disable external VM NIC | `BlackboxLocalState` reports cached ruleset active for compiled local rules while signaling `DkgOffline` / offline state accurately |
| 2 | DKG node stopped | Stop `dkg` node while Blackbox guard stays installed | Local firewall, Privacy Shield cache, and `BlackboxLocalState` guard continue; DKG probe reports disconnected |
| 3 | Blackbox dashboard stopped (`127.0.0.1:9700`) | Stop `start-dashboard.py` | UI Agent Protection settles cleanly without stuck loading (`#284`); hooks continue evaluating local guard independently of UI/dashboard |
| 4 | Guard runtime missing/renamed | Temporarily rename `venv\Scripts\python.exe` in test copy | `AntigravityProtection.IsInstalled` / probes report unprotected / `FAILED_OPEN`, never `Protected` |
| 5 | Corrupted or missing `ruleset.json` | Point test home to invalid JSON `{` or empty dir | `RulesetCorrupted = true` / `RulesetAvailable = false`, never `synchronized` |
| 6 | Stale intelligence | Set `ruleset.json` / `authoritative-sync.json` timestamp > 6h old | `SyncStale = true` surfaced in state tokens & summary |
| 7 | Full offline reboot | Reboot VM offline with Axiom Shield / rules saved | Service startup recovers persisted rules & revalidates DNS state |
| 8 | Connectivity restored | Re-enable VM NIC | Sync resumes without wiping local rules, queues, or findings |
| 9 | Privacy Shield DNS service failure / kill | Kill `Axiom.Service` while Privacy Shield pointed adapter at `127.0.0.1` | On recovery / `Restore-DnsClientServerAddress` fail-safe, connectivity recovers and UI distinguishes network recovery from active DNS filtering |
| 10 | Interrupted upgrade | Run `Axiom-Setup.exe` and inspect `UpgradeDataGuard` backup/restore logs | Reporter key, DKG home, `hermes\blackbox`, and `Axiom` DB/JSONL history remain intact |
