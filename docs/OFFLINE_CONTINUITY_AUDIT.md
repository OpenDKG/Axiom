# Axiom × Agent Blackbox — Offline Runtime Continuity & DKG Independence Audit

**Repository:** `a-51-50/Axiom`  
**Related:** Roadmap `#324`, Draft PR `#318` (`fix/agents/module-prerequisite-bootstrap`), [Enforcement Tracker](ENFORCEMENT_TRACKER.md), [Upstream Collaboration RFC](UMANITEK_UPSTREAM_COLLABORATION_RFC.md)  
**Priority:** P1 — AI Protection Reliability  
**Audit Date:** 2026-11-14

---

## 1. Architecture Dependency Audit

### 1.1 Upstream Agent Blackbox Runtime & Detector Map

Audited against the installed upstream Blackbox package under `%LOCALAPPDATA%\Axiom\modules\blackbox\agent-blackbox\plugins\blackbox`:

| Detector / Capability | Source Function / Module | Offline Without DKG? | Hot-Path Network? | Notes / Observed Live State |
|---|---|---|---|---|
| **Protected file paths** (`.ssh/*`, `.env`, `*.pem`, `*.key`, `hermes/blackbox/*`) | `detection/paths/protected.py::detect_custom_fileaccess` called by `guard/hooks.py::_raw_findings` | **Yes (100% local)** | **No** | Tagged `source="custom"`, blocks in `block` mode (`_would_block`). Matches user/default `protected_paths` in `kernel/config.py`. |
| **Trader Shield** (wallets, browser extensions, operator keys) | `shields/trader/detectors/{app_folder,browser_extension,firefox_map,own_keys}.py` via `shields.check` | **Yes (100% local)** | **No** | Blocks when shield mode is `block`. |
| **Secret exposure & key misdirection** (Solana Ed25519, Bitcoin WIF/xprv, EVM secp256k1, headers) | `detection/secrets_handled/exposure.py::{detect_secret_exposure,detect_exchange_key_misdirection}` + `guard/hooks.py::on_pre_api_request` | **Yes (100% local)** | **No** | **Windows CRLF caveat discovered:** `kernel/crypto_secrets/seed_phrase.py` pins LF SHA-256 (`2f5eed53...`), while `bip39_english.txt` cloned on Windows with CRLF is `15,164` bytes (`3b2c7274...`), causing upstream `seed-phrase detection is OFF`. |
| **Keychain access & built-in heuristics** | `detection/paths/keychain.py`, `detection/detectors.py::detect_all` | **Yes (100% local)** | **No** | Heuristic shell shapes and discovery findings (`source="heuristic"`, flag-only). |
| **Compiled small verified tiers** (`injection`, `skill`, `escalation`, `fileaccess`, `graph_threats`, `kill_list`, `community`) | `ruleset/refresh_cycle.py::get` → `ruleset/disk_cache.py::_read_cache` → `ruleset/memory_cache.py::RulesetCache` | **Yes (after 1st sync)** | **No** | Persisted in `%LOCALAPPDATA%\hermes\blackbox\ruleset.json` via atomic `.tmp` swap (`disk_cache.py`). Observed live on host: `135` `graph_threats` (`103` `injection`, `32` `skill`). |
| **Large verified tiers (`dependency`, `ioc`)** (`DKG-lookup B6`) | `ruleset/live/answering.py::LiveAnswering` → `ruleset/live/lookup.py::VerifiedLookup` → `kernel/store/client.py::StoreClient` | **Only with `verified_lookup_fallback: "index"`** (defaults to `"off"`) | **Localhost only (`127.0.0.1:7879`)** | Observed live on host: `252,860` `dependency` + `856,005` `ioc` (`1,108,865` rules across `1,111` assertion graphs) are **not** stored in `ruleset.json`; queried live from local Oxigraph (`2.0s` timeout, `10.0s` degraded circuit breaker). When store is down and `fallback: "off"`, fails open with `"verified lookups degraded — timeout"`. |
| **Background discovery / OSV / LLM review** | `guard/background.py` (`daemon=True` threads in `on_pre_tool_call`) | N/A | **Off hot path** | Spawned on daemon threads; never blocks `on_pre_tool_call`. |
| **Blackbox FastAPI Dashboard (`127.0.0.1:9700`)** | Guard `hooks.py` never calls port `9700` | **Yes (independent)** | **No** | Guard initializes and runs with dashboard stopped. |

### 1.2 Persisted Local Cache Properties (`ruleset.json`)

- **Atomicity & Corruption Resistance:** Written via temporary `.json.tmp` file + atomic replace (`ruleset/disk_cache.py`). Empty/failed refreshes preserve the last non-empty ruleset (`ruleset/refresh_cycle.py`).
- **Scope, Provenance & Revocation:** Scoped by `context_graph_id`, owner-pinned against wallet spoofing (`KI-106` in `ruleset/graph_queries.py`), envelope-checked (`ruleset/live/scope.py`), and tracks `curator_revoked`, `curator_manifest_state`, and `kill_list_refused` (`guard/hooks.py` + `killlist`).
- **Reboot Survival:** Persisted on disk in `%LOCALAPPDATA%\hermes\blackbox\ruleset.json`; survives machine reboots offline without needing the dashboard or internet.

### 1.3 Axiom Integration State (`main` + Draft PR `#318`)

- **Local State & Continuity:**
  - `Axiom.Presentation.BlackboxLocalState` and `Axiom.UI.Services.BlackboxLocalState` read `ruleset.json`, `authoritative-sync.json`, `sync_progress.json`, and `verified_lookup_state.json`.
  - `Axiom.Presentation.DkgContextAnnotator.LoadFromLocalCache` provides read-only `O(1)` IP/host graph annotations with a `6`-hour `DefaultStaleThreshold` (`EnforcesBlock => false`).
- **Enforcement & Receipt Chain:**
  - `Axiom.Core.Enforcement.{EnforcementPolicyEvaluator,EnforcementController,HostEnforcementAdapter}` and `Axiom.Contracts.Blackbox.AgentProtectionClassifier` keep OS enforcement and receipt logging (`DETECTED`, `GUARD_UNAVAILABLE`, `AUDIT_ONLY`, `DENY_REQUESTED`, `HOST_DENY_SENT`, `HOST_DENY_VERIFIED`, `OS_DENY_VERIFIED`, `UNVERIFIED`, `FAILED_OPEN`) independent of DKG availability.
  - Note: OpenCode pre-tool prompt-injection blocking and file-argument normalization (`filePath` -> `path`, exec/upload verb blocking) reside on Draft PR `#318` (`OpenCodeProtection.cs`, `ProtectionProvisioner.cs`, `AgentProtectionSelfTest.cs`, `DkgHomeResolver.cs`, `HermesPluginSettings.cs`).

---

## 2. Offline Test Matrix & Verification Results

All .NET tests (`Axiom.sln` across all 9 test assemblies) and isolated temporary-profile Python guard probes ran on Windows 11 with zero mutations to production `reporter_key.pem`, live `hermes` config, or community reporting. Destructive VM scenarios (full network disconnect, mid-session DKG kill, and full offline OS reboot) are specified for the isolated Windows 11 `lab` VM.

| Scenario | DKG Node | Internet | Host / Unit Verification Result | VM `lab` Status |
|---|---|---|---|---|
| **1. Initial installation before sync** | Available | Online | `EvaluateContinuity` reports `["GUARD_AVAILABLE", "UNPROTECTED"]` (`RulesetAvailable=false`, `TryReadSync` returns `null`). Verified by unit test. | Covered in `lab` checklist |
| **2. Successful synchronization** | Available | Online | Live host `ruleset.json` verified with `135` compiled threats + `1,108,865` `verified_scope.verified_counts` (`1,109,000` total). `TryReadSync` returns `synced`. Verified by unit tests. | Covered in `lab` checklist |
| **3. Internet disconnected, DKG running** | Available locally | Offline | All unit checks pass beyond old `10m` window (`45m` offline -> `RULESET_AVAILABLE=true`, `SyncStale=false`). Upstream `on_pre_tool_call` makes zero external blocking calls. | Pending live `lab` disconnect |
| **4. DKG process stopped** | Stopped | Online | Isolated Python guard probe against closed port `127.0.0.1:59999`: first call tripped `StoreClient` (`2,171.7 ms`, wrote `verified_lookup_state.json: degraded/timeout`); subsequent calls ran in `7.7–8.5 ms`. `EvaluateContinuity` reports `GUARD_AVAILABLE`, `RULESET_AVAILABLE`, `DKG_OFFLINE`. | Pending live `lab` kill |
| **5. DKG stopped & internet disconnected** | Stopped | Offline | `EvaluateContinuity` keeps `RULESET_AVAILABLE=true`, `IsUnprotected=false`, marks `DKG_OFFLINE=true` and `SYNC_STALE=true` after `6h`; `DkgContextAnnotator` sets `IsStaleCache=true`. | Pending live `lab` kill + net off |
| **6. Full reboot while offline** | Stopped | Offline | Simulated by deleting `authoritative-sync.json` while keeping `ruleset.json`: `TryReadSync` and `TryReadGraph` recover `1,108,867` verified rules and `CategoryTotals` (`dependency=252,860`, `ioc=856,005`). | Pending `lab` reboot test |
| **7. Dashboard (`9700`) unavailable, guard running** | Any | Any | Fixed `SecurityPageViewModel` and `SecurityViewModel` so `RefreshAgentsAsync` uses `BlackboxLocalState.EvaluateContinuity()` instead of failing agents to `OFFLINE` when port `9700` is stopped. Also verified live host hook actively blocked a synthetic `.env` path command (`injection:39d87d23ad43971ade30d025`). | Pending live `lab` E2E run |
| **8. Corrupted or missing ruleset** | Any | Offline | Corrupted `ruleset.json` returns `RulesetCorrupted=true`, `IsUnprotected=true`, `"UNPROTECTED"`, and `TryReadSync.State="unavailable"` with `VerifiedRules=0` even if `authoritative-sync.json` is fresh. Python guard fails-open cleanly in `14.9 ms` on benign read. | Covered in `lab` checklist |
| **9. Expired / revoked / stale manifest rules** | Any | Offline | `curator_manifest_state: "STALE ..."` and `kill_list_refused` surface explicitly in `EvaluateContinuity().Summary` and `TryReadSync().PhaseText`. | Covered by unit tests |
| **10. Connectivity restored** | Available | Online | Upstream `refresh_cycle` resyncs without corrupting last-known-good `ruleset.json` and resets `verified_lookup_state.json` to `"ok"`. | Pending live `lab` reconnect |

---

## 3. Gap Analysis

### Already Working
- Upstream `guard/hooks.py` (`on_pre_tool_call`) reads cached rules from disk/memory cleanly without requiring the FastAPI dashboard (`9700`) or internet access.
- Atomic `.tmp` ruleset replacement and empty-refresh preservation prevent partial downloads from wiping working rulesets.
- Axiom's `EnforcementController`, `HostEnforcementAdapter`, `EnforcementReceiptV1`, `AgentProtectionClassifier`, and `DkgContextAnnotator` keep OS enforcement and receipt integrity independent of DKG node connectivity.

### Broken / Conflated (Fixed in This Audit Remediation)
1. **10-minute false expiry in `BlackboxLocalState.TryReadSync`:** Returning `null` whenever `authoritative-sync.json` exceeded `10` minutes wiped `VerifiedSyncState` during normal `60`-minute sync intervals, offline periods, and post-reboot recovery, and nulled `_snapshotUtc` in `DkgContextAnnotator.LoadFromLocalCache`.
2. **False `"synced"` report on corrupted/missing `ruleset.json`:** Previously `TryReadSync` only read `authoritative-sync.json`, ignoring whether `ruleset.json` was missing or corrupted.
3. **Ignored `verified_scope.verified_counts` in `TryReadGraph`:** Without `authoritative-sync.json`, graph totals omitted `dependency` (`252,860`) and `ioc` (`856,005`).
4. **Dashboard Port `9700` Conflated with Guard Protection (`SecurityPageViewModel` / `SecurityViewModel`):** Stopping the dashboard UI port `9700` marked every hooked agent `OFFLINE` (`"detected agents are not protected"`) even when the guard runtime and `ruleset.json` were active.

### Unverified (Queued for Isolated Windows 11 `lab` VM)
- Live host-refusal canaries (actual file read/overwrite blocked vs absent side effect, exec/upload verb bypass tests, prompt-injection session quarantine) inside OpenCode/OpenChamber with `DKG` killed mid-session and after full offline reboot on Draft PR `#318` + `main` fixes merged together.
- Gateway dependency (`aiohttp.web`) in `lab` VM when testing `hermes blackbox` CLI gateway end-to-end.

### Upstream-Dependent (`umanitek/agent-blackbox`)
1. **`DKG-lookup B6` Default `verified_lookup_fallback: "off"`:** Over `1.1M` verified `dependency` + `ioc` rules are excluded from `ruleset.json` and require `127.0.0.1:7879` unless `verified_lookup_fallback: "index"` (`verified_index.sqlite`) is enabled.
2. **Windows CRLF Breaking Pinned `bip39_english.txt` SHA-256:** Git checkout CRLF conversion silently disables BIP-39 seed-phrase detection on Windows (`3b2c7274...` vs `2f5eed53...`).

---

## 4. Minimal Remediation Implemented in Axiom

1. **`src/Axiom.Presentation/BlackboxLocalState.cs` & `src/Axiom.UI/Services/BlackboxLocalState.cs`:**
   - Added `BlackboxContinuityReport` and `EvaluateContinuity(...)` implementing distinct tracking for `GUARD_AVAILABLE`, `RULESET_AVAILABLE`, `SYNC_STALE`, `DKG_OFFLINE`, and `UNPROTECTED`, plus corruption, missing-ruleset, stale curator manifest, and refused kill-list detection.
   - Updated `TryReadSync` to preserve valid cached `ruleset.json` across offline periods (`> 10m` and `> 6h`) and post-reboot recovery while explicitly flagging corrupted/missing rulesets as `unavailable` with `0` verified rules.
   - Updated `TryReadGraph` to aggregate `verified_scope.verified_counts` (`dependency`, `ioc`).
2. **`src/Axiom.UI.Avalonia/SecurityPageViewModel.cs` & `src/Axiom.UI/ViewModels/SecurityViewModel.cs`:**
   - Decoupled `RefreshAgentsAsync` from dashboard port `9700` using `BlackboxLocalState.EvaluateContinuity()`, preserving accurate agent hook status when only the dashboard is offline and surfacing continuity warnings accurately when the guard or ruleset is unavailable.
3. **`tests/Axiom.Presentation.Tests/BlackboxLocalStateTests.cs` & `tests/Axiom.UI.Tests/BlackboxLocalStateTests.cs`:**
   - Added unit coverage for pre-sync `UNPROTECTED`, `> 10m` cache preservation, `> 6h` `SYNC_STALE` + `DkgContextAnnotator` integration, offline reboot recovery without `authoritative-sync.json`, corrupted `ruleset.json` honesty, and stale-manifest / kill-list-refused warnings.
   - Verified with `dotnet test Axiom.sln --nologo`: **all 9 test assemblies passed (`808/808`, `0` failed, `0` skipped)**.

---

## 5. Proposed Upstream RFC (`umanitek/agent-blackbox`)

1. **Enable Bounded Local Fallback Index (`verified_lookup_fallback: "index"`) by Default (or Config-Free Auto-Warm During Sync):**
   - Blackbox already ships `ruleset/live/fallback_index.py` (`verified_index.sqlite`) to answer `dependency` and `ioc` lookups offline when `127.0.0.1:7879` is stopped. Enabling `verified_index.sqlite` automatically once an initial verified sync completes eliminates the `1.1M`-rule blind spot and `2.0s` first-call store timeout during offline operation while keeping the DKG node as the authoritative sync source.
2. **Pin LF Line Endings or Normalize Line Endings for `bip39_english.txt` Hashing:**
   - Either add `.gitattributes` (`plugins/blackbox/kernel/crypto_secrets/bip39_english.txt text eol=lf`) or strip `\r\n` before computing the SHA-256 integrity check in `seed_phrase.py` so Windows installations do not silently disable BIP-39 seed-phrase protection.
