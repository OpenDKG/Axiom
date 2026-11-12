# PR #274 — prepared replies to the review of 2026-11-12 (not posted)

Branch `buba/macos-desktop`, base merged to v0.13.2 (`79f4ff3`). Commits: `b200c00` (P0 #1), `7b2a95b` (P0 #2, P0 #3,
High #4 — one logical change: the enforcement state machine), `5dd4532` (Medium #5), plus the docs commit.

## Inline replies

### `src/Axiom.Infrastructure.MacOS/Ipc/PeerAuthorization.cs:99` (P0 #1)

Fixed in `b200c00`. The read tier that admitted any uid ≥ 501 is gone. Commands are now classified in exactly one
of PublicRead (`serviceHealth` redacted to status/version/uptime/contract, `capabilities`), PrivateRead (`snapshot`,
`live.events`, `history.query`, `traffic.history`, `rule.verify`, `rules.query`, `diagnostics.export`, `privacy.status`,
`config.get`, `protection.status`, `threatshare.status`) or Write (everything else; an unlisted command counts as a
write — enforced by a reflection test over `IpcCommandTypes`). `PeerAuthorization.Decide(uid, policy)` is a pure
function: root (documented privileged policy) and the installing uid (`protection.json AllowedUid`) get private reads
and writes, `admin` members only with `AllowAdminGroupWrites`, every other local account gets the public commands and
`unauthorized` for the rest, unknown/failed peer credentials are closed. The shared `IpcRequestDispatcher` denies by
class before any handler runs, so there is no handler that can leak. The socket stays 0666 because macOS has no group
the daemon can hand to "the installing user plus admins"; identity comes from `getpeereid` per connection and is
checked per command (documented in `docs/MACOS_ARCHITECTURE.md` §5.4). Tests: `PeerAuthorizationTests` (owner, admin
with/without the policy, other uid, root, unknown — over every private read and write),
`UnixSocketIpcTests.SecondStandardUserGetsPublicHealthOnlyOverTheSocket` (real Unix socket, peer uid 502 vs owner 501),
`IpcCommandAccessTests`. The Linux branch can take `Decide` unchanged.

### `src/Axiom.Infrastructure.MacOS/Filter/MacFirewallPolicyAdapter.cs:164` (P0 #2)

Fixed in `7b2a95b`. `UpsertOwnedRuleAsync` no longer reads success off the file it just wrote. It writes rules.json,
waits up to 2 s (`DefaultAckTimeout`) for the extension's `filter.rules` acknowledgement of that generation and then
reports exactly what was proven: `Applied` with `VerifiedUtc` = ack time only when the extension is connected and
acknowledged exactly the published generation without a file error and without listing the rule in `rejected`;
`Failed` with the filter's own reason (`filter.rule_rejected` / `filter.file_rejected`) otherwise; else `Pending` with
`ErrorCode` null and "awaiting AxiomFilter acknowledgement of generation N (never connected / disconnected / last
acknowledged G)". `ListOwnedRulesAsync` projects stored rules through the live snapshot, so a late ack flips a rule to
`Applied` without a re-apply and a disconnect flips it back to `Pending`; the shared `FirewallRuleCoordinator` stores a
`Pending` result as `Pending` (audit "pending"), never as `Applied`. Windows adapters never return `Pending`, so Windows
is unchanged. Tests: `FilterEnforcementLifecycleTests` (absent, connected without rules, older generation, correct ack,
delayed ack after the wait, rule rejected, file rejected, disconnect after enforce, removal while disconnected, daemon
restart, filter restart with a stale ack, pure `Outcome`), `FilterRulesTests`,
`FirewallRuleCoordinatorTests.Apply_pending_is_stored_as_pending_not_applied`. VM: `docs/MACOS_TEST_REPORT.md` AG–AK.

### `src/Axiom.Infrastructure.MacOS/Filter/MacFirewallPolicyAdapter.cs:393` (P0 #3)

Fixed in `7b2a95b`. `Verify` keeps `PresentInOs` (in rules.json) and `MatchesSpec`, but `EffectiveAction` is set only
under the same enforcement conditions as above (connected, exact generation acknowledged on this connection, no file
error, rule not rejected); otherwise it is null and the notes say why ("AxiomFilter has never connected", "disconnected
(last seen …)", "acknowledged generation G, not N", "rejected this rule: …"). `EffectiveRuleReport` gained
`EnforcementVerified` (bool?, null on Windows) so a client does not have to parse notes. Tests in
`FilterEnforcementLifecycleTests`; VM rows AG (verified → `block`), AH (rejected → null), AI (disconnected → null +
note), AK (reconnect → `block` again).

### `src/Axiom.Infrastructure.MacOS/Filter/FilterStatus.cs:215` (High #4)

Fixed in `7b2a95b`. `HasRecentHello`/`HelloLifetime` are removed. `FilterStatus` keeps `LastSeenUtc` (diagnostic),
`IsConnected` (live connection count), `AckedGeneration`/`LastAckUtc` (last `filter.rules` without error, tagged with
the connection it arrived on) and derives `Evaluate(published)` → `Unavailable` / `Degraded` / `Pending` / `Verified`.
A disconnect is `Degraded` immediately; a reconnect is `Pending` even if the hello repeats the current generation,
because the daemon republishes the table on every accepted filter connection (`FilterEventServer.ClientConnectedAsync`
→ `PublishAsync`), and only the fresh `filter.rules` for that generation verifies it — the Swift contract is unchanged.
`GetCapabilitiesAsync` reports `FirewallServiceRunning` = connected now and `Degraded` while disconnected;
`filterEnforcement` carries `state, connected, publishedGeneration, ackedGeneration, lastSeenUtc, lastAckUtc`; the
Firewall page shows "Filter: connected · generation N verified at hh:mm / pending acknowledgement" or "Filter:
disconnected (last seen hh:mm)" and a banner for every unverified state. Tests: `FilterEnforcementLifecycleTests`
(status block), `FilterRulesTests.CapabilitiesReportLiveConnectionNotRecentHello`,
`FilterEnforcementSummaryTests.Unverified_enforcement_is_a_banner_never_an_enforces_line`. VM rows AI, AJ
(`docs/screenshots/macos/firewall-degraded.png`), AK.

### `src/Axiom.Infrastructure.MacOS/Launchd/LaunchdServiceInstaller.cs:165` (Medium #5)

Fixed in `5dd4532`. The newsyslog entry is now `root:wheel 600`, and `MacLogPermissions.Enforce` makes
`/Library/Logs/Axiom` 0700 and `axiomd.log` plus every rotated archive 0600: the installer pre-creates the log 0600
before launchd opens `StandardOutPath` (launchd would otherwise create it 0644 under the default umask) and fixes an
older layout on upgrade; the daemon re-applies the modes at every start next to the data-directory hardening. The log
carries process names, paths and rule ids, never API keys or IPC payloads (reviewed). Tests: `MacLogPermissionsTests`
(create, fix archives, leave unrelated files, never truncate, idempotent), `LaunchdServiceInstallerTests` (install,
upgrade with a 0644 log and archive, uninstall keeps logs root-only). VM row AF: `drwx------ root:wheel`, uid 501
denied on `ls`/`cat`, conf shows `600`. A forced `newsyslog -F` rotation and the second-user `cat` were blocked by the
host's sudo guard on my side (row AL) — would appreciate a maintainer run of
`sudo newsyslog -F -f /etc/newsyslog.d/com.axiom.service.conf && ls -la /Library/Logs/Axiom`.

## PR comment (summary, handoff §13)

- Base: merged `origin/main` 6ff6061 (v0.13.2) as `79f4ff3`; one conflict (`AiAnalystPageViewModel.cs`) resolved
  keeping upstream's `_suppressApiKeyInputChanged` guard. No Windows behaviour changed (shared edits are gated on
  `RuleState.Pending`, which Windows adapters never return; `IpcCaller.FullAccess` unchanged).
- Findings: #1 `b200c00`, #2/#3/#4 `7b2a95b` (+ `7986b8f`: Firewall page re-queries the live state every 5 s), #5 `5dd4532`; design in `docs/MACOS_ARCHITECTURE.md` §5.4 (authorization
  table, why the socket stays 0666) and §5.7 (FilterStatus fields, lifecycle state machine, log modes); tick list in
  `docs/MACOS_REVIEW.md` "GitHub review 2026-11-12"; evidence rows AF–AL in `docs/MACOS_TEST_REPORT.md`;
  `docs/MACOS_PORT_REPORT.md` updated (base v0.13.2, authorization, lifecycle, Linux implications).
- Contracts: `FilterEnforcementState`, six new `FilterEnforcementReport` fields, `EffectiveRuleReport.EnforcementVerified`
  (null on Windows). `RuleState` unchanged.
- Gate (Linux, `-p:EnableWindowsTargeting=true`): `Axiom.sln` Release 0 errors / 0 warnings; Infrastructure.MacOS 199,
  Contracts 142, UI.Avalonia 40/41 (`HeadlessNavigationTests` flaky under parallel load, passes alone — pre-existing)
  pass; `Axiom.Portable.slnx` Release build 0/0; its tests: McpServer 33, Desktop.Avalonia.MacOS 35, Contracts 142,
  Presentation 93, Persistence 21, Infrastructure.MacOS 199, UI.Avalonia 41 pass, Core 117/128 (the 11 pre-existing
  Windows-path failures, identical on `origin/main`). `Axiom.Service.Tests` (net10.0-windows) has 11
  pre-existing Linux failures identical on the merge base (kernel32 / Windows paths); the new coordinator test is in
  that group and needs a Windows run.
- Still unverified: the second-standard-user IPC run and the forced newsyslog rotation on the VM (host sudo guard);
  Apple silicon; Developer ID signing.

## Review #2 (5874573617)

Prepared, not posted. Branch `buba/macos` on top of the reviewed head `fa12fe1`: `d0f8c92` (red tests), `ae418b9`
(MAC-1), `c1a4842` (MAC-2), `5e7b673` (MAC-1 follow-up found in the VM), plus the docs commit. Design:
`docs/MACOS_ARCHITECTURE.md` §5.7.1; tick list: `docs/MACOS_REVIEW.md` "GitHub review #2"; VM evidence:
`docs/MACOS_TEST_REPORT.md` rows AM–AR.

### MAC-1 — `src/Axiom.Infrastructure.MacOS/Filter/FilterStatus.cs` (`RulesReported` :323, `EvaluateLocked` :460), `MacFirewallPolicyAdapter.cs` (`Verify` :603)

Fixed in `ae418b9` and `5e7b673`; reproduced first by `d0f8c92` (9 of 11 red on `fa12fe1`).

- `FilterStatus` now keeps the **latest** `filter.rules` report as one record (generation, connection epoch, error,
  rejected ids, optional `ruleIds`, receivedUtc) instead of a sticky `_ackedGeneration/_ackEpoch`, plus the
  expected-rules snapshot the daemon published for each generation. `Evaluate(N)` is `Verified` only when the latest
  report arrived on the current connection, carries no file error and names exactly `N`. A later error report for
  the same generation revokes it, a reconnect invalidates the previous connection's report, `N-1` never verifies `N`,
  and only a new clean ack restores it.
- Per-rule proof: `FilterEnforcementSnapshot.RuleVerified` (:84) = generation verified ∧ rule id in the table
  published for it ∧ not rejected ∧, when the filter echoes `ruleIds`, listed (a disabled rule must *not* be listed).
  `ProjectState`, the apply outcome (`filter.rule_not_effective` → Failed, never Applied) and `rule.verify` (which also
  requires the on-disk rule to match the spec) use it.
- A connected filter whose latest report rejects the file makes `capability.status` `degraded`, with a reason that
  names the rejection (`5e7b673`; before that, the VM showed `available` and a note reading "acknowledged N, not N").
- Shared contract: AxiomFilter's `filter.rules` line gains an **optional, additive** `ruleIds` array (enabled compiled
  rules in force; omitted above 200 ids to keep a line under the daemon's 16 KiB limit). A missing field means
  "unknown" and the daemon falls back to its published snapshot + `rejected`, so an older extension keeps working.
- Tests (`tests/Axiom.Infrastructure.MacOS.Tests/FilterVerificationRegressionTests.cs`):
  `SameGenerationErrorReportAfterAck_RevokesVerified`, `CleanCurrentAckAfterError_RestoresVerified`,
  `PreviousGenerationAck_DoesNotVerifyThePublishedOne`, `PreviousConnectionAck_DoesNotSurviveReconnect`,
  `ExpectedRuleMissingOrMismatchedInTheAcknowledgedTable_IsNotVerified`,
  `RejectedRulesFileAfterAVerifiedApply_DegradesRuleAndOverallStatus`, `AcknowledgedTableThatDoesNotListTheRule_IsNotVerified`,
  `DisabledRule_IsVerifiedWhenTheFilterDoesNotEnforceIt`, `Parser_ReadsRuleIds_AndTreatsAMissingListAsUnknown`; Swift
  encoder check in `macos/Tests/main.swift`.
- VM (rows AM, AQ, AR): `chmod 664` on `rules.json` without changing its generation → `capability.status degraded`,
  `filterEnforcement.state pending` although `ackedGeneration == publishedGeneration`, rule `pending`,
  `rule.verify enforcementVerified false`; `chmod 644` → new clean report → `verified`, rule `applied`. Disable/enable
  sampled every ~350 ms: right after reconnect `pending, pub 1794372834, ack 1794372833` — the old ack did not count —
  then `verified` 0.4 s later.

### MAC-2 — `src/Axiom.Infrastructure.MacOS/Filter/MacFirewallPolicyAdapter.cs` (`RemoveCapturedOwnedRuleAsync` :436)

Fixed in `c1a4842`.

- Recovery removal now uses the same discipline as `RemoveOwnedRuleAsync`: publish the table without the captured
  rule (unrelated rules republished unchanged, no OS/user rules touched), wait a bounded, cancellable time for the
  extension's ack of that generation, then decide with the pure `RecoveryOutcome` (:502):
  - verified: clean current ack, rule absent from the published table and not echoed by the filter → `Success`,
    `Desired`, `VerifiedUtc` = **ack time** (never the clock);
  - pending: extension offline (`filter.disconnected`) or no clean ack yet (`filter.ack_pending`) → `Success=false`,
    `Pending`, actionable message (enable the extension, start the service, run Restore again);
  - failed: file rejected (`filter.file_rejected`) or the acknowledged table still lists the rule
    (`filter.rule_still_enforced`).
- `InspectOwnedRuleAsync` says `Absent` only when the removal is proven, so the shared `NetworkRecoveryController`
  lists the problem and never reports the network as restored. Retry is idempotent: a rule already gone from
  `managed-rules.json` is not rewritten; the outcome is re-derived from the current ack.
- Windows: the Windows adapter and `NetworkRecoveryController` are unchanged.
- Tests: `FilterVerificationRegressionTests` `RecoveryRemoval_ExtensionDisconnected_IsNotReportedVerified`,
  `_StaleGenerationReport_StaysPending`, `_RejectedRulesFile_IsNotReportedComplete`,
  `_RetryAfterReconnect_IsIdempotentAndVerifiedByTheAck`, `_NeverStampsVerifiedUtcFromTheClockAlone`,
  `_FilterStillListsTheRule_IsFailedNotVerified`; `tests/Axiom.Service.Tests/NetworkRecoveryControllerTests.cs`
  `Unverified_rule_removal_is_never_reported_as_restored_and_retry_completes`.
- VM (rows AN–AP): extension disabled → `networkRecovery.restore` → `partialFailure, verified false,
  rulesVerifiedAbsent 0`, problem `filter.disconnected` ("…removed from rules.json but the removal is not verified …
  may still be enforced …"); a second retry gives the same answer and writes no new generation; after
  `axiom-sysext enable` the third retry → `succeeded, verified true, rulesVerifiedAbsent 1`, curl HTTP 200.

### PR comment (summary for review #2)

Definition of done, honestly:

- [x] Same-generation rejected report cannot leave enforcement `Verified` — `ae418b9`/`5e7b673`, unit tests + VM AM/AQ.
- [x] Per-rule verification proves current effective state — `RuleVerified` (published table ∧ not rejected ∧ echoed
  `ruleIds` when present). Limit: an extension that does not send `ruleIds` (older build) is proven against the
  published snapshot + `rejected` list only.
- [x] Recovery removal never claims verified without filter acknowledgement — `c1a4842`, unit tests + VM AO/AP.
- [x] Disconnect, reconnect, stale generation, malformed/rejected file, timeouts (zero-timeout deterministic tests),
  rejection and retry are covered by tests (`FilterVerificationRegressionTests` 15, controller test).
- [x] IPC/privacy controls remain intact — no change to `PeerAuthorization`, `IpcCommandAccess` or log modes in this
  round; their tests still pass.
- [x] macOS build/test evidence and the limits are documented (`docs/MACOS_TEST_REPORT.md` AM–AR).
- [x] PR stays Draft; nothing merged.
- [ ] **Not done (needs the owner's Mac and an Apple Developer account):** SIP-enabled run, Developer ID signing and the
  Network Extension entitlement on a real team, notarization, Apple-silicon evidence, reboot/upgrade/uninstall on a
  clean install. All evidence above is from an Intel macOS 15.8.3 VM with SIP disabled and ad hoc signing — a
  development smoke test, not release validation.

Shared-contract change: `filter.rules` (AxiomFilter → daemon NDJSON) gains the optional `ruleIds` array; additive,
absent = unknown. No change to `Axiom.Contracts` DTOs or `RuleState` in this round.

Behaviour change: offline `sudo axiomd --recover-network --apply` on macOS (service stopped) has no filter connection,
so it can no longer report an Axiom rule removal as done. It removes the rule from the table, reports the item as
unverified (`filter.disconnected`) and tells the user to enable the extension, start the Axiom service and run
Restore network settings again; the DNS/adapter part of the recovery is unaffected.

Gate: see "Gate (review #2)" below.

### Gate (review #2)

Linux host, `-c Release -p:EnableWindowsTargeting=true`, at `031fda7` (code identical to `5e7b673`; `d657fd9` only
restores the `net10.0/win-x64` lock sections that `5e7b673` dropped by accident):

- `Axiom.sln` build 0 warnings / 0 errors; `Axiom.Portable.slnx` build 0 / 0.
- Pass: Infrastructure.MacOS 214/214, Desktop.Avalonia.MacOS 35/35, Presentation 93/93, UI.Avalonia 42/42,
  Contracts 142/142, McpServer 33/33, Persistence 21/21.
- Core 117/128 and Service.Tests 67/79 (12 failed): the failing test **names** are identical to the reviewed head
  `fa12fe1` built and run the same way (Core 11, Service 12: Windows paths / kernel32; `FirewallRuleCoordinatorTests`,
  `NetworkRecoveryCommandTests`, `PrivacyShieldTests.Settings_write_failure_restores_the_previous_resolver`). The new
  `NetworkRecoveryControllerTests` case passes on Linux. These two suites still need a Windows run for runtime evidence.

