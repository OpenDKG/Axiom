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
