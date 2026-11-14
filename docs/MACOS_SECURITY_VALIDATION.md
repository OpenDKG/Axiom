# macOS security validation (runtime, #274 review item 3)

These are runtime checks of the security fixes from the #274 review, run on the macOS dev VM
against a bundle built from this branch. Every check uses a script under
`scripts/macos/security-validation/`. Its full, unedited output is in
`docs/evidence/macos-security/`. Unit tests do not replace these runs. This is author-run
evidence, not CI.

## Tested build and machine

| | |
|---|---|
| Tested SHA | `914153d` (buba/macos = `feature/macos-port` `a2b749e` + 4 fixes + merge of `origin/main` `77cc50a`, v0.17.0) |
| Bundle | `Axiom.app` 0.17.0 (build 10). Published on Linux with `scripts/macos/package-app.sh osx-x64 --no-sign`, then installed with `scripts/macos/deploy-to-vm.sh`: the Swift parts are built on the VM, the bundle is ad hoc signed, `axiomd --install-service` runs. |
| Filter | `com.axiom.firewall.filter (0.17.0/10) [activated enabled]`. The running extension binary is the one activated from `split/f-macos-filter` (`2c5366a`): macOS keeps an activated extension of the same version. `git diff 2c5366a 914153d -- macos/` is empty, so its sources are byte-identical to the tested SHA. |
| Machine | OSX-KVM VM, Intel x86_64, macOS 15.8.3 (24H241), **SIP disabled**, ad hoc signing |
| Users | `dev` (uid 501, admin, installed Axiom). `axtest2` (uid 502, standard, not in `admin`) was created for (a)/(b) and deleted afterwards. |
| Date | 2026-11-14 01:02–01:08 UTC |

Not covered: Apple silicon, SIP enabled, Developer ID signing, notarisation and Gatekeeper. These
need the owner's hardware and Apple account (#274 item 4).

## How to reproduce

Copy `scripts/macos/security-validation/` to the Mac (e.g. `/tmp/axsec`, world-readable so the
second user can run (a)), then run as the admin user who installed Axiom. Use `nohup` for (e),
because re-enabling the filter resets existing TCP flows, including an SSH session:

```sh
python3 -u sec-c-reject.py ; python3 -u sec-d-stale.py
nohup python3 -u sec-e-disconnect.py > e.out 2>&1 &     # writes /tmp/axsec/e-samples.ndjson
python3 -u sec-f-offline.py
P=$(openssl rand -base64 18); sudo sysadminctl -addUser axtest2 -fullName "Axiom test 2" -password "$P"; unset P
python3 -u sec-a-ipc.py; sudo -u axtest2 python3 -u /tmp/axsec/sec-a-ipc.py
bash sec-b-logs.sh
sudo sysadminctl -deleteUser axtest2
```

Each step prints `== [time] label: {json}`: the daemon's claim (`rules.query`, `rule.verify`)
next to `curl https://example.com` (rc 0/HTTP 200 = reached, rc 7 = blocked by the filter).

## Results

| # | Check | Verdict | Evidence |
|---|---|---|---|
| a | Second standard user cannot read private IPC | **PASS** | `sec-a-adduser.txt`, `sec-a-ipc.txt`, `sec-a-deluser.txt` |
| b | Initial and rotated daemon logs private, forced `newsyslog` rotation | **PASS** (privacy). Finding: after rotation the daemon keeps writing to the unlinked old file until it restarts. | `sec-b-logs.txt`, `sec-b-reopen.txt` |
| c | Filter rejection never reported as applied | **PASS** | `sec-c-reject.txt` |
| d | Stale generation stays Pending | **PASS**. Minor: `lastVerifiedUtc` stays null after the late ack. | `sec-d-stale.txt` |
| e | Disconnect/reconnect | **PASS** | `sec-e-disconnect.txt`, `e-samples.ndjson` |
| f | Offline recovery removal | **PASS** | `sec-f-offline.txt` |

### (a) Second standard user

`axtest2` (uid 502, `dseditgroup -o checkmember -m axtest2 admin` → "NOT a member") over
`/var/run/axiom/axiom.sock`:

- `snapshot`, `history.query`, `diagnostics.export`, `rules.query`, `rule.verify`, `live.events`,
  `config.get` → `unauthorized`: "This command discloses machine-wide activity and is only allowed
  for root, the user who installed Axiom (uid 501) and members of the admin group; uid 502 may only
  read public service health."
- `serviceHealth` → ok, **redacted**: `connectionCount 0`, `processCount 0`,
  `lastCaptureUtc null`, `lastError null`, `limitations ["private fields redacted: …"]`.
  `dev` gets the real values for the same call (`connectionCount 2`, `processCount 1`, capture time).
- `capabilities` → ok (public: the command list and protocol version).
- `rule.apply` → `unauthorized` ("changes machine-wide settings …").
- `dev` (contrast): `snapshot`, `rules.query`, `rule.verify` and `rule.apply` succeed.
  `diagnostics.export`, `live.events` and `config.get` reply `not_supported` (not implemented in
  0.17.0); the access check runs before that, so `axtest2` gets `unauthorized`. The `rule.apply`
  rule from the contrast run was removed straight away (0 rules, curl 200).

### (b) Daemon logs

`/etc/newsyslog.d/com.axiom.service.conf`: `/Library/Logs/Axiom/axiomd.log root:wheel 600 5 5120 * J`.

| | Mode / owner |
|---|---|
| before | `drwx------ root:wheel /Library/Logs/Axiom`, `-rw------- root:wheel axiomd.log` (114804 B) |
| `sudo newsyslog -F -v -f /etc/newsyslog.d/com.axiom.service.conf` | `trimming log....`, rc 0 |
| after | dir `drwx------ root:wheel`; `axiomd.log` `-rw------- root:wheel` (new); `axiomd.log.0.bz2` `-rw------- root:wheel` |
| `dev` (admin, not root) | `ls`/`cat` → Permission denied |
| `axtest2` | `cat axiomd.log`, `cat axiomd.log.0.bz2`, `ls -l` → Permission denied |
| after `launchctl kickstart -k system/com.axiom.service` | the new daemon opens the new `axiomd.log` (`lsof`: fds 1/2 → inode 318172), still `-rw------- root:wheel`. Filter verified again, 0 rules. |

**Finding (log continuity, not privacy):** launchd opens `StandardOutPath`/`StandardErrorPath`
for the daemon. After a rotation the running daemon writes to the renamed and later compressed
file, and the new `axiomd.log` stays at newsyslog's 83-byte marker (an apply/remove did not grow
it). Those lines are lost until the daemon restarts. To fix this, either the daemon logs to its
own file and reopens it (newsyslog pid/signal), or the rotation is size-only with a restart. This
is not fixed in this round.

### (c) Filter rejection (`chmod 664` on `filter/rules.json`)

- Verified block: `rule.apply` → `applied`, `verifiedUtc` = ack time; `rules.query` state `verified`
  pub = ack; `rule.verify` `enforcementVerified true`, `effectiveAction block`; curl rc 7.
- `sudo chmod 664 rules.json` (`-rw-rw-r-- root:admin`) → within ~1.5 s: capability `degraded`,
  reason "AxiomFilter rejected the rules file (unreadable: group/world-writable (mode 664));
  generation … stays in force and … is not verified", filter `state pending` with `fileError`,
  rule `pending`; `rule.verify` `enforcementVerified false`, `effectiveAction null`. The ack of
  that same generation had come earlier, so the latest report decides, not the earlier ack. curl
  is still rc 7 because the filter keeps its previous table, but the daemon does not claim it.
- `chmod 644` → fresh ack: `verified`, rule `applied`, `enforcementVerified true`.
- `rule.remove` → 0 rules, curl 200.

### (d) Stale generation (filter frozen with `kill -STOP`)

- `sudo kill -STOP <filter pid>` (`ps` stat `Ts`), then `rule.apply` → after the bounded 2.1 s
  ack wait: `success true, state "pending", verifiedUtc null`. `rules.query`: published
  1794372867 > acked 1794372866, state `pending`, "AxiomFilter has not acknowledged rules
  generation 1794372867 yet". `rule.verify` `enforcementVerified false`, "acknowledged
  generation 1794372866, not 1794372867; enforcement of this table is pending."
- `kill -CONT` → ack 1794372867: `verified`, rule `applied`, `enforcementVerified true`, curl rc 7.
- Minor: after the late ack the rule's `lastVerifiedUtc` stays null, because only the apply path
  stamps it. That understates the evidence; it does not overclaim. Noted as open.

### (e) Disconnect / reconnect (`axiom-sysext disable` / `enable`)

The 200 ms sampler transitions (`e-samples.ndjson`) were:

```
01:04:01.265Z verified  connected=true  pub=ack=1794372871 rules=[applied]
01:04:01.476Z degraded  connected=false pub=ack=1794372871 rules=[pending]   <- disable
01:04:03.109Z verified  connected=true  pub=ack=1794372872 rules=[applied]   <- enable: republished, new ack
```

While disabled: capability `degraded`, "The AxiomFilter network extension is disconnected …;
published rules are not known to be enforced", rule `pending`, `rule.verify`
`enforcementVerified false`. curl → 200, and the daemon does not claim otherwise. The old ack
(…871) did not verify anything after the reconnect. Only the new instance's ack of the
republished generation (…872) did. The first attempt, run over SSH, lost its session at the
`enable` (the filter resets flows). It is kept as `sec-e-disconnect.attempt1.txt`, and the
recorded run used `nohup`.

### (f) Offline recovery removal

- A first run (`sec-f-offline.attempt1.txt`) hit the kept 2026-11-12 baseline, which holds
  0 rules (`alreadyCaptured`), so it removed nothing. The script was then changed: the existing baseline (2026-11-12, 0 rules) is set aside so that a fresh capture records the
  test rule: `networkRecovery.capture` → `succeeded, ruleCount 1`. The original baseline was put
  back at the end (`alreadyCaptured`, 2026-11-12).
- `sudo launchctl bootout system /Library/LaunchDaemons/com.axiom.service.plist` → socket gone.
- `sudo axiomd --recover-network` (dry run) lists the 2 adapters and
  `Axiom rule 5ec0a000-…-00000000000f OUT (group 'Axiom')`, exit 1 (plan only).
- `sudo axiomd --recover-network --apply` → **`Result: PartialFailure; verified: no`**,
  `Axiom rules removed: 0; already absent: 0`, `filter.disconnected: The Axiom rule was removed
  from rules.json but the removal is not verified: AxiomFilter has not reported to this process
  …`, "Recovery did not complete", exit 5. curl was 200 at that moment: the filter had reloaded
  the file. The command did not claim that either.
- `sudo launchctl bootstrap …` → daemon running, filter `verified` (fresh ack), 0 rules.
  `networkRecovery.restore` over IPC → `succeeded, verified true, rulesVerifiedAbsent 1`,
  adapters 2/2. curl 200.

## End state of the VM

The `914153d` bundle is installed. The daemon is running, the filter is `verified`/connected
with 0 rules, curl is 200, `axtest2` is deleted and the original recovery baseline is in place.
