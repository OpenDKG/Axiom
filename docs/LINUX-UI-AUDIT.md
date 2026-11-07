# Linux UI verification, 2026-11-07 UTC

This pass resumed existing work, not a new implementation. Commit `7e49fa5` already
contained the session/error/history/credential fixes and was already deployed before
this audit. Its three static assets match `/opt/axiom/ui/wwwroot` byte-for-byte.
The running UI started at 2026-11-06 22:19:39 EST. This audit later deployed only
an additional reviewed `app.js` paging fix, updating its installation-manifest hash
without restarting either service or rotating the token.

## Actual browser checks

Headless Chromium through the existing HTTPS LAN proxy, with the current journal
fragment token held in memory only:

- All seven tabs rendered: Overview, Connections, History, Firewall, Privacy Shield,
  AI Analyst, About. Screenshots were captured and inspected.
- Connection search produced an empty result for an impossible application; new-only
  filtering operated without browser exceptions.
- History displayed rows 1–200, advanced to 201–400, and returned to the first page.
  Search, Enter submission, one-hour window selection, and the actual CSV download
  worked. The empty-search CSV contained its BOM and header (96 bytes). A second,
  populated one-hour export downloaded 19,449 data rows (3,404,424 bytes); parsing
  confirmed all rows, including the header, had 11 columns.
- Authentication removed the fragment from the address bar. No page errors occurred.
  Console output contained only two password-field/form advisory messages.
- Firewall reported available backend, zero owned rules, and the closed write gate.
  Privacy Shield reported disabled, not listening, with zero queries.
- Both credential editors were disabled with an explicit missing-keyring reason.

A second real browser ran against the locally built UI with an absent IPC socket,
a private temporary HOME/config/data directory, and a fake `secret-tool`:

- Insecure non-loopback HTTP AI endpoints were rejected; local HTTP settings saved.
- Both key editors stored/deleted dummy keys and cleared their password fields.
- Disabled AI analysis and missing reputation key returned readable errors.
- Autostart created then removed only the disposable profile's desktop entry.
- An expired session displayed the explicit recovery banner.

No real provider request, live credential mutation, autostart mutation, firewall/DNS
change, installer, reboot, proxy edit, or deletion of live data was performed.

## Additional bug reproduced and repaired

Malformed JSON in a token-authenticated write request returned HTTP 500, leaving
clients without the expected error contract. A regression first failed with
`Expected: BadRequest; Actual: InternalServerError`. The shared JSON write guard now
returns HTTP 400 with `invalid-request` and a generic explanation, without reflecting
request content. The regression covers reputation key, AI key, AI settings,
autostart, and reputation lookup. The isolated browser also verified this response.

Independent review session `ses_e4bf45615ffesghrhgTQkfU2X0` found one further P2:
a failed History Next request advanced the internal offset but left the previous
buttons unchanged, trapping the last page. The fix restores the last successful
offset on a current-request failure. A fifth JavaScript regression covers failure
then retry. The reviewer rechecked and approved the four-file code/test diff.
A real browser then verified the deployed script with intercepted History responses
(offsets 0, 200 failing, 200 succeeding); no live history was modified.

Asset-only deployment backup:
`/tmp/opencode/axiom-ui-assets-backup-20261106-223127/` contains `app.js` and
`install-manifest.sha256`. Rollback restores those two files to
`/opt/axiom/ui/wwwroot/app.js` and `/opt/axiom/install-manifest.sha256`, then reloads
the browser; neither service needs restarting.

## Build conditions and evidence

Use SDK `/tmp/opencode/dotnet/dotnet` (10.0.403), not the system SDK (10.0.114).
Use a private TMPDIR for the suite: two existing privacy tests otherwise try to save
settings directly under the shared temporary directory, which the private-directory
validation correctly refuses. With private TMPDIR the complete Linux build and all
314 tests passed both before and after merging current `origin/main` (`61d5520`).
The post-merge build had zero warnings and zero errors. JavaScript regressions:
5/5 passed after the review remediation. Final live and isolated browser runs passed
again after that build and the asset-only deployment.
The installed payload manifest validated all 810 entries with zero mismatches;
service PIDs were unchanged throughout the audit.

Host-local evidence (not uploaded because screenshots/DOM contain local paths and
network endpoints): `/tmp/opencode/axiom-ui-evidence/`, scripts
`/tmp/opencode/axiom-browser-audit.py` and `/tmp/opencode/axiom-isolated-browser.py`,
logs `/tmp/opencode/axiom-ui-*-build.log` and
`/tmp/opencode/axiom-malformed-before.log`.

## Supported scope and deployment limitation

The browser Firewall and Privacy Shield pages are status views, not configuration
editors. Agent hooks/Blackbox installers and a tray icon remain unsupported on Linux.
AI/reputation need a user-session Secret Service keyring and provider configuration;
this headless live host has no such keyring. No external-provider success is claimed.

### Completed UI binary deployment

Following the user's instruction to complete deployment, the reviewed revision
`9f23d9bdcec7e8c90be2ac15093b5270faccc7aa` was published with SDK 10.0.403,
Release/linux-x64/self-contained, using the existing publish script's UI command.
Only changed files in `/opt/axiom/ui` were atomically replaced, root-owned; the
installation manifest was regenerated for the actual UI payload. No service or
MCP payload was updated. Backup of the entire previous UI plus manifest:
`/tmp/opencode/axiom-ui-binary-backup-20261106-223410/`.

Only `axiom-ui.service` restarted. Its per-run token rotated and was not disclosed.
The backend PID remained `1501067`, its socket inode/ownership/mode stayed unchanged,
and both units remained active. UI persisted profile hashes were identical (the
profile contained no files), as were unit, nginx configuration and resolver hashes.
All 810 installation-manifest entries validated. Installed UI DLL SHA-256:
`8f3e8418d2f88667d24798b72c5e0104fe77bdd9f014d0924449b819bf5fe2fc`.

Post-restart real authenticated LAN Chromium repeated all seven pages, filters,
history pagination/search/time window and empty/populated CSV downloads. The real
browser paging-failure/retry check passed again. Five authenticated malformed-JSON
write routes returned HTTP 400 `invalid-request`; missing and previous tokens
returned 401, while the new token worked. No settings were written by these malformed
requests. Evidence: `binary-deployment.json`, `postdeploy-validation.json` and
`postdeploy-overview.png` in the existing host-local evidence directory.

Binary rollback: stop only `axiom-ui.service`, restore the backup `ui/` and
`install-manifest.sha256` into `/opt/axiom`, then start only `axiom-ui.service`.
That restart also rotates the token. No backend restart, proxy, firewall or DNS
change is required.
