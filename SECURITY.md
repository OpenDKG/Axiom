# Security policy

## Supported versions

| Version | Status |
|---|---|
| 0.1.x (pre-release, FND-005) | Best-effort fixes; no production support claim |
| Older builds | Not supported |

The project is pre-1.0. Interfaces, storage schema and IPC protocol may change between milestones.

## Reporting a vulnerability

Use **GitHub Security Advisories** on this repository:

1. Open the repository's **Security** tab.
2. Choose **Report a vulnerability** (private advisory).
3. Include affected version/commit, Windows version, reproduction steps and impact.

Do not open a public issue for a vulnerability before a fix is available. Do not include real
credentials, SID lists, private paths, packet payloads or other personal data in the report; redact
them.

There is no bug bounty and no guaranteed response time. Reports are handled on a best-effort basis
by the maintainers.

## In scope

- Named Pipe IPC: DACL, SID checks, request validation, limits, rate limiting.
- Service behaviour: privilege boundaries, lifecycle, crash/restart handling.
- Firewall rule handling (from FND-006): scope, read-back, rollback, ownership checks.
- Local data handling: SQLite contents, retention, export, redaction.
- Supply chain: pinned dependencies, lock files, build/publish scripts.
- Anything that could make the UI claim protection that the OS is not enforcing.

## Out of scope

- Attacks that require a local administrator (documented boundary).
- Vulnerabilities in Windows, Microsoft Defender or third-party firewalls.
- Optional modules that are not part of the Standard build (Blackbox, DKG, wallet extension,
  community feeds) until they are implemented and enabled.
- Social engineering and physical access.

## Security expectations for contributions

- Never add secrets, tokens or personal data to the repository, logs, tests or fixtures.
- Do not add external network calls to the Standard path.
- Firewall writes are only developed and tested in an isolated Windows VM with explicit approval.
- New dependencies require a license and security review; see `docs/LICENSING.md` and
  `THIRD_PARTY_NOTICES.md`.
- Security-sensitive changes need an independent review before merge.
