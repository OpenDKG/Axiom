# Security policy

## Supported versions

| Version | Status |
|---|---|
| Current Windows release (see [Releases](https://github.com/OpenDKG/Axiom/releases/latest)) | Best-effort security fixes |
| Linux and macOS developer previews | Experimental builds with platform-specific limits |
| Earlier development milestones | Not maintained; upgrade for current fixes |

Interfaces, storage schema and IPC protocol may change between releases.

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
- Vulnerabilities in upstream third-party products themselves are reported to their own maintainers.
  **Axiom's adapters, installers, credential handling and integration boundaries remain in scope** when those optional components are enabled.
- Proposed/unimplemented features, including direct paid VM publishing or a future wallet extension.
- Social engineering and physical access.

## Security expectations for contributions

- Never add secrets, tokens or personal data to the repository, logs, tests or fixtures.
- Do not add external network calls to the Standard path.
- Firewall writes are only developed and tested in an isolated Windows VM with explicit approval.
- New dependencies require a license and security review; see `docs/LICENSING.md` and
  `THIRD_PARTY_NOTICES.md`.
- Security-sensitive changes need an independent review before merge.
