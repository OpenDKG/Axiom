# ADR 0008 — Axiom Shield: consented enforcement through Windows Firewall

- **Status:** accepted
- **Date:** 2026-11-07
- **Milestone:** 0.7.0
- **Supersedes:** the "test-VM only" decision in ADR 0007, section 3

## Context

ADR 0007 kept every firewall write behind two environment variables so a development workstation
could not be changed accidentally. That made the shipped application read-only: it could list rules
and show sockets but could not protect the computer, and it could not stop an agent from reaching the
internet.

The product now needs real enforcement on a normal Windows PC. The design constraints remain:
nothing is written without explicit user consent, only Axiom-owned rules are ever created or removed,
every change is verified by OS read-back and audited, and disabling protection must restore the
previous state.

## Decisions

### 1. Enforcement runs only in the Windows service

Windows firewall rules are machine-wide and need elevation. The desktop app therefore stays
unprivileged. Turning protection on installs and starts `Axiom.Service` as a Windows service
(LocalSystem) through a single UAC prompt; removing it is an explicit separate action.

`ProtectionWriteConsent.IsServiceHost` is `!Environment.UserInteractive`, so an interactive process
holding the same consent still cannot write. This prevents a copied state file from becoming a
write path in the UI process.

### 2. Consent is persisted, not ambient

Consent lives in `%ProgramData%\Axiom\protection.json` together with the decision list and the
persisted pipe SID. The service loads it at start and the background worker re-reads it every five
seconds, so a manual edit takes effect without a restart. An absent or corrupt file means "off".

The two environment variables remain as a test override on an isolated VM; they are no longer the
shipped path.

### 3. Ask policy — never silent blocking

The default policy is `ask`. New outbound applications are surfaced with path, socket count and
first-seen time. The operator chooses:

- **Block** — creates `Axiom::{id}::OUT` for that executable path, all profiles, any protocol.
- **Allow** — records the decision and removes an existing Axiom block for that path.

A decision is persisted, so the same application is not asked again. Loopback and inbound traffic
are out of scope in 0.7.0.

### 4. Agent lockdown keeps localhost

The agent lockdown blocks the same executable paths with a remote scope built from 16 CIDR blocks
that cover every non-loopback IPv4 and IPv6 address. Loopback is never in scope, so the local
Blackbox guard on `127.0.0.1:9700` keeps working while the agent loses internet access. The
background worker applies the same scope to agent executables that appear later.

### 5. Disable is the rollback

Disabling the shield removes every owned rule through the coordinator, clears the decisions and
writes `Enabled=false` before the write gate closes. The rollback path is therefore the same code
that created the rules, and it is audited row by row.

## Consequences

- A normal install is no longer read-only; it is read-only **until the user enables the shield**.
- The service must be installed for enforcement. Without it the app degrades to monitoring and the
  Firewall page explains why.
- Rule conflicts with Group Policy or another product remain possible; read-back reports the
  effective state instead of claiming success.
- Installer uninstall, service removal, and network behaviour of a blocked executable still need
  isolated-VM verification before they are treated as proven.

## Alternatives considered

- **WFP callout driver.** Strongest enforcement, but requires a signed kernel driver and a much
  larger security surface. Rejected for 0.7.0.
- **Per-user firewall rules.** Windows Firewall rules are machine-wide; there is no per-user scope
  in the COM API. Rejected.
- **Silent default-deny.** Too easy to lock the operator out of the network. Rejected; the ask
  policy is the default.
