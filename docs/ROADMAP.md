# Roadmap

This is a short English summary of the V2 milestone plan. The authoritative internal specification
is kept outside the public repository; this page is the public, English roadmap.

## Core path

| Ticket | Scope | State |
|---|---|---|
| FND-001 | Repository, build, WPF shell, demo data, CI | ✅ baseline; V2 eight-page navigation aligned |
| FND-002 | Read-only TCP/UDP inventory and process attribution | ✅ implemented (PID + path; start time/signature pending) |
| FND-003 | Windows service + secure local Named Pipe IPC | ✅ implemented (console mode; installer pending) |
| FND-004 | ETW traffic estimate, real-time charts | ⛔ deferred: requires elevation/VM |
| FND-005 | SQLite history, retention, query, export | ✅ implemented (bytes/JSON export pending) |
| FND-006 | Click-to-block through Windows Firewall COM | 🟡 code complete and gated; real VM block test pending |
| FND-007 | Alerts and WFP/5157 blocked-event evidence | ⏳ |
| FND-008 | Scope rules, profiles, import/export | 🟡 CIDR/port validation done; scope UI/import-export pending |
| FND-009 | Installer, service hardening, recovery, QA | ⏳ portable per-user install script available; MSI/service pending |
| FND-010 | GeoIP, DNS hints, timeline polish, performance | ⏳ |

## Optional modules (after a stable core)

- FND-015 — File Tracker + local reputation.
- FND-016 — Provider-neutral reputation gate / manual VirusTotal hash lookup.
- FND-011 — Blackbox compatibility adapter.
- FND-012 — OriginTrail DKG adapter and signed bundles.
- FND-013 — Separate agent security research memory package.
- FND-014 — Optional TRAC publishing / grants (testnet first, explicit approval).
- FND-017 — Wallet-protection browser extension R&D.
- FND-018 — Community reports, moderation, anti-abuse.

## Ground rules

- One ticket per change; no jumping to firewall writes before read-only telemetry is stable.
- No fake `Protected`, `Blocked`, `Scanned` or `Connected` states; unknown is better than invented.
- No admin rights, service installation, firewall changes, external calls or kernel drivers in
  read-only milestones.
- Firewall writes are developed and tested only in an isolated Windows VM with explicit approval.
- Every milestone ends with build/test evidence, known limitations, manual checks and rollback.
