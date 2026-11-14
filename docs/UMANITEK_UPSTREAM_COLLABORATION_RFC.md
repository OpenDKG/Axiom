# Axiom × Umanitek Agent Blackbox — Upstream Collaboration RFC (Phase G)

> Draft discussion notes for upstream maintainers (`umanitek/agent-blackbox`). These are proposals
> for schema alignment and testing contracts, **not** implemented upstream APIs or agreed terms.

## Background

Axiom integrates locally with Agent Blackbox on Windows hosts as an OS-level network observer,
host-hook bridge (`OpenCode`/`OpenChamber`, `Claude Code`, `Codex`), and optional manual IOC reporter.
To preserve reporter trust, avoid noisy `REJECTED` reports, and keep graph provenance honest without
exposing private prompts or paths, Axiom proposes the following small, versioned improvements.

## Discussion Questions & Proposed Minimal Contracts

1. **Manual IOC `--reason` propagation (`report_cli/report_command.py::_ioc_args`)**
   - Currently manual CLI submissions omit a reason token or require fallback behavior in callers.
   - Question: Would upstream accept a targeted PR forwarding validated Blackbox reason codes
     (`c2-callback`, `exfiltration`, `malware-delivery`, `phishing`, `crypto-drainer`,
     `malicious-skill`, `prompt-injection`) via `--reason` with tests?

2. **Minimal typed evidence & enforcement-outcome vocabulary**
   - Axiom's local `axiom.enforcement.receipt.v1` strictly separates:
     `DETECTED`, `GUARD_UNAVAILABLE`, `AUDIT_ONLY`, `DENY_REQUESTED`, `HOST_DENY_SENT`,
     `HOST_DENY_VERIFIED`, `OS_DENY_VERIFIED`, `UNVERIFIED`, and `FAILED_OPEN`.
   - Question: What minimal public metadata fields should distinguish `observed`, `flagged`,
     `host-deny sent`, `host-deny verified`, `OS deny verified`, and public-feed context without
     disclosing private paths, prompts, or sessions?

3. **Authenticated, bounded local per-indicator lookup**
   - Instead of desktop integrations parsing internal cache files (`ruleset.json`,
     `authoritative-sync.json`), could Blackbox expose an authenticated loopback batch lookup
     returning tier (`verified` vs `community` vs `revoked`/`disputed`), Knowledge Asset UAL,
     source provenance, and snapshot freshness?

4. **Machine-readable public standing vs private novelty ledger**
   - Axiom currently surfaces `Potentially new`, `Already known`, and `Unknown` strictly from local
     graph state while reminding operators that curators decide `CONFIRMED` and `NOVEL`.
   - Question: Can `blackbox report --status --json` / `--standing --json` expose public curator
     outcomes and approximate standing without disclosing private curator novelty-credit internals?

5. **Official Sandbox / Non-Production Test Fixture Contract**
   - Standardized documentation for isolated test identities, sandbox DKG lanes, and canary fixtures
     so CI/integration suites never touch production graphs or real `reporter_key.pem` identities.

6. **Corroboration Hygiene Across Multi-Install Feeds**
   - How should independent OS observations be tagged when a user investigates an indicator initially
     flagged by a shared blocklist or community feed so multiple Axiom installs never artificially
     inflate independent corroboration counts?

7. **Cross-Review of Guard Tamper & Host-Deny Canaries**
   - Invitation to cross-review Axiom's synthetic guard-tamper and disposable canary test harness so
     both upstream guards and host bridges share reproducible refusal evidence.
