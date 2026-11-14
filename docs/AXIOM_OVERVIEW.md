# What Axiom is

Axiom is an **agent-first endpoint security** application. It protects the computer **from the
agents that run on it**, and it protects those agents **from the world they read**. It does that by
putting a verifiable guard around agent tool calls, an operating-system boundary around agent
network traffic, and a shared, verifiable memory behind both.

The project's centre of gravity is the agent, not a browser or a firewall page. A modern desktop
runs coding agents, assistants and automation that read files, execute commands, install packages
and fetch pages. Those agents are the new privileged user. Axiom is built for that assumption.

## The two directions of the threat

1. **Agent → machine.** An agent can read `.ssh`, `.env`, wallet keys or browser data, copy them
   out, delete evidence, launch a downloaded binary, or run a remote script. Axiom's guard decides
   each tool call locally, in the user's session, before the tool runs.
2. **World → agent.** A page, a skill, a package or a prompt can hijack the agent. Axiom scans
   prompt text and tool output, quarantines a session on a high-severity injection finding, and
   keeps dependency and skill rules next to the file and execution rules.

Both directions share one decision path: an observed action, a local rule or model, a recorded
decision, and a UI that says honestly whether the action was blocked by the agent hook, blocked at
the OS boundary, or only flagged.

## The layers

| Layer | What it does | Where it runs |
| --- | --- | --- |
| **Agent guard (Blackbox hooks)** | Decides every tool call: protected paths, secrets, seed phrases, known threats, injection, dependency and skill findings. Block mode is the default on a complete install. | Inside the agent process (11 agent families) |
| **Axiom policy and receipts (E1/E2)** | Deterministic policy evaluation, a community-only advisory gate, a hash-chained `EnforcementReceiptV1` journal, and a UI that distinguishes cooperative signals from verified host decisions. | Axiom service, named pipe |
| **OS network boundary (E4)** | Per-agent Windows Firewall rules with a dual-destination canary and automatic rollback; `OS_DENY_VERIFIED` only when the OS read-back and the canary both prove it. | Windows Firewall |
| **Privacy Shield** | Local DNS filtering from eight threat/ad/tracking lists, with allowed upstream queries upgraded to encrypted RFC 8484 DoH. | Local resolver on `127.0.0.1:53` |
| **Evidence and UI** | Agent Dashboard, findings, activity, enforcement receipts, offline continuity state and DKG context annotations. | Axiom desktop |

Axiom deliberately does **not** install a kernel driver and does **not** rewrite the user's ACLs.
File protection for an agent that runs as the signed-in user is enforced at the hook layer
(`HOST_DENY_VERIFIED`); the network boundary is enforced by the OS (`OS_DENY_VERIFIED`). The UI names
the difference instead of claiming a boundary that does not exist.

## Why Blackbox and DKG are part of Axiom

**Agent Blackbox** is the decision engine: a portable, local guard with a ruleset, hooks for many
agent frameworks, trade and secret shields, and a reporter. Axiom does not reimplement it; Axiom
makes it installable, observable and trustworthy:

- a complete install provisions block mode, all hooks, the Trader Shield, a longer plugin load
  deadline and a self-test that proves a protected read and write are blocked;
- the reporter runs through the interpreter that actually matches its dependency environment, with
  graceful fallbacks, so a share never fails because of packaging drift;
- a local preflight refuses synthetic canaries, EICAR, tracking and shared-hosting hosts, and
  indicators already in the ruleset, so the community graph stays worth reading;
- an offline continuity model distinguishes "guard available, rules cached" from "DKG offline" and
  from "unprotected", so an air-gapped machine is not reported as if its guard had failed;
- upgrade protection copies findings, history, the reporter key and the DKG identity before the
  vendor installer runs and restores anything that disappears.

**OriginTrail DKG** is the shared memory: a node holds the verified graph, a reporter identity signs
what this machine observed, and the community graph returns corroborated threats as rules to every
node. Axiom strengthens that loop in both directions:

- it provisions the DKG home and binary the guard actually reads, keeps the node reachable for the
  dashboard, and annotates local indicators with verified, community or unknown provenance;
- it treats the reporter key and consent as first-class local state, never signs in the service
  account, and never sends a synthetic value;
- the graph in turn gives Axiom's ruleset, the dashboard and the AI Analyst their evidence, so a
  decision can cite a verified threat instead of a guess.

This is the mutual reinforcement the project is built on: **Axiom makes Blackbox and DKG usable and
honest; Blackbox and DKG make Axiom's decisions verifiable and shared.**

## Computer protection, not only agent protection

The same install also protects the machine around the agents: a scoped Windows Firewall enforcer
for agent processes, a DNS resolver that blocks eight lists and encrypts allowed lookups, and a
privacy layer that does not proxy or decrypt TLS. Those controls are opt-in where the OS requires
consent, and the UI reports their real state.

## The update contract

An update must never cost the user their history:

- findings, audit, ruleset, reporter key, consent, verified state and the DKG identity are backed up
  before the vendor installer runs and restored if they disappear (`UpgradeDataGuard`);
- block mode, protected paths, the Trader Shield and the plugin load deadline are re-applied after
  an upgrade and are idempotent, so a restart does not rewrite the config;
- the installer waits for a stopping service, retries a locked file and prints the reason when a
  silent run fails;
- the BIP-39 wordlist is normalized to LF, restoring seed-phrase detection on Windows.

## Roadmap

- **0.23.0** — this release: complete-install provisioning, hardened agent bridge, reputation-safe
  sharing, update data guard, BIP-39 fix, offline continuity from 0.22.0.
- **0.24.0 – 0.25.0** — Linux and macOS ports, upstream Blackbox RFC items.
- **1.0.0** — production sign-off.

See [SECURITY_MODEL.md](SECURITY_MODEL.md), [ARCHITECTURE.md](ARCHITECTURE.md),
[THREAT_INTELLIGENCE.md](THREAT_INTELLIGENCE.md) and [OFFLINE_CONTINUITY_AUDIT.md](OFFLINE_CONTINUITY_AUDIT.md)
for the detailed contracts.
