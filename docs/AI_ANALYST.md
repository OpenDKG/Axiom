# AI Security Analyst

AI Security Analyst is an optional, **default-disabled** read-only investigation surface. It is
not an enforcement path and cannot change Windows Firewall, execute commands, read arbitrary files
or modify agent configuration.

## What is implemented

- **Seamless OpenChamber/OpenCode provider.** The built-in `opencode://local` provider runs the
  already-installed and signed-in OpenCode CLI in headless plan mode
  (`opencode run --format json --agent plan`). It needs no Ollama, LM Studio, extra API key or
  separate HTTP server. The default model is `opencode-go/deepseek-v4.1-flash`.
- Provider-neutral OpenAI-compatible chat-completions adapter:
  - HTTPS cloud endpoint;
  - HTTP is allowed only for a loopback local inference endpoint;
  - configurable endpoint, model, API key, path redaction, connection limit and token limit.
- API keys are protected with Windows DPAPI for the current user; they are never shown, logged or
  written to findings. The OpenChamber/OpenCode provider uses the existing OpenCode login instead.
- Bounded evidence v2 from the current read-only monitor snapshot:
  - application name, PID, parent PID/name/chain, protocol, direction, state, endpoints, quality and
    first-observation time;
  - Authenticode signer status and subject, product and file version;
  - sanitised and truncated command line (secret-like arguments are masked);
  - observed duration, well-known remote port service names and local host/subnet/gateway context;
  - Axiom-owned firewall rule status (`NoOwnedRule`, `AllowedByOwnedRule`, `BlockedByOwnedRule`);
  - aggregated 30-day local flow baseline (first/last seen, flow-row count and typical remotes);
  - paths are reduced to file names when redaction is enabled;
  - no packet contents, credentials, cookies, agent histories or arbitrary files.
- Structured result contract with status, severity, confidence, observations, evidence references,
  alternative explanations, missing evidence and text-only next steps.
- Bounded local finding history in `%LOCALAPPDATA%\Axiom\ai-findings.json`; no prompts or provider
  responses are stored.
- The model result is sanitized: unknown/SAFE-like statuses become `UNKNOWN`, list lengths are
  bounded, and no action field exists in the result contract.
- Copy result / Copy all export every field as plain text. An indeterminate progress bar, elapsed
  seconds and Cancel are shown while the agent is running; the result panel returns to the top when
  a new finding arrives.
- Optional automatic analysis:
  - default off;
  - only new non-loopback destinations are considered;
  - keys are deduplicated;
  - configurable minimum interval and hourly request limit;
  - no request is made while the analyst is disabled or unconfigured.
- Optional second verifier model:
  - uses a separate request/context and the same provider;
  - records verifier status and summary without changing the primary finding;
  - verifier failure is surfaced, not treated as agreement.
- Existing MCP server remains separate and read-only. No second MCP server and no MCP write tool is
  added.

## What is intentionally not implemented

- MCP tool orchestration from the UI. This initial path reads the same service-backed monitor
  snapshot directly; the existing MCP server remains available to external MCP clients.
- Model-controlled firewall writes, shell execution, active scanning, reputation invention or
  guaranteed model confidence.
- Direct OriginTrail VM/Knowledge Asset publication, independent Blackbox curation or an autonomous research-memory service. **User-approved Blackbox IOC reporting is implemented** as documented below.
- Storage of raw prompts or raw provider responses.
- Full cost accounting beyond token and hourly request bounds.

## Privacy

Cloud use requires an explicitly configured provider and the analyst to be enabled. Manual **Analyze** sends a bounded evidence request; optional automatic analysis may also send requests when the user enables it and its interval/hourly limits permit. Before enabling external analysis, the page should state exactly which evidence categories may be sent. No request is made while the analyst is disabled or unconfigured. Provider failures are reported locally and do not affect
monitoring, history or firewall behavior.

## Prompt-injection and action boundary

Evidence strings are untrusted data. The system prompt instructs the model to treat them as data,
return one JSON object and never propose or perform a change. The application parses only the
structured result and has no firewall/shell/file API in the AI code path. Recommended actions are
plain text for a human to review; they are never executed.

## Threat sharing

The analyst returns a structured `indicators` array (`type`, `value`, `role`). Axiom proposes only
`role: malicious` entries from a `SUSPICIOUS` or `SUPPORTED_ALERT` finding at high or critical
severity, and only when the value matches a remote endpoint Axiom itself put in the evidence
package. A value already present in Axiom's local malware-list block history is suppressed as
list-derived. Summary, observations, evidence references and recommended actions are never scanned, so
a domain named in prose or in a suggested block list cannot become a report. Queued values are shown
on the Agents page and are signed and sent only after the user presses **Share** or **Send now**.

While the evidence package carries no file hash computed by Axiom, hash indicators are never
proposed. The Blackbox report still uses the closest available context label (`in-tool-output`) and
`malware-delivery`; a dedicated observed-endpoint context should be requested from Umanitek.

## Limitations

- A model finding is one source, not proof of compromise. `INSUFFICIENT_DATA`, `UNKNOWN`,
  `LOW_OBSERVED_RISK`, `SUSPICIOUS` and `SUPPORTED_ALERT` are not equivalent to a confirmed incident.
- ETW telemetry is not integrated yet, so SNI, TLS certificate subjects, DNS query names, exact
  per-connection byte counts and TIME_WAIT ownership remain missing evidence.
- AI Analyst does not automatically consume VirusTotal, community or DKG reputation lookups as investigation evidence; those are separate optional modules. It does not invent a reputation score.
- Command lines are sanitised and truncated, and protected processes may not expose them.
- Axiom reports only its own firewall rules; effective Windows default policy and third-party rules
  remain outside `ruleStatus`.
- File hashes and full Authenticode chain details are not part of the evidence package.
- Provider APIs and model availability can change; verify the endpoint and model at configuration
  time.
