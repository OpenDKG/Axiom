# AI Security Analyst

AI Security Analyst is an optional, **default-disabled** read-only investigation surface. It is
not an enforcement path and cannot change Windows Firewall, execute commands, read arbitrary files
or modify agent configuration.

See [PROVIDER_TOS_COMPLIANCE.md](PROVIDER_TOS_COMPLIANCE.md) for the full provider Terms of Service
matrix and hook/MCP audit results.

## Supported providers & compliance policy

Every request is validated before execution by `AiProviderCompliancePolicy` (`Axiom.Contracts.Ai`).
Axiom supports official API keys, local inference, and strictly scoped OpenCode providers:

| Provider (`AiProviderKind`) | Endpoint | Auth / Notes |
|---|---|---|
| `LocalOpenAiCompatible` (recommended for zero cloud ToS risk) | `http://127.0.0.1:11434/v1/chat/completions` (Ollama, LM Studio, `llama.cpp`) | No API key required. Plain HTTP is allowed **only** on loopback (`127.0.0.1` / `localhost`); zero data leaves the device. |
| `OpenAi` | `https://api.openai.com/v1/chat/completions` | Official OpenAI Platform API key (`Authorization: Bearer`). |
| `Anthropic` | `https://api.anthropic.com/v1/messages` | Official Anthropic Console API key (`x-api-key` + `anthropic-version: 2023-06-01`). |
| `GoogleGemini` | `https://generativelanguage.googleapis.com/v1beta/openai/chat/completions` | Official Google AI Studio / Gemini Developer API key (`AIza...`, `Authorization: Bearer`). |
| `OpenRouter` | `https://openrouter.ai/api/v1/chat/completions` | Official OpenRouter BYOK API key (`Authorization: Bearer`, `HTTP-Referer: https://github.com/OpenDKG/Axiom`, `X-Title: Axiom Firewall`). |
| `DeepSeek` | `https://api.deepseek.com/chat/completions` | Official DeepSeek API key (`Authorization: Bearer`). |
| `Zai` | `https://api.z.ai/api/paas/v4/chat/completions` | Official Z.ai GLM API key (`Authorization: Bearer`). |
| `OpenCodeZen` | `https://opencode.ai/zen/v1/chat/completions` | Official OpenCode Zen API key (`Authorization: Bearer`). |
| `OpenAiCompatible` | Custom `https://...` URL | Custom HTTPS OpenAI-compatible BYOK API. |
| `OpenChamberLocal` (restricted) | `opencode://local` | Runs installed OpenCode CLI (`>= 2.2.3`, 2.x) in `--standalone` mode with deny-all tool/MCP/plugin/skill policies and `OPENCODE_DB=:memory:`. Restricted to authorized OpenCode-native or local providers (e.g., `opencode-go/*`, `ollama/*`, `lmstudio/*`, `deepseek/*`, `openrouter/*`). Default model: `opencode-go/deepseek-v4.1-flash`. |

### Compliance restrictions enforced in code

- **Blocked consumer & private endpoints:** `AiProviderCompliancePolicy.ValidateRequest` rejects
  `cloudcode-pa.googleapis.com` (`*.cloudcode-pa.googleapis.com`), `claude.ai` (`*.claude.ai`),
  `chatgpt.com` (`*.chatgpt.com`), `chat.openai.com`, `api.githubcopilot.com`, and
  `copilot-proxy.githubusercontent.com`.
- **Blocked consumer OAuth tokens:** `sk-ant-oat*` tokens (Claude Free/Pro/Max/Claude Code OAuth) on
  Anthropic and `ya29.*` tokens (Google Antigravity/Gemini CLI OAuth) on Google Gemini are rejected
  with guidance to use an official API key or the read-only MCP workflow.
- **Restricted `OpenChamberLocal` (`opencode://local`) policy:**
  - `AiProviderCompliancePolicy.ValidateOpenCodeModel` validates both `Model` and `VerifierModel`,
    blocking third-party consumer OAuth provider prefixes (`anthropic`, `claude`, `claude-code`,
    `antigravity`, `google`, `google-gemini-cli`, `gemini`, `gemini-cli`, `vertex-antigravity`,
    `github-copilot`, `copilot`, `chatgpt`, `codex`, `openai-codex`, `cursor`, `windsurf`) and
    bare `claude-*` / `antigravity*` / `gemini-cli*` names.
  - External-routing-restricted free-tier models (`*:free`, `free`, `opencode/free*`) are also
    blocked.
  - `OpenCodeAnalystLaunch` explicitly removes `CLAUDE_CODE_OAUTH_TOKEN`, `ANTHROPIC_AUTH_TOKEN`,
    `GOOGLE_CLOUD_ACCESS_TOKEN`, and `GEMINI_CLI_OAUTH_TOKEN` from the child process environment and
    sets `OPENCODE_DISABLE_CLAUDE_CODE=true` and `OPENCODE_DISABLE_PROJECT_CONFIG=true`.
  - When using flat-rate OpenCode plans (such as `opencode-go/*`), keep **Automatic analysis**
    disabled or conservatively throttled rather than polling continuously in the background.

## Safe read-only MCP workflow for existing agent subscriptions

If you already hold a subscription to **Claude Code**, **Antigravity**, **Codex CLI**,
**Gemini CLI**, or **GitHub Copilot CLI**, do **not** extract OAuth tokens (`sk-ant-oat*`,
`ya29.*`) or route those logins into standalone harnesses. Instead, register Axiom's read-only
stdio MCP server (`Axiom.McpServer.exe`) directly inside your official unmodified agent client
(see [MCP.md](MCP.md)). The client retains its native first-party authentication and calls Axiom's 9
read-only telemetry tools over local stdio JSON-RPC backed by `\\.\pipe\Axiom.Service.v1`.

## What is implemented

- **Compliance & transport adapters:** `AiProviderCompliancePolicy` validates provider, endpoint,
  credential shape, and `OpenChamberLocal` model before any request runs. Cloud providers require
  HTTPS; plain HTTP is permitted only on loopback for `LocalOpenAiCompatible`.
- API keys are protected with Windows DPAPI for the current user; they are never shown, logged or
  written to findings. `OpenChamberLocal` uses authorized OpenCode-native or local provider logins
  while scrubbing leaked consumer OAuth environment variables.
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
- The history and result panel both label findings: red for high-priority findings, amber for
  flagged activity, green for low observed risk, and grey for inconclusive or failed analysis.
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
  - uses a separate request/context and the same provider (and is also validated by
    `AiProviderCompliancePolicy` for `OpenChamberLocal`);
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
proposed. A URL indicator with a non-root path is rejected by default; only a domain or root URL is
shareable, and no path opt-in ships yet. If the local list/provenance lookup is unavailable, Axiom
fails closed and queues no AI indicator: an empty fallback set must not turn a list-derived value
into an independent report. The Blackbox report still uses the closest available context label
(`in-tool-output`) and `malware-delivery`; a dedicated observed-endpoint context should be requested
from Umanitek.

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
