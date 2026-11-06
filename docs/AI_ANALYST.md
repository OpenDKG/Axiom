# AI Security Analyst

AI Security Analyst is an optional, **default-disabled** read-only investigation surface. It is
not an enforcement path and cannot change Windows Firewall, execute commands, read arbitrary files
or modify agent configuration.

## What is implemented

- Provider-neutral OpenAI-compatible chat-completions adapter:
  - HTTPS cloud endpoint;
  - HTTP is allowed only for a loopback local inference endpoint;
  - configurable endpoint, model, API key, path redaction, connection limit and token limit.
- API keys are protected with Windows DPAPI for the current user; they are never shown, logged or
  written to findings.
- Manual **Analyze current activity** action builds a bounded evidence package from the current
  read-only monitor snapshot:
  - application name, PID, protocol, direction, state, endpoints, quality and first-observation time;
  - paths are reduced to file names when redaction is enabled;
  - no packet contents, credentials, cookies, agent histories or arbitrary files.
- Structured result contract with status, severity, confidence, observations, evidence references,
  alternative explanations, missing evidence and text-only next steps.
- Bounded local finding history in `%LOCALAPPDATA%\Netpetra\ai-findings.json`; no prompts or provider
  responses are stored.
- The model result is sanitized: unknown/SAFE-like statuses become `UNKNOWN`, list lengths are
  bounded, and no action field exists in the result contract.
- Existing MCP server remains separate and read-only. No second MCP server and no MCP write tool is
  added.

## What is intentionally not implemented

- Automatic background analysis. The toggle is not present; analysis is an explicit button action.
- Model-controlled firewall writes, shell execution, active scanning, reputation invention or
  guaranteed model confidence.
- A second verifier model, OriginTrail publication, Blackbox integration or local research memory.
- Storage of raw prompts or raw provider responses.
- Cost accounting beyond the configured token/request bounds.

## Privacy

Cloud use requires the user to enable the analyst, enter an endpoint/model and press Analyze. Before
sending evidence, the page states exactly which categories are included. No request is made while
the analyst is disabled or unconfigured. Provider failures are reported locally and do not affect
monitoring, history or firewall behavior.

## Prompt-injection and action boundary

Evidence strings are untrusted data. The system prompt instructs the model to treat them as data,
return one JSON object and never propose or perform a change. The application parses only the
structured result and has no firewall/shell/file API in the AI code path. Recommended actions are
plain text for a human to review; they are never executed.

## Limitations

- A model finding is one source, not proof of compromise. `INSUFFICIENT_DATA`, `UNKNOWN`,
  `LOW_OBSERVED_RISK`, `SUSPICIOUS` and `SUPPORTED_ALERT` are not equivalent to a confirmed incident.
- Missing ETW bytes, WFP block evidence and reputation stores remain visible as missing evidence.
- Provider APIs and model availability can change; verify the endpoint and model at configuration
  time.
- DNS/Domain attribution is not included in the default evidence package.

## Verification

- `AiAnalystSettingsStore` DPAPI round trip and `AiFindingStore` history tests are in the UI test
  suite.
- `AiEvidenceBuilder`/client unit tests cover redaction, structured parsing, invalid provider
  responses, HTTPS enforcement and status normalization.
- The existing MCP and firewall tests remain unchanged; the AI path has no write capability.
- The AI Analyst page was opened in the real WPF shell with the provider disabled.
