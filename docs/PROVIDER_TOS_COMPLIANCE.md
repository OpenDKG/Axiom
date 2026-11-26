# Provider Terms of Service Compliance & Hook Audit

Axiom integrates with AI coding agents and LLM providers across three distinct surfaces:

1. **AI Security Analyst** (`Axiom.Contracts.Ai`, `AiAnalystClient`) — optional, default-disabled network investigation.
2. **Agent Protection Hooks** (`*Protection.cs`, `AgentHookScript.cs`, `AgentHookMaintenance.cs`) — local pre/post-tool safety guards using official vendor hook extension points.
3. **Read-Only MCP Server** (`Axiom.McpServer`) — local stdio JSON-RPC server exposing read-only telemetry to unmodified official AI clients.

Axiom enforces provider boundaries in code via `AiProviderCompliancePolicy` and keeps all hook, session, and MCP integrations strictly compliant with provider Terms of Service (ToS).

---

## 1. Provider Compliance Matrix

| Provider | AI Security Analyst (`AiAnalystClient` / `AiProviderCompliancePolicy`) | Agent Protection Hooks | Read-Only MCP Server (`Axiom.McpServer`) | Strictly Prohibited / Blocked |
|---|---|---|---|---|
| **Anthropic (Claude)** | **Compliant** with an official Anthropic Console API key (`AiProviderKind.Anthropic`, `https://api.anthropic.com/v1/messages`, `x-api-key` + `anthropic-version: 2023-06-01`). | **Compliant** (`ClaudeProtection`): merges Axiom's 5 documented lifecycle hooks (`SessionStart`, `UserPromptSubmit`, `PreToolUse`, `PostToolUse`, `Stop`) into `~/.claude/settings.json`. | **Compliant**: connect official unmodified Claude Code to `Axiom.McpServer` via stdio MCP. | Reusing or spoofing Claude Free/Pro/Max/Claude Code OAuth tokens (`sk-ant-oat*` prefix blocked), calling `claude.ai` / `*.claude.ai`, or routing `anthropic/*`, `claude/*`, `claude-code/*`, or `claude-*` through `OpenChamberLocal`. |
| **Google (Antigravity & Gemini)** | **Compliant** with an official Google AI Studio / Gemini Developer API key (`AiProviderKind.GoogleGemini`, `https://generativelanguage.googleapis.com/v1beta/openai/chat/completions`, `AIza...` Bearer key). | **Compliant**: `AntigravityProtection` merges `"axiom-guard"` (`PreToolUse`) into `~/.gemini/config/hooks.json`; `GeminiProtection` merges `BeforeTool` into `~/.gemini/settings.json` only when Gemini CLI is detected. | **Compliant**: connect official unmodified Antigravity or Gemini CLI to `Axiom.McpServer` via stdio MCP. | Piggybacking Antigravity/Gemini CLI OAuth tokens (`ya29.*` prefix blocked), calling private endpoints (`cloudcode-pa.googleapis.com`, `*.cloudcode-pa.googleapis.com`), or routing `antigravity/*`, `google/*`, `google-gemini-cli/*`, `gemini/*`, `gemini-cli/*`, `vertex-antigravity/*`, or `antigravity*` / `gemini-cli*` through `OpenChamberLocal`. |
| **OpenAI (ChatGPT & Codex)** | **Compliant** with an official OpenAI Platform API key (`AiProviderKind.OpenAi`, `https://api.openai.com/v1/chat/completions`). | **Compliant** (`CodexProtection`): merges Axiom's 5 documented lifecycle hooks into `~/.codex/hooks.json`. `CodexTrustInspector` reads `~/.codex/config.toml` read-only and never grants `/hooks` trust. | **Compliant**: connect official unmodified Codex CLI to `Axiom.McpServer` via stdio MCP. | Scraping or automating consumer web endpoints (`chatgpt.com`, `*.chatgpt.com`, `chat.openai.com`) or routing `chatgpt/*`, `codex/*`, or `openai-codex/*` through `OpenChamberLocal`. |
| **GitHub Copilot** | **Not supported as a standalone analyst endpoint** — use an official API provider, OpenRouter, or local inference instead. | **Compliant** (`CopilotProtection`): writes only Axiom's dedicated user hook file `~/.copilot/hooks/axiom.json` (`preToolUse`) for official Copilot CLI. | **Compliant**: connect official unmodified GitHub Copilot CLI / IDE to `Axiom.McpServer` via stdio MCP. | Proxying `api.githubcopilot.com` or `copilot-proxy.githubusercontent.com`, reusing Copilot subscription OAuth tokens from standalone apps, or routing `github-copilot/*` / `copilot/*` through `OpenChamberLocal`. |
| **OpenRouter** | **Compliant** with an official OpenRouter BYOK API key (`AiProviderKind.OpenRouter`, `https://openrouter.ai/api/v1/chat/completions`). Sends `Authorization: Bearer`, `HTTP-Referer: https://github.com/OpenDKG/Axiom`, and `X-Title: Axiom Firewall`. | N/A (API gateway). | Official clients configured with OpenRouter may connect to `Axiom.McpServer` via stdio MCP. | Consumer OAuth tokens or `:free` models routed via `OpenChamberLocal`. |
| **DeepSeek & Z.ai (GLM)** | **Compliant** with official pay-per-token API keys (`AiProviderKind.DeepSeek` → `https://api.deepseek.com/chat/completions`; `AiProviderKind.Zai` → `https://api.z.ai/api/paas/v4/chat/completions`). | **Compliant**: `DeepSeekProtection` writes `~/.dsh/axiom-hooks.json` and mounts `@deepseek-ai/dsh-hooks-claude-code` in `~/.dsh/cordis.patch.yml` for DeepSeek Harness (`dsh`; skips plain `deepseek-cli`). `ZCodeProtection` merges user hooks in `~/.zcode/cli/config.json`. | **Compliant** via official clients connected to `Axiom.McpServer` over stdio MCP. | Unofficial proxies or consumer session token reuse. |
| **OpenCode / OpenChamber** | **Conditional**: `AiProviderKind.OpenCodeZen` (`https://opencode.ai/zen/v1/chat/completions`) with an official OpenCode Zen API key is **compliant**. `AiProviderKind.OpenChamberLocal` (`opencode://local`) is **restricted** to authorized OpenCode-native or local models (`opencode-go/*`, `ollama/*`, `lmstudio/*`, `deepseek/*`, `openrouter/*`). Avoid aggressive `AutomaticAnalysis` background polling on flat-rate plans (`opencode-go/*`). | **Compliant** (`OpenCodeProtection`): installs Axiom's official V2 plugin (`~/.config/opencode/plugins/axiom-blackbox/index.ts`), V1 fallback (`axiom-blackbox.ts`), and local Python bridge (`axiom-guard-bridge.py`), and reads only the local loopback `/api/event` stream. | **Compliant**: connect official OpenCode / OpenChamber to `Axiom.McpServer` via stdio MCP. | Using `OpenChamberLocal` with third-party consumer OAuth logins (`anthropic`, `claude`, `claude-code`, `antigravity`, `google`, `google-gemini-cli`, `gemini`, `gemini-cli`, `vertex-antigravity`, `github-copilot`, `copilot`, `chatgpt`, `codex`, `openai-codex`, `cursor`, `windsurf`) or external-routing-restricted `:free` models (`*:free`, `free`, `opencode/free*`). |
| **Local Models (Ollama, LM Studio, llama.cpp)** | **100% Compliant / Zero Cloud ToS Risk**: `AiProviderKind.LocalOpenAiCompatible` (preset `http://127.0.0.1:11434/v1/chat/completions`). Plain HTTP is allowed **only** on loopback (`127.0.0.1` / `localhost`); zero telemetry or evidence leaves the device. | Local harnesses (`CursorProtection`, `WindsurfProtection`, `ClineProtection`) use documented user-level hook paths only. | **Compliant** when paired with any local stdio MCP host. | Non-loopback plain HTTP endpoints (blocked by `AiAnalystClient.TryValidateEndpoint`). |

---

## 2. Runtime Policy Enforcement (`AiProviderCompliancePolicy`)

`Axiom.Contracts.Ai.AiProviderCompliancePolicy` validates every AI Security Analyst request before any HTTP call is constructed or any `opencode` child process is spawned (`AiAnalystClient.AnalyzeAsync`):

1. **Blocked Consumer & Private Endpoints** (`ValidateRequest`):
   - `cloudcode-pa.googleapis.com` and `*.cloudcode-pa.googleapis.com` (Google Antigravity / Gemini Code Assist private OAuth backend)
   - `claude.ai` and `*.claude.ai` (Anthropic consumer web endpoint)
   - `chatgpt.com`, `*.chatgpt.com`, and `chat.openai.com` (OpenAI consumer web endpoint)
   - `api.githubcopilot.com` and `copilot-proxy.githubusercontent.com` (GitHub Copilot internal proxy)
2. **Blocked Consumer OAuth Token Prefixes** (`ValidateRequest`):
   - `sk-ant-oat*` (case-insensitive) when targeting `AiProviderKind.Anthropic` or `api.anthropic.com` — rejects Claude Pro/Max/Claude Code OAuth tokens and directs users to an Anthropic Console API key (`sk-ant-api...`) or official Claude Code + `Axiom.McpServer`.
   - `ya29.*` (case-insensitive) when targeting `AiProviderKind.GoogleGemini` or `generativelanguage.googleapis.com` — rejects Google Antigravity/Gemini CLI OAuth access tokens and directs users to a Google AI Studio API key (`AIza...`) or official Antigravity/Gemini CLI + `Axiom.McpServer`.
3. **Restricted `OpenChamberLocal` (`opencode://local`) Model Policy** (`ValidateOpenCodeModel`):
   - Validates both `settings.Model` and (when set) `settings.VerifierModel`.
   - Blocks third-party consumer OAuth provider prefixes (`anthropic`, `claude`, `claude-code`, `antigravity`, `google`, `google-gemini-cli`, `gemini`, `gemini-cli`, `vertex-antigravity`, `github-copilot`, `copilot`, `chatgpt`, `codex`, `openai-codex`, `cursor`, `windsurf`) and bare prefixes (`claude-*`, `antigravity*`, `gemini-cli*`).
   - Blocks external-routing-restricted free-tier models (`*:free`, `free`, `opencode/free*`).
4. **Child Environment Scrubbing (`OpenCodeAnalystLaunch`)**:
   - Explicitly removes `CLAUDE_CODE_OAUTH_TOKEN`, `ANTHROPIC_AUTH_TOKEN`, `GOOGLE_CLOUD_ACCESS_TOKEN`, and `GEMINI_CLI_OAUTH_TOKEN` (alongside `OPENCODE_CONFIG`, `OPENCODE_CONFIG_DIR`, `OPENCODE_CLI_CONFIG_CONTENT`, `OPENCODE_PERMISSION`) from the child process environment.
   - Enforces `OPENCODE_DISABLE_CLAUDE_CODE=true`, `OPENCODE_DISABLE_PROJECT_CONFIG=true`, `OPENCODE_DISABLE_AUTOUPDATE=true`, `OPENCODE_DB=:memory:`, an isolated `XDG_CONFIG_HOME`, and deny-all `tool.use` / `mcp.use` / `plugin.use` / `skill.use` policies.

---

## 3. Codebase Audit Verification Results

All agent hook adapters, probes, session readers, MCP server files, and AI analyst clients were audited directly against source:

### 3.1 Protection Adapters & Hook Scripts

Every protection adapter writes only to documented user-level hook configurations and Axiom-owned local scripts under `%LOCALAPPDATA%\Axiom\modules\blackbox\agent-blackbox\`, checks `StorageSafety.IsReparsePointInPath(...)` before touching files, backs up modified JSON/YAML configs with `StorageSafety.BackupFile(...)`, and preserves unrelated user settings and hooks.

| Component | Files Touched (Merged / Owned) | Credential / OAuth Files Touched? | Vendor Binaries Patched? |
|---|---|---|---|
| `src/Axiom.Presentation/AntigravityProtection.cs` | `~/.gemini/config/hooks.json` (`"axiom-guard"` under `PreToolUse`), `axiom-antigravity-hook.py` (+ `.cmd` wrapper if needed) | **No** (never reads `~/.gemini/oauth_creds.json` or `Antigravity/credential-user-scope`) | **No** (read-only `File.Exists` check for `Antigravity.exe`) |
| `src/Axiom.Presentation/ClaudeProtection.cs` | `~/.claude/settings.json` (`hooks.{SessionStart,UserPromptSubmit,PreToolUse,PostToolUse,Stop}`), `axiom-claude-hook.py` | **No** (never reads `~/.claude/.credentials.json` or `~/.claude.json`) | **No** |
| `src/Axiom.Presentation/CodexProtection.cs` (+ `CodexTrustInspector.cs`) | `~/.codex/hooks.json` (5 lifecycle events), `axiom-codex-hook.py`; reads `~/.codex/config.toml` **read-only** to report `CodexTrustState` | **No** (never reads `~/.codex/auth.json`, `auth.lock`, or `.sandbox-secrets`; never writes `config.toml`) | **No** |
| `src/Axiom.Presentation/GeminiProtection.cs` | `~/.gemini/settings.json` (`hooks.BeforeTool`), `axiom-gemini-hook.py` (requires `settings.json` or `gemini` CLI; never touches Antigravity history/MCP) | **No** (never reads `~/.gemini/oauth_creds.json`) | **No** |
| `src/Axiom.Presentation/CopilotProtection.cs` | `~/.copilot/hooks/axiom.json` (`preToolUse`; refuses to overwrite non-Axiom files), `axiom-copilot-hook.py` | **No** (never reads `~/.config/github-copilot/hosts.json` or `gh/hosts.yml`) | **No** |
| `src/Axiom.Presentation/AgentHookScript.cs` | Generates shared Python hook template (`claude`, `codex`, `deepseek`, `zcode`) using `AgentCommandGuard.PythonHelpers` + local `plugins.blackbox.guard.hooks`; logs bounded metadata to `agent-evidence.jsonl` | **No** (and actively blocks agent tool calls attempting to read `.git-credentials`, `.aws`, `.gnupg`, `.npmrc`, `.kube/config`, `gh/hosts.yml`, browser stores, etc.) | **No** |
| `src/Axiom.Presentation/AgentHookProbe.cs` | Executes only Axiom-owned hook scripts (`axiom-*-hook.py`, Cline `PreToolUse.py`, or a temp-dir copy of OpenCode `index.ts` with a synthetic `node` shim) on synthetic `axiom-hook-test.txt` inputs | **No** | **No** (never launches vendor agent binaries) |
| `src/Axiom.Presentation/AgentHookMaintenance.cs` & `UnixAgentSetup.cs` | Writes `%LOCALAPPDATA%\Axiom\hook-maintenance.version` (and `install-profile.json` / Axiom config in `UnixAgentSetup`) and delegates to detected `*Protection` adapters | **No** | **No** |
| `src/Axiom.Presentation/AgentProcessProbe.cs` & `AgentBinaryLocator.cs` | None (read-only `Process.GetProcesses()` process names and `PATH` / standard install-path `File.Exists` checks) | **No** | **No** (never launches, hashes, or patches discovered binaries) |

> **Note on `UserStateProtection.cs`:** `UserStateProtection` references user credential paths (`~/.claude/.credentials.json`, `~/.codex/auth.json`, `~/.local/share/opencode/auth.json`, etc.) **solely** as a defensive integrity snapshot around Axiom setup, hook installation, and uninstall to verify Axiom did not alter or delete user files. It never parses, logs, transmits, or reuses credential contents.

### 3.2 Session Readers, MCP Server, and AI Analyst Connection Paths

- **`src/Axiom.Persistence/AgentSessionReader.cs`**: Strictly read-only (`SqliteOpenMode.ReadOnly`, `Pooling = false`, 7-day history bound, max 30 items, SHA-256 hashed `SessionKey`).
  - Reads only `~/.claude/sessions/*.json` (`kind`, `sessionId`, `pid`, `name`, `cwd`), `~/.codex/(sqlite/)state_*.sqlite` (`threads` table), `~/.local/share/opencode/opencode.db` (`session_v2`/`session` tables), and `~/.gemini/antigravity/conversation_summaries.db` (plus mtime checks on `transcript.jsonl` / `conversations/*.db*`).
  - **Never** reads `~/.claude/.credentials.json`, `~/.gemini/oauth_creds.json`, `~/.codex/auth.json`, `~/.config/github-copilot/hosts.json`, or `~/.local/share/opencode/auth.json`.
- **`src/Axiom.McpServer/` (`Program.cs`, `AxiomTools.cs`, `AxiomServiceClient.cs`, `McpAuditLog.cs`)**:
  - Uses `WithStdioServerTransport()` only — zero HTTP listeners, zero outbound network calls, zero file/command execution tools, and zero credential reads.
  - Queries only the authenticated local Named Pipe (`\\.\pipe\Axiom.Service.v1`) via `AxiomServiceClient` using the 5 read-only IPC commands (`ServiceHealth`, `Capabilities`, `Snapshot`, `HistoryQuery`, `RulesQuery`), exposing 9 read-only MCP tools (`axiom_get_status`, `axiom_list_connections`, `axiom_get_connection_history`, `axiom_inspect_process`, `axiom_analyze_connection`, `axiom_get_threat_alerts`, `axiom_get_reputation`, `axiom_get_firewall_rules`, `axiom_generate_security_report`).
  - Logs only tool name, outcome, and duration to `%LOCALAPPDATA%\Axiom\mcp-audit.jsonl`.
- **`src/Axiom.Contracts/Ai/OpenCodeAnalystLaunch.cs` & `src/Axiom.Presentation/AiAnalystClient.cs`**:
  - `AiAnalystClient` uses standard `HttpClient` without spoofing any provider client `User-Agent` (no `User-Agent` header is injected).
  - Anthropic requests use official `x-api-key` and `anthropic-version: 2023-06-01` headers; OpenAI-compatible requests use `Authorization: Bearer` (with `HTTP-Referer` and `X-Title` added for `AiProviderKind.OpenRouter`); loopback plain HTTP is permitted only for `AiProviderKind.LocalOpenAiCompatible`.
  - No private internal endpoints or OAuth token files are ever read or targeted.
