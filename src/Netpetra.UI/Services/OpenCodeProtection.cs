// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using System.Text;

namespace Netpetra.UI.Services;

/// <summary>
/// Installs the Netpetra/Blackbox guard plugin for OpenCode. OpenChamber uses the same
/// <c>~/.config/opencode</c> plugin directory, so one plugin covers both. The plugin calls the
/// Blackbox Python guard for every tool call; bridge failures fail open, matching Hermes.
/// </summary>
public sealed class OpenCodeProtection
{
    private readonly string _userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

    private readonly string _localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

    private readonly string _roamingAppData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

    public string ConfigDirectory => Path.Combine(_userProfile, ".config", "opencode");

    public string PluginPath => Path.Combine(ConfigDirectory, "plugins", "netpetra-blackbox.ts");

    public string LegacyPluginPath => Path.Combine(ConfigDirectory, "plugin", "netpetra-blackbox.ts");

    public string OpenChamberPath => Path.Combine(
        _localAppData,
        "Programs",
        "@openchamberelectron",
        "OpenChamber.exe");

    private string BlackboxAgentRoot => Path.Combine(
        _localAppData,
        "Netpetra",
        "modules",
        "blackbox",
        "agent-blackbox");

    private string PythonPath => Path.Combine(BlackboxAgentRoot, "venv", "Scripts", "python.exe");

    public string BridgePath => Path.Combine(BlackboxAgentRoot, "netpetra-guard-bridge.py");

    public bool IsOpenCodeDetected => Directory.Exists(ConfigDirectory);

    public bool IsOpenChamberDetected =>
        File.Exists(OpenChamberPath) ||
        Directory.Exists(Path.Combine(_roamingAppData, "openchamber"));

    public bool IsInstalled => File.Exists(PluginPath) && File.Exists(BridgePath);

    /// <summary>Writes the bridge and plugin when OpenCode and the Blackbox venv are present.</summary>
    public bool EnsureInstalled()
    {
        if (!IsOpenCodeDetected || !File.Exists(PythonPath))
        {
            return false;
        }

        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(PluginPath)!);

            if (File.Exists(LegacyPluginPath) &&
                File.ReadAllText(LegacyPluginPath).Contains("Managed by Netpetra", StringComparison.Ordinal))
            {
                File.Delete(LegacyPluginPath);
            }

            var bridge = BuildBridge();
            if (!File.Exists(BridgePath) || File.ReadAllText(BridgePath) != bridge)
            {
                File.WriteAllText(BridgePath, bridge, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
            }

            var plugin = BuildPlugin();
            if (!File.Exists(PluginPath) || File.ReadAllText(PluginPath) != plugin)
            {
                File.WriteAllText(PluginPath, plugin, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
            }

            return true;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    private string BuildPlugin()
    {
        var python = JsPath(PythonPath);
        var bridge = JsPath(BridgePath);
        var workingDirectory = JsPath(BlackboxAgentRoot);

        return $$"""
            // Managed by Netpetra. Installed only when Blackbox is present.
            import { spawnSync } from "node:child_process"

            const python = "{{python}}"
            const bridge = "{{bridge}}"
            const workingDirectory = "{{workingDirectory}}"

            export default {
              id: "netpetra-blackbox",
              async setup(context) {
                context.tool.hook("execute.before", async (event) => {
                  let decision
                  try {
                    const result = spawnSync(python, [bridge], {
                      input: JSON.stringify({
                        tool: event.tool,
                        args: event.input,
                        session: event.sessionID,
                        call: event.id,
                      }),
                      cwd: workingDirectory,
                      encoding: "utf8",
                      timeout: 8000,
                      windowsHide: true,
                    })
                    if (result.status !== 0 || !result.stdout) return
                    decision = JSON.parse(result.stdout)
                  } catch {
                    return
                  }

                  if (decision && decision.action === "block") {
                    throw new Error(decision.message || "Blocked by Netpetra/Blackbox")
                  }
                })
              },
            }
            """;
    }

    private static string BuildBridge() => """
        # Managed by Netpetra. Calls the local Blackbox guard for OpenCode/OpenChamber tool calls.
        import contextlib
        import json
        import sys
        from pathlib import Path

        ROOT = Path(__file__).resolve().parent
        sys.path.insert(0, str(ROOT))


        def main() -> None:
            try:
                payload = json.load(sys.stdin)
                with contextlib.redirect_stdout(sys.stderr):
                    from plugins.blackbox.guard.hooks import on_pre_tool_call

                    decision = on_pre_tool_call(
                        tool_name=str(payload.get("tool", "")),
                        args=payload.get("args") or {},
                        session_id=str(payload.get("session", "")),
                        tool_call_id=str(payload.get("call", "")),
                    )
                print(json.dumps(decision or {}))
            except Exception:
                # Fail open: a Blackbox or bridge fault must not break the host agent.
                print("{}")


        if __name__ == "__main__":
            main()
        """;

    private static string JsPath(string path) =>
        path.Replace("\\", "\\\\", StringComparison.Ordinal)
            .Replace("\"", "\\\"", StringComparison.Ordinal);
}
