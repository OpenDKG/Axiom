// SPDX-License-Identifier: GPL-3.0-or-later
using System.ComponentModel;
using System.Diagnostics;
using System.Text;

namespace Axiom.Contracts.Ai;

/// <summary>Runs the analyst with OpenCode's standalone server and a deny-all tool policy.</summary>
public static class OpenCodeAnalystLaunch
{
    private static readonly Version MinimumVersion = new(2, 2, 3);

    private const string AgentName = "axiom-analyst";

    private const string AnalystConfiguration = """
        {
          "autoupdate": false,
          "agents": {
            "axiom-analyst": {
              "mode": "primary",
              "steps": 1,
              "permissions": [{ "action": "*", "resource": "*", "effect": "deny" }]
            }
          },
          "policies": [
            { "action": "tool.use", "resource": "*", "effect": "deny" },
            { "action": "mcp.use", "resource": "*", "effect": "deny" },
            { "action": "plugin.use", "resource": "*", "effect": "deny" },
            { "action": "skill.use", "resource": "*", "effect": "deny" }
          ]
        }
        """;

    public static ProcessStartInfo CreateRequest(string executable, string workingDirectory, string model)
    {
        var start = CreateStartInfo(executable, workingDirectory);
        start.ArgumentList.Add("run");
        start.ArgumentList.Add("--standalone");
        start.ArgumentList.Add("--format");
        start.ArgumentList.Add("json");
        start.ArgumentList.Add("--agent");
        start.ArgumentList.Add(AgentName);
        start.ArgumentList.Add("--model");
        start.ArgumentList.Add(model.Trim());
        return start;
    }

    public static async Task<bool> SupportsToolPolicyAsync(
        string executable,
        string workingDirectory,
        CancellationToken cancellationToken)
    {
        if (cancellationToken.IsCancellationRequested)
        {
            return false;
        }

        var start = CreateStartInfo(executable, workingDirectory);
        start.ArgumentList.Add("--version");
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(5));
        try
        {
            using var process = Process.Start(start);
            if (process is null)
            {
                return false;
            }

            process.StandardInput.Close();
            try
            {
                var output = process.StandardOutput.ReadToEndAsync(timeout.Token);
                var errors = process.StandardError.ReadToEndAsync(timeout.Token);
                await Task.WhenAll(output, errors, process.WaitForExitAsync(timeout.Token)).ConfigureAwait(false);
                return process.ExitCode == 0 && IsSupportedVersion(await output.ConfigureAwait(false));
            }
            catch (OperationCanceledException)
            {
                if (!process.HasExited)
                {
                    process.Kill(entireProcessTree: true);
                }

                return false;
            }
        }
        catch (Exception exception) when (exception is Win32Exception or InvalidOperationException or IOException)
        {
            return false;
        }
    }

    private static bool IsSupportedVersion(string output)
    {
        var versionText = output.Trim();
        const string prefix = "opencode ";
        if (versionText.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
        {
            versionText = versionText[prefix.Length..];
        }

        return Version.TryParse(versionText.TrimStart('v'), out var version) &&
               version.Major == MinimumVersion.Major &&
               version >= MinimumVersion;
    }

    private static ProcessStartInfo CreateStartInfo(string executable, string workingDirectory)
    {
        var start = new ProcessStartInfo
        {
            FileName = executable,
            WorkingDirectory = workingDirectory,
            CreateNoWindow = true,
            UseShellExecute = false,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
        };
        start.Environment.Remove("OPENCODE_CONFIG");
        start.Environment.Remove("OPENCODE_CONFIG_DIR");
        start.Environment.Remove("OPENCODE_CLI_CONFIG_CONTENT");
        start.Environment.Remove("OPENCODE_PERMISSION");
        start.Environment.Remove("CLAUDE_CODE_OAUTH_TOKEN");
        start.Environment.Remove("ANTHROPIC_AUTH_TOKEN");
        start.Environment.Remove("GOOGLE_CLOUD_ACCESS_TOKEN");
        start.Environment.Remove("GEMINI_CLI_OAUTH_TOKEN");
        start.Environment["OPENCODE_CONFIG_CONTENT"] = AnalystConfiguration;
        start.Environment["OPENCODE_DISABLE_PROJECT_CONFIG"] = "true";
        start.Environment["OPENCODE_DISABLE_CLAUDE_CODE"] = "true";
        start.Environment["OPENCODE_DISABLE_AUTOUPDATE"] = "true";
        // Keep the existing provider sign-in in the OpenCode data directory. Use a separate
        // configuration directory and keep analyst sessions out of the shared session database.
        start.Environment["XDG_CONFIG_HOME"] = Path.Combine(workingDirectory, "config");
        start.Environment["OPENCODE_DB"] = ":memory:";
        start.Environment["NO_COLOR"] = "1";
        return start;
    }
}
