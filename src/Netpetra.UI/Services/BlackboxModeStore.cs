// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics;
using System.IO;

namespace Netpetra.UI.Services;

/// <summary>
/// Reads and writes Blackbox's enforcement mode in the Hermes config. It uses the Blackbox venv's
/// Python + PyYAML, changes only plugins.entries.blackbox.mode, and does not reinstall anything.
/// </summary>
public sealed class BlackboxModeStore
{
    public string BlackboxRoot { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "Netpetra",
        "modules",
        "blackbox",
        "agent-blackbox");

    public string PythonPath => Path.Combine(BlackboxRoot, "venv", "Scripts", "python.exe");

    public string ConfigPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
        ".hermes",
        "config.yaml");

    public bool IsAvailable => File.Exists(PythonPath);

    public string GetMode() => RunPython(null) ?? "audit";

    public bool SetMode(string mode)
    {
        if (mode is not ("audit" or "block"))
        {
            return false;
        }

        if (File.Exists(ConfigPath))
        {
            StorageSafety.BackupFile(ConfigPath);
        }

        return string.Equals(RunPython(mode), mode, StringComparison.OrdinalIgnoreCase);
    }

    private string? RunPython(string? mode)
    {
        if (!IsAvailable)
        {
            return null;
        }

        var script = """
            import os, sys
            try:
                import yaml
            except Exception:
                print("audit")
                sys.exit(0)
            path = sys.argv[1]
            data = {}
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as handle:
                    data = yaml.safe_load(handle) or {}
            plugins = data.setdefault("plugins", {}).setdefault("entries", {}).setdefault("blackbox", {})
            if len(sys.argv) > 2:
                plugins["mode"] = sys.argv[2]
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, "w", encoding="utf-8") as handle:
                    yaml.safe_dump(data, handle, sort_keys=False)
            print(str(plugins.get("mode", "audit")).lower())
            """;

        var startInfo = new ProcessStartInfo(PythonPath)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };

        startInfo.ArgumentList.Add("-c");
        startInfo.ArgumentList.Add(script);
        startInfo.ArgumentList.Add(ConfigPath);
        if (mode is not null)
        {
            startInfo.ArgumentList.Add(mode);
        }

        using var process = Process.Start(startInfo);
        if (process is null)
        {
            return null;
        }

        var output = process.StandardOutput.ReadToEnd().Trim();
        if (!process.WaitForExit(5000))
        {
            process.Kill(entireProcessTree: true);
            return null;
        }

        return output.Length == 0 ? null : output;
    }
}
