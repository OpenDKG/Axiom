// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using System.Text;

namespace Axiom.Presentation;

/// <summary>
/// Reads and writes Blackbox's enforcement mode in the Hermes config. The write is a line-preserving
/// edit of only <c>plugins.entries.blackbox.mode</c>; comments, key order and unrelated YAML stay
/// byte-identical. The original file is backed up before any change.
/// </summary>
public sealed class BlackboxModeStore
{
    private const string DefaultConfig = """
        plugins:
          entries:
            blackbox:
              mode: audit
        """;

    public BlackboxModeStore(string? userProfile = null, string? localAppData = null)
    {
        var profile = userProfile ?? Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var local = localAppData ?? Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        BlackboxRoot = Path.Combine(local, "Axiom", "modules", "blackbox", "agent-blackbox");
        ConfigPath = Path.Combine(
            BlackboxPaths.ResolveHermesHome(profile, local),
            "config.yaml");
    }

    public string BlackboxRoot { get; }

    public string PythonPath => AgentPlatform.VenvPython(BlackboxRoot);

    public string ConfigPath { get; }

    public bool IsAvailable => File.Exists(PythonPath);

    public string GetMode()
    {
        try
        {
            return File.Exists(ConfigPath)
                ? BlackboxYamlMode.ReadMode(File.ReadAllText(ConfigPath))
                : "audit";
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return "audit";
        }
    }

    public bool SetMode(string mode)
    {
        if (mode is not ("audit" or "block") || StorageSafety.IsReparsePointInPath(ConfigPath))
        {
            return false;
        }

        try
        {
            var yaml = File.Exists(ConfigPath) ? File.ReadAllText(ConfigPath) : DefaultConfig;
            var updated = BlackboxYamlMode.SetMode(yaml, mode);
            if (updated is null)
            {
                return false;
            }

            if (File.Exists(ConfigPath))
            {
                StorageSafety.BackupFile(ConfigPath);
            }
            else
            {
                Directory.CreateDirectory(Path.GetDirectoryName(ConfigPath)!);
            }

            File.WriteAllText(ConfigPath, updated, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
            return string.Equals(BlackboxYamlMode.ReadMode(updated), mode, StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }
}
