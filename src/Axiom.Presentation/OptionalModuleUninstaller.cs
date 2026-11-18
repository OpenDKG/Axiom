// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics;
using System.IO;
using System.Text;
using Axiom.Contracts;
using Axiom.Contracts.Modules;

namespace Axiom.Presentation;

/// <summary>
/// Removes only Axiom-owned optional-module files. Blackbox and DKG cleanup runs in a hidden
/// PowerShell process; the UI reports the outcome. Unrelated Hermes profiles, global Python/npm
/// packages, user data and user-authored agent files are kept.
/// </summary>
public sealed class OptionalModuleUninstaller
{
    private readonly string _userProfile;

    private readonly string _localAppData;

    /// <summary>Tail of the last failed cleanup, for the module card.</summary>
    public string? LastError { get; private set; }

    public OptionalModuleUninstaller(string? userProfile = null, string? localAppData = null)
    {
        _userProfile = userProfile ?? Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        _localAppData = localAppData ?? Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
    }

    private string ModulesRoot => Path.Combine(_localAppData, "Axiom", "modules");

    public string BlackboxRoot => Path.Combine(ModulesRoot, "blackbox");

    public string DkgRoot => Path.Combine(ModulesRoot, "dkg");

    public string DkgHome => Path.Combine(ModulesRoot, "dkg-home");

    public string BlackboxCommand => Path.Combine(
        _userProfile,
        ".local",
        "bin",
        "blackbox.cmd");

    public string OpenCodePluginDirectory => Path.Combine(
        _userProfile,
        ".config",
        "opencode",
        "plugins",
        "axiom-blackbox");

    public string OpenCodePlugin => Path.Combine(OpenCodePluginDirectory, "index.ts");

    public string OpenCodeV1Plugin => Path.Combine(
        _userProfile,
        ".config",
        "opencode",
        "plugins",
        "axiom-blackbox.ts");

    public string OpenCodeLegacyPlugin => Path.Combine(
        _userProfile,
        ".config",
        "opencode",
        "plugin",
        "axiom-blackbox.ts");

    public string BlackboxPython => Path.Combine(BlackboxRoot, "agent-blackbox", "venv", "Scripts", "python.exe");

    public string BlackboxPythonW => Path.Combine(BlackboxRoot, "agent-blackbox", "venv", "Scripts", "pythonw.exe");

    public string DkgCommand => Path.Combine(DkgRoot, "node_modules", ".bin", "dkg.cmd");

    public bool HasBlackboxFiles => Directory.Exists(BlackboxRoot) || File.Exists(BlackboxCommand);

    public bool IsBlackboxRuntimeInstalled =>
        AgentPlatform.HasVenvPython(Path.Combine(BlackboxRoot, "agent-blackbox")) ||
        AgentPlatform.HasVenvPython(Path.Combine(HermesBlackboxRoot, "agent-blackbox"));

    public string HermesBlackboxRoot => Path.Combine(_localAppData, "hermes", "blackbox");

    public bool IsBlackboxInstalled => HasBlackboxFiles;

    public string ReputationSettingsPath => Path.Combine(_localAppData, "Axiom", "reputation.json");

    public string CommunitySettingsPath => Path.Combine(_localAppData, "Axiom", "community-feed.json");

    public bool HasDkgFiles => Directory.Exists(DkgRoot) || Directory.Exists(DkgHome);

    public bool IsDkgRuntimeInstalled => File.Exists(DkgCommand);

    public bool IsDkgInstalled => HasDkgFiles;

    /// <summary>
    /// Removes only Axiom-managed OpenCode V2/V1 plugins. A user-authored plugin at any current
    /// or legacy path is never deleted.
    /// </summary>
    public bool RemoveManagedOpenCodePlugin()
    {
        if (DistributionContext.IsStorePackage)
        {
            return false;
        }

        var removed = false;
        removed |= RemoveManagedFile(OpenCodePlugin);
        removed |= RemoveManagedFile(OpenCodeV1Plugin);
        removed |= RemoveManagedFile(OpenCodeLegacyPlugin);
        TryRemoveEmptyDirectory(OpenCodePluginDirectory);
        return removed;
    }

    private static void TryRemoveEmptyDirectory(string path)
    {
        try
        {
            if (Directory.Exists(path) &&
                !StorageSafety.IsReparsePointInPath(path) &&
                !Directory.EnumerateFileSystemEntries(path).Any())
            {
                Directory.Delete(path);
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
        }
    }

    public void UninstallBlackbox()
    {
        if (DistributionContext.IsStorePackage)
        {
            return;
        }

        PrepareBlackboxRemoval();
        StartPowerShell(BuildBlackboxUninstallScript());
    }

    public bool UninstallBlackboxAndWait()
    {
        if (DistributionContext.IsStorePackage)
        {
            return false;
        }

        PrepareBlackboxRemoval();
        return RunPowerShellScript(BuildBlackboxUninstallScript());
    }

    public void UninstallDkg()
    {
        if (DistributionContext.IsStorePackage)
        {
            return;
        }

        StartPowerShell(BuildDkgUninstallScript());
    }

    public bool UninstallDkgAndWait() =>
        !DistributionContext.IsStorePackage && RunPowerShellScript(BuildDkgUninstallScript());

    private void PrepareBlackboxRemoval()
    {
        new CodexProtection().Remove();
        new ClaudeProtection().Remove();
        new AntigravityProtection().Remove();
        new CursorProtection().Remove();
        new CopilotProtection().Remove();
        new GeminiProtection().Remove();
        new WindsurfProtection().Remove();
        new ClineProtection().Remove();
        new ZCodeProtection().Remove();
        new DeepSeekProtection().Remove();
        RemoveManagedOpenCodePlugin();
    }

    private string BuildBlackboxUninstallScript() =>
        ModuleUninstallScripts.BuildBlackboxScript(
            BlackboxRoot,
            BlackboxPaths.ResolveHermesHome(_userProfile, _localAppData),
            BlackboxPaths.ResolveBlackboxHome(_userProfile, _localAppData),
            BlackboxCommand);

    private string BuildDkgUninstallScript() =>
        ModuleUninstallScripts.BuildDkgScript(DkgRoot, DkgHome);

    public void RemoveReputationSettings() => DeleteFile(ReputationSettingsPath);

    public void RemoveCommunitySettings() => DeleteFile(CommunitySettingsPath);

    private static bool RemoveManagedFile(string path)
    {
        try
        {
            if (!File.Exists(path) ||
                StorageSafety.IsReparsePointInPath(path) ||
                !File.ReadAllText(path).Contains("Managed by Axiom", StringComparison.Ordinal))
            {
                return false;
            }

            StorageSafety.BackupFile(path);
            File.Delete(path);
            return true;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    private static void DeleteFile(string path)
    {
        try
        {
            if (File.Exists(path) && !StorageSafety.IsReparsePointInPath(path))
            {
                File.Delete(path);
            }
        }
#pragma warning disable CA1031 // Cleanup is best effort; the UI reports the next probe state.
        catch (Exception)
#pragma warning restore CA1031
        {
        }
    }

    private bool RunPowerShellScript(string script)
    {
        if (!OperatingSystem.IsWindows())
        {
            // The uninstall scripts are PowerShell; nothing was installed by them elsewhere.
            return false;
        }

        LastError = null;
        var lines = new List<string>();
        var ok = LocalModuleRuntime.RunHiddenPowerShell(
            script,
            line =>
            {
                lock (lines)
                {
                    lines.Add(line);
                }
            },
            TimeSpan.FromMinutes(3));
        if (!ok)
        {
            string tail;
            lock (lines)
            {
                tail = string.Join(" ", lines.TakeLast(6));
            }

            LastError = string.IsNullOrWhiteSpace(tail)
                ? "The uninstall script did not finish cleanly."
                : tail;
        }

        return ok;
    }

    private static void StartPowerShell(string script)
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
        var startInfo = new ProcessStartInfo(
            "powershell.exe",
            $"-NoProfile -ExecutionPolicy Bypass -NoExit -EncodedCommand {encoded}")
        {
            UseShellExecute = true,
            WorkingDirectory = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
        };

        Process.Start(startInfo);
    }
}
