// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics;
using System.IO;
using System.Text;
using Axiom.Contracts;
using Axiom.Contracts.Modules;

namespace Axiom.UI.Services;

/// <summary>
/// Removes only Axiom-owned optional-module files. Blackbox and DKG cleanup runs in a visible
/// PowerShell window; unrelated Hermes profiles, global Python/npm packages, user data and
/// user-authored agent files are kept.
/// </summary>
public sealed class OptionalModuleUninstaller
{
    private readonly string _userProfile;

    private readonly string _localAppData;

    private readonly string? _environmentHome;

    private readonly string? _environmentBlackboxHome;

    public OptionalModuleUninstaller(string? userProfile = null, string? localAppData = null)
        : this(userProfile, localAppData, environmentHome: null, environmentBlackboxHome: null)
    {
    }

    internal OptionalModuleUninstaller(
        string? userProfile,
        string? localAppData,
        string? environmentHome,
        string? environmentBlackboxHome)
    {
        _userProfile = userProfile ?? Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        _localAppData = localAppData ?? Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        _environmentHome = environmentHome;
        _environmentBlackboxHome = environmentBlackboxHome;
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

    public bool IsBlackboxRuntimeInstalled => File.Exists(BlackboxPython) || File.Exists(BlackboxPythonW);

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
            BlackboxPaths.ResolveHermesHome(_userProfile, _localAppData, _environmentHome),
            BlackboxPaths.ResolveBlackboxHome(
                _userProfile,
                _localAppData,
                _environmentHome,
                _environmentBlackboxHome),
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

    private static bool RunPowerShellScript(string script)
    {
        var encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
        var startInfo = new ProcessStartInfo(
            "powershell.exe",
            $"-NoProfile -ExecutionPolicy Bypass -EncodedCommand {encoded}")
        {
            UseShellExecute = true,
            WorkingDirectory = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            WindowStyle = ProcessWindowStyle.Normal,
        };

        using var process = Process.Start(startInfo);
        if (process is null)
        {
            return false;
        }

        process.WaitForExit();
        return process.ExitCode == 0;
    }

    private static void StartPowerShell(string script)
    {
        var encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
        var startInfo = new ProcessStartInfo(
            "powershell.exe",
            $"-NoProfile -ExecutionPolicy Bypass -NoExit -EncodedCommand {encoded}")
        {
            UseShellExecute = true,
            WorkingDirectory = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
        };

        try
        {
            using var _ = Process.Start(startInfo);
        }
        catch (System.ComponentModel.Win32Exception)
        {
        }
        catch (InvalidOperationException)
        {
        }
    }
}
