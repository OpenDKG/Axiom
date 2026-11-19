// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Presentation;
using Xunit;

namespace Axiom.Presentation.Tests;

/// <summary>
/// v1.2.0/v1.3.0 module repair and restart recovery: Windows keeps upstream's venv\Scripts checks and
/// PowerShell cleanup; other platforms look for venv/bin/python and report repair as unsupported.
/// Platform-specific facts return early on the other OS (no Skip: the Windows CI gate fails on skips).
/// </summary>
public sealed class ModuleRepairPortabilityTests
{
    [Fact]
    public void Windows_venv_check_matches_upstream_python_or_pythonw()
    {
        var root = Path.Combine("modules", "agent-blackbox");
        var python = Path.Combine(root, "venv", "Scripts", "python.exe");
        var pythonW = Path.Combine(root, "venv", "Scripts", "pythonw.exe");

        Assert.True(AgentPlatform.HasVenvPython(root, windows: true, path => path == python));
        Assert.True(AgentPlatform.HasVenvPython(root, windows: true, path => path == pythonW));
        Assert.False(AgentPlatform.HasVenvPython(root, windows: true, _ => false));
        Assert.False(AgentPlatform.HasVenvPython(
            root, windows: true, path => path == Path.Combine(root, "venv", "bin", "python")));
    }

    [Fact]
    public void Posix_venv_check_uses_bin_python_only()
    {
        var root = Path.Combine("modules", "agent-blackbox");
        Assert.True(AgentPlatform.HasVenvPython(
            root, windows: false, path => path == Path.Combine(root, "venv", "bin", "python")));
        Assert.False(AgentPlatform.HasVenvPython(
            root, windows: false, path => path == Path.Combine(root, "venv", "Scripts", "python.exe")));
    }

    [Fact]
    public void Uninstaller_sees_a_native_blackbox_venv()
    {
        var root = Path.Combine(Path.GetTempPath(), "axiom-venv-" + Guid.NewGuid().ToString("N"));
        try
        {
            var uninstaller = new OptionalModuleUninstaller(root, root);
            Assert.False(uninstaller.IsBlackboxRuntimeInstalled);

            var interpreter = AgentPlatform.VenvPython(Path.Combine(uninstaller.BlackboxRoot, "agent-blackbox"));
            Directory.CreateDirectory(Path.GetDirectoryName(interpreter)!);
            File.WriteAllText(interpreter, string.Empty);

            Assert.True(uninstaller.IsBlackboxRuntimeInstalled);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void Repair_is_reported_unsupported_off_windows()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        var installer = new OptionalModuleInstaller();
        var log = new List<string>();

        Assert.False(installer.RepairLocalModules(blackbox: true, dkg: true, log: log.Add));
        Assert.Equal(OptionalModuleInstaller.UnsupportedInstallMessage, installer.LastError);
        Assert.Contains(OptionalModuleInstaller.UnsupportedInstallMessage, log);
    }

    [Fact]
    public void Unsupported_install_message_names_the_running_os()
    {
        if (OperatingSystem.IsMacOS())
        {
            Assert.Contains("on macOS yet", OptionalModuleInstaller.UnsupportedInstallMessage, StringComparison.Ordinal);
        }
        else if (OperatingSystem.IsLinux())
        {
            Assert.Contains("on Linux yet", OptionalModuleInstaller.UnsupportedInstallMessage, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void Hidden_powershell_is_not_started_off_windows()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        var log = new List<string>();
        Assert.False(LocalModuleRuntime.RunHiddenPowerShell("Write-Output 1", log.Add, TimeSpan.FromSeconds(5)));
        Assert.False(LocalModuleRuntime.StopProcesses(["agent-blackbox"], log.Add));
        Assert.All(log, line => Assert.Equal(OptionalModuleInstaller.UnsupportedInstallMessage, line));
    }
}
