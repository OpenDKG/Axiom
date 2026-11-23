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
    public void Posix_venv_check_uses_the_native_interpreter_layout()
    {
        var root = Path.Combine("modules", "agent-blackbox");
        Assert.True(AgentPlatform.HasVenvPython(
            root, windows: false, path => path == Path.Combine(root, "venv", "bin", "python")));
        Assert.False(AgentPlatform.HasVenvPython(
            root, windows: false, path => path == Path.Combine(root, "venv", "Scripts", "python.exe")));
    }

    [Fact]
    public void Posix_venv_check_accepts_the_managed_hermes_interpreter_launcher()
    {
        var root = Path.Combine("modules", "agent-blackbox");
        var launcher = Path.Combine(root, "axiom-blackbox-python");

        Assert.Equal(launcher, AgentPlatform.VenvPythonNoConsole(root, windows: false, path => path == launcher));
        Assert.True(AgentPlatform.HasVenvPython(root, windows: false, path => path == launcher));
        Assert.False(AgentPlatform.HasVenvPython(root, windows: true, path => path == launcher));
    }

    [Fact]
    public void Threat_report_venv_interpreter_uses_the_native_layout()
    {
        // 1.4.0 manual reports run only through the runtime or venv interpreter, so the venv path
        // must be the one the platform actually creates.
        var expected = OperatingSystem.IsWindows()
            ? Path.Combine(ThreatShareCli.BlackboxRoot(), "venv", "Scripts", "python.exe")
            : Path.Combine(ThreatShareCli.BlackboxRoot(), "venv", "bin", "python");
        Assert.Equal(expected, ThreatShareCli.VenvPython());
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
    public void Repair_and_install_are_supported_on_windows_linux_and_macos()
    {
        Assert.Equal(
            OperatingSystem.IsWindows() || OperatingSystem.IsLinux() || OperatingSystem.IsMacOS(),
            OptionalModuleInstaller.IsInstallSupported);

        if (OperatingSystem.IsWindows())
        {
            return;
        }

        var installer = new OptionalModuleInstaller();
        var log = new List<string>();
        Assert.True(installer.RepairLocalModules(blackbox: false, dkg: false, log: log.Add));
        Assert.Null(installer.LastError);
    }

    [Fact]
    public void HasVcRuntime_returns_true_off_windows_by_default()
    {
        if (!OperatingSystem.IsWindows())
        {
            Assert.True(OptionalModuleInstaller.HasVcRuntime());
        }

        Assert.False(OptionalModuleInstaller.HasVcRuntime(Path.Combine(Path.GetTempPath(), "nonexistent-win-dir")));
    }

    [Fact]
    public void Hidden_powershell_is_not_started_off_windows_while_unix_shell_is_available()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        var log = new List<string>();
        Assert.False(LocalModuleRuntime.RunHiddenPowerShell("Write-Output 1", log.Add, TimeSpan.FromSeconds(5)));
        Assert.Contains(OptionalModuleInstaller.UnsupportedInstallMessage, log);
        Assert.True(LocalModuleRuntime.RunHiddenShell("echo ok", null, TimeSpan.FromSeconds(5)));
    }
}
