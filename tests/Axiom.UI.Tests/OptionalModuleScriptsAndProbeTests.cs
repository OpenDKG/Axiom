// SPDX-License-Identifier: GPL-3.0-or-later
using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using Axiom.Contracts.Modules;
using Axiom.UI.Services;
using Xunit;

namespace Axiom.UI.Tests;

public sealed class OptionalModuleScriptsAndProbeTests
{
    [Fact]
    public void Bootstrap_script_includes_vcredist_npm_to_nodejs_and_non_interactive_exits()
    {
        var report = ModulePrerequisites.Probe(null, _ => false);

        var script = ModulePrerequisites.BuildBootstrapScript(report, includeVcRedist: true, interactive: false);

        Assert.Contains("Microsoft.VCRedist.2015+.x64", script, StringComparison.Ordinal);
        Assert.Contains("OpenJS.NodeJS.LTS", script, StringComparison.Ordinal);
        Assert.Contains("-1978335189", script, StringComparison.Ordinal);
        Assert.DoesNotContain("Read-Host", script, StringComparison.Ordinal);
        Assert.Contains("exit 0", script, StringComparison.Ordinal);
        Assert.Contains("exit 2", script, StringComparison.Ordinal);
    }

    [Fact]
    public void Dkg_uninstall_script_uses_dkg_home_without_overwriting_readonly_powershell_home()
    {
        var script = ModuleUninstallScripts.BuildDkgScript(
            @"C:\Users\alice\.dkg\node",
            @"C:\Users\alice\.dkg\testnet");

        Assert.Contains("$dkgHome =", script, StringComparison.Ordinal);
        Assert.Contains("Remove-SafeDirectory $dkgHome", script, StringComparison.Ordinal);
        Assert.DoesNotContain("$home =", script, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Wait-Process -Id $p.ProcessId -Timeout 5", script, StringComparison.Ordinal);
    }

    [Fact]
    public void Blackbox_uninstall_script_clears_readonly_waits_for_processes_and_guards_tasks()
    {
        var script = ModuleUninstallScripts.BuildBlackboxScript(
            @"C:\Users\alice\.hermes\blackbox",
            @"C:\Users\alice\.hermes",
            @"C:\Users\alice\.blackbox",
            @"C:\Users\alice\AppData\Local\Programs\Python\Python312\Scripts\blackbox.exe");

        Assert.Contains("-Attributes ReadOnly", script, StringComparison.Ordinal);
        Assert.Contains("Wait-Process -Id $p.ProcessId -Timeout 5", script, StringComparison.Ordinal);
        Assert.Contains("Unregister-ScheduledTask", script, StringComparison.Ordinal);
        Assert.Contains("Could not remove scheduled task", script, StringComparison.Ordinal);
    }

    [Fact]
    public void Uninstaller_distinguishes_empty_folders_from_installed_runtimes()
    {
        var root = Path.Combine(Path.GetTempPath(), $"axiom-mod-detect-{Guid.NewGuid():N}");
        var userProfile = Path.Combine(root, "profile");
        var localAppData = Path.Combine(root, "local");
        try
        {
            var uiUninstaller = new OptionalModuleUninstaller(userProfile, localAppData);
            Directory.CreateDirectory(uiUninstaller.BlackboxRoot);
            Directory.CreateDirectory(uiUninstaller.DkgRoot);

            Assert.True(uiUninstaller.HasBlackboxFiles);
            Assert.False(uiUninstaller.IsBlackboxRuntimeInstalled);
            Assert.True(uiUninstaller.HasDkgFiles);
            Assert.False(uiUninstaller.IsDkgRuntimeInstalled);

            Directory.CreateDirectory(Path.GetDirectoryName(uiUninstaller.BlackboxPython)!);
            File.WriteAllText(uiUninstaller.BlackboxPython, string.Empty);
            Directory.CreateDirectory(Path.GetDirectoryName(uiUninstaller.DkgCommand)!);
            File.WriteAllText(uiUninstaller.DkgCommand, "@echo off\n");

            Assert.True(uiUninstaller.IsBlackboxRuntimeInstalled);
            Assert.True(uiUninstaller.IsDkgRuntimeInstalled);
        }
        finally
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    [Fact]
    public async Task Loopback_probe_fails_fast_without_proxy_stall()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var unusedPort = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();

        using var client = OptionalModuleProbe.CreateLoopbackHttpClient(TimeSpan.FromSeconds(2));
        var stopwatch = Stopwatch.StartNew();

        await Assert.ThrowsAnyAsync<Exception>(async () =>
            await client.GetAsync($"http://127.0.0.1:{unusedPort}/api/status"));

        stopwatch.Stop();
        Assert.True(stopwatch.Elapsed < TimeSpan.FromSeconds(3), $"Loopback probe took {stopwatch.Elapsed}");
    }
}
