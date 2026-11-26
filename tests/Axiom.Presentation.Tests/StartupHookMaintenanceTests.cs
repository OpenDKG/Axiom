// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Presentation;
using Xunit;

namespace Axiom.Presentation.Tests;

public sealed class StartupHookMaintenanceTests
{
    [Fact]
    public async Task Startup_continues_while_hook_provisioning_is_still_running()
    {
        using var release = new ManualResetEventSlim();

        var running = AgentHookMaintenance.RunInBackground(() => release.Wait(TimeSpan.FromSeconds(10)));

        Assert.False(running.IsCompleted, "the caller must get control back before provisioning ends");
        release.Set();
        await running.WaitAsync(TimeSpan.FromSeconds(10));
    }

    [Fact]
    public async Task A_provisioning_failure_is_reported_and_does_not_fault_startup()
    {
        Exception? reported = null;

        await AgentHookMaintenance.RunInBackground(() => throw new IOException("disk"), error => reported = error);

        Assert.IsType<IOException>(reported);
    }

    [Theory]
    [InlineData("Axiom.Desktop.Avalonia.Windows")]
    [InlineData("Axiom.Desktop.Avalonia.Linux")]
    [InlineData("Axiom.Desktop.Avalonia.MacOS")]
    public void Desktop_apps_do_not_provision_hooks_on_the_startup_thread(string project)
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "PRIVACY.md")))
        {
            directory = directory.Parent;
        }

        var app = File.ReadAllText(Path.Combine(directory!.FullName, "src", project, "App.axaml.cs"));

        Assert.Contains("AgentHookMaintenance.RunInBackground(", app, StringComparison.Ordinal);
        Assert.DoesNotContain("AgentHookMaintenance.ProvisionDetectedHooks();", app, StringComparison.Ordinal);
    }
}
