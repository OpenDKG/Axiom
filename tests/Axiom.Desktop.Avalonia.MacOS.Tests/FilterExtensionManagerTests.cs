// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts;
using Axiom.Desktop.Avalonia.MacOS;
using Xunit;

namespace Axiom.Desktop.Avalonia.MacOS.Tests;

/// <summary>The activation host is the only path; no in-process dylib remains.</summary>
public sealed class FilterExtensionManagerTests
{
    private static readonly FilterExtensionEnvironment InBundle = new(
        IsMacOS: true,
        IsInsideAppBundle: true,
        HostInApplicationsFolder: true,
        HostPath: "/Applications/AxiomFilterHost.app/Contents/MacOS/axiom-sysext",
        HostPresent: true);

    [Theory]
    [InlineData("""{"command":"activate","exitCode":0,"ok":true,"state":"running","filter":{"configured":true,"enabled":true}}""", 0, "running", true, false, false)]
    [InlineData("""{"command":"activate","exitCode":2,"ok":false,"state":"timeout"}""", 2, "timeout", false, false, false)]
    [InlineData("""{"command":"activate","exitCode":3,"ok":false,"state":"needs_approval"}""", 3, "needs_approval", false, true, false)]
    [InlineData("""{"command":"activate","exitCode":4,"ok":false,"state":"reboot_required"}""", 4, "reboot_required", false, false, true)]
    [InlineData("""{"command":"status","exitCode":1,"ok":false,"state":"error","error":{"message":"boom"}}""", 1, "error", false, false, false)]
    public void Host_json_maps_exit_codes(
        string json, int exitCode, string state, bool running, bool needsApproval, bool needsReboot)
    {
        var status = FilterExtensionStatus.Parse("activate", exitCode, json);

        Assert.Equal(exitCode, status.ExitCode);
        Assert.Equal(state, status.State);
        Assert.Equal(running, status.IsRunning);
        Assert.Equal(needsApproval, status.NeedsApproval);
        Assert.Equal(needsReboot, status.NeedsReboot);
        Assert.Equal(exitCode == 0, status.Ok);
    }

    [Fact]
    public async Task Runs_the_signed_host_with_the_protocol_arguments()
    {
        var host = new FakeHost
        {
            Result = new ToolProcessResult(0, """{"command":"activate","exitCode":0,"ok":true,"state":"running","filter":{"configured":true,"enabled":true}}""", string.Empty),
        };
        var log = new List<string>();
        var manager = new FilterExtensionManager(() => InBundle, host.RunAsync, log.Add);

        var status = await manager.ActivateAsync(CancellationToken.None);

        Assert.True(status.IsRunning);
        Assert.Equal(FilterExtensionPath.Host, manager.LastPath);
        var call = Assert.Single(host.Calls);
        Assert.Equal(InBundle.HostPath, call.Path);
        Assert.Equal(["activate", "--timeout", "120"], call.Arguments);
        Assert.Equal(TimeSpan.FromSeconds(150), call.Timeout);
        Assert.Contains(log, line => line.Contains("activate via host", StringComparison.Ordinal));
        Assert.True(manager.IsAvailable);
    }

    [Fact]
    public async Task Passes_a_path_with_spaces_as_one_argument_without_a_shell()
    {
        var environment = InBundle with { HostPath = "/Applications/Axiom Filter Host.app/Contents/MacOS/axiom-sysext" };
        var host = new FakeHost
        {
            Result = new ToolProcessResult(0, """{"exitCode":0,"ok":true,"state":"running","filter":{"enabled":true}}""", string.Empty),
        };
        var manager = new FilterExtensionManager(() => environment, host.RunAsync, _ => { });

        await manager.StatusAsync(CancellationToken.None);

        var call = Assert.Single(host.Calls);
        Assert.Equal(environment.HostPath, call.Path);
        Assert.Equal(["status", "--timeout", "15"], call.Arguments);
    }

    [Fact]
    public async Task Status_is_allowed_before_the_host_is_in_Applications()
    {
        var host = new FakeHost
        {
            Result = new ToolProcessResult(0, """{"exitCode":0,"ok":true,"state":"running","filter":{"enabled":true}}""", string.Empty),
        };
        var manager = new FilterExtensionManager(
            () => InBundle with { HostInApplicationsFolder = false }, host.RunAsync, _ => { });

        Assert.True((await manager.StatusAsync(CancellationToken.None)).IsRunning);

        var activate = await manager.ActivateAsync(CancellationToken.None);
        Assert.Equal("unavailable", activate.State);
        Assert.Contains("AxiomFilterHost.app", activate.Message, StringComparison.Ordinal);
        Assert.Single(host.Calls); // activation never reached the host
    }

    [Fact]
    public async Task Missing_host_and_non_mac_platform_are_unavailable_without_running_anything()
    {
        var host = new FakeHost();
        var missing = new FilterExtensionManager(
            () => InBundle with { HostPresent = false }, host.RunAsync, _ => { });
        Assert.False(missing.IsAvailable);
        var status = await missing.StatusAsync(CancellationToken.None);
        Assert.Equal("unavailable", status.State);
        Assert.Contains("AxiomFilterHost.app", status.Message, StringComparison.Ordinal);

        var notMac = new FilterExtensionManager(
            () => InBundle with { IsMacOS = false }, host.RunAsync, _ => { });
        Assert.Equal("unavailable", (await notMac.ActivateAsync(CancellationToken.None)).State);
        Assert.Empty(host.Calls);
        Assert.Equal(FilterExtensionPath.None, missing.LastPath);
    }

    [Fact]
    public async Task Timeout_and_a_process_that_never_started_map_like_the_cli()
    {
        var timedOut = new FakeHost { Result = new ToolProcessResult(ToolProcessResult.TimedOutExitCode, string.Empty, string.Empty) };
        var manager = new FilterExtensionManager(() => InBundle, timedOut.RunAsync, _ => { });
        var status = await manager.ActivateAsync(CancellationToken.None);
        Assert.Equal(2, status.ExitCode);
        Assert.Equal("timeout", status.State);

        var notStarted = new FakeHost { Result = new ToolProcessResult(ToolProcessResult.NotStartedExitCode, string.Empty, "denied") };
        var unavailable = await new FilterExtensionManager(() => InBundle, notStarted.RunAsync, _ => { }).StatusAsync(CancellationToken.None);
        Assert.Equal("unavailable", unavailable.State);
        Assert.Contains("denied", unavailable.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Garbage_output_is_an_error_not_a_crash()
    {
        Assert.Equal("error", FilterExtensionStatus.Parse("status", 1, "boom").State);
        Assert.Equal("error", FilterExtensionStatus.Parse("status", 1, "{not json}").State);
        Assert.False(FilterExtensionStatus.Parse("status", 0, string.Empty).Ok);
    }

    private sealed class FakeHost
    {
        public ToolProcessResult Result { get; init; } = new(1, string.Empty, "unused");

        public List<(string Path, string[] Arguments, TimeSpan Timeout)> Calls { get; } = [];

        public Task<ToolProcessResult> RunAsync(string path, string[] arguments, TimeSpan timeout, CancellationToken cancellationToken)
        {
            Calls.Add((path, arguments, timeout));
            return Task.FromResult(Result);
        }
    }
}
