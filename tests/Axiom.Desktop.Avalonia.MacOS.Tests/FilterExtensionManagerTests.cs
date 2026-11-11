// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts;
using Axiom.Desktop.Avalonia.MacOS;
using Xunit;

namespace Axiom.Desktop.Avalonia.MacOS.Tests;

/// <summary>The dylib (P/Invoke) activation path and its fallback to the helper (review #4).</summary>
public sealed class FilterExtensionManagerTests
{
    private static readonly FilterExtensionEnvironment InBundle = new(
        IsMacOS: true,
        IsInsideAppBundle: true,
        IsInApplicationsFolder: true,
        HelperPath: "/Applications/Axiom.app/Contents/MacOS/axiom-sysext",
        HelperPresent: true);

    [Theory]
    [InlineData("""{"command":"activate","exitCode":0,"ok":true,"state":"running","filter":{"configured":true,"enabled":true}}""", 0, "running", true, false, false)]
    [InlineData("""{"command":"activate","exitCode":2,"ok":false,"state":"timeout"}""", 2, "timeout", false, false, false)]
    [InlineData("""{"command":"activate","exitCode":3,"ok":false,"state":"needs_approval"}""", 3, "needs_approval", false, true, false)]
    [InlineData("""{"command":"activate","exitCode":4,"ok":false,"state":"reboot_required"}""", 4, "reboot_required", false, false, true)]
    [InlineData("""{"command":"status","exitCode":1,"ok":false,"state":"error","error":{"message":"boom"}}""", 1, "error", false, false, false)]
    public void Library_json_maps_exit_codes_like_the_helper(
        string json, int exitCode, string state, bool running, bool needsApproval, bool needsReboot)
    {
        var status = FilterExtensionStatus.FromLibrary("activate", json);

        Assert.Equal(exitCode, status.ExitCode);
        Assert.Equal(state, status.State);
        Assert.Equal(running, status.IsRunning);
        Assert.Equal(needsApproval, status.NeedsApproval);
        Assert.Equal(needsReboot, status.NeedsReboot);
        Assert.Equal(exitCode == 0, status.Ok);

        // The helper path with the same JSON and exit code gives the same answer.
        Assert.Equal(status, FilterExtensionStatus.Parse("activate", exitCode, json));
    }

    [Fact]
    public void Library_json_without_exit_code_or_garbage_is_safe()
    {
        Assert.Equal(0, FilterExtensionStatus.FromLibrary("status", """{"ok":true,"state":"running"}""").ExitCode);
        Assert.Equal(1, FilterExtensionStatus.FromLibrary("status", """{"ok":false,"state":"error"}""").ExitCode);
        Assert.Equal("error", FilterExtensionStatus.FromLibrary("status", null).State);
        Assert.Equal("error", FilterExtensionStatus.FromLibrary("status", "{not json").State);
        Assert.Equal("libAxiomSysext returned no status.", FilterExtensionStatus.FromLibrary("status", " ").Message);
    }

    [Fact]
    public async Task Prefers_the_dylib_when_present()
    {
        var library = new FakeLibrary(present: true)
        {
            Answer = """{"command":"activate","exitCode":0,"ok":true,"state":"running","filter":{"configured":true,"enabled":true}}""",
        };
        var helper = new FakeHelper();
        var log = new List<string>();
        var manager = new FilterExtensionManager(() => InBundle, library, helper.RunAsync, log.Add);

        var status = await manager.ActivateAsync(CancellationToken.None);

        Assert.True(status.IsRunning);
        Assert.Equal(FilterExtensionPath.Library, manager.LastPath);
        Assert.Equal((SysextLibraryCommand.Activate, 120), Assert.Single(library.Calls));
        Assert.Empty(helper.Calls);
        Assert.Contains(log, line => line.Contains("activate via dylib", StringComparison.Ordinal));
        Assert.True(manager.IsAvailable);
    }

    [Theory]
    [InlineData(typeof(DllNotFoundException))]
    [InlineData(typeof(EntryPointNotFoundException))]
    [InlineData(typeof(BadImageFormatException))]
    public async Task Falls_back_to_the_helper_when_the_dylib_cannot_be_loaded(Type exceptionType)
    {
        var library = new FakeLibrary(present: true) { Throw = (Exception)Activator.CreateInstance(exceptionType, "nope")! };
        var helper = new FakeHelper
        {
            Result = new ToolProcessResult(3, """{"command":"activate","exitCode":3,"ok":false,"state":"needs_approval"}""", string.Empty),
        };
        var log = new List<string>();
        var manager = new FilterExtensionManager(() => InBundle, library, helper.RunAsync, log.Add);

        var status = await manager.ActivateAsync(CancellationToken.None);

        Assert.True(status.NeedsApproval);
        Assert.Equal(3, status.ExitCode);
        Assert.Equal(FilterExtensionPath.Helper, manager.LastPath);
        var call = Assert.Single(helper.Calls);
        Assert.Equal(InBundle.HelperPath, call.Path);
        Assert.Equal(["activate", "--timeout", "120"], call.Arguments);
        Assert.Contains(log, line => line.Contains("falling back to axiom-sysext", StringComparison.Ordinal));
        Assert.Contains(log, line => line.Contains("activate via helper", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Uses_the_helper_when_the_dylib_is_missing_and_reports_unavailable_when_both_are()
    {
        var helper = new FakeHelper
        {
            Result = new ToolProcessResult(0, """{"command":"status","exitCode":0,"ok":true,"state":"running","filter":{"configured":true,"enabled":true}}""", string.Empty),
        };
        var manager = new FilterExtensionManager(() => InBundle, new FakeLibrary(present: false), helper.RunAsync, _ => { });

        Assert.True((await manager.StatusAsync(CancellationToken.None)).IsRunning);
        Assert.Equal(FilterExtensionPath.Helper, manager.LastPath);
        Assert.Equal(["status", "--timeout", "15"], Assert.Single(helper.Calls).Arguments);

        var none = new FilterExtensionManager(
            () => InBundle with { HelperPresent = false }, new FakeLibrary(present: false), helper.RunAsync, _ => { });
        Assert.False(none.IsAvailable);
        var status = await none.StatusAsync(CancellationToken.None);
        Assert.Equal("unavailable", status.State);
        Assert.Contains("libAxiomSysext.dylib", status.Message, StringComparison.Ordinal);

        var brokenOnly = new FilterExtensionManager(
            () => InBundle with { HelperPresent = false },
            new FakeLibrary(present: true) { Throw = new DllNotFoundException("x") },
            helper.RunAsync,
            _ => { });
        Assert.Equal("unavailable", (await brokenOnly.StatusAsync(CancellationToken.None)).State);
        Assert.Equal(FilterExtensionPath.None, brokenOnly.LastPath);
    }

    [Fact]
    public async Task Helper_timeout_and_not_started_map_like_before()
    {
        var timedOut = new FakeHelper { Result = new ToolProcessResult(ToolProcessResult.TimedOutExitCode, string.Empty, string.Empty) };
        var manager = new FilterExtensionManager(() => InBundle, null, timedOut.RunAsync, _ => { });
        var status = await manager.ActivateAsync(CancellationToken.None);
        Assert.Equal(2, status.ExitCode);
        Assert.Equal("timeout", status.State);

        var notStarted = new FakeHelper { Result = new ToolProcessResult(ToolProcessResult.NotStartedExitCode, string.Empty, "denied") };
        var unavailable = await new FilterExtensionManager(() => InBundle, null, notStarted.RunAsync, _ => { }).StatusAsync(CancellationToken.None);
        Assert.Equal("unavailable", unavailable.State);
        Assert.Contains("denied", unavailable.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Platform_and_location_gates_come_first()
    {
        var library = new FakeLibrary(present: true) { Answer = """{"exitCode":0,"ok":true,"state":"running"}""" };
        var helper = new FakeHelper();

        var notMac = new FilterExtensionManager(() => InBundle with { IsMacOS = false }, library, helper.RunAsync, _ => { });
        Assert.Equal("unavailable", (await notMac.ActivateAsync(CancellationToken.None)).State);

        var outsideApplications = new FilterExtensionManager(
            () => InBundle with { IsInApplicationsFolder = false }, library, helper.RunAsync, _ => { });
        Assert.Contains("/Applications", (await outsideApplications.ActivateAsync(CancellationToken.None)).Message, StringComparison.Ordinal);
        Assert.Equal("running", (await outsideApplications.StatusAsync(CancellationToken.None)).State); // status is allowed anywhere

        Assert.Empty(helper.Calls);
        Assert.Equal((SysextLibraryCommand.Status, 15), Assert.Single(library.Calls));
    }

    private sealed class FakeLibrary(bool present) : ISysextLibrary
    {
        public string Path => "/Applications/Axiom.app/Contents/MacOS/libAxiomSysext.dylib";

        public bool IsPresent => present;

        public string? Answer { get; init; }

        public Exception? Throw { get; init; }

        public List<(SysextLibraryCommand Command, int Timeout)> Calls { get; } = [];

        public string? Invoke(SysextLibraryCommand command, int timeoutSeconds)
        {
            Calls.Add((command, timeoutSeconds));
            if (Throw is not null)
            {
                throw Throw;
            }

            return Answer;
        }
    }

    private sealed class FakeHelper
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
