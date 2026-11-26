// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Core.Protection;
using Axiom.Infrastructure.Windows.Ipc;
using Axiom.Service.Hosting.Ipc;
using Xunit;

namespace Axiom.Service.Tests;

/// <summary>
/// Right after boot Windows may not resolve a domain or Entra ID user. These tests run the real
/// load check and transport with a lookup that fails first; only the pipe itself is replaced.
/// </summary>
public sealed class PipeAllowedSidRetryTests : IDisposable
{
    private const string User = "S-1-12-1-1111111111-2222222222-3333333333-444444444";
    private const string ServiceAccount = "S-1-5-18";

    private readonly string _directory = Directory.CreateTempSubdirectory("axiom-pipe-retry-").FullName;
    private readonly List<string> _served = [];
    private readonly List<string> _log = [];
    private readonly List<TimeSpan> _waits = [];
    private int _lookups;
    private int _openServers;

    public void Dispose() => Directory.Delete(_directory, recursive: true);

    [Theory]
    [InlineData(1)]
    [InlineData(4)]
    [InlineData(9)]
    public async Task The_pipe_allows_the_user_once_the_lookup_succeeds(int failures)
    {
        var transport = Transport(_ => ++_lookups <= failures ? null : SidNameUse.User);
        Assert.Equal(ServiceAccount, transport.Prepare());

        await RunUntilAsync(transport, () => _served.Count == 2);

        Assert.Equal([ServiceAccount, User], _served);
        Assert.Equal(failures + 1, _lookups);
        Assert.Equal(NamedPipeIpcTransport.DefaultRetryDelays.Take(failures), _waits);
        Assert.Equal(User, transport.Prepare());
        Assert.Contains(_log, line => line.Contains($"now allows SID {User}", StringComparison.Ordinal));
        if (OperatingSystem.IsWindows())
        {
            var rules = PipeSecurityFactory.Create(_served[^1])
                .GetAccessRules(true, false, typeof(System.Security.Principal.SecurityIdentifier));
            Assert.Contains(
                rules.Cast<System.IO.Pipes.PipeAccessRule>(),
                rule => rule.IdentityReference.Value == User);
        }
    }

    [Fact]
    public async Task Retries_are_bounded_to_about_five_minutes()
    {
        var transport = Transport(_ =>
        {
            _lookups++;
            return null;
        });

        await RunUntilAsync(transport, () => _log.Any(line => line.Contains("Restart the service", StringComparison.Ordinal)));

        Assert.Equal([ServiceAccount], _served);
        Assert.Equal(1 + NamedPipeIpcTransport.DefaultRetryDelays.Count, _lookups);
        Assert.Equal(TimeSpan.FromMinutes(5), _waits.Aggregate(TimeSpan.Zero, (sum, wait) => sum + wait));
    }

    [Fact]
    public async Task A_sid_that_turns_out_to_be_a_group_is_never_allowed()
    {
        var transport = Transport(_ => ++_lookups <= 2 ? null : SidNameUse.Group);

        await RunUntilAsync(transport, () => _lookups == 3);

        Assert.Equal([ServiceAccount], _served);
        Assert.Equal(3, _lookups);
    }

    [Fact]
    public async Task A_resolved_user_starts_one_server_without_retries()
    {
        var transport = Transport(_ => SidNameUse.User);

        await RunUntilAsync(transport, () => _served.Count == 1);

        Assert.Equal([User], _served);
        Assert.Empty(_waits);
    }

    private NamedPipeIpcTransport Transport(Func<string, SidNameUse?> lookup)
    {
        var store = new ProtectionSettingsStore(Path.Combine(_directory, "protection.json"));
        Assert.True(store.Save(new ProtectionSettings { AllowedSid = User }));
        return new NamedPipeIpcTransport(
            "Axiom.Test.Retry",
            () => ServiceInfo.ResolveAllowedSid(null, store, ServiceAccount, lookup, _ => { }),
            NamedPipeIpcTransport.DefaultRetryDelays,
            (wait, token) =>
            {
                _waits.Add(wait);
                return Task.Delay(TimeSpan.FromMilliseconds(1), token);
            },
            async (sid, _, _, token) =>
            {
                Assert.Equal(1, Interlocked.Increment(ref _openServers)); // never two servers at once
                _served.Add(sid);
                try
                {
                    await Task.Delay(Timeout.Infinite, token);
                }
                finally
                {
                    await Task.Delay(TimeSpan.FromMilliseconds(5), CancellationToken.None);
                    Interlocked.Decrement(ref _openServers);
                }
            });
    }

    private async Task RunUntilAsync(NamedPipeIpcTransport transport, Func<bool> done)
    {
        using var stop = new CancellationTokenSource();
        var dispatcher = new IpcRequestDispatcher(
            new IpcRequestHandlers { SnapshotProvider = () => null, HealthProvider = () => null! },
            () => false,
            _ => { });
        var run = transport.RunAsync(dispatcher, _log.Add, stop.Token);
        var deadline = DateTime.UtcNow.AddSeconds(10);
        while (!done() && !run.IsCompleted && DateTime.UtcNow < deadline)
        {
            await Task.Delay(5);
        }

        await Task.Delay(50); // allow anything unexpected to happen
        Assert.True(done(), "condition not reached");
        await stop.CancelAsync();
        try
        {
            await run;
        }
        catch (OperationCanceledException)
        {
        }
    }
}
