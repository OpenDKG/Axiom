// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO.Pipes;
using System.Security.Principal;
using Axiom.Infrastructure.Windows.Ipc;
using Axiom.Service.Hosting.Ipc;
using Xunit;

namespace Axiom.Infrastructure.Windows.Tests;

public sealed class PipeSidRetryPipeTests
{
    [Fact]
    public async Task The_live_pipe_carries_the_new_acl_after_the_user_resolves()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        // The current user stands in for the service account, so this test may open the pipe both
        // before and after the switch. The user that resolves later is a different SID.
        var serviceSid = WindowsIdentity.GetCurrent().User!.Value;
        const string LaterUser = "S-1-5-21-1111111111-2222222222-3333333333-1001";
        var resolved = false;
        var switched = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var transport = new NamedPipeIpcTransport(
            $"Axiom.Test.{Guid.NewGuid():N}",
            () =>
            {
                var pending = !resolved;
                resolved = true;
                return pending ? new AllowedPipeSid(serviceSid, Pending: true) : new AllowedPipeSid(LaterUser);
            },
            [TimeSpan.FromMilliseconds(500)],
            Task.Delay,
            serve: null);
        var dispatcher = new IpcRequestDispatcher(
            new IpcRequestHandlers { SnapshotProvider = () => null, HealthProvider = () => null! },
            () => false,
            _ => { });
        using var stop = new CancellationTokenSource();
        var run = transport.RunAsync(
            dispatcher,
            line =>
            {
                if (line.Contains("now allows SID", StringComparison.Ordinal))
                {
                    switched.TrySetResult();
                }
            },
            stop.Token);

        try
        {
            await switched.Task.WaitAsync(TimeSpan.FromSeconds(20));
            await using var client = new NamedPipeClientStream(".", transport.Endpoint, PipeDirection.InOut, PipeOptions.Asynchronous);
            await client.ConnectAsync(TimeSpan.FromSeconds(10), CancellationToken.None);

            var rules = client.GetAccessControl().GetAccessRules(true, false, typeof(SecurityIdentifier));

            Assert.Contains(rules.Cast<PipeAccessRule>(), rule => rule.IdentityReference.Value == LaterUser);
        }
        finally
        {
            await stop.CancelAsync();
            try
            {
                await run.WaitAsync(TimeSpan.FromSeconds(10));
            }
            catch (OperationCanceledException)
            {
            }
        }
    }
}
