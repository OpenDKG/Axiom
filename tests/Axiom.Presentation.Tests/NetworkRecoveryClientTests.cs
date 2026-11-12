// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Ipc;
using Axiom.Contracts.NetworkRecovery;
using Axiom.Presentation;
using Xunit;

namespace Axiom.Presentation.Tests;

public sealed class NetworkRecoveryClientTests
{
    [Fact]
    public async Task Capture_uses_the_typed_command_and_sends_no_state()
    {
        var transport = new FakeTransport
        {
            Capture = new NetworkRecoveryCaptureResult
            {
                Status = NetworkRecoveryStatus.Succeeded,
                CapturedUtc = DateTimeOffset.UnixEpoch,
                AdapterCount = 2,
                RuleCount = 1,
                Persisted = true,
            },
        };

        var result = await new NetworkRecoveryClient(transport)
            .CaptureAsync(CancellationToken.None);

        Assert.Equal(NetworkRecoveryStatus.Succeeded, result.Status);
        Assert.Equal(IpcCommandTypes.NetworkRecoveryCapture, transport.LastCommand);
        Assert.Null(transport.LastPayload);
    }

    [Fact]
    public async Task Restore_uses_the_typed_command_and_sends_no_state()
    {
        var transport = new FakeTransport
        {
            Restore = new NetworkRecoveryRestoreResult
            {
                Status = NetworkRecoveryStatus.Succeeded,
                AdaptersRestored = 1,
                AdaptersVerified = 1,
                RulesRemoved = 1,
                Verified = true,
            },
        };

        var result = await new NetworkRecoveryClient(transport)
            .RestoreAsync(CancellationToken.None);

        Assert.True(result.Verified);
        Assert.Equal(IpcCommandTypes.NetworkRecoveryRestore, transport.LastCommand);
        Assert.Null(transport.LastPayload);
    }

    [Fact]
    public async Task An_unverified_success_is_not_reported_as_success()
    {
        var transport = new FakeTransport
        {
            Restore = new NetworkRecoveryRestoreResult
            {
                Status = NetworkRecoveryStatus.Succeeded,
                AdaptersRestored = 1,
                Verified = false,
            },
        };

        var result = await new NetworkRecoveryClient(transport)
            .RestoreAsync(CancellationToken.None);

        Assert.Equal(NetworkRecoveryStatus.PartialFailure, result.Status);
        Assert.Contains(result.Problems, problem => problem.Code == "restore.not_verified");
    }

    [Theory]
    [InlineData(IpcErrorCodes.UnknownCommand, NetworkRecoveryStatus.Incompatible)]
    [InlineData(IpcErrorCodes.NotSupported, NetworkRecoveryStatus.Incompatible)]
    [InlineData(IpcErrorCodes.InvalidRequest, NetworkRecoveryStatus.Incompatible)]
    [InlineData(IpcErrorCodes.Unauthorized, NetworkRecoveryStatus.NotAuthorized)]
    [InlineData(IpcErrorCodes.ServiceUnavailable, NetworkRecoveryStatus.Unavailable)]
    [InlineData("unexpected", NetworkRecoveryStatus.Failed)]
    public async Task Service_errors_map_to_truthful_statuses(
        string code,
        NetworkRecoveryStatus expected)
    {
        var transport = new FakeTransport
        {
            Error = new ServiceUnavailableException(code, "test"),
        };
        var client = new NetworkRecoveryClient(transport);

        var capture = await client.CaptureAsync(CancellationToken.None);
        var restore = await client.RestoreAsync(CancellationToken.None);

        Assert.Equal(expected, capture.Status);
        Assert.Equal(expected, restore.Status);
        Assert.False(restore.Verified);
        Assert.NotEmpty(restore.Problems);
    }

    [Fact]
    public void Text_never_claims_success_for_a_partial_or_refused_restore()
    {
        var partial = NetworkRecoveryText.DescribeRestore(new NetworkRecoveryRestoreResult
        {
            Status = NetworkRecoveryStatus.PartialFailure,
            AdaptersRestored = 1,
            AdaptersVerified = 0,
            Problems = [new NetworkRecoveryProblem { Code = "dns.verify_failed", Message = "No read-back.", Item = "Ethernet" }],
        });
        var missing = NetworkRecoveryText.DescribeRestore(new NetworkRecoveryRestoreResult
        {
            Status = NetworkRecoveryStatus.NoSnapshot,
        });
        var incompatible = NetworkRecoveryText.DescribeCapture(new NetworkRecoveryCaptureResult
        {
            Status = NetworkRecoveryStatus.Incompatible,
        });

        Assert.StartsWith("Restore incomplete", partial, StringComparison.Ordinal);
        Assert.Contains("Ethernet: No read-back.", partial, StringComparison.Ordinal);
        Assert.Contains("Nothing was changed", missing, StringComparison.Ordinal);
        Assert.Contains("does not support network recovery", incompatible, StringComparison.Ordinal);
        Assert.DoesNotContain("verified", missing, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Successful_empty_restore_says_nothing_was_restored_and_is_verified()
    {
        var text = NetworkRecoveryText.DescribeRestore(new NetworkRecoveryRestoreResult
        {
            Status = NetworkRecoveryStatus.Succeeded,
            Verified = true,
        });

        Assert.Contains("nothing to restore", text, StringComparison.Ordinal);
        Assert.Contains("verified", text, StringComparison.OrdinalIgnoreCase);
    }

    private sealed class FakeTransport : IServiceRequestClient
    {
        public NetworkRecoveryCaptureResult? Capture { get; init; }

        public NetworkRecoveryRestoreResult? Restore { get; init; }

        public Exception? Error { get; init; }

        public string? LastCommand { get; private set; }

        public object? LastPayload { get; private set; }

        public Task<T> SendAsync<T>(string command, object? payload, CancellationToken cancellationToken)
        {
            LastCommand = command;
            LastPayload = payload;

            if (Error is not null)
            {
                throw Error;
            }

            object? result = command == IpcCommandTypes.NetworkRecoveryCapture ? Capture : Restore;
            return result is T typed
                ? Task.FromResult(typed)
                : throw new InvalidOperationException($"Unexpected command {command}.");
        }
    }
}
