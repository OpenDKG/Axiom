// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO.Pipes;
using System.Text;
using Axiom.Contracts.Ipc;
using Xunit;

namespace Axiom.Contracts.Tests;

public sealed class IpcProtocolTests
{
    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(IpcProtocol.CurrentVersion + 1)]
    public void Unsupported_versions_are_rejected(int version)
    {
        Assert.False(IpcProtocol.IsSupported(version));
    }

    [Fact]
    public void Current_version_is_supported()
    {
        Assert.True(IpcProtocol.IsSupported(IpcProtocol.CurrentVersion));
    }

    [Fact]
    public void Message_limit_is_bounded()
    {
        Assert.InRange(IpcProtocol.MaxMessageBytes, 64 * 1024, 1024 * 1024);
    }

    [Fact]
    public void Command_names_are_unique_and_contain_no_generic_exec()
    {
        Assert.Equal(IpcCommandTypes.All.Count, IpcCommandTypes.All.Distinct(StringComparer.Ordinal).Count());
        Assert.DoesNotContain(IpcCommandTypes.All, name => name.Contains("exec", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Pipe_client_wraps_oversized_response_as_ipc_client_exception()
    {
        var pipeName = $"Axiom.Contracts.Test.{Guid.NewGuid():N}";
        using var server = new NamedPipeServerStream(
            pipeName,
            PipeDirection.InOut,
            1,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous);

        var serverTask = Task.Run(async () =>
        {
            await server.WaitForConnectionAsync().ConfigureAwait(false);
            _ = await IpcLineProtocol.ReadLineAsync(server, IpcProtocol.MaxMessageBytes, CancellationToken.None)
                .ConfigureAwait(false);
            var oversized = new string('a', IpcProtocol.MaxResponseBytes + 128);
            var bytes = Encoding.UTF8.GetBytes(oversized + "\n");
            await server.WriteAsync(bytes).ConfigureAwait(false);
            await server.FlushAsync().ConfigureAwait(false);
        });

        var client = new IpcPipeClient(pipeName);
        var ex = await Assert.ThrowsAsync<IpcClientException>(() =>
            client.SendAsync<ServiceHealth>(IpcCommandTypes.ServiceHealth, null, CancellationToken.None));

        Assert.Equal(IpcErrorCodes.MessageTooLarge, ex.Code);
        await serverTask;
    }
}
