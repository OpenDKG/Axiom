// SPDX-License-Identifier: GPL-3.0-or-later
using System.Net.Sockets;
using Axiom.Contracts.Ipc;
using Xunit;

namespace Axiom.Contracts.Tests;

/// <summary>
/// On Unix the pipe client is a Unix domain socket. .NET's pipe stream retries ENOENT and
/// ECONNREFUSED until the connect timeout (which the client already reports as service
/// unavailable) but rethrows every other connect error as a raw <see cref="SocketException"/>.
/// Right after the daemon restarts its socket exists before its mode is set, so EACCES reached
/// the desktop app unhandled and aborted it (VM look, macOS). Off Windows only: Windows named
/// pipes never raise socket errors.
/// </summary>
public sealed class IpcPipeClientSocketFailureTests
{
    [Fact]
    public async Task Socket_permission_denied_is_a_typed_client_failure_not_a_raw_socket_error()
    {
        if (OperatingSystem.IsWindows() || Environment.UserName == "root")
        {
            return; // root ignores the socket mode, so EACCES cannot be produced.
        }

        var dir = Directory.CreateTempSubdirectory("axiom-ipc-");
        var path = Path.Combine(dir.FullName, "axiom.sock");
        using var listener = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        try
        {
            listener.Bind(new UnixDomainSocketEndPoint(path));
            listener.Listen(1);
            // The daemon's state between bind() and chmod(): the socket is there, nobody may connect.
            File.SetUnixFileMode(path, UnixFileMode.None);

            var client = new IpcPipeClient(path, TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(2));
            var exception = await Assert.ThrowsAsync<IpcClientException>(
                () => client.SendAsync<object>(IpcCommandTypes.ProtectionStatus, null, CancellationToken.None));

            Assert.Equal(IpcErrorCodes.Unauthorized, exception.Code);
            var socketError = Assert.IsType<SocketException>(exception.InnerException);
            Assert.Equal(SocketError.AccessDenied, socketError.SocketErrorCode);
        }
        finally
        {
            listener.Dispose();
            dir.Delete(recursive: true);
        }
    }

    [Fact]
    public async Task A_missing_socket_is_service_unavailable_and_not_a_service_answer()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        var dir = Directory.CreateTempSubdirectory("axiom-ipc-");
        try
        {
            var client = new IpcPipeClient(
                Path.Combine(dir.FullName, "absent.sock"),
                TimeSpan.FromMilliseconds(300),
                TimeSpan.FromSeconds(2));
            var exception = await Assert.ThrowsAsync<IpcClientException>(
                () => client.SendAsync<object>(IpcCommandTypes.ProtectionStatus, null, CancellationToken.None));

            Assert.Equal(IpcErrorCodes.ServiceUnavailable, exception.Code);
        }
        finally
        {
            dir.Delete(recursive: true);
        }
    }
}
