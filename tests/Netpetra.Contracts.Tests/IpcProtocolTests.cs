// SPDX-License-Identifier: GPL-3.0-or-later
using Netpetra.Contracts.Ipc;
using Xunit;

namespace Netpetra.Contracts.Tests;

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
}
