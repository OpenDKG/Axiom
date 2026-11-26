// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Ai;
using Axiom.Contracts.Monitoring;
using Axiom.Presentation;
using Xunit;

namespace Axiom.Presentation.Tests;

public sealed class EvidenceCommandLineTests
{
    [Fact]
    public void Enrich_sanitises_the_command_line_again()
    {
        var now = DateTimeOffset.UtcNow;
        var item = new AiEvidenceConnection(
            "connection-1", "app", null, 0, "Tcp", "Outbound", "Established",
            "127.0.0.1:1", "127.0.0.1:2", true, false, now, "Observed");
        var source = new LiveConnection
        {
            AppDisplayName = "app",
            AppPath = string.Empty,
            ProcessId = 0,
            Protocol = TransportProtocol.Tcp,
            LocalEndpoint = "127.0.0.1:1",
            RemoteEndpoint = "127.0.0.1:2",
            State = "Established",
            Direction = ConnectionDirection.Outbound,
            InterfaceName = "lo",
            FirstObservedUtc = now,
            CommandLine = "app --token s3cr3t",
        };

        var enriched = AiEvidenceContext.Enrich(item, source, now);

        Assert.DoesNotContain("s3cr3t", enriched.CommandLine, StringComparison.Ordinal);
        Assert.Equal("app --token ***", enriched.CommandLine);
    }
}
