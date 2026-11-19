// SPDX-License-Identifier: GPL-3.0-or-later
using System.Net;
using Axiom.Contracts.Monitoring;
using Axiom.Contracts.Protection;
using Axiom.Core.Firewall;
using Axiom.Core.Protection;
using Axiom.Contracts.Firewall;
using Xunit;

namespace Axiom.Core.Tests;

public sealed class ProtectionTests
{
    [Fact]
    public void Store_round_trips_consent_and_decisions()
    {
        var path = Path.Combine(Path.GetTempPath(), $"axiom-protection-{Guid.NewGuid():N}.json");
        try
        {
            var store = new ProtectionSettingsStore(path);
            var saved = store.Save(new ProtectionSettings
            {
                Enabled = true,
                AgentLockdown = true,
                DefaultPolicy = "ask",
                Decisions =
                [
                    new ProtectionDecision
                    {
                        AppPath = @"C:\Tools\agent.exe",
                        AppName = "agent.exe",
                        Action = ProtectionDecisionAction.Block,
                        DecidedUtc = DateTimeOffset.UnixEpoch,
                        IsAgentLockdown = true,
                    },
                ],
            });

            Assert.True(saved);
            var loaded = store.Load();
            Assert.True(loaded.Enabled);
            Assert.True(loaded.AgentLockdown);
            Assert.Single(loaded.Decisions!);
            Assert.Equal(ProtectionDecisionAction.Block, loaded.Decisions![0].Action);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Store_treats_corrupt_file_as_no_consent()
    {
        var path = Path.Combine(Path.GetTempPath(), $"axiom-protection-{Guid.NewGuid():N}.json");
        try
        {
            File.WriteAllText(path, "{ not json");
            var loaded = new ProtectionSettingsStore(path).Load();
            Assert.False(loaded.Enabled);
            Assert.Empty(loaded.Decisions!);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Pending_detector_skips_loopback_decided_and_pathless_connections()
    {
        var now = DateTimeOffset.UtcNow;
        var connections = new[]
        {
            Connection(@"C:\Apps\new.exe", now, isLoopback: false, ConnectionDirection.Outbound),
            Connection(@"C:\Apps\new.exe", now.AddSeconds(1), isLoopback: false, ConnectionDirection.Outbound),
            Connection(@"C:\Apps\decided.exe", now, isLoopback: false, ConnectionDirection.Outbound),
            Connection(@"C:\Apps\loop.exe", now, isLoopback: true, ConnectionDirection.Outbound),
            Connection(string.Empty, now, isLoopback: false, ConnectionDirection.Outbound),
            Connection(@"C:\Apps\inbound.exe", now, isLoopback: false, ConnectionDirection.Inbound),
        };

        var pending = PendingAppDetector.Detect(
            connections,
            [
                new ProtectionDecision
                {
                    AppPath = @"C:\Apps\decided.exe",
                    AppName = "decided.exe",
                    Action = ProtectionDecisionAction.Allow,
                    DecidedUtc = now,
                },
            ]);

        var only = Assert.Single(pending);
        Assert.Equal(@"C:\Apps\new.exe", only.AppPath);
        Assert.Equal(2, only.SocketCount);
        Assert.Equal(now, only.FirstObservedUtc);
        Assert.Equal(["203.0.113.5:443"], only.RemoteEndpoints);
    }

    [Fact]
    public void Pending_detector_marks_agents_and_respects_the_limit()
    {
        // Native path per OS: Windows-style rule paths are rejected off Windows (#441).
        var windows = OperatingSystem.IsWindows();
        var agent = windows ? @"C:\Tools\opencode.exe" : "/usr/local/bin/opencode";
        var now = DateTimeOffset.UtcNow;
        var connections = Enumerable.Range(0, 10)
            .Select(index => Connection(windows ? $@"C:\Apps\app{index}.exe" : $"/opt/apps/app{index}", now.AddSeconds(-index), false, ConnectionDirection.Outbound))
            .Append(Connection(agent, now.AddSeconds(-20), false, ConnectionDirection.Outbound))
            .ToList();

        var pending = PendingAppDetector.Detect(connections, [], limit: 5);

        Assert.Equal(5, pending.Count);
        Assert.True(pending[0].IsAgent);
        Assert.Equal(agent, pending[0].AppPath);
    }

    [Fact]
    public void Agent_executable_detection_is_name_and_path_based()
    {
        if (!OperatingSystem.IsWindows())
        {
            // Native separators only (#441): POSIX agent paths match, Windows shapes do not.
            Assert.True(AgentExecutables.IsAgentPath("/usr/local/bin/opencode"));
            Assert.True(AgentExecutables.IsAgentPath("/home/me/.local/bin/codex"));
            Assert.False(AgentExecutables.IsAgentPath(@"C:\Tools\opencode.exe"));
            Assert.False(AgentExecutables.IsAgentPath("/usr/bin/nautilus"));
            Assert.False(AgentExecutables.IsAgentPath(string.Empty));
            return;
        }

        Assert.True(AgentExecutables.IsAgentPath(@"C:\Tools\opencode.exe"));
        Assert.True(AgentExecutables.IsAgentPath(@"C:\Users\me\AppData\Local\Programs\@openchamberelectron\resources\opencode-cli\opencode.exe"));
        Assert.True(AgentExecutables.IsAgentPath(@"C:\Tools\Codex.exe"));
        Assert.True(AgentExecutables.IsAgentPath(
            @"C:\Users\me\AppData\Local\Programs\antigravity\Antigravity.exe"));
        Assert.False(AgentExecutables.IsAgentPath(@"C:\Windows\explorer.exe"));
        Assert.False(AgentExecutables.IsAgentPath(string.Empty));
    }

    [Fact]
    public void Non_loopback_ranges_are_valid_cidr_and_exclude_loopback()
    {
        Assert.InRange(NonLoopbackRanges.All.Count, 1, RuleSpecValidator.MaxRemoteAddresses);

        Assert.DoesNotContain(
            NonLoopbackRanges.All,
            range => Contains(range, IPAddress.Parse("127.0.0.1")));
        Assert.DoesNotContain(
            NonLoopbackRanges.All,
            range => Contains(range, IPAddress.Parse("::1")));
        Assert.Contains(
            NonLoopbackRanges.All,
            range => Contains(range, IPAddress.Parse("8.8.8.8")));
        Assert.Contains(
            NonLoopbackRanges.All,
            range => Contains(range, IPAddress.Parse("2001:4860:4860::8888")));
    }

    [Fact]
    public void Every_non_loopback_range_passes_rule_validation()
    {
        // Native path per OS: Windows-style rule paths are rejected off Windows (#441).
        var agent = OperatingSystem.IsWindows() ? @"C:\Tools\opencode.exe" : "/usr/local/bin/opencode";
        var spec = new RuleSpec
        {
            ManagedRuleId = RuleIdentity.ForApp(agent, FirewallDirection.Outbound),
            AppPath = agent,
            Direction = FirewallDirection.Outbound,
            Action = FirewallAction.Block,
            Profiles = FirewallProfile.All,
            Protocol = NetworkProtocol.Any,
            RemoteAddresses = NonLoopbackRanges.All,
            CreatedBy = "test",
        };

        Assert.True(RuleSpecValidator.Validate(spec).IsValid);
    }

    private static LiveConnection Connection(
        string path,
        DateTimeOffset firstSeen,
        bool isLoopback,
        ConnectionDirection direction) => new()
    {
        AppDisplayName = path.Split(['\\', '/'], StringSplitOptions.RemoveEmptyEntries) is { Length: > 0 } segments ? segments[^1] : "unknown",
        AppPath = path,
        ProcessId = 1,
        Protocol = TransportProtocol.Tcp,
        LocalEndpoint = "127.0.0.1:5000",
        RemoteEndpoint = "203.0.113.5:443",
        State = "Established",
        Direction = direction,
        InterfaceName = string.Empty,
        FirstObservedUtc = firstSeen,
        IsLoopback = isLoopback,
    };

    private static bool Contains(string cidr, IPAddress address)
    {
        var parts = cidr.Split('/');
        var network = IPAddress.Parse(parts[0]);
        var prefix = int.Parse(parts[1], System.Globalization.CultureInfo.InvariantCulture);

        if (network.AddressFamily != address.AddressFamily)
        {
            return false;
        }

        var networkBytes = network.GetAddressBytes();
        var addressBytes = address.GetAddressBytes();
        var fullBytes = prefix / 8;
        var remainingBits = prefix % 8;

        for (var index = 0; index < fullBytes; index++)
        {
            if (networkBytes[index] != addressBytes[index])
            {
                return false;
            }
        }

        if (remainingBits == 0)
        {
            return true;
        }

        var mask = (byte)(0xFF << (8 - remainingBits));
        return (networkBytes[fullBytes] & mask) == (addressBytes[fullBytes] & mask);
    }
}
