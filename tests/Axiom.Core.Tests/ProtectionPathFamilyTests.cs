// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Monitoring;
using Axiom.Contracts.Protection;
using Axiom.Core.Protection;
using Xunit;

namespace Axiom.Core.Tests;

public sealed class ProtectionPathFamilyTests
{
    [Fact]
    public void Version_folder_is_normalized()
    {
        var key = ProtectionPathFamily.Key(
            @"C:\Program Files (x86)\Google\GoogleUpdater\157.0.8089.0\updater.exe");

        Assert.Equal(@"C:\Program Files (x86)\Google\GoogleUpdater\*\updater.exe", key);
    }

    [Fact]
    public void Hash_folder_and_windowsapps_package_are_normalized()
    {
        Assert.Equal(
            @"C:\Users\llm\AppData\Local\OpenAI\Codex\bin\*\codex.exe",
            ProtectionPathFamily.Key(@"C:\Users\llm\AppData\Local\OpenAI\Codex\bin\f71a721e0e6193a9\codex.exe"));

        Assert.Equal(
            @"C:\Program Files\WindowsApps\*\app\ChatGPT.exe",
            ProtectionPathFamily.Key(
                @"C:\Program Files\WindowsApps\OpenAI.Codex_26.1103.4239.0_x64__2p2nqsd0c76g0\app\ChatGPT.exe"));
    }

    [Fact]
    public void Ordinary_path_is_unchanged()
    {
        const string path = @"C:\Program Files\Google\Chrome\Application\chrome.exe";

        Assert.Equal(path, ProtectionPathFamily.Key(path));
    }

    [Fact]
    public void Detector_applies_a_decision_to_the_next_versioned_path()
    {
        var decisions = new[]
        {
            new ProtectionDecision
            {
                AppPath = @"C:\Program Files (x86)\Google\GoogleUpdater\157.0.8089.0\updater.exe",
                AppName = "updater.exe",
                Action = ProtectionDecisionAction.Block,
                DecidedUtc = DateTimeOffset.UtcNow,
            },
        };

        var pending = PendingAppDetector.Detect(
            [
                Connection(@"C:\Program Files (x86)\Google\GoogleUpdater\158.0.9000.0\updater.exe"),
                Connection(@"C:\Program Files\Other\newapp.exe"),
            ],
            decisions);

        var item = Assert.Single(pending);
        Assert.Equal("newapp.exe", item.AppName);
    }

    private static LiveConnection Connection(string path) => new()
    {
        AppDisplayName = path.Split(['\\', '/'], StringSplitOptions.RemoveEmptyEntries) is { Length: > 0 } segments ? segments[^1] : "unknown",
        AppPath = path,
        ProcessId = 100,
        Protocol = TransportProtocol.Tcp,
        LocalEndpoint = "192.0.2.10:50000",
        RemoteEndpoint = "203.0.113.10:443",
        State = "Established",
        Direction = ConnectionDirection.Outbound,
        InterfaceName = string.Empty,
        FirstObservedUtc = DateTimeOffset.UtcNow,
        Quality = DataQuality.Observed,
    };
}
