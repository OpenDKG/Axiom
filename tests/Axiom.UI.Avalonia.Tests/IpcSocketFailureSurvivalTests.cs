// SPDX-License-Identifier: GPL-3.0-or-later
using System.Net.Sockets;
using System.Reflection;
using Axiom.Presentation;
using Axiom.UI.Avalonia;
using Xunit;

namespace Axiom.UI.Avalonia.Tests;

/// <summary>
/// VM look (macOS): about one second after the daemon restarted, its socket existed without its
/// final mode and <c>AgentsPageViewModel.RefreshThreatShareAsync</c> received a raw
/// <c>SocketException (13): Permission denied</c> that no view-model catch filter names; the async
/// event handler rethrew it and the app aborted. Drive the real Unix client against such a socket:
/// every refresh must report the service as unavailable, never throw. Off Windows only.
/// </summary>
[Collection(DaemonStoppedStaleStateSerial.Name)]
public sealed class IpcSocketFailureSurvivalTests
{
    [Fact]
    public async Task Agents_threat_share_refresh_survives_a_socket_the_daemon_has_not_opened_up_yet()
    {
        if (OperatingSystem.IsWindows() || Environment.UserName == "root")
        {
            return;
        }

        var dir = Directory.CreateTempSubdirectory("axiom-ui-ipc-");
        var path = Path.Combine(dir.FullName, "axiom.sock");
        using var listener = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        listener.Bind(new UnixDomainSocketEndPoint(path));
        listener.Listen(1);
        File.SetUnixFileMode(path, UnixFileMode.None);

        var client = new ServicePipeClient(path, TimeSpan.FromSeconds(2));
        var shell = new ShellViewModel(
            new ServiceSnapshotSource(client),
            new NullTimers(),
            serviceProbe: new ServiceStatusProbe(client),
            serviceClient: client,
            uiModeService: new FixedUiModeService(UiMode.Advanced));
        try
        {
            var refresh = typeof(AgentsPageViewModel)
                .GetMethod("RefreshThreatShareAsync", BindingFlags.NonPublic | BindingFlags.Instance)!;
            await (Task)refresh.Invoke(shell.Agents, null)!;
            Assert.StartsWith("Indicator preview is unavailable", shell.Agents.ThreatShareQueueText, StringComparison.Ordinal);

            // The shell's own reads over the same socket end in the unknown state, not a crash.
            await shell.ProbeProtectionAsync(force: true);
            Assert.Equal("UNKNOWN", shell.StatusFirewallBadgeText);
        }
        finally
        {
            shell.Dispose();
            listener.Dispose();
            dir.Delete(recursive: true);
        }
    }

    private sealed class NullTimers : IUiTimerFactory
    {
        public IUiTimer Create(TimeSpan interval) => new Timer { Interval = interval };

        private sealed class Timer : IUiTimer
        {
            public TimeSpan Interval { get; set; }

            public bool IsEnabled { get; private set; }

            public event EventHandler? Tick
            {
                add { }
                remove { }
            }

            public void Start() => IsEnabled = true;

            public void StopTimer() => IsEnabled = false;

            public void Dispose()
            {
            }
        }
    }
}
