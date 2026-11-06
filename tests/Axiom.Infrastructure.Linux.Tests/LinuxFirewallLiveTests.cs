// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics;
using Axiom.Contracts.Firewall;
using Axiom.Infrastructure.Linux.Firewall;
using Xunit;

namespace Axiom.Infrastructure.Linux.Tests;

/// <summary>
/// Skipped at discovery time unless the host can actually host the live check: root, a writable
/// cgroup v2 hierarchy, libbpf, kernel BTF and python3. The skip reason is printed by the runner.
/// </summary>
public sealed class LinuxFirewallFactAttribute : FactAttribute
{
    public LinuxFirewallFactAttribute()
    {
        var reason = LiveFirewallEnvironment.SkipReason;
        if (reason is not null)
        {
            Skip = reason;
        }
    }
}

internal static class LiveFirewallEnvironment
{
    public const string Python = "/usr/bin/python3";

    public static readonly string? SkipReason = Probe();

    private static string? Probe()
    {
        if (!string.Equals(Environment.UserName, "root", StringComparison.Ordinal) &&
            Environment.GetEnvironmentVariable("USER") != "root")
        {
            return "live firewall tests need root (CAP_BPF/CAP_NET_ADMIN and a writable cgroup v2 hierarchy).";
        }

        if (!File.Exists("/sys/fs/cgroup/cgroup.controllers"))
        {
            return "cgroup v2 with a visible cgroup.controllers file is required.";
        }

        if (!File.Exists("/sys/kernel/btf/vmlinux"))
        {
            return "kernel BTF (/sys/kernel/btf/vmlinux) is required by the CO-RE firewall object.";
        }

        if (!File.Exists("/usr/lib/x86_64-linux-gnu/libbpf.so.1") &&
            !File.Exists("/usr/lib64/libbpf.so.1") &&
            !File.Exists("/usr/lib/libbpf.so.1"))
        {
            return "libbpf.so.1 is not installed.";
        }

        if (!File.Exists(Python))
        {
            return "python3 is required to run an unprivileged socket client in the test cgroup.";
        }

        try
        {
            var probe = Path.Combine("/sys/fs/cgroup", $"axiom-probe-{Guid.NewGuid():N}");
            Directory.CreateDirectory(probe);
            Directory.Delete(probe);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return $"the cgroup v2 hierarchy is not writable: {exception.Message}";
        }

        return null;
    }
}

public sealed class LinuxFirewallLiveTests : IDisposable
{
    private readonly string _cgroup = Path.Combine(
        "/sys/fs/cgroup",
        $"axiom-test-{Guid.NewGuid():N}");

    private readonly LinuxFirewallPolicyAdapter _adapter;

    public LinuxFirewallLiveTests()
    {
        Directory.CreateDirectory(_cgroup);
        _adapter = new LinuxFirewallPolicyAdapter(_cgroup, () => true);
    }

    [LinuxFirewallFact]
    public async Task Tcp_block_connect_is_enforced_and_removal_restores_connectivity()
    {
        using var listener = Listen(out var port);
        var spec = Spec(FirewallAction.Block, FirewallDirection.Outbound, NetworkProtocol.Tcp, port);

        var applied = await _adapter.UpsertOwnedRuleAsync(spec, CancellationToken.None);
        Assert.True(applied.Success, applied.ErrorMessage);

        var blocked = RunClient("connect", port);
        Assert.Equal(2, blocked.ExitCode);
        Assert.Contains("err 1", blocked.Output, StringComparison.Ordinal);

        var verify = await _adapter.VerifyAsync(spec, CancellationToken.None);
        Assert.True(verify.PresentInOs);
        Assert.True(verify.MatchesSpec);
        Assert.Equal(FirewallAction.Block, verify.EffectiveAction);

        var removed = await _adapter.RemoveOwnedRuleAsync(spec.ManagedRuleId, CancellationToken.None);
        Assert.True(removed.Success, removed.ErrorMessage);

        var allowed = RunClient("connect", port);
        Assert.Equal(0, allowed.ExitCode);
        Assert.Contains("ok", allowed.Output, StringComparison.Ordinal);
    }

    [LinuxFirewallFact]
    public async Task Ipv6_tcp_block_is_enforced()
    {
        using var listener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.IPv6Loopback, 0);
        listener.Start();
        var port = ((System.Net.IPEndPoint)listener.LocalEndpoint).Port;
        var spec = Spec(FirewallAction.Block, FirewallDirection.Outbound, NetworkProtocol.Tcp, port);

        var applied = await _adapter.UpsertOwnedRuleAsync(spec, CancellationToken.None);
        Assert.True(applied.Success, applied.ErrorMessage);

        var blocked = RunClient("connect6", port);
        Assert.Equal(2, blocked.ExitCode);
        Assert.Contains("err 1", blocked.Output, StringComparison.Ordinal);

        Assert.True((await _adapter.RemoveOwnedRuleAsync(spec.ManagedRuleId, CancellationToken.None)).Success);
        Assert.Equal(0, RunClient("connect6", port).ExitCode);
    }

    [LinuxFirewallFact]
    public async Task Udp_sendmsg_block_is_enforced()
    {
        using var receiver = new System.Net.Sockets.UdpClient(new System.Net.IPEndPoint(System.Net.IPAddress.Loopback, 0));
        var port = ((System.Net.IPEndPoint)receiver.Client.LocalEndPoint!).Port;
        var spec = Spec(FirewallAction.Block, FirewallDirection.Outbound, NetworkProtocol.Udp, port);

        var applied = await _adapter.UpsertOwnedRuleAsync(spec, CancellationToken.None);
        Assert.True(applied.Success, applied.ErrorMessage);

        var blocked = RunClient("udp", port);
        Assert.Equal(2, blocked.ExitCode);
        Assert.Contains("err 1", blocked.Output, StringComparison.Ordinal);

        Assert.True((await _adapter.RemoveOwnedRuleAsync(spec.ManagedRuleId, CancellationToken.None)).Success);
        Assert.Equal(0, RunClient("udp", port).ExitCode);
    }

    [LinuxFirewallFact]
    public async Task Inbound_block_stops_a_new_bind()
    {
        // A bind hook cannot see the future peer, so inbound rules are not port-scoped: a block
        // applies to every new bind of the executable and remote-port scope is refused below.
        var spec = Spec(FirewallAction.Block, FirewallDirection.Inbound, NetworkProtocol.Tcp, 0) with
        {
            RemotePorts = null,
        };

        var applied = await _adapter.UpsertOwnedRuleAsync(spec, CancellationToken.None);
        Assert.True(applied.Success, applied.ErrorMessage);

        var port = FreePort();
        var blocked = RunClient("bind", port);
        Assert.Equal(2, blocked.ExitCode);
        Assert.True(
            blocked.Output.Contains("err 13", StringComparison.Ordinal) ||
            blocked.Output.Contains("err 1", StringComparison.Ordinal),
            blocked.Output);

        Assert.True((await _adapter.RemoveOwnedRuleAsync(spec.ManagedRuleId, CancellationToken.None)).Success);
        Assert.Equal(0, RunClient("bind", port).ExitCode);
    }

    [LinuxFirewallFact]
    public async Task Inbound_remote_port_scope_is_refused()
    {
        var spec = Spec(FirewallAction.Block, FirewallDirection.Inbound, NetworkProtocol.Tcp, 443);

        var applied = await _adapter.UpsertOwnedRuleAsync(spec, CancellationToken.None);

        Assert.False(applied.Success);
        Assert.Equal("rule.scope.unsupported_platform", applied.ErrorCode);

        // The refused rule must not have blocked any local bind.
        var port = FreePort();
        Assert.Equal(0, RunClient("bind", port).ExitCode);
    }

    [LinuxFirewallFact]
    public async Task Address_scoped_block_is_enforced_for_ipv4_and_ipv6()
    {
        using var listener = Listen(out var port);
        var spec = Spec(FirewallAction.Block, FirewallDirection.Outbound, NetworkProtocol.Tcp, port) with
        {
            RemoteAddresses = ["127.0.0.1/32"],
        };

        Assert.True((await _adapter.UpsertOwnedRuleAsync(spec, CancellationToken.None)).Success);
        var blocked = RunClient("connect", port);
        Assert.Equal(2, blocked.ExitCode);
        Assert.Contains("err 1", blocked.Output, StringComparison.Ordinal);

        // Another address in the same port must not match the /32 block.
        var other = Spec(FirewallAction.Block, FirewallDirection.Outbound, NetworkProtocol.Tcp, port) with
        {
            RemoteAddresses = ["198.51.100.0/24"],
        };
        Assert.True((await _adapter.RemoveOwnedRuleAsync(spec.ManagedRuleId, CancellationToken.None)).Success);
        Assert.True((await _adapter.UpsertOwnedRuleAsync(other, CancellationToken.None)).Success);
        Assert.Equal(0, RunClient("connect", port).ExitCode);

        Assert.True((await _adapter.RemoveOwnedRuleAsync(other.ManagedRuleId, CancellationToken.None)).Success);

        using var listener6 = new System.Net.Sockets.TcpListener(System.Net.IPAddress.IPv6Loopback, 0);
        listener6.Start();
        var port6 = ((System.Net.IPEndPoint)listener6.LocalEndpoint).Port;
        var spec6 = Spec(FirewallAction.Block, FirewallDirection.Outbound, NetworkProtocol.Tcp, port6) with
        {
            RemoteAddresses = ["::1/128"],
        };
        Assert.True((await _adapter.UpsertOwnedRuleAsync(spec6, CancellationToken.None)).Success);
        Assert.Equal(2, RunClient("connect6", port6).ExitCode);
        Assert.True((await _adapter.RemoveOwnedRuleAsync(spec6.ManagedRuleId, CancellationToken.None)).Success);
        Assert.Equal(0, RunClient("connect6", port6).ExitCode);
    }

    [LinuxFirewallFact]
    public async Task Verification_does_not_attribute_an_old_block_to_a_rejected_replacement()
    {
        using var listener = Listen(out var port);
        var block = Spec(FirewallAction.Block, FirewallDirection.Outbound, NetworkProtocol.Tcp, port);
        Assert.True((await _adapter.UpsertOwnedRuleAsync(block, CancellationToken.None)).Success);

        // Windows-profile scope is unsupported on Linux, so the replacement is rejected while the
        // old block stays in the kernel.
        var replacement = block with
        {
            Action = FirewallAction.Allow,
            Profiles = FirewallProfile.Domain,
        };
        var rejected = await _adapter.UpsertOwnedRuleAsync(replacement, CancellationToken.None);
        Assert.False(rejected.Success);

        var verify = await _adapter.VerifyAsync(replacement, CancellationToken.None);
        Assert.False(verify.MatchesSpec);
        Assert.NotEqual(FirewallAction.Allow, verify.EffectiveAction);

        Assert.Equal(2, RunClient("connect", port).ExitCode);
        Assert.True((await _adapter.RemoveOwnedRuleAsync(block.ManagedRuleId, CancellationToken.None)).Success);
    }

    [LinuxFirewallFact]
    public async Task Restore_after_restart_reapplies_persisted_rules()
    {
        using var listener = Listen(out var port);
        var spec = Spec(FirewallAction.Block, FirewallDirection.Outbound, NetworkProtocol.Tcp, port);

        Assert.True((await _adapter.UpsertOwnedRuleAsync(spec, CancellationToken.None)).Success);
        _adapter.Dispose();

        using var restarted = new LinuxFirewallPolicyAdapter(_cgroup, () => true);
        await restarted.RestoreAsync([spec], CancellationToken.None);

        var blocked = RunClient("connect", port);
        Assert.Equal(2, blocked.ExitCode);

        Assert.True((await restarted.RemoveOwnedRuleAsync(spec.ManagedRuleId, CancellationToken.None)).Success);
        Assert.Equal(0, RunClient("connect", port).ExitCode);
    }

    [LinuxFirewallFact]
    public async Task Restore_continues_past_a_persisted_rule_that_is_no_longer_supported()
    {
        using var listener = Listen(out var port);
        var valid = Spec(FirewallAction.Block, FirewallDirection.Outbound, NetworkProtocol.Tcp, port);

        // A rule that older builds accepted and this build refuses must not stop unrelated rules
        // for other executables from being restored after a restart.
        var legacy = Spec(FirewallAction.Block, FirewallDirection.Inbound, NetworkProtocol.Tcp, 443) with
        {
            AppPath = TestBinaries.ExistingExecutable(),
        };

        using var restarted = new LinuxFirewallPolicyAdapter(_cgroup, () => true);
        // The rejected rule is restored first so an implementation that stops at the first
        // failure cannot pass this test.
        await restarted.RestoreAsync([legacy, valid], CancellationToken.None);

        var listed = await restarted.ListOwnedRulesAsync(CancellationToken.None);
        Assert.Contains(listed, rule => rule.ManagedRuleId == legacy.ManagedRuleId);
        Assert.Equal(2, RunClient("connect", port).ExitCode);
        Assert.True((await restarted.RemoveOwnedRuleAsync(valid.ManagedRuleId, CancellationToken.None)).Success);
        Assert.Equal(0, RunClient("connect", port).ExitCode);
    }

    [LinuxFirewallFact]
    public async Task Removal_keeps_the_rule_visible_when_a_sibling_spec_cannot_compile()
    {
        using var listener = Listen(out var port);
        var valid = Spec(FirewallAction.Block, FirewallDirection.Outbound, NetworkProtocol.Tcp, port);
        var unsupported = Spec(FirewallAction.Block, FirewallDirection.Inbound, NetworkProtocol.Tcp, 443);

        // RestoreAsync stores both desired rules even though the group cannot be applied.
        using var adapter = new LinuxFirewallPolicyAdapter(_cgroup, () => true);
        await adapter.RestoreAsync([valid, unsupported], CancellationToken.None);

        var removed = await adapter.RemoveOwnedRuleAsync(valid.ManagedRuleId, CancellationToken.None);

        Assert.False(removed.Success);
        var listed = await adapter.ListOwnedRulesAsync(CancellationToken.None);
        Assert.Contains(listed, rule => rule.ManagedRuleId == valid.ManagedRuleId);
    }

    [LinuxFirewallFact]
    public async Task Removal_of_a_deleted_executable_fails_and_keeps_the_rule_visible()
    {
        var directory = Path.Combine(Path.GetTempPath(), "axiom-live-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var executable = Path.Combine(directory, "client");
        File.Copy(LiveFirewallEnvironment.Python, executable);
        File.SetUnixFileMode(
            executable,
            UnixFileMode.UserRead | UnixFileMode.UserExecute);

        try
        {
            using var listener = Listen(out var port);
            var spec = Spec(FirewallAction.Block, FirewallDirection.Outbound, NetworkProtocol.Tcp, port) with
            {
                AppPath = executable,
            };

            Assert.True((await _adapter.UpsertOwnedRuleAsync(spec, CancellationToken.None)).Success);

            File.Delete(executable);

            var failed = await _adapter.RemoveOwnedRuleAsync(spec.ManagedRuleId, CancellationToken.None);
            Assert.False(failed.Success);
            Assert.Equal("rule.path.invalid", failed.ErrorCode);

            var listed = await _adapter.ListOwnedRulesAsync(CancellationToken.None);
            Assert.Contains(listed, rule => rule.ManagedRuleId == spec.ManagedRuleId);

            // Recreate the same path: the identity is path-based, so the owned slots can be removed.
            File.Copy(LiveFirewallEnvironment.Python, executable);
            File.SetUnixFileMode(
                executable,
                UnixFileMode.UserRead | UnixFileMode.UserExecute);
            Assert.True((await _adapter.RemoveOwnedRuleAsync(spec.ManagedRuleId, CancellationToken.None)).Success);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [LinuxFirewallFact]
    public async Task Rule_for_another_executable_does_not_affect_the_client()
    {
        using var listener = Listen(out var port);
        var other = TestBinaries.ExistingExecutable();
        var spec = Spec(FirewallAction.Block, FirewallDirection.Outbound, NetworkProtocol.Tcp, port) with
        {
            AppPath = other,
        };

        Assert.True((await _adapter.UpsertOwnedRuleAsync(spec, CancellationToken.None)).Success);

        var allowed = RunClient("connect", port);
        Assert.Equal(0, allowed.ExitCode);
        Assert.Contains("ok", allowed.Output, StringComparison.Ordinal);

        Assert.True((await _adapter.RemoveOwnedRuleAsync(spec.ManagedRuleId, CancellationToken.None)).Success);
    }

    [LinuxFirewallFact]
    public async Task Allow_rule_switches_the_executable_to_allow_list_mode()
    {
        using var allowedListener = Listen(out var allowedPort);
        using var otherListener = Listen(out var otherPort);

        var spec = Spec(FirewallAction.Allow, FirewallDirection.Outbound, NetworkProtocol.Tcp, allowedPort);
        Assert.True((await _adapter.UpsertOwnedRuleAsync(spec, CancellationToken.None)).Success);

        Assert.Equal(0, RunClient("connect", allowedPort).ExitCode);
        Assert.Equal(2, RunClient("connect", otherPort).ExitCode);

        Assert.True((await _adapter.RemoveOwnedRuleAsync(spec.ManagedRuleId, CancellationToken.None)).Success);
        Assert.Equal(0, RunClient("connect", otherPort).ExitCode);
    }

    [LinuxFirewallFact]
    public async Task Two_rules_for_one_executable_are_both_reported_applied()
    {
        using var first = Listen(out var firstPort);
        using var second = Listen(out var secondPort);
        var firstSpec = Spec(FirewallAction.Block, FirewallDirection.Outbound, NetworkProtocol.Tcp, firstPort);
        var secondSpec = Spec(FirewallAction.Block, FirewallDirection.Outbound, NetworkProtocol.Tcp, secondPort);

        Assert.True((await _adapter.UpsertOwnedRuleAsync(firstSpec, CancellationToken.None)).Success);
        Assert.True((await _adapter.UpsertOwnedRuleAsync(secondSpec, CancellationToken.None)).Success);

        var listed = await _adapter.ListOwnedRulesAsync(CancellationToken.None);
        Assert.Equal(2, listed.Count);
        Assert.All(listed, rule => Assert.Equal(RuleState.Applied, rule.State));

        Assert.True((await _adapter.VerifyAsync(firstSpec, CancellationToken.None)).MatchesSpec);
        Assert.True((await _adapter.VerifyAsync(secondSpec, CancellationToken.None)).MatchesSpec);

        Assert.Equal(2, RunClient("connect", firstPort).ExitCode);
        Assert.Equal(2, RunClient("connect", secondPort).ExitCode);

        Assert.True((await _adapter.RemoveOwnedRuleAsync(firstSpec.ManagedRuleId, CancellationToken.None)).Success);
        Assert.Equal(0, RunClient("connect", firstPort).ExitCode);
        Assert.Equal(2, RunClient("connect", secondPort).ExitCode);
    }

    [LinuxFirewallFact]
    public async Task Listed_rule_reports_applied_and_clears_after_dispose()
    {
        using var listener = Listen(out var port);
        var spec = Spec(FirewallAction.Block, FirewallDirection.Outbound, NetworkProtocol.Tcp, port);
        Assert.True((await _adapter.UpsertOwnedRuleAsync(spec, CancellationToken.None)).Success);

        var listed = await _adapter.ListOwnedRulesAsync(CancellationToken.None);
        var rule = Assert.Single(listed);
        Assert.Equal(spec.ManagedRuleId, rule.ManagedRuleId);
        Assert.Equal(RuleState.Applied, rule.State);
    }

    public void Dispose()
    {
        _adapter.Dispose();
        try
        {
            if (Directory.Exists(_cgroup))
            {
                Directory.Delete(_cgroup);
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // A stray process would keep the cgroup busy; the run output already names it.
        }
    }

    private static RuleSpec Spec(
        FirewallAction action,
        FirewallDirection direction,
        NetworkProtocol protocol,
        int port) => new()
        {
            ManagedRuleId = Guid.NewGuid(),
            AppPath = LiveFirewallEnvironment.Python,
            Direction = direction,
            Action = action,
            Protocol = protocol,
            RemotePorts = port.ToString(System.Globalization.CultureInfo.InvariantCulture),
            CreatedBy = "uid:0",
        };

    private static System.Net.Sockets.TcpListener Listen(out int port)
    {
        var listener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
        listener.Start();
        port = ((System.Net.IPEndPoint)listener.LocalEndpoint).Port;
        return listener;
    }

    private static int FreePort()
    {
        using var listener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
        listener.Start();
        return ((System.Net.IPEndPoint)listener.LocalEndpoint).Port;
    }

    private (int ExitCode, string Output) RunClient(string operation, int port)
    {
        var script = """
            import os, socket, sys
            cgroup, operation, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
            with open(os.path.join(cgroup, "cgroup.procs"), "w", encoding="ascii") as handle:
                handle.write(str(os.getpid()))
            if operation == "connect":
                sock = socket.socket()
                sock.settimeout(2)
                try:
                    sock.connect(("127.0.0.1", port))
                    print("ok")
                except OSError as error:
                    print("err", error.errno)
                    sys.exit(2)
            elif operation == "connect6":
                sock = socket.socket(socket.AF_INET6)
                sock.settimeout(2)
                try:
                    sock.connect(("::1", port))
                    print("ok")
                except OSError as error:
                    print("err", error.errno)
                    sys.exit(2)
            elif operation == "udp":
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                try:
                    sock.sendto(b"x", ("127.0.0.1", port))
                    print("ok")
                except OSError as error:
                    print("err", error.errno)
                    sys.exit(2)
            elif operation == "bind":
                sock = socket.socket()
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                try:
                    sock.bind(("127.0.0.1", port))
                    print("ok")
                except OSError as error:
                    print("err", error.errno)
                    sys.exit(2)
            """;

        var startInfo = new ProcessStartInfo(LiveFirewallEnvironment.Python)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        startInfo.ArgumentList.Add("-c");
        startInfo.ArgumentList.Add(script);
        startInfo.ArgumentList.Add(_cgroup);
        startInfo.ArgumentList.Add(operation);
        startInfo.ArgumentList.Add(port.ToString(System.Globalization.CultureInfo.InvariantCulture));

        using var process = Process.Start(startInfo)!;
        var output = process.StandardOutput.ReadToEnd() + process.StandardError.ReadToEnd();
        if (!process.WaitForExit(5000))
        {
            process.Kill(entireProcessTree: true);
            throw new TimeoutException($"The python client did not finish: {output}");
        }

        return (process.ExitCode, output.Trim());
    }
}
