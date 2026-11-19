// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Infrastructure.Linux.Bpf;

namespace Axiom.Infrastructure.Linux.Nft.Tests;

/// <summary>
/// PR #276 review (brxtrac), finding 3: the stop path logged "BPF layer detached and … removed"
/// after a detach that failed. The line is written only when the detach is confirmed by a readable
/// <c>bpftool cgroup show</c> without Axiom programs and the pin directory is gone.
/// </summary>
public sealed class BpfStopConfirmationTests
{
    private const string DetachedLine = "BPF layer detached and";

    [Fact]
    public async Task Clean_stop_logs_the_detach_and_removes_the_pins()
    {
        using var h = new BpfEffectiveStateTests.Harness();
        await h.AttachAsync();

        await h.Engine.StopAsync();

        Assert.Empty(h.Bpftool.Attached);
        Assert.False(Directory.Exists(h.BpfPaths.PinDirectory));
        Assert.Contains(h.Log, line => line.StartsWith(DetachedLine, StringComparison.Ordinal));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("shim: <<not json>> {")]
    [InlineData("exit1")]
    public async Task Failed_detach_is_never_logged_as_detached(string? showFault)
    {
        using var h = new BpfEffectiveStateTests.Harness();
        await h.AttachAsync();
        h.Bpftool.FailPrefixes.Add("bpftool cgroup detach");
        if (showFault == "exit1")
        {
            h.Bpftool.FailPrefixes.Add("bpftool -j cgroup show");
        }
        else
        {
            h.Bpftool.CgroupShowOutput = showFault;
        }

        await h.Engine.StopAsync();

        Assert.Equal(4, h.Bpftool.Attached.Count);
        Assert.DoesNotContain(h.Log, line => line.StartsWith(DetachedLine, StringComparison.Ordinal));
        Assert.True(Directory.Exists(h.BpfPaths.PinDirectory), "pins are the only handle to still-attached programs");
        Assert.Contains(h.Log, line => line.Contains("not confirmed", StringComparison.Ordinal));
    }
}
