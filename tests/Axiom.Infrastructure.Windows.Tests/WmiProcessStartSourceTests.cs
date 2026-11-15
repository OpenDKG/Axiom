// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Infrastructure.Windows.ProcessIdentity;
using Xunit;

namespace Axiom.Infrastructure.Windows.Tests;

public sealed class WmiProcessStartSourceTests
{
    private static readonly DateTimeOffset At = new(2026, 11, 15, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void A_resolved_image_path_is_used_for_the_child_and_parent()
    {
        var resolved = new Dictionary<int, string>
        {
            [100] = @"C:\Users\lab\Downloads\dropper.exe",
            [50] = @"C:\Users\lab\opencode.exe",
        };

        var spawn = WmiProcessStartSource.Map(100, 50, "dropper.exe", pid => resolved.GetValueOrDefault(pid), At);

        Assert.NotNull(spawn);
        Assert.Equal(@"C:\Users\lab\Downloads\dropper.exe", spawn!.ImagePath);
        Assert.Equal(@"C:\Users\lab\opencode.exe", spawn.ParentImagePath);
        Assert.Equal(100, spawn.ProcessId);
        Assert.Equal(50, spawn.ParentProcessId);
    }

    [Fact]
    public void Without_a_resolver_the_trace_image_name_is_used()
    {
        var spawn = WmiProcessStartSource.Map(101, 50, "notepad.exe", null, At);

        Assert.NotNull(spawn);
        Assert.Equal("notepad.exe", spawn!.ImagePath);
        Assert.Equal(string.Empty, spawn.ParentImagePath);
    }

    [Fact]
    public void An_unresolved_child_falls_back_to_the_name_but_a_resolved_parent_is_kept()
    {
        var spawn = WmiProcessStartSource.Map(
            102,
            50,
            "cmd.exe",
            pid => pid == 50 ? @"C:\Users\lab\opencode.exe" : null,
            At);

        Assert.NotNull(spawn);
        Assert.Equal("cmd.exe", spawn!.ImagePath);
        Assert.Equal(@"C:\Users\lab\opencode.exe", spawn.ParentImagePath);
    }

    [Fact]
    public void An_event_without_a_process_id_is_ignored()
    {
        Assert.Null(WmiProcessStartSource.Map(0, 50, "x.exe", null, At));
    }

    [Fact]
    public void An_event_without_any_name_or_path_is_ignored()
    {
        Assert.Null(WmiProcessStartSource.Map(103, 50, "  ", null, At));
    }
}
