// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics;
using Xunit;

namespace Axiom.Infrastructure.Linux.Tests;

/// <summary>
/// The package maintainer scripts must keep Axiom's BPF pins unless the kernel confirms nothing is
/// attached. Runs the real <c>packaging/linux/bpf-pins.sh</c> against a fake bpftool: the pin
/// directory lives in a temp folder, so no host state is touched.
/// </summary>
public sealed class BpfPinCleanupTests
{
    private const string FakeBpftool = """
        #!/bin/sh
        printf '%s\n' "$*" >> "$AXIOM_FAKE_BPFTOOL_LOG"
        case " $* " in
          *" cgroup detach "*)
            case "$AXIOM_FAKE_BPFTOOL_MODE" in
              detach-fails|stale) exit 1 ;;
              *) exit 0 ;;
            esac
            ;;
          *" cgroup show "*)
            case "$AXIOM_FAKE_BPFTOOL_MODE" in
              unreadable) exit 1 ;;
              malformed) echo "not json at all" ; exit 0 ;;
              custom) printf '%s' "$AXIOM_FAKE_BPFTOOL_SHOW" ; exit 0 ;;
              attached|detach-fails)
                echo '[{"id":7,"attach_type":"connect4","attach_flags":"multi","name":"axiom_connect4"}]'
                exit 0
                ;;
              *) echo '[]' ; exit 0 ;;            esac
            ;;
        esac
        exit 0
        """;

    [Theory]
    [InlineData("normal", 0)]
    [InlineData("stale", 0)]
    [InlineData("unreadable", 1)]
    [InlineData("malformed", 1)]
    [InlineData("attached", 1)]
    [InlineData("detach-fails", 1)]
    public void Pins_are_removed_only_after_a_confirmed_detach(string mode, int expectedExit)
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        using var temp = new TempDirectory();
        var pins = Path.Combine(temp.Path, "pins");
        Directory.CreateDirectory(pins);
        foreach (var hook in new[] { "connect4", "connect6", "sendmsg4", "sendmsg6" })
        {
            File.WriteAllText(Path.Combine(pins, "axiom_" + hook), "pin");
        }

        // A sibling that belongs to something else must survive.
        var unrelated = Path.Combine(temp.Path, "other-pins");
        Directory.CreateDirectory(unrelated);
        File.WriteAllText(Path.Combine(unrelated, "keep"), "keep");

        var result = RunScript(temp, pins, mode);

        Assert.Equal(expectedExit, result.ExitCode);
        Assert.True(File.Exists(Path.Combine(unrelated, "keep")));
        if (expectedExit == 0)
        {
            Assert.False(Directory.Exists(pins));
        }
        else
        {
            Assert.True(Directory.Exists(pins));
            Assert.NotEmpty(Directory.GetFileSystemEntries(pins));
            Assert.False(string.IsNullOrWhiteSpace(result.StandardError));
        }
    }

    public static IEnumerable<object[]> AttachmentLists() =>
    [
        // bpftool prints nothing at all when the cgroup has no attached program.
        ["", 0],
        ["[]", 0],
        ["  \n", 0],
        ["""[{"id":1,"name":"foreign_prog"}]""", 0],
        ["""[{"id":1,"name":"x","attach_type":"connect4","attach_flags":"multi"}]""", 0],
        ["""[{"id":1,"name":"x","meta":{"tags":[1,true,null]}}]""", 0],
        ["""[{"id":1,"name":"x"},{"id":2,"name":"y"}]""", 0],
        ["""[{"id":1,"name":"i\u0064"}]""", 0],
        ["""[{"id":4294967295,"name":"x"}]""", 0],
        // A decoded Axiom name is an attachment, however it is escaped.
        ["""[{"id":1,"name":"axiom_connect4"}]""", 1],
        ["""[{"id":1,"name":"axiom_connect\u0034"}]""", 1],
        ["""[{"id":1,"name":"axiom_sendmsg6"}]""", 1],
        ["""[{"id":1,"name":"axiom_sendmsg"},{"id":2,"name":"axiom_sendmsg6"}]""", 1],
        // Anything that is not a complete array of objects with a uint32 id and string name.
        ["[{}]", 1],
        ["[broken]", 1],
        ["not json at all", 1],
        ["{}", 1],
        ["null", 1],
        ["[1]", 1],
        ["""["x"]""", 1],
        ["""[{"id":0,"name":"x"}]""", 1],
        ["""[{"id":"1","name":"x"}]""", 1],
        ["""[{"id":-1,"name":"x"}]""", 1],
        ["""[{"id":1.0,"name":"x"}]""", 1],
        ["""[{"id":0001,"name":"x"}]""", 1],
        ["""[{"id":4294967296,"name":"x"}]""", 1],
        ["""[{"id":1}]""", 1],
        ["""[{"id":1,"name":7}]""", 1],
        ["""[{"id":1,"name":"x","name":"y"}]""", 1],
        ["""[{"id":1,"name":"x"},]""", 1],
        ["""[{"id":1,"name":"x"},{"id":2}]""", 1],
        ["""[] x""", 1],
        ["""[{"id":1,"name":"x"}]{}""", 1],
        ["""[{"id":1,"name":"x\q"}]""", 1],
        ["""[{"id":1,"name":"\ud83d"}]""", 1],
    ];

    [Theory]
    [MemberData(nameof(AttachmentLists))]
    public void Only_a_complete_valid_attachment_list_permits_removal(string show, int expectedExit)
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        using var temp = new TempDirectory();
        var pins = Path.Combine(temp.Path, "pins");
        Directory.CreateDirectory(pins);
        File.WriteAllText(Path.Combine(pins, "axiom_connect4"), "pin");

        var result = RunScript(temp, pins, "custom", show: show);

        Assert.Equal(expectedExit, result.ExitCode);
        if (expectedExit == 0)
        {
            Assert.False(Directory.Exists(pins));
        }
        else
        {
            Assert.True(Directory.Exists(pins));
            Assert.False(string.IsNullOrWhiteSpace(result.StandardError));
        }
    }

    [Fact]
    public void Staging_tree_left_by_an_interrupted_start_is_removed_with_the_pins()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        using var temp = new TempDirectory();
        var pins = Path.Combine(temp.Path, "axiom");
        foreach (var tree in new[] { pins, pins + ".next" })
        {
            Directory.CreateDirectory(tree);
            foreach (var hook in new[] { "connect4", "connect6", "sendmsg4", "sendmsg6" })
            {
                File.WriteAllText(Path.Combine(tree, "axiom_" + hook), "pin");
            }
        }

        var result = RunScript(temp, pins, "normal");

        Assert.Equal(0, result.ExitCode);
        Assert.False(Directory.Exists(pins));
        Assert.False(Directory.Exists(pins + ".next"));
    }

    [Fact]
    public void Missing_awk_keeps_the_pins()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        using var temp = new TempDirectory();
        var pins = Path.Combine(temp.Path, "pins");
        Directory.CreateDirectory(pins);
        File.WriteAllText(Path.Combine(pins, "axiom_connect4"), "pin");

        // Only the fake bpftool is on PATH: the JSON parser is unavailable, so removal must fail.
        var result = RunScript(temp, pins, "custom", show: "[]", includeSystemPath: false);

        Assert.NotEqual(0, result.ExitCode);
        Assert.True(Directory.Exists(pins));
        Assert.Contains("awk is unavailable", result.StandardError, StringComparison.Ordinal);
    }

    [Fact]
    public void Missing_bpftool_keeps_the_pins()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        using var temp = new TempDirectory();
        var pins = Path.Combine(temp.Path, "pins");
        Directory.CreateDirectory(pins);
        File.WriteAllText(Path.Combine(pins, "axiom_connect4"), "pin");

        // PATH without /usr/sbin: the host's real bpftool wrapper is not reachable, so no fake is present.
        var result = RunScript(temp, pins, "normal", installBpftool: false);

        Assert.NotEqual(0, result.ExitCode);
        Assert.True(Directory.Exists(pins));
        Assert.Contains("bpftool is unavailable", result.StandardError, StringComparison.Ordinal);
    }

    [Fact]
    public void Absent_pin_directory_is_a_no_op()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        using var temp = new TempDirectory();
        var result = RunScript(temp, Path.Combine(temp.Path, "missing"), "normal");

        Assert.Equal(0, result.ExitCode);
    }

    private static (int ExitCode, string StandardError) RunScript(
        TempDirectory temp, string pinDirectory, string mode, bool installBpftool = true,
        string? show = null, bool includeSystemPath = true)
    {
        var bin = Path.Combine(temp.Path, "bin");
        Directory.CreateDirectory(bin);
        if (installBpftool)
        {
            var fake = Path.Combine(bin, "bpftool");
            File.WriteAllText(fake, FakeBpftool.ReplaceLineEndings("\n"));
            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(fake, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            }
        }

        var log = Path.Combine(temp.Path, "bpftool.log");
        File.WriteAllText(log, string.Empty);

        var start = new ProcessStartInfo("/bin/sh")
        {
            RedirectStandardError = true,
            RedirectStandardOutput = true,
        };
        start.ArgumentList.Add("-c");
        start.ArgumentList.Add(". \"$1\"; axiom_bpf_pins_remove \"$2\" \"$3\"");
        start.ArgumentList.Add("sh");
        start.ArgumentList.Add(ScriptPath());
        start.ArgumentList.Add(pinDirectory);
        start.ArgumentList.Add("/sys/fs/cgroup");
        start.Environment["PATH"] = includeSystemPath ? bin + ":/usr/bin:/bin" : bin;
        start.Environment["AXIOM_FAKE_BPFTOOL_LOG"] = log;
        start.Environment["AXIOM_FAKE_BPFTOOL_MODE"] = mode;
        if (show is not null)
        {
            start.Environment["AXIOM_FAKE_BPFTOOL_SHOW"] = show;
        }

        using var process = Process.Start(start)!;
        var stderr = process.StandardError.ReadToEnd();
        process.StandardOutput.ReadToEnd();
        process.WaitForExit();
        return (process.ExitCode, stderr);
    }

    private static string ScriptPath()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "Axiom.sln")))
        {
            directory = directory.Parent;
        }

        Assert.NotNull(directory);
        return Path.Combine(directory!.FullName, "packaging", "linux", "bpf-pins.sh");
    }
}
