// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics;
using System.Globalization;
using Xunit;

namespace Axiom.Infrastructure.Linux.Tests;

/// <summary>
/// The package maintainer scripts may delete Axiom's leftover unit/image only after the service
/// stop is confirmed. Runs the real <c>packaging/linux/debian/postrm</c> and
/// <c>packaging/linux/rpm/postremove</c> against a fake systemctl and a relocated test root, so
/// no host unit, service or path is touched.
/// </summary>
public sealed class MaintainerScriptCleanupTests
{
    private const string FakeSystemctl = """
        #!/bin/sh
        case "$1" in
          is-active) printf '%s\n' "$AXIOM_FAKE_ACTIVE_STATE"; exit "$AXIOM_FAKE_ACTIVE_EXIT" ;;
          daemon-reload) exit 0 ;;
        esac
        exit 0
        """;

    // deb-systemd-invoke (stop) and deb-systemd-helper (disable) carry the exit code under test;
    // postrm must still read the state back with systemctl before deleting anything.
    private const string FakeSystemdHelper = """
        #!/bin/sh
        exit "$AXIOM_FAKE_DISABLE_EXIT"
        """;

    [Fact]
    public void Deb_remove_after_a_confirmed_stop_removes_leftovers_but_keeps_machine_data()
    {
        using var sandbox = new Sandbox();
        var result = sandbox.Run(DebPostrm, "remove", disableExit: 0, state: "inactive", activeExit: 3);

        Assert.Equal(0, result.ExitCode);
        Assert.False(sandbox.Exists(Sandbox.Unit));
        Assert.False(sandbox.Exists(Sandbox.Image));
        Assert.False(sandbox.Exists(Sandbox.RunDir));
        Assert.True(sandbox.Exists(Sandbox.Data));
        Assert.True(sandbox.Exists(Sandbox.Log));
    }

    [Fact]
    public void Deb_purge_after_a_confirmed_stop_removes_data_and_logs()
    {
        using var sandbox = new Sandbox();
        var result = sandbox.Run(DebPostrm, "purge", disableExit: 0, state: "inactive", activeExit: 3);

        Assert.Equal(0, result.ExitCode);
        Assert.False(sandbox.Exists(Sandbox.Unit));
        Assert.False(sandbox.Exists(Sandbox.Image));
        Assert.False(sandbox.Exists(Sandbox.RunDir));
        Assert.False(sandbox.Exists(Sandbox.Data));
        Assert.False(sandbox.Exists(Sandbox.Log));
    }

    [Fact]
    public void Deb_remove_keeps_everything_when_the_service_is_still_active()
    {
        using var sandbox = new Sandbox();
        var result = sandbox.Run(DebPostrm, "remove", disableExit: 1, state: "active", activeExit: 0);

        Assert.NotEqual(0, result.ExitCode);
        Assert.False(string.IsNullOrWhiteSpace(result.StandardError));
        Assert.True(sandbox.Exists(Sandbox.Unit));
        Assert.True(sandbox.Exists(Sandbox.Image));
        Assert.True(sandbox.Exists(Sandbox.RunDir));
        Assert.True(sandbox.Exists(Sandbox.Data));
    }

    [Fact]
    public void Deb_remove_keeps_everything_when_the_stop_times_out_or_is_unknown()
    {
        using var sandbox = new Sandbox();
        var result = sandbox.Run(DebPostrm, "remove", disableExit: 124, state: string.Empty, activeExit: 124);

        Assert.NotEqual(0, result.ExitCode);
        Assert.True(sandbox.Exists(Sandbox.Unit));
        Assert.True(sandbox.Exists(Sandbox.Image));
        Assert.True(sandbox.Exists(Sandbox.RunDir));
    }

    [Fact]
    public void Deb_purge_keeps_data_and_logs_when_the_stop_is_unconfirmed()
    {
        using var sandbox = new Sandbox();
        var result = sandbox.Run(DebPostrm, "purge", disableExit: 1, state: "active", activeExit: 0);

        Assert.NotEqual(0, result.ExitCode);
        Assert.True(sandbox.Exists(Sandbox.Unit));
        Assert.True(sandbox.Exists(Sandbox.Image));
        Assert.True(sandbox.Exists(Sandbox.RunDir));
        Assert.True(sandbox.Exists(Sandbox.Data));
        Assert.True(sandbox.Exists(Sandbox.Log));
    }

    [Fact]
    public void Deb_remove_keeps_everything_when_systemctl_is_unavailable()
    {
        using var sandbox = new Sandbox(installSystemctl: false);
        var result = sandbox.Run(DebPostrm, "remove", disableExit: 0, state: "inactive", activeExit: 3);

        Assert.NotEqual(0, result.ExitCode);
        Assert.True(sandbox.Exists(Sandbox.Unit));
        Assert.True(sandbox.Exists(Sandbox.Image));
        Assert.True(sandbox.Exists(Sandbox.RunDir));
    }

    [Fact]
    public void Deb_remove_accepts_a_failed_disable_when_the_state_reads_stopped()
    {
        using var sandbox = new Sandbox();
        var result = sandbox.Run(DebPostrm, "remove", disableExit: 1, state: "inactive", activeExit: 3);

        Assert.Equal(0, result.ExitCode);
        Assert.False(sandbox.Exists(Sandbox.Unit));
        Assert.False(sandbox.Exists(Sandbox.Image));
        Assert.False(sandbox.Exists(Sandbox.RunDir));
    }

    [Fact]
    public void Deb_remove_without_the_stop_helpers_still_requires_a_stopped_state()
    {
        using var sandbox = new Sandbox();
        sandbox.RemoveStopHelpers();

        var running = sandbox.Run(DebPostrm, "remove", disableExit: 0, state: "active", activeExit: 0);
        Assert.NotEqual(0, running.ExitCode);
        Assert.True(sandbox.Exists(Sandbox.Image));

        var stopped = sandbox.Run(DebPostrm, "remove", disableExit: 0, state: "inactive", activeExit: 3);
        Assert.Equal(0, stopped.ExitCode);
        Assert.False(sandbox.Exists(Sandbox.Image));
    }

    [Fact]
    public void Deb_remove_with_a_confirmed_stop_removes_a_leftover_enablement_symlink()
    {
        using var sandbox = new Sandbox();
        sandbox.CreateEnablementLink();

        var result = sandbox.Run(DebPostrm, "remove", disableExit: 0, state: "inactive", activeExit: 3);

        Assert.Equal(0, result.ExitCode);
        Assert.False(sandbox.Exists("etc/systemd/system/multi-user.target.wants/axiomd.service"));
    }

    [Fact]
    public void Deb_remove_without_a_unit_removes_the_leftover_image()
    {
        using var sandbox = new Sandbox();
        sandbox.Delete(Sandbox.Unit);

        var result = sandbox.Run(DebPostrm, "remove", disableExit: 0, state: "inactive", activeExit: 3);

        Assert.Equal(0, result.ExitCode);
        Assert.False(sandbox.Exists(Sandbox.Image));
        Assert.False(sandbox.Exists(Sandbox.RunDir));
    }

    [Fact]
    public void Deb_remove_without_a_unit_keeps_the_image_when_the_service_still_reads_active()
    {
        using var sandbox = new Sandbox();
        sandbox.Delete(Sandbox.Unit);

        var result = sandbox.Run(DebPostrm, "remove", disableExit: 1, state: "active", activeExit: 0);

        Assert.NotEqual(0, result.ExitCode);
        Assert.True(sandbox.Exists(Sandbox.Image));
        Assert.True(sandbox.Exists(Sandbox.RunDir));
    }

    [Fact]
    public void Deb_remove_without_a_running_systemd_removes_the_leftover_unit()
    {
        using var sandbox = new Sandbox();
        sandbox.DeleteDirectory(Sandbox.SystemdRun);

        var result = sandbox.Run(DebPostrm, "remove", disableExit: 1, state: "active", activeExit: 0);

        Assert.Equal(0, result.ExitCode);
        Assert.False(sandbox.Exists(Sandbox.Unit));
        Assert.False(sandbox.Exists(Sandbox.Image));
    }

    [Fact]
    public void Deb_upgrade_never_cleans()
    {
        using var sandbox = new Sandbox();
        var result = sandbox.Run(DebPostrm, "upgrade", disableExit: 1, state: "active", activeExit: 0);

        Assert.Equal(0, result.ExitCode);
        Assert.True(sandbox.Exists(Sandbox.Unit));
        Assert.True(sandbox.Exists(Sandbox.Image));
        Assert.True(sandbox.Exists(Sandbox.RunDir));
        Assert.True(sandbox.Exists(Sandbox.Data));
    }

    [Fact]
    public void Rpm_erase_after_a_confirmed_stop_removes_unit_and_image_but_keeps_data()
    {
        using var sandbox = new Sandbox();
        var result = sandbox.Run(RpmPostRemove, "0", disableExit: 0, state: "inactive", activeExit: 3);

        Assert.Equal(0, result.ExitCode);
        Assert.False(sandbox.Exists(Sandbox.Unit));
        Assert.False(sandbox.Exists(Sandbox.Image));
        Assert.False(sandbox.Exists(Sandbox.RunDir));
        Assert.True(sandbox.Exists(Sandbox.Data));
        Assert.True(sandbox.Exists(Sandbox.Log));
    }

    [Fact]
    public void Rpm_erase_keeps_everything_when_the_service_is_still_active()
    {
        using var sandbox = new Sandbox();
        var result = sandbox.Run(RpmPostRemove, "0", disableExit: 1, state: "active", activeExit: 0);

        Assert.NotEqual(0, result.ExitCode);
        Assert.True(sandbox.Exists(Sandbox.Unit));
        Assert.True(sandbox.Exists(Sandbox.Image));
        Assert.True(sandbox.Exists(Sandbox.RunDir));
    }

    [Fact]
    public void Rpm_upgrade_never_cleans()
    {
        using var sandbox = new Sandbox();
        var result = sandbox.Run(RpmPostRemove, "1", disableExit: 1, state: "active", activeExit: 0);

        Assert.Equal(0, result.ExitCode);
        Assert.True(sandbox.Exists(Sandbox.Unit));
        Assert.True(sandbox.Exists(Sandbox.Image));
    }

    private sealed class Sandbox : IDisposable
    {
        public const string Unit = "etc/systemd/system/axiomd.service";
        public const string Image = "usr/libexec/axiom";
        public const string RunDir = "run/axiom";
        public const string Data = "var/lib/axiom";
        public const string Log = "var/log/axiom";
        public const string SystemdRun = "run/systemd/system";

        private readonly TempDirectory _temp = new();

        public Sandbox(bool installSystemctl = true)
        {
            foreach (var directory in new[] { "etc/systemd/system", "usr/libexec/axiom", "run/axiom", "run/systemd/system", "var/lib/axiom", "var/log/axiom", "bin" })
            {
                Directory.CreateDirectory(Absolute(directory));
            }

            File.WriteAllText(Absolute(Unit), "unit");
            File.WriteAllText(Path.Combine(Absolute(Image), "axiomd"), "image");
            File.WriteAllText(Path.Combine(Absolute(RunDir), "axiom.sock"), "run");
            File.WriteAllText(Path.Combine(Absolute(Data), "axiom.db"), "data");
            File.WriteAllText(Path.Combine(Absolute(Log), "axiomd.log"), "log");
            File.CreateSymbolicLink(Path.Combine(Absolute("bin"), "rm"), "/bin/rm");
            File.CreateSymbolicLink(Path.Combine(Absolute("bin"), "find"), "/usr/bin/find");

            if (installSystemctl)
            {
                var systemctl = Path.Combine(Absolute("bin"), "systemctl");
                File.WriteAllText(systemctl, FakeSystemctl.ReplaceLineEndings("\n"));
                var invoke = Path.Combine(Absolute("bin"), "deb-systemd-invoke");
                var helper = Path.Combine(Absolute("bin"), "deb-systemd-helper");
                File.WriteAllText(invoke, FakeSystemdHelper.ReplaceLineEndings("\n"));
                File.WriteAllText(helper, FakeSystemdHelper.ReplaceLineEndings("\n"));
                if (!OperatingSystem.IsWindows())
                {
                    foreach (var script in new[] { systemctl, invoke, helper })
                    {
                        File.SetUnixFileMode(script, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
                    }
                }
            }
        }

        public bool Exists(string relative) => File.Exists(Absolute(relative)) || Directory.Exists(Absolute(relative));

        public void Delete(string relative) => File.Delete(Absolute(relative));

        public void DeleteDirectory(string relative) => Directory.Delete(Absolute(relative));

        public void CreateEnablementLink()
        {
            var directory = Absolute("etc/systemd/system/multi-user.target.wants");
            Directory.CreateDirectory(directory);
            File.CreateSymbolicLink(Path.Combine(directory, "axiomd.service"), "../../axiomd.service");
        }

        public void RemoveStopHelpers()
        {
            Delete("bin/deb-systemd-invoke");
            Delete("bin/deb-systemd-helper");
        }

        public (int ExitCode, string StandardError) Run(
            string script, string argument, int disableExit, string state, int activeExit)
        {
            var start = new ProcessStartInfo("/bin/sh")
            {
                RedirectStandardError = true,
                RedirectStandardOutput = true,
            };
            start.ArgumentList.Add(script);
            start.ArgumentList.Add(argument);
            start.Environment["AXIOM_MAINTAINER_TEST_ROOT"] = _temp.Path;
            start.Environment["PATH"] = Absolute("bin");
            start.Environment["AXIOM_FAKE_DISABLE_EXIT"] = disableExit.ToString(CultureInfo.InvariantCulture);
            start.Environment["AXIOM_FAKE_ACTIVE_STATE"] = state;
            start.Environment["AXIOM_FAKE_ACTIVE_EXIT"] = activeExit.ToString(CultureInfo.InvariantCulture);

            using var process = Process.Start(start)!;
            var stderr = process.StandardError.ReadToEnd();
            process.StandardOutput.ReadToEnd();
            process.WaitForExit();
            return (process.ExitCode, stderr);
        }

        private string Absolute(string relative) => Path.Combine(_temp.Path, relative);

        public void Dispose() => _temp.Dispose();
    }

    private static string DebPostrm => ScriptPath("debian", "postrm");

    private static string RpmPostRemove => ScriptPath("rpm", "postremove");

    private static string ScriptPath(string directory, string name)
    {
        var directoryInfo = new DirectoryInfo(AppContext.BaseDirectory);
        while (directoryInfo is not null && !File.Exists(Path.Combine(directoryInfo.FullName, "Axiom.sln")))
        {
            directoryInfo = directoryInfo.Parent;
        }

        Assert.NotNull(directoryInfo);
        return Path.Combine(directoryInfo!.FullName, "packaging", "linux", directory, name);
    }
}
