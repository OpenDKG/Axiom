// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics;
using Xunit;

namespace Axiom.Infrastructure.Linux.Tests;

/// <summary>
/// Runs the real <c>packaging/linux/debian/postinst</c> against a relocated root and a private
/// dpkg administrative directory, so the package-file migration is tested without touching the
/// host: the replaced <c>axiom</c> package's purge script is disarmed only when it carries our
/// marker lines, and the bundled daemon is the install source under the new payload path.
/// </summary>
public sealed class PackageUpgradeMigrationTests
{
    private const string OldPostrm = """
        #!/bin/sh
        AXIOM_DATA_DIR=$AXIOM_ROOT/var/lib/axiom
        AXIOM_UNIT=$AXIOM_ROOT/etc/systemd/system/axiomd.service
        [ "$1" = purge ] && rm -rf "$AXIOM_DATA_DIR"
        exit 0
        """;

    [Fact]
    public void Configure_disarms_the_replaced_package_script_and_runs_the_bundled_daemon()
    {
        if (!OperatingSystem.IsLinux())
        {
            // Exercises the Linux postinst and systemd install path.
            return;
        }

        using var sandbox = new Sandbox(OldPostrm);

        var result = sandbox.Run("configure");

        Assert.Equal(0, result.ExitCode);
        Assert.Equal("--install-service", sandbox.DaemonArguments);
        Assert.Contains("Replaced by axiom-firewall", File.ReadAllText(sandbox.OldPostrmPath), StringComparison.Ordinal);
        if (!OperatingSystem.IsWindows())
        {
            Assert.True((File.GetUnixFileMode(sandbox.OldPostrmPath) & UnixFileMode.UserExecute) != 0);
        }
    }

    [Fact]
    public void Configure_leaves_an_unrelated_axiom_postrm_untouched()
    {
        const string archive = "#!/bin/sh\n# The archive's own axiom package (computer algebra).\nexit 0\n";
        using var sandbox = new Sandbox(archive);

        var result = sandbox.Run("configure");

        Assert.Equal(0, result.ExitCode);
        Assert.Equal(archive, File.ReadAllText(sandbox.OldPostrmPath));
        Assert.Equal("--install-service", sandbox.DaemonArguments);
    }

    [Fact]
    public void Configure_without_the_replaced_package_still_installs_the_service()
    {
        using var sandbox = new Sandbox(oldPostrm: null);

        var result = sandbox.Run("configure");

        Assert.Equal(0, result.ExitCode);
        Assert.False(File.Exists(sandbox.OldPostrmPath));
        Assert.Equal("--install-service", sandbox.DaemonArguments);
    }

    [Fact]
    public void Configure_fails_when_the_bundled_daemon_is_missing()
    {
        using var sandbox = new Sandbox(OldPostrm);
        sandbox.DeleteDaemon();

        var result = sandbox.Run("configure");

        Assert.NotEqual(0, result.ExitCode);
        Assert.Contains("is missing", result.StandardError, StringComparison.Ordinal);
        Assert.Equal(string.Empty, sandbox.DaemonArguments);
    }

    [Fact]
    public void Maintainer_scripts_and_desktop_entry_use_the_staged_payload_paths()
    {
        var postinst = File.ReadAllText(PackagingPath("debian", "postinst"));
        var prerm = File.ReadAllText(PackagingPath("debian", "prerm"));
        var desktop = File.ReadAllText(PackagingPath("com.axiom.firewall.desktop"));

        Assert.Contains("/usr/lib/axiom-firewall/axiomd/axiomd", postinst, StringComparison.Ordinal);
        Assert.Contains("/usr/lib/axiom-firewall/bpf-pins.sh", prerm, StringComparison.Ordinal);
        Assert.Contains("Exec=/usr/bin/axiom-firewall", desktop, StringComparison.Ordinal);
        Assert.DoesNotContain("/opt/axiom", postinst, StringComparison.Ordinal);
        Assert.DoesNotContain("/opt/axiom", prerm, StringComparison.Ordinal);
        Assert.DoesNotContain("/opt/axiom", desktop, StringComparison.Ordinal);
    }

    private sealed class Sandbox : IDisposable
    {
        private readonly string _root;
        private readonly string _admin;
        private readonly string _daemonMarker;

        public Sandbox(string? oldPostrm)
        {
            _root = Path.Combine(Path.GetTempPath(), "axiom-postinst-" + Guid.NewGuid().ToString("N"));
            _admin = Path.Combine(_root, "dpkg");
            _daemonMarker = Path.Combine(_root, "daemon-args");
            Directory.CreateDirectory(Path.Combine(_root, "usr/lib/axiom-firewall/axiomd"));
            Directory.CreateDirectory(Path.Combine(_root, "run/systemd/system"));
            Directory.CreateDirectory(Path.Combine(_admin, "info"));
            File.WriteAllText(Path.Combine(_admin, "status"),
                "Package: axiom\nStatus: deinstall ok config-files\nArchitecture: amd64\nVersion: 0.17.0\n" +
                "Maintainer: x <x@y>\nDescription: unrelated\n");
            if (oldPostrm is not null)
            {
                File.WriteAllText(OldPostrmPath, oldPostrm.ReplaceLineEndings("\n"));
                if (!OperatingSystem.IsWindows())
                {
                    File.SetUnixFileMode(OldPostrmPath, (UnixFileMode)Convert.ToInt32("755", 8));
                }
            }

            var daemon = Path.Combine(_root, "usr/lib/axiom-firewall/axiomd/axiomd");
            File.WriteAllText(daemon, "#!/bin/sh\nprintf '%s' \"$*\" >\"$AXIOM_TEST_DAEMON_MARKER\"\nexit 0\n");
            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(daemon, (UnixFileMode)Convert.ToInt32("755", 8));
            }
        }

        public string OldPostrmPath => Path.Combine(_admin, "info/axiom.postrm");

        public string DaemonArguments => File.Exists(_daemonMarker) ? File.ReadAllText(_daemonMarker) : string.Empty;

        public void DeleteDaemon() => File.Delete(Path.Combine(_root, "usr/lib/axiom-firewall/axiomd/axiomd"));

        public (int ExitCode, string StandardError) Run(string argument)
        {
            var start = new ProcessStartInfo("/bin/sh")
            {
                RedirectStandardError = true,
                RedirectStandardOutput = true,
            };
            start.ArgumentList.Add(PostinstPath);
            start.ArgumentList.Add(argument);
            start.Environment["AXIOM_MAINTAINER_TEST_ROOT"] = _root;
            start.Environment["DPKG_ADMINDIR"] = _admin;
            start.Environment["AXIOM_TEST_DAEMON_MARKER"] = _daemonMarker;

            using var process = Process.Start(start)!;
            var stderr = process.StandardError.ReadToEnd();
            process.StandardOutput.ReadToEnd();
            process.WaitForExit();
            return (process.ExitCode, stderr);
        }

        public void Dispose()
        {
            try
            {
                Directory.Delete(_root, recursive: true);
            }
            catch (IOException)
            {
            }
        }
    }

    private static string PostinstPath => PackagingPath("debian", "postinst");

    private static string PackagingPath(params string[] segments)
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "Axiom.sln")))
        {
            directory = directory.Parent;
        }

        Assert.NotNull(directory);
        return Path.Combine([directory!.FullName, "packaging", "linux", .. segments]);
    }
}
