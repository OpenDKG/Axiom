// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Infrastructure.Linux.Nft;

namespace Axiom.Infrastructure.Linux.Nft.Tests;

public sealed class AppCgroupManagerTests
{
    private static FakeCgroupFs Box()
    {
        var fs = new FakeCgroupFs();
        fs.AppPaths["/usr/bin/curl"] = "/usr/bin/curl";
        fs.AppPaths["/bin/curl"] = "/usr/bin/curl"; // /bin -> usr/bin symlink
        fs.AppPaths["/opt/App"] = "/opt/App";
        fs.Processes[100] = ("/usr/bin/curl", "user.slice/user-1000.slice/session-3.scope");
        fs.Processes[101] = ("/usr/bin/curl", "user.slice/user-1000.slice/user@1000.service/app.slice/app-gnome-curl-101.scope");
        fs.Processes[102] = ("/usr/bin/curl", "system.slice/cron.service");
        fs.Processes[103] = ("/usr/bin/wget", "user.slice/user-1000.slice/session-3.scope");
        fs.Processes[104] = ("/opt/App/bin/app", "user.slice/user-1000.slice/user@1000.service/app.slice/app-gnome-org.gnome.Terminal.slice/vte-spawn-1.scope");
        fs.Processes[105] = ("/opt/Application/bin/x", "user.slice/user-1000.slice/session-3.scope");
        // Real cgroup directories outlive their last process (systemd garbage-collects them later).
        foreach (var process in fs.Processes.Values)
        {
            fs.CreateCgroup(process.Cgroup);
        }

        return fs;
    }

    [Fact]
    public void Resolve_creates_one_cgroup_per_canonical_app_and_rejects_unreachable_paths()
    {
        var fs = Box();
        var manager = new AppCgroupManager(fs);

        Assert.True(manager.TryResolve("/usr/bin/curl", out var a, out _));
        Assert.True(manager.TryResolve("/bin/curl", out var b, out _));
        Assert.Equal(a, b);
        Assert.Equal("axiom.slice/" + AppCgroupManager.CgroupNameFor("/usr/bin/curl"), a);
        Assert.Matches("^axiom.slice/a-[0-9a-f]{16}$", a);
        Assert.Contains(a, fs.Cgroups);
        Assert.False(manager.TryResolve("/usr/bin/nope", out _, out var reason));
        Assert.Equal("appPath is not reachable on this system: /usr/bin/nope", reason);

        fs.CreateFails = true;
        Assert.False(manager.TryResolve("/opt/App", out _, out var createReason));
        Assert.StartsWith("cannot create cgroup axiom.slice/", createReason, StringComparison.Ordinal);
    }

    [Fact]
    public void Attribute_moves_every_matching_pid_classifies_the_source_and_reports_system_services()
    {
        var fs = Box();
        var manager = new AppCgroupManager(fs);
        manager.TryResolve("/usr/bin/curl", out var curlCgroup, out _);
        manager.TryResolve("/opt/App", out var appCgroup, out _);

        var report = manager.Attribute();

        Assert.Equal([100, 101, 102, 104], report.Placements.Select(p => p.Pid));
        Assert.All(report.Placements, p => Assert.True(p.Moved));
        Assert.Equal(SourceCgroupKind.UserSessionLeaf, report.Placements[0].SourceKind);
        Assert.Equal(SourceCgroupKind.AppScope, report.Placements[1].SourceKind);
        Assert.Equal(SourceCgroupKind.SystemService, report.Placements[2].SourceKind);
        Assert.Equal(SourceCgroupKind.AppScope, report.Placements[3].SourceKind);
        Assert.True(report.Placements[2].Reportable);
        Assert.False(report.Placements[0].Reportable);
        Assert.Equal(curlCgroup, fs.Processes[100].Cgroup);
        Assert.Equal(curlCgroup, fs.Processes[102].Cgroup);
        Assert.Equal(appCgroup, fs.Processes[104].Cgroup);
        Assert.Equal("user.slice/user-1000.slice/session-3.scope", fs.Processes[103].Cgroup);
        Assert.Equal("user.slice/user-1000.slice/session-3.scope", fs.Processes[105].Cgroup);

        // Second pass is idempotent: everything already sits in the Axiom cgroups.
        Assert.Empty(manager.Attribute().Placements);
    }

    [Fact]
    public void Unmovable_pids_are_reported_not_hidden()
    {
        var fs = Box();
        fs.Unmovable.Add(101);
        var manager = new AppCgroupManager(fs);
        manager.TryResolve("/usr/bin/curl", out _, out _);

        var report = manager.Attribute();

        var failed = Assert.Single(report.Placements, p => !p.Moved);
        Assert.Equal(101, failed.Pid);
        Assert.Equal("Permission denied", failed.Error);
        Assert.True(failed.Reportable);
        Assert.Contains("could not be moved", AppCgroupManager.Describe(failed), StringComparison.Ordinal);
    }

    [Fact]
    public void Retain_prunes_cgroups_of_apps_without_rules_once_empty()
    {
        var fs = Box();
        var manager = new AppCgroupManager(fs);
        manager.TryResolve("/usr/bin/curl", out var curlCgroup, out _);
        manager.TryResolve("/opt/App", out var appCgroup, out _);
        manager.Attribute();

        fs.Unmovable.Add(100); // cannot be returned: the cgroup stays until it exits
        manager.Retain(["/opt/App"]);
        var report = manager.Attribute();

        Assert.Empty(report.RemovedCgroups);
        Assert.Equal(curlCgroup, fs.Processes[100].Cgroup);
        fs.Processes.Remove(100);

        Assert.Equal([curlCgroup], manager.Attribute().RemovedCgroups);
        Assert.Contains(appCgroup, fs.Cgroups);
        Assert.DoesNotContain(curlCgroup, fs.Cgroups);
    }

    [Fact]
    public void RemoveAll_returns_processes_to_their_origin_and_deletes_the_slice()
    {
        var fs = Box();
        var manager = new AppCgroupManager(fs);
        manager.TryResolve("/usr/bin/curl", out var curlCgroup, out _);
        manager.TryResolve("/opt/App", out var appCgroup, out _);
        manager.Attribute();
        // 200: forked inside the Axiom cgroup by 100 (no recorded origin) -> parent's cgroup.
        fs.Processes[200] = ("/usr/bin/curl", curlCgroup);
        fs.Parents[200] = 100;
        // 201: unknown origin, parent gone -> cgroup root.
        fs.Processes[201] = ("/usr/bin/curl", curlCgroup);
        // 102's origin cgroup disappeared; its parent 100 is released first (pid order), so 102 follows it.
        fs.Cgroups.Remove("system.slice/cron.service");
        fs.Parents[102] = 100;
        Assert.False(fs.CgroupExists("system.slice/cron.service"));

        var removed = manager.RemoveAll();

        Assert.Equal(3, removed.Count);
        Assert.Contains(curlCgroup, removed);
        Assert.Contains(appCgroup, removed);
        Assert.Contains("axiom.slice", removed);
        Assert.Empty(manager.Apps);
        Assert.Equal("user.slice/user-1000.slice/session-3.scope", fs.Processes[100].Cgroup);
        Assert.Equal("user.slice/user-1000.slice/user@1000.service/app.slice/app-gnome-curl-101.scope", fs.Processes[101].Cgroup);
        Assert.Equal("user.slice/user-1000.slice/session-3.scope", fs.Processes[102].Cgroup);
        Assert.Equal("user.slice/user-1000.slice/user@1000.service/app.slice/app-gnome-org.gnome.Terminal.slice/vte-spawn-1.scope", fs.Processes[104].Cgroup);
        Assert.Equal("user.slice/user-1000.slice/session-3.scope", fs.Processes[200].Cgroup);
        Assert.Equal("", fs.Processes[201].Cgroup);
    }

    [Fact]
    public void Dropping_an_apps_rules_releases_its_processes_before_pruning()
    {
        var fs = Box();
        var manager = new AppCgroupManager(fs);
        manager.TryResolve("/usr/bin/curl", out var curlCgroup, out _);
        manager.TryResolve("/opt/App", out _, out _);
        manager.Attribute();

        manager.Retain(["/opt/App"]);
        var report = manager.Attribute();

        Assert.Equal([curlCgroup], report.RemovedCgroups);
        Assert.Equal("user.slice/user-1000.slice/session-3.scope", fs.Processes[100].Cgroup);
        Assert.Equal("system.slice/cron.service", fs.Processes[102].Cgroup);
        Assert.DoesNotContain(curlCgroup, fs.Cgroups);
    }

    [Theory]
    [InlineData("/usr/bin/curl", "/usr/bin/curl")]
    [InlineData("/opt/App/bin/app", "/opt/App")]
    [InlineData("/opt/App/lib/helper", "/opt/App")]
    [InlineData("/opt/Application/bin/x", null)]
    [InlineData("/usr/bin/Curl", null)]
    public void Match_is_exact_or_directory_prefix_and_case_sensitive(string exe, string? expected)
    {
        Assert.Equal(expected, AppCgroupManager.MatchApp(exe, ["/usr/bin/curl", "/opt/App"]));
    }

    [Theory]
    [InlineData("axiom.slice/a-0123456789abcdef", SourceCgroupKind.AxiomOwned)]
    [InlineData("user.slice/user-1000.slice/user@1000.service/app.slice/app-com.google.Chrome-1703.scope", SourceCgroupKind.AppScope)]
    [InlineData("user.slice/user-1000.slice/user@1000.service/app.slice/app-org.gnome.Terminal.slice/vte-spawn-1.scope", SourceCgroupKind.AppScope)]
    [InlineData("user.slice/user-1000.slice/user@1000.service/app.slice/run-u1.scope", SourceCgroupKind.AppScope)]
    [InlineData("user.slice/user-1000.slice/session-3.scope", SourceCgroupKind.UserSessionLeaf)]
    [InlineData("user.slice/user-1000.slice/user@1000.service/app.slice/hermes-gateway.service", SourceCgroupKind.AppScope)]
    [InlineData("system.slice/cron.service", SourceCgroupKind.SystemService)]
    [InlineData("init.scope", SourceCgroupKind.SystemService)]
    [InlineData("", SourceCgroupKind.SystemService)]
    [InlineData("machine.slice/docker-abc.scope", SourceCgroupKind.Other)]
    public void Classify_recognises_app_scopes_session_leaves_and_system_services(string cgroup, SourceCgroupKind expected)
    {
        Assert.Equal(expected, new AppCgroupManager(new FakeCgroupFs()).Classify(cgroup));
    }
}
