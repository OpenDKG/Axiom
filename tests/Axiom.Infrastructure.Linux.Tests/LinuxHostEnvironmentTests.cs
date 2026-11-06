// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Infrastructure.Linux;
using Xunit;

namespace Axiom.Infrastructure.Linux.Tests;

public sealed class LinuxHostEnvironmentTests
{
    [Fact]
    public void Wsl_container_and_lsm_facts_are_detected_and_described()
    {
        var environment = LinuxHostEnvironment.Detect(path => path switch
        {
            "/proc/version" => "Linux version 6.6.0-microsoft-standard-WSL2",
            "/proc/self/cgroup" => "0::/docker/abc",
            "/.dockerenv" => string.Empty,
            "/sys/kernel/security/lsm" => "lockdown,capability,apparmor",
            "/proc/self/attr/current" => "docker-default (enforce)",
            _ => null,
        });

        Assert.True(environment.IsWsl);
        Assert.True(environment.IsContainer);
        Assert.Contains("apparmor", environment.SecurityModules);
        Assert.Equal("docker-default (enforce)", environment.AppArmorProfile);

        var notes = environment.Describe();
        Assert.Contains(notes, note => note.Contains("WSL", StringComparison.Ordinal));
        Assert.Contains(notes, note => note.Contains("container", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(notes, note => note.Contains("AppArmor", StringComparison.Ordinal));
    }

    [Fact]
    public void A_plain_host_reports_no_extra_limitations()
    {
        var environment = LinuxHostEnvironment.Detect(path => path switch
        {
            "/proc/version" => "Linux version 6.8.0-generic",
            "/proc/self/cgroup" => "0::/user.slice/session.scope",
            _ => null,
        });

        Assert.False(environment.IsWsl);
        Assert.False(environment.IsContainer);
        Assert.Empty(environment.Describe());
    }

    [Fact]
    public void Selinux_enforcing_is_reported()
    {
        var environment = LinuxHostEnvironment.Detect(path => path switch
        {
            "/sys/fs/selinux/enforce" => "1",
            _ => null,
        });

        Assert.Equal("1", environment.SelinuxEnforcement);
        Assert.Contains(environment.Describe(), note => note.Contains("SELinux is enforcing", StringComparison.Ordinal));
    }
}
