// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Presentation;
using Xunit;

namespace Axiom.Presentation.Tests;

public sealed class BlackboxPathsTests : IDisposable
{
    private readonly string _root;
    private readonly string _profile;
    private readonly string _local;

    public BlackboxPathsTests()
    {
        _root = Path.Combine(Path.GetTempPath(), "axiom-blackbox-paths-" + Guid.NewGuid().ToString("N"));
        _profile = Path.Combine(_root, "profile");
        _local = Path.Combine(_root, "local");
        Directory.CreateDirectory(_profile);
        Directory.CreateDirectory(_local);
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

    [Fact]
    public void Local_app_data_hermes_is_preferred_when_it_has_a_profile()
    {
        var localHome = Path.Combine(_local, "hermes");
        Directory.CreateDirectory(localHome);
        File.WriteAllText(Path.Combine(localHome, "config.yaml"), "plugins: {}");
        var profileHome = Path.Combine(_profile, ".hermes");
        Directory.CreateDirectory(profileHome);
        File.WriteAllText(Path.Combine(profileHome, "config.yaml"), "plugins: {}");

        Assert.Equal(
            localHome,
            BlackboxPaths.ResolveHermesHome(_profile, _local, environmentHome: string.Empty));
    }

    [Fact]
    public void Legacy_dot_hermes_is_used_when_local_app_data_has_no_profile()
    {
        var profileHome = Path.Combine(_profile, ".hermes");
        Directory.CreateDirectory(profileHome);
        Directory.CreateDirectory(Path.Combine(profileHome, "blackbox"));

        Assert.Equal(
            profileHome,
            BlackboxPaths.ResolveHermesHome(_profile, _local, environmentHome: string.Empty));
    }

    [Fact]
    public void Missing_profiles_fall_back_to_the_windows_hermes_location()
    {
        Assert.Equal(
            Path.Combine(_local, "hermes"),
            BlackboxPaths.ResolveHermesHome(_profile, _local, environmentHome: string.Empty));
    }

    [Fact]
    public void Environment_override_wins_and_blackbox_home_follows_it()
    {
        var configured = Path.Combine(_root, "elsewhere");

        Assert.Equal(
            configured,
            BlackboxPaths.ResolveHermesHome(
                _profile,
                _local,
                environmentHome: configured));

        Assert.Equal(
            Path.Combine(configured, "blackbox"),
            BlackboxPaths.ResolveBlackboxHome(
                _profile,
                _local,
                environmentHome: configured,
                environmentBlackboxHome: string.Empty));
    }

    [Fact]
    public void Blackbox_home_override_is_used_for_consent_and_key_paths()
    {
        var blackbox = Path.Combine(_root, "custom-blackbox");

        Assert.Equal(
            Path.Combine(blackbox, "sharing_consent.json"),
            BlackboxPaths.ConsentPath(
                _profile,
                _local,
                environmentHome: string.Empty,
                environmentBlackboxHome: blackbox));
        Assert.Equal(
            Path.Combine(blackbox, "reporter_key.pem"),
            BlackboxPaths.ReporterKeyPath(
                _profile,
                _local,
                environmentHome: string.Empty,
                environmentBlackboxHome: blackbox));
    }
}
