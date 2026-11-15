// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using Axiom.Contracts.Blackbox;
using Xunit;

namespace Axiom.Presentation.Tests;

public sealed class DkgHomeResolverTests
{
    [Fact]
    public void Reads_the_configured_home_from_the_hermes_config()
    {
        const string yaml = """
            plugins:
              entries:
                blackbox:
                  dkg_home: C:\Users\lab\AppData\Local\Axiom\modules\blackbox\agent-blackbox\.dkg
                  mode: block
            """;

        Assert.Equal(
            @"C:\Users\lab\AppData\Local\Axiom\modules\blackbox\agent-blackbox\.dkg",
            DkgHomeResolver.ReadConfiguredHome(yaml));
    }

    [Fact]
    public void Quoted_and_indented_values_are_trimmed()
    {
        Assert.Equal(@"D:\dkg home", DkgHomeResolver.ReadConfiguredHome("    dkg_home: \"D:\\dkg home\""));
        Assert.Null(DkgHomeResolver.ReadConfiguredHome("plugins:\n  entries: {}\n"));
        Assert.Null(DkgHomeResolver.ReadConfiguredHome(""));
    }

    [Fact]
    public void Resolve_prefers_the_configured_home()
    {
        var local = Path.Combine("C:", "Users", "lab", "AppData", "Local");
        var config = Path.Combine(local, "hermes", "config.yaml");
        var configured = Path.Combine("C:", "lab", ".dkg");

        var resolved = DkgHomeResolver.Resolve(
            local,
            path => path == config ? "    dkg_home: " + configured : null);

        Assert.Equal(configured, resolved);
    }

    [Fact]
    public void Resolve_falls_back_to_the_axiom_managed_home()
    {
        var local = Path.Combine("C:", "Users", "lab", "AppData", "Local");

        var resolved = DkgHomeResolver.Resolve(local, _ => null);

        Assert.Equal(Path.Combine(local, "Axiom", "modules", "dkg"), resolved);
    }

    [Fact]
    public void ReadToken_skips_the_comment_line_the_node_writes_above_the_token()
    {
        Assert.Equal("abc123", DkgHomeResolver.ReadToken("# bearer token for the local API\nabc123\r\n"));
        Assert.Equal("abc123", DkgHomeResolver.ReadToken("abc123"));
        Assert.Null(DkgHomeResolver.ReadToken("# only a comment\n\n"));
        Assert.Null(DkgHomeResolver.ReadToken(""));
    }

    [Fact]
    public void ReadApiPort_accepts_a_trimmed_port_and_rejects_invalid_text()
    {
        Assert.Equal(9320, DkgHomeResolver.ReadApiPort("9320\r\n"));
        Assert.Equal(9200, DkgHomeResolver.ReadApiPort(" 9200 "));
        Assert.Null(DkgHomeResolver.ReadApiPort("not-a-port"));
        Assert.Null(DkgHomeResolver.ReadApiPort("0"));
        Assert.Null(DkgHomeResolver.ReadApiPort(null));
    }

    [Fact]
    public void ResolveEffective_prefers_an_existing_configured_home()
    {
        var local = Path.Combine("C:", "Users", "lab", "AppData", "Local");
        var config = Path.Combine(local, "hermes", "config.yaml");
        var configured = Path.Combine("C:", "lab", ".dkg");

        var resolved = DkgHomeResolver.ResolveEffective(
            local,
            path => path == config ? "    dkg_home: " + configured : null,
            path => path == configured);

        Assert.Equal(configured, resolved);
    }

    [Fact]
    public void ResolveEffective_uses_the_bundled_blackbox_home_when_the_config_is_missing()
    {
        var local = Path.Combine("C:", "Users", "lab", "AppData", "Local");
        var bundled = DkgHomeResolver.BundledBlackboxHome(local);

        var resolved = DkgHomeResolver.ResolveEffective(local, _ => null, path => path == bundled);

        Assert.Equal(bundled, resolved);
        Assert.Equal(
            Path.Combine(local, "Axiom", "modules", "blackbox", "agent-blackbox", ".dkg"),
            bundled);
    }

    [Fact]
    public void ResolveEffective_falls_back_to_the_standalone_home_when_only_it_exists()
    {
        var local = Path.Combine("C:", "Users", "lab", "AppData", "Local");
        var standalone = DkgHomeResolver.StandaloneHome(local);

        var resolved = DkgHomeResolver.ResolveEffective(local, _ => null, path => path == standalone);

        Assert.Equal(standalone, resolved);
    }
}
