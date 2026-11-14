// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using Axiom.Presentation;
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
}
