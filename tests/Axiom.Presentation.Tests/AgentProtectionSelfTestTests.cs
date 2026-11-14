// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using Axiom.Presentation;
using Xunit;

namespace Axiom.Presentation.Tests;

public sealed class AgentProtectionSelfTestTests
{
    [Fact]
    public void The_protected_read_check_uses_the_current_user_profile()
    {
        var check = Assert.Single(
            AgentProtectionSelfTest.DefaultChecks(), candidate => candidate.Name == "protected read");
        var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        Assert.StartsWith(profile, check.Path, StringComparison.OrdinalIgnoreCase);
        Assert.EndsWith(Path.Combine(".ssh", "id_rsa"), check.Path, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void The_checks_keep_an_allowed_read_and_a_protected_write()
    {
        var checks = AgentProtectionSelfTest.DefaultChecks();

        Assert.Contains(checks, check => check.Name == "allowed read" && !check.ExpectBlock);
        Assert.Contains(checks, check => check.Name == "protected write" && check.ExpectBlock);
    }
}
