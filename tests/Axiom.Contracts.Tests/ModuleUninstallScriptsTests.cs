// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Modules;
using Xunit;

namespace Axiom.Contracts.Tests;

public sealed class ModuleUninstallScriptsTests
{
    [Fact]
    public void Blackbox_script_avoids_the_powershell_51_contains_overload()
    {
        var script = ModuleUninstallScripts.BuildBlackboxScript(
            @"C:\Users\alice\AppData\Local\Axiom\modules\blackbox",
            @"C:\Users\alice\AppData\Local\hermes",
            @"C:\Users\alice\AppData\Local\hermes\blackbox",
            @"C:\Users\alice\.local\bin\blackbox.cmd");

        // Windows PowerShell 5.1 is .NET Framework and has no Contains(string, StringComparison).
        Assert.DoesNotContain(".Contains(", script, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("IndexOf([string]$needle, [System.StringComparison]::OrdinalIgnoreCase)", script, StringComparison.Ordinal);
        Assert.Contains("Agent Blackbox DKG node", script, StringComparison.Ordinal);
        Assert.Contains("Agent Blackbox dashboard", script, StringComparison.Ordinal);
    }

    [Fact]
    public void Dkg_script_avoids_the_powershell_51_contains_overload()
    {
        var script = ModuleUninstallScripts.BuildDkgScript(
            @"C:\Users\alice\AppData\Local\Axiom\modules\dkg",
            @"C:\Users\alice\AppData\Local\Axiom\modules\dkg-home");

        Assert.DoesNotContain(".Contains(", script, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("IndexOf([string]$needle, [System.StringComparison]::OrdinalIgnoreCase)", script, StringComparison.Ordinal);
        // Only Axiom's own tree is matched: uninstalling it must never kill another DKG node.
        Assert.DoesNotContain("origintrail-official", script, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("$dkgRoot", script, StringComparison.Ordinal);
    }

    [Fact]
    public void Scripts_escape_a_single_quote_in_a_user_path()
    {
        var script = ModuleUninstallScripts.BuildDkgScript(
            @"C:\Users\o'neil\Axiom\modules\dkg",
            @"C:\Users\o'neil\Axiom\modules\dkg-home");

        Assert.Contains(@"C:\Users\o''neil\Axiom\modules\dkg", script, StringComparison.Ordinal);
    }
}
