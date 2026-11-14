// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Presentation;
using Xunit;

namespace Axiom.Presentation.Tests;

public sealed class AxiomModuleProcessMatcherTests
{
    [Theory]
    [InlineData(@"node.exe C:\Users\alice\AppData\Local\Axiom\modules\dkg\node_modules\@origintrail-official\dkg\bin\dkg.js start")]
    [InlineData(@"node /home/alice/AppData/Local/Axiom/modules/dkg/server.js")]
    [InlineData(@"powershell.exe -WindowStyle Hidden -File C:\Users\alice\.hermes\blackbox\start-blackbox-dkg.ps1")]
    [InlineData(@"node.exe C:\Users\alice\AppData\Local\hermes\blackbox\dkg-node\index.mjs")]
    [InlineData(@"node.exe C:\Users\alice\.hermes\blackbox\dkg\dkg-engine.mjs")]
    [InlineData(@"pythonw.exe C:\Users\alice\AppData\Local\Axiom\modules\blackbox\agent-blackbox\start-dashboard.py")]
    [InlineData(@"powershell.exe -File C:\Users\alice\.hermes\blackbox\start-blackbox-dashboard.ps1")]
    [InlineData(@"python.exe C:\Users\alice\AppData\Local\hermes\blackbox\start-dashboard.py")]
    [InlineData(@"hermes.exe blackbox dashboard --port 9700")]
    [InlineData(@"python.exe C:\Users\alice\.hermes\plugins\blackbox\dashboard\server.py")]
    public void Matches_axiom_module_and_wrapper_command_lines(string commandLine)
    {
        Assert.True(AxiomModuleProcessMatcher.IsAxiomModuleCommandLine(commandLine));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(@"node.exe C:\projects\myapp\server.js")]
    [InlineData(@"python.exe C:\work\train.py --epochs 10")]
    [InlineData(@"powershell.exe -NoLogo")]
    [InlineData(@"cmd.exe /c dir")]
    [InlineData(@"hermes.exe status")]
    public void Ignores_unrelated_user_processes(string? commandLine)
    {
        Assert.False(AxiomModuleProcessMatcher.IsAxiomModuleCommandLine(commandLine));
    }
}
