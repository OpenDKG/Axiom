// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Core.Enforcement;
using Xunit;

namespace Axiom.Core.Tests;

public sealed class AgentProcessSpawnPolicyTests
{
    private static readonly DateTimeOffset At = new(2026, 11, 15, 9, 0, 0, TimeSpan.Zero);

    private static ProcessSpawnEvent Spawn(string image, string parent) =>
        new(100, 50, image, parent, At);

    [Fact]
    public void Agent_spawning_a_staged_executable_is_blocked()
    {
        var decision = AgentProcessSpawnPolicy.Evaluate(
            Spawn(@"C:\Users\lab\Downloads\dropper.exe", @"C:\Users\lab\.config\opencode\opencode.exe"));

        Assert.Equal(ProcessSpawnVerdict.Block, decision.Verdict);
        Assert.Contains("staging", decision.Reason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Agent_spawning_a_temp_script_is_blocked()
    {
        var decision = AgentProcessSpawnPolicy.Evaluate(
            Spawn(@"C:\Users\lab\AppData\Local\Temp\x.ps1", @"C:\Program Files\Hermes\hermes.exe"));

        Assert.Equal(ProcessSpawnVerdict.Block, decision.Verdict);
    }

    [Fact]
    public void Agent_spawning_an_ordinary_binary_is_recorded()
    {
        var decision = AgentProcessSpawnPolicy.Evaluate(
            Spawn(@"C:\Windows\System32\notepad.exe", @"C:\Users\lab\opencode.exe"));

        Assert.Equal(ProcessSpawnVerdict.Record, decision.Verdict);
        Assert.Contains("agent", decision.Reason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Allowlisted_image_passes_even_from_downloads()
    {
        var decision = AgentProcessSpawnPolicy.Evaluate(
            Spawn(@"C:\Users\lab\Downloads\tool.exe", @"C:\Users\lab\opencode.exe"),
            [@"C:\Users\lab\Downloads\tool.exe"]);

        Assert.Equal(ProcessSpawnVerdict.Allow, decision.Verdict);
        Assert.Contains("allowlisted", decision.Reason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Unrelated_parent_spawning_notepad_is_allowed()
    {
        var decision = AgentProcessSpawnPolicy.Evaluate(
            Spawn(@"C:\Windows\System32\notepad.exe", @"C:\Windows\System32\svchost.exe"));

        Assert.Equal(ProcessSpawnVerdict.Allow, decision.Verdict);
    }

    [Fact]
    public void Risky_binary_outside_an_agent_is_recorded()
    {
        var decision = AgentProcessSpawnPolicy.Evaluate(
            Spawn(@"C:\Windows\System32\certutil.exe", @"C:\Windows\explorer.exe"));

        Assert.Equal(ProcessSpawnVerdict.Record, decision.Verdict);
        Assert.Contains("risky", decision.Reason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Matching_is_case_insensitive_and_accepts_forward_slashes()
    {
        var decision = AgentProcessSpawnPolicy.Evaluate(
            Spawn(
                "c:/users/lab/downloads/DROPPER.EXE",
                @"C:\Users\lab\.config\opencode\opencode.exe"));

        Assert.Equal(ProcessSpawnVerdict.Block, decision.Verdict);
    }

    [Fact]
    public void An_empty_image_path_is_allowed_with_a_reason()
    {
        var decision = AgentProcessSpawnPolicy.Evaluate(Spawn(string.Empty, @"C:\Users\lab\opencode.exe"));

        Assert.Equal(ProcessSpawnVerdict.Allow, decision.Verdict);
        Assert.Contains("no image", decision.Reason, StringComparison.OrdinalIgnoreCase);
    }
}
