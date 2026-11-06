// SPDX-License-Identifier: GPL-3.0-or-later
using Netpetra.UI.ViewModels;
using Xunit;

namespace Netpetra.UI.Tests;

public sealed class ProtectedAgentStatusTests
{
    [Theory]
    [InlineData("HOOK INSTALLED", "HOOKED")]
    [InlineData("HOOK LOADED", "CONNECTED")]
    [InlineData("VERIFIED BLOCKING", "VERIFIED")]
    [InlineData("PROTECTED", "PROTECTED")]
    [InlineData("DETECTED", "DETECTED")]
    [InlineData("OFFLINE", "OFFLINE")]
    public void Display_status_is_normalized_without_overstating_protection(
        string classifierStatus,
        string expectedDisplayStatus)
    {
        var agent = new ProtectedAgent("codex", "target", classifierStatus, "detail");

        Assert.Equal(expectedDisplayStatus, agent.DisplayStatus);
    }
}
