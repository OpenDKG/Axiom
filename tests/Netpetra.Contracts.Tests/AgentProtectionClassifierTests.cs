// SPDX-License-Identifier: GPL-3.0-or-later
using Netpetra.Contracts.Blackbox;
using Xunit;

namespace Netpetra.Contracts.Tests;

public sealed class AgentProtectionClassifierTests
{
    [Fact]
    public void File_presence_alone_is_not_protected()
    {
        Assert.Equal(
            "HOOK INSTALLED",
            AgentProtectionClassifier.Classify(true, true, false, false, true));
    }

    [Fact]
    public void Runtime_evidence_without_block_test_is_only_loaded()
    {
        Assert.Equal(
            "HOOK LOADED",
            AgentProtectionClassifier.Classify(true, true, true, false, true));
    }

    [Fact]
    public void Verified_blocking_requires_explicit_test_evidence()
    {
        Assert.Equal(
            "VERIFIED BLOCKING",
            AgentProtectionClassifier.Classify(true, true, true, false, true, verifiedBlocking: true));
    }

    [Theory]
    [InlineData(false, true, "NOT DETECTED")]
    [InlineData(true, false, "DETECTED")]
    public void Missing_detection_or_hook_is_reported_honestly(bool detected, bool hook, string expected)
    {
        Assert.Equal(expected, AgentProtectionClassifier.Classify(detected, hook, false, false, true));
    }

    [Fact]
    public void Offline_blackbox_is_not_protected()
    {
        Assert.Equal(
            "OFFLINE",
            AgentProtectionClassifier.Classify(true, true, true, false, false));
    }

    [Fact]
    public void Observed_guard_failure_degrades_protection()
    {
        Assert.Equal(
            "DEGRADED",
            AgentProtectionClassifier.Classify(true, true, true, true, true));
    }

    [Fact]
    public void Untrusted_host_hooks_are_not_reported_as_loaded()
    {
        Assert.Equal(
            "TRUST REQUIRED",
            AgentProtectionClassifier.Classify(
                true,
                true,
                true,
                false,
                true,
                trustRequired: true));
    }

    [Fact]
    public void Audit_mode_is_distinct_from_blocking()
    {
        Assert.Equal(
            "AUDIT ONLY",
            AgentProtectionClassifier.Classify(true, true, true, false, true, auditOnly: true));
    }
}
