// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Presentation;
using Xunit;

namespace Axiom.Presentation.Tests;

public sealed class ShieldProtectionTests
{
    [Fact]
    public void Unknown_is_never_protected_or_unprotected()
    {
        Assert.Null(ShieldProtection.Level(known: false, enabled: true, enforcementVerified: true));
        Assert.Null(ShieldProtection.Level(known: false, enabled: false, enforcementVerified: null));
        Assert.Equal("Unknown", ShieldProtection.LevelText(null));
        Assert.Equal("idle", ShieldProtection.Tone(null));
        Assert.Equal(ShieldProtection.UnknownColor, ShieldProtection.LampColor(null));
    }

    [Fact]
    public void Shield_on_without_proven_enforcement_is_degraded()
    {
        Assert.Equal(EnforcementLevel.Degraded, ShieldProtection.Level(true, true, enforcementVerified: false));
        Assert.Equal(EnforcementLevel.Protected, ShieldProtection.Level(true, true, enforcementVerified: true));
        // Windows Firewall does not report filter enforcement: upstream's green is kept.
        Assert.Equal(EnforcementLevel.Protected, ShieldProtection.Level(true, true, enforcementVerified: null));
        Assert.Equal(EnforcementLevel.Unprotected, ShieldProtection.Level(true, false, enforcementVerified: true));
    }

    [Fact]
    public void Words_and_tones_follow_the_upstream_enforcement_vocabulary()
    {
        foreach (var level in new[] { EnforcementLevel.Protected, EnforcementLevel.Degraded, EnforcementLevel.Unprotected })
        {
            var guard = EnforcementSurfaceState.Current with
            {
                VerificationLabel = level switch
                {
                    EnforcementLevel.Unprotected => "UNAVAILABLE - NOT PROTECTED",
                    EnforcementLevel.Protected => "HOOK BLOCKING ACTIVE",
                    _ => "HOOK MODE UNKNOWN - NOT VERIFIED",
                },
            };
            Assert.Equal(level, guard.Level);
            Assert.Equal(guard.LevelText, ShieldProtection.LevelText(level));
        }

        Assert.Equal("ok", ShieldProtection.Tone(EnforcementLevel.Protected));
        Assert.Equal("warn", ShieldProtection.Tone(EnforcementLevel.Degraded));
        Assert.Equal("fail", ShieldProtection.Tone(EnforcementLevel.Unprotected));
    }

    [Theory]
    [InlineData(EnforcementLevel.Protected, null, "Settings on")]
    [InlineData(EnforcementLevel.Protected, false, "Settings on")]
    [InlineData(EnforcementLevel.Protected, true, "Protected")]
    [InlineData(EnforcementLevel.Degraded, false, "Degraded")]
    [InlineData(EnforcementLevel.Unprotected, null, "Not protected")]
    [InlineData(null, null, "Unknown")]
    public void Shield_label_says_protected_only_with_a_verified_result(
        EnforcementLevel? level, bool? verified, string expected) =>
        Assert.Equal(expected, ShieldProtection.ShieldText(level, verified));
}
