// SPDX-License-Identifier: GPL-3.0-or-later
using System;
using System.IO;
using Axiom.Presentation;
using Xunit;

namespace Axiom.Presentation.Tests;

public sealed class ThreatSharingConsentTests : IDisposable
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), "axiom-consent-" + Guid.NewGuid().ToString("N"));

    public ThreatSharingConsentTests() => Directory.CreateDirectory(_directory);

    public void Dispose()
    {
        try
        {
            Directory.Delete(_directory, recursive: true);
        }
        catch (IOException)
        {
        }
    }

    [Fact]
    public void Complete_consent_is_read_from_the_install_profile()
    {
        var profile = Path.Combine(_directory, "install-profile.json");
        File.WriteAllText(profile, """{"profile":"complete","threatSharingConsent":true}""");

        Assert.True(ThreatSharingConsent.HasConsent(profile));
    }

    [Fact]
    public void Missing_or_partial_consent_is_false()
    {
        Assert.False(ThreatSharingConsent.HasConsent(Path.Combine(_directory, "missing.json")));

        var profile = Path.Combine(_directory, "install-profile.json");
        File.WriteAllText(profile, """{"profile":"partial"}""");
        Assert.False(ThreatSharingConsent.HasConsent(profile));
    }

    [Fact]
    public void Applied_marker_round_trips()
    {
        var marker = Path.Combine(_directory, "applied");

        Assert.False(ThreatSharingConsent.WasApplied(marker));
        ThreatSharingConsent.MarkApplied(marker);
        Assert.True(ThreatSharingConsent.WasApplied(marker));
    }
}
