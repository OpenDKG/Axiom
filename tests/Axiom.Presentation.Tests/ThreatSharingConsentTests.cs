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
    public void Legacy_complete_consent_does_not_authorize_manual_reporting()
    {
        var profile = Path.Combine(_directory, "install-profile.json");
        File.WriteAllText(profile, """{"profile":"complete","threatSharingConsent":true}""");

        Assert.False(ThreatSharingConsent.HasConsent(profile));
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
    public void Manual_permission_can_be_granted_and_withdrawn()
    {
        var path = Path.Combine(_directory, "manual-threat-sharing");
        Assert.False(ThreatSharingConsent.HasConsent(path));
        Assert.True(ThreatSharingConsent.TrySetPermission(true, path));
        Assert.True(ThreatSharingConsent.HasConsent(path));
        Assert.True(ThreatSharingConsent.TrySetPermission(false, path));
        Assert.False(ThreatSharingConsent.HasConsent(path));
    }
}
