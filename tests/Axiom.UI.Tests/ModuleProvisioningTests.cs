// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using Axiom.UI.Services;
using Xunit;

namespace Axiom.UI.Tests;

public sealed class ModuleProvisioningTests
{
    [Fact]
    public void Light_profile_plans_nothing_and_stays_in_audit()
    {
        var steps = ModuleProvisioningPlanner.Plan(
            InstallProfile.Light,
            prerequisitesMissing: true,
            blackboxInstalled: false,
            dkgInstalled: false,
            hooksInstalled: false);

        Assert.Empty(steps);
        Assert.Equal(ModuleProvisioningPlanner.AuditMode, ModuleProvisioningPlanner.TargetMode(InstallProfile.Light));
    }

    [Fact]
    public void Complete_profile_stops_at_missing_prerequisites()
    {
        var steps = ModuleProvisioningPlanner.Plan(
            InstallProfile.Complete,
            prerequisitesMissing: true,
            blackboxInstalled: false,
            dkgInstalled: false,
            hooksInstalled: false);

        var step = Assert.Single(steps);
        Assert.Equal("prerequisites", step.Id);
    }

    [Fact]
    public void Complete_profile_orders_install_configure_and_self_test()
    {
        var steps = ModuleProvisioningPlanner.Plan(
            InstallProfile.Complete,
            prerequisitesMissing: false,
            blackboxInstalled: false,
            dkgInstalled: false,
            hooksInstalled: false);

        Assert.Equal(
            "dkg,blackbox,configure,hooks,self-test",
            string.Join(",", steps.Select(step => step.Id)));
        Assert.Equal(ModuleProvisioningPlanner.BlockMode, ModuleProvisioningPlanner.TargetMode(InstallProfile.Complete));
    }

    [Fact]
    public void Complete_profile_skips_installed_modules()
    {
        var steps = ModuleProvisioningPlanner.Plan(
            InstallProfile.Complete,
            prerequisitesMissing: false,
            blackboxInstalled: true,
            dkgInstalled: true,
            hooksInstalled: true);

        Assert.Equal(
            "configure,self-test",
            string.Join(",", steps.Select(step => step.Id)));
    }

    [Fact]
    public void ApplyMode_rewrites_only_the_mode_line()
    {
        const string config = """
            plugins:
              entries:
                blackbox:
                  mode: audit
                  block_severity: critical
                  report: false
            """;

        var result = ModuleProvisioningPlanner.ApplyMode(config, ModuleProvisioningPlanner.BlockMode);

        Assert.Contains("mode: block", result, StringComparison.Ordinal);
        Assert.Contains("block_severity: critical", result, StringComparison.Ordinal);
        Assert.Contains("report: false", result, StringComparison.Ordinal);
        Assert.DoesNotContain("mode: audit", result, StringComparison.Ordinal);
    }

    [Fact]
    public void ApplyMode_leaves_config_without_a_mode_line_untouched()
    {
        const string config = "plugins:\n  entries:\n    blackbox:\n      report: false\n";

        Assert.Equal(config, ModuleProvisioningPlanner.ApplyMode(config, ModuleProvisioningPlanner.BlockMode));
    }

    [Fact]
    public void InstallProfileStore_reads_complete_and_falls_back_to_light()
    {
        var root = Path.Combine(Path.GetTempPath(), $"axiom-profile-{Guid.NewGuid():N}");
        try
        {
            Directory.CreateDirectory(Path.Combine(root, "Axiom"));
            File.WriteAllText(
                Path.Combine(root, "Axiom", "install-profile.json"),
                """{"profile":"complete"}""");

            Assert.Equal(InstallProfile.Complete, InstallProfileStore.Read(root));

            File.WriteAllText(Path.Combine(root, "Axiom", "install-profile.json"), """{"profile":"partial"}""");
            Assert.Equal(InstallProfile.Light, InstallProfileStore.Read(root));

            File.Delete(Path.Combine(root, "Axiom", "install-profile.json"));
            Assert.Equal(InstallProfile.Light, InstallProfileStore.Read(root));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }
}
