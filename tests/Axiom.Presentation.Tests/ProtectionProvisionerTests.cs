// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using Axiom.Presentation;
using Xunit;

namespace Axiom.Presentation.Tests;

public sealed class ProtectionProvisionerTests
{
    // Composed with Path.Combine so the fixtures match HermesConfigLocation.Candidates on every
    // host: literal Windows paths diverge from the product's own composition on macOS/Linux.
    private static readonly string LocalRoot = Path.Combine("lab", "AppData", "Local");

    private static readonly string ProfileRoot = "lab";

    private static readonly string LocalConfig = Path.Combine(LocalRoot, "hermes", "config.yaml");

    private static readonly string ProfileConfig = Path.Combine(ProfileRoot, ".hermes", "config.yaml");

    [Fact]
    public void Provision_writes_block_mode_to_the_config_the_guard_reads()
    {
        var files = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            [LocalConfig] = "plugins:\r\n  entries:\r\n    blackbox:\r\n      mode: audit\r\n",
        };

        var result = ProtectionProvisioner.Provision(
            LocalRoot,
            ProfileRoot,
            path => files.ContainsKey(path),
            path => files.TryGetValue(path, out var text) ? text : null,
            (path, text) => files[path] = text,
            SuccessfulRunner,
            rulesPresent: true);

        Assert.True(result.BlockMode);
        Assert.True(result.Passed);
        Assert.Equal(LocalConfig, result.ConfigPath);
        Assert.Contains("mode: block", files[LocalConfig], StringComparison.Ordinal);
    }

    [Fact]
    public void Provision_falls_back_to_the_profile_config_when_local_app_data_is_absent()
    {
        var files = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            [ProfileConfig] = "plugins:\r\n  entries:\r\n    blackbox:\r\n      mode: audit\r\n",
        };

        var result = ProtectionProvisioner.Provision(
            LocalRoot,
            ProfileRoot,
            path => files.ContainsKey(path),
            path => files.TryGetValue(path, out var text) ? text : null,
            (path, text) => files[path] = text,
            SuccessfulRunner,
            rulesPresent: true);

        Assert.Equal(ProfileConfig, result.ConfigPath);
        Assert.True(result.BlockMode);
        Assert.True(result.Passed);
    }

    [Fact]
    public void Provision_fails_when_block_mode_cannot_be_verified()
    {
        var files = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            [LocalConfig] = "plugins:\r\n  entries:\r\n    blackbox:\r\n      mode: audit\r\n",
        };

        var result = ProtectionProvisioner.Provision(
            LocalRoot,
            ProfileRoot,
            path => files.ContainsKey(path),
            path => files.TryGetValue(path, out var text) ? text : null,
            (_, _) => { },
            SuccessfulRunner,
            rulesPresent: true);

        Assert.False(result.BlockMode);
        Assert.False(result.Passed);
        Assert.Contains("block mode is not active", result.Summary, StringComparison.Ordinal);
    }

    [Fact]
    public void Provision_fails_when_a_protected_check_is_allowed()
    {
        var files = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            [LocalConfig] = "plugins:\r\n  entries:\r\n    blackbox:\r\n      mode: block\r\n",
        };

        var result = ProtectionProvisioner.Provision(
            LocalRoot,
            ProfileRoot,
            path => files.ContainsKey(path),
            path => files.TryGetValue(path, out var text) ? text : null,
            (path, text) => files[path] = text,
            check => new ProtectionCheckResult(check.Name, check.ExpectBlock, false, string.Empty));

        Assert.True(result.BlockMode);
        Assert.False(result.Passed);
        Assert.Contains("FAIL", result.Summary, StringComparison.Ordinal);
    }

    [Fact]
    public void Provision_without_a_runner_cannot_claim_success()
    {
        var files = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            [LocalConfig] = "plugins:\r\n  entries:\r\n    blackbox:\r\n      mode: block\r\n",
        };

        var result = ProtectionProvisioner.Provision(
            LocalRoot,
            ProfileRoot,
            path => files.ContainsKey(path),
            path => files.TryGetValue(path, out var text) ? text : null,
            (path, text) => files[path] = text,
            runner: null);

        Assert.True(result.BlockMode);
        Assert.Empty(result.Checks);
        Assert.False(result.Passed);
    }

    [Fact]
    public void Startup_provisioning_skips_the_light_profile()
    {
        var root = Path.Combine(Path.GetTempPath(), $"axiom-protect-{Guid.NewGuid():N}");
        try
        {
            Directory.CreateDirectory(Path.Combine(root, "Axiom"));
            File.WriteAllText(Path.Combine(root, "Axiom", "install-profile.json"), """{"profile":"partial"}""");

            Assert.Null(ProtectionProvisioner.ProvisionAtStartup(root));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void An_empty_ruleset_reports_unprotected()
    {
        var files = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            [LocalConfig] = "plugins:\r\n  entries:\r\n    blackbox:\r\n      mode: block\r\n",
        };

        var result = ProtectionProvisioner.Provision(
            LocalRoot,
            ProfileRoot,
            path => files.ContainsKey(path),
            path => files.TryGetValue(path, out var text) ? text : null,
            (path, text) => files[path] = text,
            SuccessfulRunner,
            rulesPresent: false);

        Assert.True(result.BlockMode);
        Assert.False(result.RulesPresent);
        Assert.False(result.Passed);
        Assert.Equal("unprotected", result.State);
        Assert.Contains("UNPROTECTED", result.Summary, StringComparison.Ordinal);
        Assert.Contains("threat ruleset is empty", result.Summary, StringComparison.Ordinal);
    }

    [Fact]
    public void A_non_empty_ruleset_with_passing_checks_is_protected()
    {
        var files = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            [LocalConfig] = "plugins:\r\n  entries:\r\n    blackbox:\r\n      mode: block\r\n",
        };

        var result = ProtectionProvisioner.Provision(
            LocalRoot,
            ProfileRoot,
            path => files.ContainsKey(path),
            path => files.TryGetValue(path, out var text) ? text : null,
            (path, text) => files[path] = text,
            SuccessfulRunner,
            rulesPresent: true);

        Assert.True(result.Passed);
        Assert.Equal("protected", result.State);
        Assert.DoesNotContain("UNPROTECTED", result.Summary, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("""{"injection":[{"identifier":"injection:x"}],"skill":[]}""", true)]
    [InlineData("""{"injection":[],"skill":[],"graph_threats":[]}""", false)]
    [InlineData("""{"verified_scope":{"verified_counts":{"dependency:252860":1}}}""", true)]
    [InlineData("{}", false)]
    [InlineData("not-json", false)]
    public void Ruleset_presence_is_decided_by_content(string json, bool expected)
    {
        Assert.Equal(expected, ProtectionProvisioner.HasVerifiedRules(json));
    }

    private static ProtectionCheckResult SuccessfulRunner(ProtectionCheck check) =>
        new(check.Name, check.ExpectBlock, check.ExpectBlock, check.ExpectBlock ? "fileaccess:read:user-protected" : string.Empty);
}
