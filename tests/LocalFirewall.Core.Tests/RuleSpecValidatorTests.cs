// SPDX-License-Identifier: GPL-3.0-or-later
using LocalFirewall.Contracts.Firewall;
using LocalFirewall.Core.Firewall;
using Xunit;

namespace LocalFirewall.Core.Tests;

public sealed class RuleSpecValidatorTests
{
    private static RuleSpec ValidSpec() => new()
    {
        ManagedRuleId = Guid.NewGuid(),
        AppPath = @"C:\Program Files\Example\example.exe",
        Direction = FirewallDirection.Outbound,
        Action = FirewallAction.Block,
        Profiles = FirewallProfile.Domain | FirewallProfile.Private | FirewallProfile.Public,
        CreatedBy = "S-1-5-21-1000",
    };

    [Fact]
    public void A_complete_spec_is_valid()
    {
        var result = RuleSpecValidator.Validate(ValidSpec());

        Assert.True(result.IsValid);
        Assert.Empty(result.Errors);
    }

    [Fact]
    public void Null_spec_is_rejected()
    {
        var result = RuleSpecValidator.Validate(null);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, error => error.Code == "rule.spec.missing");
    }

    [Fact]
    public void Empty_managed_rule_id_is_rejected()
    {
        var spec = ValidSpec() with { ManagedRuleId = Guid.Empty };

        var result = RuleSpecValidator.Validate(spec);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, error => error.Code == "rule.id.empty");
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void Blank_path_is_rejected(string path)
    {
        var spec = ValidSpec() with { AppPath = path };

        var result = RuleSpecValidator.Validate(spec);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, error => error.Code == "rule.path.missing");
    }

    [Theory]
    [InlineData(@"example.exe")]
    [InlineData(@"Program Files\Example\example.exe")]
    [InlineData(@"..\Example\example.exe")]
    public void Relative_path_is_rejected(string path)
    {
        var spec = ValidSpec() with { AppPath = path };

        var result = RuleSpecValidator.Validate(spec);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, error => error.Code == "rule.path.not_absolute");
    }

    [Theory]
    [InlineData(@"\\server\share\example.exe")]
    [InlineData(@"\\?\C:\Program Files\Example\example.exe")]
    public void Unc_and_extended_paths_are_rejected_for_now(string path)
    {
        var spec = ValidSpec() with { AppPath = path };

        var result = RuleSpecValidator.Validate(spec);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, error => error.Code == "rule.path.unc_not_supported");
    }

    [Fact]
    public void Parent_segment_is_rejected()
    {
        var spec = ValidSpec() with { AppPath = @"C:\Program Files\Example\..\Other\example.exe" };

        var result = RuleSpecValidator.Validate(spec);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, error => error.Code == "rule.path.unstable_segment");
    }

    [Fact]
    public void Control_characters_in_path_are_rejected()
    {
        var spec = ValidSpec() with { AppPath = "C:\\Program Files\\Example\\exam\u0001ple.exe" };

        var result = RuleSpecValidator.Validate(spec);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, error => error.Code == "rule.path.control_character");
    }

    [Fact]
    public void Empty_profiles_are_rejected()
    {
        var spec = ValidSpec() with { Profiles = FirewallProfile.None };

        var result = RuleSpecValidator.Validate(spec);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, error => error.Code == "rule.profiles.empty");
    }

    [Fact]
    public void Undefined_profile_bits_are_rejected()
    {
        var spec = ValidSpec() with { Profiles = (FirewallProfile)64 };

        var result = RuleSpecValidator.Validate(spec);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, error => error.Code == "rule.profiles.invalid");
    }

    [Fact]
    public void Undefined_action_is_rejected()
    {
        var spec = ValidSpec() with { Action = (FirewallAction)99 };

        var result = RuleSpecValidator.Validate(spec);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, error => error.Code == "rule.action.undefined");
    }

    [Fact]
    public void Undefined_direction_is_rejected()
    {
        var spec = ValidSpec() with { Direction = (FirewallDirection)99 };

        var result = RuleSpecValidator.Validate(spec);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, error => error.Code == "rule.direction.undefined");
    }

    [Fact]
    public void Missing_created_by_is_rejected()
    {
        var spec = ValidSpec() with { CreatedBy = "  " };

        var result = RuleSpecValidator.Validate(spec);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, error => error.Code == "rule.created_by.missing");
    }

    [Fact]
    public void Unsupported_schema_version_is_rejected()
    {
        var spec = ValidSpec() with { SchemaVersion = RuleSpecSchema.CurrentVersion + 1 };

        var result = RuleSpecValidator.Validate(spec);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, error => error.Code == "rule.schema.unsupported");
    }

    [Fact]
    public void Oversized_description_is_rejected()
    {
        var spec = ValidSpec() with { Description = new string('x', RuleSpecValidator.MaxDescriptionLength + 1) };

        var result = RuleSpecValidator.Validate(spec);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, error => error.Code == "rule.description.too_long");
    }

    [Fact]
    public void Multiple_problems_are_all_reported()
    {
        var spec = ValidSpec() with
        {
            ManagedRuleId = Guid.Empty,
            Profiles = FirewallProfile.None,
            CreatedBy = string.Empty,
        };

        var result = RuleSpecValidator.Validate(spec);

        Assert.False(result.IsValid);
        Assert.True(result.Errors.Count >= 3);
    }
}
