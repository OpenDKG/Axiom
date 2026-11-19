// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Firewall;
using Axiom.Core.Firewall;
using Xunit;

namespace Axiom.Core.Tests;

public sealed class RuleSpecValidatorTests
{
    private static RuleSpec ValidSpec() => new()
    {
        ManagedRuleId = Guid.NewGuid(),
        // Native path per OS: Windows shapes are valid only on Windows (#441).
        AppPath = OperatingSystem.IsWindows() ? @"C:\Program Files\Example\example.exe" : "/usr/lib/example/example",
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
        // Off Windows a backslash path is refused as Windows-style before the absolute check.
        var expected = !OperatingSystem.IsWindows() && path.Contains('\\', StringComparison.Ordinal)
            ? "rule.path.windows_style"
            : "rule.path.not_absolute";
        Assert.Contains(result.Errors, error => error.Code == expected);
    }

    [Theory]
    [InlineData(@"C:\Program Files\Example\example.exe")]
    [InlineData(@"c:/tools/agent")]
    [InlineData(@"/usr/lib\example\agent")]
    public void Windows_style_paths_are_rejected_as_native_rule_paths_off_windows(string path)
    {
        var result = RuleSpecValidator.Validate(ValidSpec() with { AppPath = path });
        if (OperatingSystem.IsWindows())
        {
            // Windows behaviour unchanged: never the Windows-style code on Windows.
            Assert.DoesNotContain(result.Errors, error => error.Code == "rule.path.windows_style");
            return;
        }

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, error => error.Code == "rule.path.windows_style");
    }

    [Theory]
    [InlineData("/usr/bin/curl")]
    [InlineData("/home/user/.local/bin/agent")]
    [InlineData("/Applications/Example.app/Contents/MacOS/Example")]
    public void Native_posix_paths_are_valid_off_windows(string path)
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        var result = RuleSpecValidator.Validate(ValidSpec() with { AppPath = path });

        Assert.True(result.IsValid, string.Join("; ", result.Errors.Select(error => error.Code)));
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
        var spec = ValidSpec() with
        {
            AppPath = OperatingSystem.IsWindows() ? @"C:\Program Files\Example\..\Other\example.exe" : "/usr/lib/example/../other/example",
        };

        var result = RuleSpecValidator.Validate(spec);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, error => error.Code == "rule.path.unstable_segment");
    }

    [Fact]
    public void Control_characters_in_path_are_rejected()
    {
        var spec = ValidSpec() with
        {
            AppPath = OperatingSystem.IsWindows() ? "C:\\Program Files\\Example\\exam\u0001ple.exe" : "/usr/lib/example/exam\u0001ple",
        };

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

    [Fact]
    public void Valid_cidr_and_port_scope_is_accepted()
    {
        var spec = ValidSpec() with
        {
            Protocol = NetworkProtocol.Tcp,
            RemoteAddresses = ["192.168.1.0/24", "2001:db8::/32"],
            RemotePorts = "443,8000-8100",
        };

        var result = RuleSpecValidator.Validate(spec);

        Assert.True(result.IsValid);
        Assert.Empty(result.Errors);
    }

    [Fact]
    public void Wildcard_address_alone_is_accepted()
    {
        var spec = ValidSpec() with { RemoteAddresses = ["*"] };

        var result = RuleSpecValidator.Validate(spec);

        Assert.True(result.IsValid);
    }

    [Theory]
    [InlineData("example.com")]
    [InlineData("999.1.1.1")]
    [InlineData("1.2.3.4/33")]
    [InlineData("2001:db8::/129")]
    [InlineData("1.2.3.4/")]
    [InlineData("/24")]
    [InlineData("1.2.3.4-1.2.3.5")]
    public void Invalid_remote_address_is_rejected(string address)
    {
        var spec = ValidSpec() with { RemoteAddresses = [address] };

        var result = RuleSpecValidator.Validate(spec);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, error => error.Code == "rule.addresses.invalid");
    }

    [Fact]
    public void Wildcard_mixed_with_other_addresses_is_rejected()
    {
        var spec = ValidSpec() with { RemoteAddresses = ["*", "192.168.1.1"] };

        var result = RuleSpecValidator.Validate(spec);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, error => error.Code == "rule.addresses.any_mixed");
    }

    [Fact]
    public void Too_many_remote_addresses_are_rejected()
    {
        var addresses = Enumerable
            .Range(0, RuleSpecValidator.MaxRemoteAddresses + 1)
            .Select(index => $"10.0.0.{index % 255}")
            .ToArray();

        var spec = ValidSpec() with { RemoteAddresses = addresses };

        var result = RuleSpecValidator.Validate(spec);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, error => error.Code == "rule.addresses.too_many");
    }

    [Theory]
    [InlineData("0")]
    [InlineData("65536")]
    [InlineData("100-50")]
    [InlineData("443,")]
    [InlineData("abc")]
    [InlineData("1-2-3")]
    public void Invalid_remote_port_is_rejected(string ports)
    {
        var spec = ValidSpec() with
        {
            Protocol = NetworkProtocol.Tcp,
            RemotePorts = ports,
        };

        var result = RuleSpecValidator.Validate(spec);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, error => error.Code.StartsWith("rule.ports.", StringComparison.Ordinal));
    }

    [Fact]
    public void Ports_with_any_protocol_are_rejected()
    {
        var spec = ValidSpec() with { Protocol = NetworkProtocol.Any, RemotePorts = "443" };

        var result = RuleSpecValidator.Validate(spec);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, error => error.Code == "rule.ports.protocol_required");
    }

    [Fact]
    public void Valid_udp_port_range_is_accepted()
    {
        var spec = ValidSpec() with
        {
            Protocol = NetworkProtocol.Udp,
            RemotePorts = "53,123-124",
        };

        var result = RuleSpecValidator.Validate(spec);

        Assert.True(result.IsValid);
    }
}
