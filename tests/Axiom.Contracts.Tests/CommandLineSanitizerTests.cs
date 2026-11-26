// SPDX-License-Identifier: GPL-3.0-or-later
using System.Text.RegularExpressions;
using Axiom.Contracts.Monitoring;
using Xunit;

namespace Axiom.Contracts.Tests;

/// <summary>All values are made up. Token-shaped strings are assembled at run time.</summary>
public sealed class CommandLineSanitizerTests
{
    private static readonly string Filler = new('a', 36);

    // No time limit, so that a busy machine cannot change what these tests see.
    private static string Sanitise(string? commandLine, string? homeDirectory = null) =>
        CommandLineSanitizer.Sanitize(commandLine, homeDirectory, Regex.InfiniteMatchTimeout);

    [Fact]
    public void A_timed_out_pattern_leaves_the_placeholder_instead_of_any_part_of_the_line()
    {
        var sanitised = CommandLineSanitizer.Sanitize(
            "app --password hunter2", "/home/al", Regex.InfiniteMatchTimeout,
            () => throw new RegexMatchTimeoutException());

        Assert.Equal("[sanitiser timeout]", sanitised);
        Assert.Equal(CommandLineSanitizer.TimeoutPlaceholder, sanitised);
        Assert.Equal(sanitised, Sanitise(sanitised));
    }

    [Fact]
    public void The_default_call_and_a_chosen_timeout_mask_the_same_way() =>
        Assert.Equal(
            Sanitise("run now"),
            CommandLineSanitizer.Sanitize("run now", null, TimeSpan.FromMinutes(1)));

    [Theory]
    [InlineData("curl -H \"Authorization: Bearer abc123\" https://host/", "abc123")]
    [InlineData("curl -H 'Authorization: Basic dXNlcjpwYXNz' https://host/", "dXNlcjpwYXNz")]
    [InlineData("curl -H Authorization:token9876 https://host/", "token9876")]
    [InlineData("tool --header bearer abc123", "abc123")]
    [InlineData("tool --authorization \"Bearer abc123\"", "abc123")]
    [InlineData("mysql --password=hunter2 -h db", "hunter2")]
    [InlineData("app --password hunter2", "hunter2")]
    [InlineData("app --password \"a b\" --verbose", "a b")]
    [InlineData("app --password 'a b' --verbose", "a b")]
    [InlineData("app --password=\"a b\" --verbose", "a b")]
    [InlineData("app --password \"open ended", "open ended")]
    [InlineData("git clone https://u:p4ss@host/r", "p4ss")]
    [InlineData("psql postgres://admin:p@ss@db:5432/app", "p@ss")]
    [InlineData("tool --api-key sk-abcdef", "sk-abcdef")]
    [InlineData("tool --client-secret s3cr3t", "s3cr3t")]
    [InlineData("AWS_SECRET_ACCESS_KEY=xyz run", "xyz")]
    [InlineData("MY_SERVICE_TOKEN=xyz run", "xyz")]
    [InlineData("DB_PASSWORD=\"a b\" run", "a b")]
    [InlineData("STRIPE_KEY=xyz APP_SECRET=qrs run", "xyz")]
    [InlineData("STRIPE_KEY=xyz APP_SECRET=qrs run", "qrs")]
    [InlineData("curl https://host/?access_token=abc123", "abc123")]
    [InlineData("curl -u alice:hunter2 https://host/", "hunter2")]
    [InlineData("curl --user alice:hunter2 https://host/", "hunter2")]
    [InlineData("curl --user=alice:hunter2 https://host/", "hunter2")]
    [InlineData("curl --proxy-user alice:hunter2 https://host/", "hunter2")]
    [InlineData("curl -u \"alice:two words\" https://host/", "two words")]
    [InlineData("curl --user 'alice:two words' https://host/", "two words")]
    [InlineData("curl -u alice:pa/ss:word https://host/", "pa/ss:word")]
    [InlineData("curl -u :hunter2 https://host/", "hunter2")]
    [InlineData("aws configure set aws_secret_access_key abc123", "abc123")]
    [InlineData("aws configure set aws_session_token abc123 --profile dev", "abc123")]
    [InlineData("tool config set db.password hunter2", "hunter2")]
    [InlineData("tool set API_KEY \"two words\"", "two words")]
    [InlineData("tool set client-secret-value abc123", "abc123")]
    public void Sensitive_values_are_masked_and_a_second_pass_changes_nothing(string commandLine, string value)
    {
        var sanitised = Sanitise(commandLine);

        Assert.DoesNotContain(value, sanitised, StringComparison.Ordinal);
        Assert.Contains("***", sanitised, StringComparison.Ordinal);
        Assert.Equal(sanitised, Sanitise(sanitised));
    }

    [Theory]
    [InlineData("sk-")]
    [InlineData("sk-ant-api03-")]
    [InlineData("ghp_")]
    [InlineData("github_pat_")]
    [InlineData("xoxb-")]
    [InlineData("xoxp-")]
    [InlineData("xoxa-")]
    public void Recognised_token_shapes_are_masked_without_a_flag(string prefix)
    {
        var sanitised = Sanitise($"run {prefix}{Filler} now");

        Assert.Equal("run *** now", sanitised);
    }

    [Fact]
    public void Access_key_ids_and_json_web_tokens_are_masked()
    {
        var accessKeyId = "AKIA" + new string('Q', 16);
        var webToken = "eyJ" + Filler + ".eyJ" + Filler + "." + Filler;

        Assert.Equal("run *** ***", Sanitise($"run {accessKeyId} {webToken}"));
    }

    [Theory]
    [InlineData("curl https://example.org")]
    [InlineData("curl http://host:8080/path@v2")]
    [InlineData("git clone git@github.com:org/repo.git")]
    [InlineData("task-runner-aaaaaaaaaaaaaaaa --monkey=1 --token-file /etc/app/token")]
    [InlineData("node server.js --max-connections 25 --keyboard us")]
    [InlineData("git push -u origin main")]
    [InlineData("journalctl -u nginx --since today")]
    [InlineData("tool -u https://host/path")]
    [InlineData("ssh --user alice host")]
    [InlineData("git config set user.name alice")]
    [InlineData("offset token_count 5")]
    public void Ordinary_command_lines_are_unchanged(string commandLine) =>
        Assert.Equal(commandLine, Sanitise(commandLine));

    [Theory]
    [InlineData("/home/al/bin/app --config /home/al/.app", "/home/al", "~/bin/app --config ~/.app")]
    [InlineData("ls /home/alice \"/home/al\"", "/home/al/", "ls /home/alice \"~\"")]
    [InlineData(@"C:\Users\Al\app.exe --log c:\users\al\log.txt", @"C:\Users\Al", @"%USERPROFILE%\app.exe --log %USERPROFILE%\log.txt")]
    [InlineData("ls /etc", "/", "ls /etc")]
    public void Home_directory_is_shortened_only_at_path_boundaries(string commandLine, string home, string expected)
    {
        var sanitised = Sanitise(commandLine, home);

        Assert.Equal(expected, sanitised);
        Assert.Equal(sanitised, Sanitise(sanitised, home));
    }

    [Fact]
    public void Output_is_capped_and_stable_wherever_the_cap_falls()
    {
        for (var padding = 480; padding <= 520; padding++)
        {
            var sanitised = Sanitise(new string('x', padding) + " --password=hunter2 tail");

            Assert.True(sanitised.Length <= CommandLineSanitizer.MaxLength + 1, $"padding {padding}");
            Assert.DoesNotContain("hunter", sanitised, StringComparison.Ordinal);
            Assert.Equal(sanitised, Sanitise(sanitised));
        }
    }

    [Fact]
    public void Very_long_input_returns_promptly()
    {
        var hostile = new string('a', 200_000) + " " + string.Concat(Enumerable.Repeat("--a-", 20_000));
        var watch = System.Diagnostics.Stopwatch.StartNew();

        var sanitised = CommandLineSanitizer.Sanitize(hostile);

        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(5), watch.Elapsed.ToString());
        Assert.True(sanitised.Length <= CommandLineSanitizer.MaxLength + 1);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("   ")]
    public void Empty_input_gives_empty_output(string? commandLine) =>
        Assert.Equal(string.Empty, Sanitise(commandLine));
}
