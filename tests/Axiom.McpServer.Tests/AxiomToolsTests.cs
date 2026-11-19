// SPDX-License-Identifier: GPL-3.0-or-later
using System.Text.Json;
using Xunit;

namespace Axiom.McpServer.Tests;

public sealed class AxiomToolsTests
{
    [Theory]
    [InlineData("127.0.0.1", true)]
    [InlineData("10.2.3.4", true)]
    [InlineData("172.16.0.1", true)]
    [InlineData("172.31.255.254", true)]
    [InlineData("192.168.1.1", true)]
    [InlineData("169.254.1.1", true)]
    [InlineData("100.64.0.1", true)]
    [InlineData("::1", true)]
    [InlineData("fe80::1", true)]
    [InlineData("fc00::1", true)]
    [InlineData("localhost", true)]
    [InlineData("", false)]
    [InlineData("203.0.113.10", false)]
    [InlineData("172.32.0.1", false)]
    [InlineData("8.8.8.8", false)]
    [InlineData("2001:4860:4860::8888", false)]
    public void ClassifiesLocalAndPublicAddresses(string host, bool expected)
    {
        Assert.Equal(expected, AxiomTools.IsPrivateOrLoopback(host));
    }

    [Theory]
    [InlineData("203.0.113.10:443", "203.0.113.10")]
    [InlineData("[2001:db8::1]:443", "2001:db8::1")]
    [InlineData("2001:4860:4860::8888", "2001:4860:4860::8888")]
    [InlineData("example.test:8080", "example.test")]
    [InlineData("—", "")]
    [InlineData("", "")]
    public void ParsesEndpointHost(string endpoint, string expected)
    {
        Assert.Equal(expected, AxiomTools.EndpointHost(endpoint));
    }

    [Theory]
    [InlineData("203.0.113.10:443", 443)]
    [InlineData("[2001:db8::1]:8443", 8443)]
    [InlineData("2001:4860:4860::8888", null)]
    [InlineData("example.test", null)]
    [InlineData("—", null)]
    public void ParsesEndpointPort(string endpoint, int? expected)
    {
        Assert.Equal(expected, AxiomTools.EndpointPort(endpoint));
    }

    [Theory]
    [InlineData("203.0.113.10", "ip")]
    [InlineData("example.test", "domain")]
    [InlineData("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "sha256")]
    [InlineData("not-a-hash", "domain")]
    public void InfersIndicatorType(string indicator, string expected)
    {
        Assert.Equal(expected, AxiomTools.InferIndicatorType(indicator));
    }

    [Fact]
    public async Task ThreatAlertsReportUnavailableInsteadOfClean()
    {
        using var document = JsonDocument.Parse(await AxiomTools.GetThreatAlerts());
        var root = document.RootElement;

        Assert.Equal("UNAVAILABLE", root.GetProperty("status").GetString());
        Assert.Empty(root.GetProperty("alerts").EnumerateArray());
        Assert.Contains("not a clean bill of health", root.GetProperty("message").GetString());
    }

    [Fact]
    public async Task InvalidDateIsRejectedInsteadOfSilentlyDefaulting()
    {
        using var document = JsonDocument.Parse(
            await AxiomTools.GetConnectionHistory(fromUtc: "not-a-date"));
        var root = document.RootElement;

        Assert.Equal("INVALID_INPUT", root.GetProperty("status").GetString());
        Assert.Contains("ISO-8601", root.GetProperty("error").GetString());
    }

    [Fact]
    public async Task AnalysisWithoutASelectorIsRejected()
    {
        using var document = JsonDocument.Parse(await AxiomTools.AnalyzeConnection());
        var root = document.RootElement;

        Assert.Equal("INVALID_INPUT", root.GetProperty("status").GetString());
        Assert.Contains("deterministic", root.GetProperty("error").GetString());
    }

    [Fact]
    public async Task ReputationReportsUnavailableWithoutClaimingClean()
    {
        using var document = JsonDocument.Parse(await AxiomTools.GetReputation("203.0.113.10"));
        var root = document.RootElement;

        Assert.Equal("UNAVAILABLE", root.GetProperty("status").GetString());
        Assert.Equal("ip", root.GetProperty("indicatorType").GetString());
        Assert.Equal("none", root.GetProperty("confidence").GetString());
        Assert.False(root.GetProperty("current").GetBoolean());
        Assert.Contains("Unknown is not clean", root.GetProperty("message").GetString());
    }

    [Fact]
    public async Task Mcp_tool_calls_write_bounded_json_audit_records_without_disrupting_responses()
    {
        var tempRoot = Directory.CreateDirectory(
            Path.Combine(Path.GetTempPath(), $"axiom-mcp-audit-{Guid.NewGuid():N}"));
        var auditPath = Path.Combine(tempRoot.FullName, "mcp-audit.jsonl");

        try
        {
            McpAuditLog.AuditPathResolver = () => auditPath;

            var alertJson = await AxiomTools.GetThreatAlerts(limit: 5);
            var invalidAnalyzeJson = await AxiomTools.AnalyzeConnection();
            await Task.WhenAll(Enumerable.Range(0, 12)
                .Select(index => AxiomTools.GetReputation($"203.0.113.{index}")));

            Assert.Contains("UNAVAILABLE", alertJson, StringComparison.Ordinal);
            Assert.Contains("INVALID_INPUT", invalidAnalyzeJson, StringComparison.Ordinal);
            Assert.True(File.Exists(auditPath), "Expected MCP audit log file to exist.");

            var lines = File.ReadAllLines(auditPath);
            Assert.Equal(14, lines.Length);

            var toolsSeen = new List<string>();
            foreach (var line in lines)
            {
                using var doc = JsonDocument.Parse(line);
                var entry = doc.RootElement;
                toolsSeen.Add(entry.GetProperty("tool").GetString() ?? string.Empty);
                Assert.True(entry.TryGetProperty("timestampUtc", out _));
                Assert.True(entry.GetProperty("durationMs").GetInt64() >= 0);
            }

            Assert.Contains("axiom_get_threat_alerts", toolsSeen);
            Assert.Contains("axiom_analyze_connection", toolsSeen);
            Assert.Contains("axiom_get_reputation", toolsSeen);

            // An unwritable or invalid audit target must never break MCP tool calls.
            var blockingFile = Path.Combine(tempRoot.FullName, "file-not-dir");
            File.WriteAllText(blockingFile, "lock");
            McpAuditLog.AuditPathResolver = () => Path.Combine(blockingFile, "mcp-audit.jsonl");

            using var resilientDoc = JsonDocument.Parse(await AxiomTools.GetThreatAlerts());
            Assert.Equal("UNAVAILABLE", resilientDoc.RootElement.GetProperty("status").GetString());
        }
        finally
        {
            McpAuditLog.AuditPathResolver = McpAuditLog.DefaultAuditPath;
            Directory.Delete(tempRoot.FullName, recursive: true);
        }
    }
}
