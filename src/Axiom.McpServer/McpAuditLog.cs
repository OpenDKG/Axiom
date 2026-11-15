// SPDX-License-Identifier: GPL-3.0-or-later
using System.Text.Json;

namespace Axiom.McpServer;

/// <summary>
/// Bounded, thread-safe local JSONL audit log for read-only MCP tool invocations.
/// Records tool name, outcome classification, and latency without secrets or query payloads.
/// </summary>
internal static class McpAuditLog
{
    private const long MaxBytes = 512 * 1024;
    private const int KeepLines = 500;
    private static readonly Lock WriteLock = new();

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = false,
    };

    internal static Func<string?> AuditPathResolver { get; set; } = DefaultAuditPath;

    internal static string? DefaultAuditPath()
    {
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        if (string.IsNullOrWhiteSpace(localAppData))
        {
            return null;
        }

        return Path.Combine(localAppData, "Axiom", "mcp-audit.jsonl");
    }

    internal static void Record(string toolName, string outcome, long durationMs)
    {
        if (string.IsNullOrWhiteSpace(toolName))
        {
            return;
        }

        try
        {
            var path = AuditPathResolver();
            if (string.IsNullOrWhiteSpace(path))
            {
                return;
            }

            var directory = Path.GetDirectoryName(path);
            if (!string.IsNullOrWhiteSpace(directory))
            {
                Directory.CreateDirectory(directory);
            }

            var entry = JsonSerializer.Serialize(new McpAuditEntry(
                DateTimeOffset.UtcNow,
                toolName,
                outcome,
                Math.Max(0, durationMs)), JsonOptions);

            lock (WriteLock)
            {
                if (File.Exists(path) && new FileInfo(path).Length > MaxBytes)
                {
                    var lines = File.ReadAllLines(path);
                    var tail = lines.Length > KeepLines ? lines[^KeepLines..] : lines;
                    File.WriteAllLines(path, tail);
                }

                File.AppendAllText(path, entry + Environment.NewLine);
            }
        }
        catch (Exception exception) when (exception is
                     IOException or UnauthorizedAccessException or NotSupportedException or JsonException)
        {
            // Audit logging must never disrupt or fail the read-only MCP stdio channel.
        }
    }

    internal sealed record McpAuditEntry(
        DateTimeOffset TimestampUtc,
        string Tool,
        string Outcome,
        long DurationMs);
}
