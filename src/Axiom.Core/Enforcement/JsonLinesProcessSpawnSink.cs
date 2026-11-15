// SPDX-License-Identifier: GPL-3.0-or-later
using System.Text.Json;

namespace Axiom.Core.Enforcement;

/// <summary>
/// Writes one JSON line per process-spawn audit row to an injected writer (the service opens the
/// audit file). Keeping the writer injected makes the format testable and keeps file policy out
/// of Core.
/// </summary>
public sealed class JsonLinesProcessSpawnSink : IProcessSpawnAuditSink
{
    private static readonly JsonSerializerOptions Options = new() { WriteIndented = false };

    private readonly TextWriter _writer;

    public JsonLinesProcessSpawnSink(TextWriter writer)
    {
        _writer = writer ?? throw new ArgumentNullException(nameof(writer));
    }

    public void Record(ProcessSpawnAudit audit)
    {
        ArgumentNullException.ThrowIfNull(audit);

        var row = new
        {
            timestampUtc = audit.Spawn.At.UtcDateTime.ToString("O"),
            pid = audit.Spawn.ProcessId,
            parentPid = audit.Spawn.ParentProcessId,
            image = audit.Spawn.ImagePath,
            parentImage = audit.Spawn.ParentImagePath,
            verdict = audit.Decision.Verdict.ToString().ToLowerInvariant(),
            reason = audit.Decision.Reason,
        };

        _writer.WriteLine(JsonSerializer.Serialize(row, Options));
        _writer.Flush();
    }
}
