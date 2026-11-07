// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Axiom.Contracts.Ai;

namespace Axiom.Presentation;

/// <summary>Bounded local audit of structured AI findings. No prompts, provider responses or secrets are stored.</summary>
public sealed class AiFindingStore
{
    public const int MaxFindings = 50;

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) },
    };

    private readonly string _path;

    public AiFindingStore(string? path = null)
    {
        _path = path ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Axiom",
            "ai-findings.json");
    }

    public string FindingsPath => _path;

    public IReadOnlyList<AiFinding> LoadRecent(int max = MaxFindings)
    {
        try
        {
            if (!File.Exists(_path))
            {
                return [];
            }

            return (JsonSerializer.Deserialize<List<AiFinding>>(
                        File.ReadAllText(_path),
                        JsonOptions)
                    ?? [])
                .OrderByDescending(finding => finding.AnalysisTimestampUtc)
                .Take(Math.Clamp(max, 1, MaxFindings))
                .ToArray();
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or JsonException)
        {
            return [];
        }
    }

    public bool Save(AiFinding finding)
    {
        ArgumentNullException.ThrowIfNull(finding);
        try
        {
            var findings = LoadRecent(MaxFindings)
                .Where(item => !string.Equals(item.FindingId, finding.FindingId, StringComparison.Ordinal))
                .Prepend(finding)
                .Take(MaxFindings)
                .ToArray();

            var directory = Path.GetDirectoryName(_path)
                ?? throw new InvalidOperationException("AI finding path has no directory.");
            Directory.CreateDirectory(directory);
            var temporary = _path + ".tmp-" + Guid.NewGuid().ToString("N");
            File.WriteAllText(
                temporary,
                JsonSerializer.Serialize(findings, JsonOptions),
                new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
            File.Move(temporary, _path, overwrite: true);
            return true;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or JsonException)
        {
            return false;
        }
    }

    public void Clear()
    {
        try
        {
            if (File.Exists(_path))
            {
                File.Delete(_path);
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
        }
    }
}
