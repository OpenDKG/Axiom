// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using System.Text;
using System.Text.Json;
using Axiom.Contracts.Privacy;

namespace Axiom.Service;

/// <summary>
/// Stores the compiled, validated source rules atomically. The previous file is retained as a
/// rollback copy; malformed files are ignored rather than partially applied.
/// </summary>
public sealed class PrivacyShieldRuleStore
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = false,
        PropertyNameCaseInsensitive = true,
    };

    private readonly string _path;

    public PrivacyShieldRuleStore(string? path = null)
    {
        _path = path ?? PrivacyShieldPaths.Resolve("privacy-shield-rules.json");
    }

    public string RulesPath => _path;

    public string PreviousPath => _path + ".previous";

    public IReadOnlyList<PrivacyShieldStoredRule> Load()
    {
        if (!File.Exists(_path))
        {
            return [];
        }

        try
        {
            // Stream the ruleset instead of reading a ~43 MB string first; the string alone would
            // add roughly 86 MB to the large object heap for the life of the process.
            using var stream = new FileStream(
                _path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                bufferSize: 64 * 1024,
                FileOptions.SequentialScan);
            return JsonSerializer.Deserialize<List<PrivacyShieldStoredRule>>(stream, JsonOptions)
                   ?? [];
        }
        catch (Exception exception) when (exception is
                     IOException or UnauthorizedAccessException or JsonException)
        {
            return [];
        }
    }

    public bool Save(IReadOnlyList<PrivacyShieldStoredRule> rules)
    {
        ArgumentNullException.ThrowIfNull(rules);

        try
        {
            var directory = Path.GetDirectoryName(_path)
                ?? throw new InvalidOperationException("Privacy Shield rules path has no directory.");
            Directory.CreateDirectory(directory);

            var temporary = _path + ".tmp-" + Guid.NewGuid().ToString("N");
            File.WriteAllText(
                temporary,
                JsonSerializer.Serialize(rules, JsonOptions),
                new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
            ServiceFiles.SetOwnerOnly(temporary);

            if (File.Exists(_path))
            {
                File.Copy(_path, PreviousPath, overwrite: true);
                ServiceFiles.SetOwnerOnly(PreviousPath);
            }

            File.Move(temporary, _path, overwrite: true);
            return true;
        }
        catch (Exception exception) when (exception is
                     IOException or UnauthorizedAccessException or JsonException)
        {
            return false;
        }
    }
}
