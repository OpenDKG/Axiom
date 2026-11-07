// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using Axiom.Contracts.Firewall;

namespace Axiom.Presentation;

/// <summary>Default scope used when the user creates an Axiom-owned firewall rule.</summary>
public sealed record FirewallDefaults(
    FirewallProfile Profiles,
    NetworkProtocol Protocol,
    string RemotePorts,
    string RemoteAddresses)
{
    public static FirewallDefaults Default { get; } = new(
        FirewallProfile.All,
        NetworkProtocol.Any,
        string.Empty,
        string.Empty);
}

/// <summary>
/// Per-user defaults for new firewall rules. It stores only scope preferences; it never creates,
/// changes or removes a Windows Firewall rule.
/// </summary>
public sealed class FirewallDefaultsStore
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = false,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) },
    };

    public static FirewallDefaultsStore Shared { get; } = new();

    private readonly string _path;

    public FirewallDefaultsStore(string? path = null)
    {
        _path = path ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Axiom",
            "firewall-defaults.json");
    }

    public event EventHandler? Changed;

    public FirewallDefaults Load()
    {
        try
        {
            if (!File.Exists(_path))
            {
                return FirewallDefaults.Default;
            }

            var loaded = JsonSerializer.Deserialize<FirewallDefaults>(File.ReadAllText(_path), JsonOptions);
            if (loaded is null ||
                loaded.Profiles == FirewallProfile.None ||
                (loaded.Profiles & ~FirewallProfile.All) != 0 ||
                !Enum.IsDefined(loaded.Protocol))
            {
                return FirewallDefaults.Default;
            }

            return loaded with
            {
                RemotePorts = loaded.RemotePorts?.Trim() ?? string.Empty,
                RemoteAddresses = loaded.RemoteAddresses?.Trim() ?? string.Empty,
            };
        }
        catch (Exception exception) when (exception is
                     IOException or UnauthorizedAccessException or JsonException or NotSupportedException)
        {
            return FirewallDefaults.Default;
        }
    }

    public bool Save(FirewallDefaults defaults)
    {
        ArgumentNullException.ThrowIfNull(defaults);

        if (defaults.Profiles == FirewallProfile.None ||
            (defaults.Profiles & ~FirewallProfile.All) != 0 ||
            !Enum.IsDefined(defaults.Protocol))
        {
            return false;
        }

        try
        {
            var directory = Path.GetDirectoryName(_path)
                ?? throw new InvalidOperationException("Firewall defaults path has no directory.");
            Directory.CreateDirectory(directory);
            File.WriteAllText(
                _path,
                JsonSerializer.Serialize(defaults, JsonOptions),
                new System.Text.UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
            Changed?.Invoke(this, EventArgs.Empty);
            return true;
        }
        catch (Exception exception) when (exception is
                     IOException or UnauthorizedAccessException or NotSupportedException)
        {
            return false;
        }
    }
}
