// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.Presentation;

/// <summary>Platform operations needed to capture and restore the network state.</summary>
public interface INetworkRecoveryPlatform
{
    IReadOnlyList<NetworkAdapterDns> CaptureAdapters();

    /// <summary>Display names of Axiom-owned firewall rules only.</summary>
    IReadOnlyList<string> CaptureAxiomRules();

    /// <summary>Re-applies the adapter's previous DNS servers, or DHCP when it was automatic.</summary>
    void ApplyAdapterDns(NetworkAdapterDns adapter);

    /// <summary>Removes exactly one Axiom-owned rule by its captured display name.</summary>
    void RemoveAxiomRule(string displayName);
}

/// <summary>Outcome of a capture or restore, including non-fatal per-item failures.</summary>
public sealed record NetworkRecoveryResult(
    int AdaptersRestored,
    int RulesRemoved,
    IReadOnlyList<string> Problems)
{
    public bool Succeeded => Problems.Count == 0;
}

/// <summary>
/// Captures the last known-good state before a protection change and restores it on demand. It
/// never touches a rule that was not captured as Axiom-owned, and it never invents DNS servers.
/// </summary>
public sealed class NetworkRecoveryService
{
    private readonly INetworkRecoveryPlatform _platform;
    private readonly Func<DateTimeOffset> _clock;
    private readonly Action<NetworkRecoverySnapshot> _persist;

    public NetworkRecoveryService(
        INetworkRecoveryPlatform platform,
        Func<DateTimeOffset>? clock = null,
        Action<NetworkRecoverySnapshot>? persist = null)
    {
        ArgumentNullException.ThrowIfNull(platform);
        _platform = platform;
        _clock = clock ?? (() => DateTimeOffset.UtcNow);
        _persist = persist ?? NetworkRecoveryStore.Save;
    }

    /// <summary>Captures and persists the state before a firewall or DNS change.</summary>
    public NetworkRecoverySnapshot Capture(bool protectionActive)
    {
        var snapshot = new NetworkRecoverySnapshot(
            _clock(),
            _platform.CaptureAdapters(),
            _platform.CaptureAxiomRules(),
            protectionActive);

        if (!snapshot.IsEmpty)
        {
            _persist(snapshot);
        }

        return snapshot;
    }

    /// <summary>
    /// Restores the stored snapshot: previous DNS per adapter, then removal of the captured
    /// Axiom-owned rules. Partial failures are reported instead of hidden.
    /// </summary>
    public NetworkRecoveryResult Restore(NetworkRecoverySnapshot? snapshot = null)
    {
        var state = snapshot ?? NetworkRecoveryStore.Load();
        if (state.IsEmpty)
        {
            return new NetworkRecoveryResult(0, 0, ["No saved network state is available."]);
        }

        var problems = new List<string>();
        var adapters = 0;
        var rules = 0;

        foreach (var adapter in state.Adapters)
        {
            try
            {
                _platform.ApplyAdapterDns(adapter);
                adapters++;
            }
            catch (Exception exception) when (exception is InvalidOperationException or UnauthorizedAccessException)
            {
                problems.Add($"DNS for '{adapter.Description}' was not restored: {exception.Message}");
            }
        }

        foreach (var rule in state.AxiomRuleIds)
        {
            try
            {
                _platform.RemoveAxiomRule(rule);
                rules++;
            }
            catch (Exception exception) when (exception is InvalidOperationException or UnauthorizedAccessException)
            {
                problems.Add($"Rule '{rule}' was not removed: {exception.Message}");
            }
        }

        return new NetworkRecoveryResult(adapters, rules, problems);
    }
}
