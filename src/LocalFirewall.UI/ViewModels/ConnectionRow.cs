// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using CommunityToolkit.Mvvm.ComponentModel;
using LocalFirewall.Contracts.Monitoring;
using LocalFirewall.UI.Services;

namespace LocalFirewall.UI.ViewModels;

/// <summary>
/// Presentation wrapper around <see cref="LiveConnection"/>. Updated in place on every poll so the
/// table keeps its sorting and selection instead of rebuilding every second.
/// </summary>
public sealed class ConnectionRow : ObservableObject
{
    private LiveConnection _source;
    private string _searchBlob = string.Empty;

    public ConnectionRow(LiveConnection source)
    {
        _source = source;
        RebuildSearchBlob();
    }

    public LiveConnection Source => _source;

    public void Update(LiveConnection source)
    {
        _source = source;
        RebuildSearchBlob();
        OnPropertyChanged(string.Empty);
    }

    public string AppDisplayName => _source.AppDisplayName;

    public int ProcessId => _source.ProcessId;

    public TransportProtocol Protocol => _source.Protocol;

    public string ProtocolText => _source.Protocol == TransportProtocol.Tcp ? "TCP" : "UDP";

    public string LocalEndpoint => _source.LocalEndpoint;

    public string RemoteEndpoint => _source.RemoteEndpoint;

    public string State => _source.State;

    public string DirectionText => _source.Direction switch
    {
        ConnectionDirection.Outbound => "Out",
        ConnectionDirection.Inbound => "In",
        _ => "?",
    };

    public string PathText => _source.AppPath.Length == 0 ? "—" : _source.AppPath;

    /// <summary>
    /// No GeoIP database is loaded, so the country is explicitly unknown. A flag is never guessed
    /// from an IP address.
    /// </summary>
    public string CountryText => "—";

    public DateTimeOffset FirstObservedUtc => _source.FirstObservedUtc;

    public string FirstSeenText => _source.FirstObservedUtc.ToLocalTime()
        .ToString("HH:mm:ss", CultureInfo.InvariantCulture);

    public string UploadText => _source.EstimatedUploadBytesPerSecond is double upload
        ? ByteFormatter.Rate(upload)
        : "—";

    public string DownloadText => _source.EstimatedDownloadBytesPerSecond is double download
        ? ByteFormatter.Rate(download)
        : "—";

    public string RuleStatusText => _source.RuleStatus switch
    {
        ConnectionRuleStatus.BlockedByOwnedRule => "Blocked (owned)",
        ConnectionRuleStatus.BlockedByExternalPolicy => "Blocked (external)",
        ConnectionRuleStatus.AllowedByDefaultPolicy => "Allowed by default",
        ConnectionRuleStatus.NoOwnedRule => "No rule",
        _ => "Not verified",
    };

    public string QualityText => _source.Quality switch
    {
        DataQuality.Observed => "observed",
        DataQuality.Partial => "partial",
        _ => "unknown",
    };

    public bool IsNew => _source.IsNew;

    public bool IsLoopback => _source.IsLoopback;

    /// <summary>Ordering hint: active connections first, listeners and TIME_WAIT later.</summary>
    public int StateRank => _source.State switch
    {
        "Established" => 0,
        "SynSent" or "SynReceived" => 1,
        "FinWait1" or "FinWait2" or "CloseWait" or "Closing" or "LastAck" => 2,
        "Listen" => 3,
        "TimeWait" => 4,
        _ => 5,
    };

    public string RowTooltip =>
        $"Path: {PathText}\nQuality: {QualityText} · Rule: {RuleStatusText}\n" +
        $"Country: unknown (no GeoIP database loaded)\n" +
        $"First observed: {FirstSeenText} · State: {State}";

    public string SearchBlob => _searchBlob;

    private void RebuildSearchBlob() =>
        _searchBlob = string.Join(
            ' ',
            _source.AppDisplayName,
            _source.AppPath,
            _source.ProcessId.ToString(CultureInfo.InvariantCulture),
            _source.LocalEndpoint,
            _source.RemoteEndpoint,
            _source.State,
            _source.Direction,
            _source.Protocol);
}
