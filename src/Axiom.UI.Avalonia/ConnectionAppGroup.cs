// SPDX-License-Identifier: GPL-3.0-or-later
using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using Axiom.Presentation;

namespace Axiom.UI.Avalonia;

/// <summary>
/// Grouped connections for one executable identity. The instance is reused between polls so an
/// expanded group stays expanded and the rows do not flicker while the list is refreshed.
/// </summary>
public sealed partial class ConnectionAppGroup : ObservableObject
{
    public ConnectionAppGroup(string key)
    {
        Key = key;
    }

    public string Key { get; }

    public ObservableCollection<ConnectionRow> Rows { get; } = [];

    [ObservableProperty]
    private string _name = string.Empty;

    [ObservableProperty]
    private string _path = string.Empty;

    [ObservableProperty]
    private long _bytesSent;

    [ObservableProperty]
    private long _bytesReceived;

    [ObservableProperty]
    private double _sentBytesPerSecond;

    [ObservableProperty]
    private double _receivedBytesPerSecond;

    [ObservableProperty]
    private DateTimeOffset? _measuredSinceUtc;

    [ObservableProperty]
    private bool _hasMeasurement;

    [ObservableProperty]
    private bool _isExpanded;

    public int SocketCount => Rows.Count;

    public long TotalBytes => BytesSent + BytesReceived;

    public string CountText => $"{SocketCount} socket{(SocketCount == 1 ? string.Empty : "s")}";

    public string ProtocolText =>
        $"{Rows.Count(row => row.ProtocolText == "TCP")} TCP · {Rows.Count(row => row.ProtocolText == "UDP")} UDP";

    public string PathText => Path.Length == 0 ? "Executable path not readable" : Path;

    public string TrafficText => HasMeasurement
        ? $"↑ {ByteFormatter.Megabytes(BytesSent)} · ↓ {ByteFormatter.Megabytes(BytesReceived)}"
        : "traffic not measured";

    public string RateText => !HasMeasurement
        ? string.Empty
        : SentBytesPerSecond < 0.5 && ReceivedBytesPerSecond < 0.5
            ? "now idle"
            : $"now ↑ {ByteFormatter.Rate(SentBytesPerSecond)} · ↓ {ByteFormatter.Rate(ReceivedBytesPerSecond)}";

    public bool HasRateText => HasMeasurement;

    public string TrafficTooltip => MeasuredSinceUtc is { } since
        ? $"TCP payload bytes measured since {since.ToLocalTime():HH:mm:ss}.\n" +
          "The second line is the rate measured in the latest poll. " +
          "UDP and connections shorter than one poll are not included."
        : "Per-connection TCP statistics are unavailable in this process.";

    public void Update(
        string name,
        string path,
        IReadOnlyList<ConnectionRow> rows,
        long bytesSent,
        long bytesReceived,
        double sentBytesPerSecond,
        double receivedBytesPerSecond,
        DateTimeOffset? measuredSinceUtc)
    {
        Name = name;
        Path = path;
        BytesSent = bytesSent;
        BytesReceived = bytesReceived;
        SentBytesPerSecond = sentBytesPerSecond;
        ReceivedBytesPerSecond = receivedBytesPerSecond;
        MeasuredSinceUtc = measuredSinceUtc;
        HasMeasurement = measuredSinceUtc is not null ||
                         rows.Any(row => row.ObservedBytesSent is not null);
        SyncRows(rows);
        OnPropertyChanged(string.Empty);
    }

    /// <summary>Applies the new row set by moving existing rows instead of replacing containers.</summary>
    private void SyncRows(IReadOnlyList<ConnectionRow> rows)
    {
        var live = rows.ToHashSet();
        for (var index = Rows.Count - 1; index >= 0; index--)
        {
            if (!live.Contains(Rows[index]))
            {
                Rows.RemoveAt(index);
            }
        }

        for (var index = 0; index < rows.Count; index++)
        {
            var row = rows[index];
            var current = Rows.IndexOf(row);
            if (current < 0)
            {
                Rows.Insert(index, row);
            }
            else if (current != index)
            {
                Rows.Move(current, index);
            }
        }
    }
}
