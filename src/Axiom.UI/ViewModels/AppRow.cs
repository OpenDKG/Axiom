// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using CommunityToolkit.Mvvm.ComponentModel;

namespace Axiom.UI.ViewModels;

/// <summary>Presentation row for one executable observed in the live socket inventory.</summary>
public sealed partial class AppRow : ObservableObject
{
    public AppRow(AppGroup group, double barWidth)
    {
        ArgumentNullException.ThrowIfNull(group);

        Key = group.Key;
        Name = group.Name;
        Path = group.Path;
        ProcessIds = group.ProcessIds;
        Initial = group.Name.StartsWith("OpenCode", StringComparison.OrdinalIgnoreCase) ||
                  group.Name.StartsWith("OpenChamber", StringComparison.OrdinalIgnoreCase)
            ? "OC"
            : group.Name.Length == 0 ? "?" : group.Name[..1].ToUpperInvariant();

        Update(group, barWidth);
    }

    public string Key { get; }

    public string Name { get; }

    public string Path { get; }

    public IReadOnlyList<int> ProcessIds { get; }

    public string PidText => ProcessIds.Count == 0 ? "—" : string.Join(", ", ProcessIds);

    public string Initial { get; }

    public bool HasPath => Path.Length > 0;

    public string PathText => HasPath ? Path : "Executable path not readable";

    [ObservableProperty]
    private int _socketCount;

    [ObservableProperty]
    private string _socketsText = string.Empty;

    [ObservableProperty]
    private string _protocolText = string.Empty;

    [ObservableProperty]
    private string _statesText = string.Empty;

    [ObservableProperty]
    private string _firstSeenText = string.Empty;

    [ObservableProperty]
    private double _barWidth;

    public string RuleText => "Not verified · no rule read";

    public void Update(AppGroup group, double barWidth)
    {
        ArgumentNullException.ThrowIfNull(group);

        SocketCount = group.SocketCount;
        SocketsText = $"{group.SocketCount} sockets";
        ProtocolText = $"{group.TcpCount} TCP · {group.UdpCount} UDP";
        StatesText = group.States;
        FirstSeenText = group.FirstSeenUtc.ToLocalTime().ToString("HH:mm:ss", CultureInfo.InvariantCulture);
        BarWidth = barWidth;
    }
}
