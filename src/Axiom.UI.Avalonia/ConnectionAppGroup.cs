// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Presentation;

namespace Axiom.UI.Avalonia;

/// <summary>Grouped connections for one executable identity in the Connections page.</summary>
public sealed record ConnectionAppGroup(
    string Key,
    string Name,
    string Path,
    IReadOnlyList<ConnectionRow> Rows)
{
    public string CountText => $"{Rows.Count} socket{(Rows.Count == 1 ? string.Empty : "s")}";

    public string ProtocolText =>
        $"{Rows.Count(row => row.ProtocolText == "TCP")} TCP · {Rows.Count(row => row.ProtocolText == "UDP")} UDP";

    public string PathText => Path.Length == 0 ? "Executable path not readable" : Path;
}
