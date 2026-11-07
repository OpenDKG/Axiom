// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;

namespace Axiom.Presentation;

/// <summary>One first-observed connection retained for this UI session only.</summary>
public sealed record NewConnectionMarkerEvent(
    int Number,
    DateTimeOffset FirstSeenUtc,
    string App,
    string Remote,
    string Direction,
    string State,
    int ProcessId,
    string AppPath,
    string Protocol,
    string Local)
{
    public string TimeText => FirstSeenUtc.ToLocalTime().ToString("HH:mm:ss", CultureInfo.InvariantCulture);

    public string Summary => $"{App} · {Direction} · {Remote} · {State}";

    public string Details =>
        $"{FirstSeenUtc.ToLocalTime():yyyy-MM-dd HH:mm:ss} · {App} (PID {ProcessId})" +
        $"\n{Protocol} {Direction}: {Local} → {Remote}" +
        $"\nState: {State} · Executable: {(string.IsNullOrEmpty(AppPath) ? "unresolved" : AppPath)}" +
        "\nCountry: unknown (GeoIP not configured) · Security: not assessed";
}
