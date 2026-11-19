// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.Infrastructure.MacOS;

/// <summary>
/// Modes of the daemon log <c>/Library/Logs/Axiom</c> (review 2026-11-12, Medium #5): the shared
/// <see cref="UnixLogPermissions"/> (directory 0700, log and rotated archives 0600) plus the
/// newsyslog mode column. Kept as a facade so the launchd installer and the macOS daemon keep
/// their names.
/// </summary>
public static class MacLogPermissions
{
    /// <summary>0700.</summary>
    public const UnixFileMode DirectoryMode = UnixLogPermissions.DirectoryMode;

    /// <summary>0600.</summary>
    public const UnixFileMode FileMode = UnixLogPermissions.FileMode;

    /// <summary>The newsyslog <c>mode</c> column for the daemon log.</summary>
    public const string NewsyslogMode = "600";

    /// <inheritdoc cref="UnixLogPermissions.Enforce"/>
    public static IReadOnlyList<string> Enforce(string logDirectory, string logFilePath) =>
        UnixLogPermissions.Enforce(logDirectory, logFilePath);

    /// <inheritdoc cref="UnixLogPermissions.Archives"/>
    public static IEnumerable<string> Archives(string logDirectory, string logFilePath) =>
        UnixLogPermissions.Archives(logDirectory, logFilePath);
}
