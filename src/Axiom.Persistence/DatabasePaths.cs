// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts;

namespace Axiom.Persistence;

/// <summary>Default on-disk locations.</summary>
public static class DatabasePaths
{
    public const string DataDirectoryName = "Axiom";

    public const string DatabaseFileName = "axiom.db";

    /// <summary>Installation path used by the future service installer (FND-009).</summary>
    public static string DefaultDatabasePath => Path.Combine(
        AxiomPaths.MachineDataDirectory,
        DatabaseFileName);

    /// <summary>
    /// Console development and per-user runs write under LocalAppData; an installed service
    /// (non-interactive on Windows, launchd/root on macOS) uses the machine data directory
    /// (ProgramData, /Library/Application Support). AXIOM_DATA_DIR overrides both.
    /// </summary>
    public static string ResolveForCurrentProcess()
    {
        var configured = Environment.GetEnvironmentVariable("AXIOM_DATA_DIR")
                         ?? Environment.GetEnvironmentVariable(LegacyIdentity.ProductName + "_DATA_DIR");
        if (!string.IsNullOrWhiteSpace(configured))
        {
            return Path.Combine(configured, DatabaseFileName);
        }

        return Path.Combine(AxiomPaths.ProcessDataDirectory, DatabaseFileName);
    }
}
