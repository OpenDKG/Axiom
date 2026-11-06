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
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        DataDirectoryName,
        DatabaseFileName);

    /// <summary>
    /// Console development and per-user runs write under LocalAppData; an installed service
    /// (non-interactive) uses ProgramData. AXIOM_DATA_DIR overrides both.
    /// </summary>
    public static string ResolveForCurrentProcess()
    {
        var configured = Environment.GetEnvironmentVariable("AXIOM_DATA_DIR")
                         ?? Environment.GetEnvironmentVariable(LegacyIdentity.ProductName + "_DATA_DIR");
        if (!string.IsNullOrWhiteSpace(configured))
        {
            return Path.Combine(configured, DatabaseFileName);
        }

        var root = Environment.UserInteractive
            ? Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)
            : Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);

        return Path.Combine(root, DataDirectoryName, DatabaseFileName);
    }
}
