// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;

namespace Axiom.Service;

/// <summary>
/// Resolves the Privacy Shield data files. Privacy Shield filters the whole machine, so an
/// installed (non-interactive) service keeps its state under ProgramData where the interactive
/// UI and administrators can see it. A portable or interactive run keeps the previous per-user
/// location. Existing service data is copied once from LocalAppData when the machine-wide file
/// does not exist yet.
/// </summary>
public static class PrivacyShieldPaths
{
    public const string DirectoryName = "Axiom";

    public static string Resolve(string fileName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(fileName);

        var configured = Environment.GetEnvironmentVariable("AXIOM_DATA_DIR");
        if (!string.IsNullOrWhiteSpace(configured))
        {
            return Path.Combine(configured, fileName);
        }

        var localRoot = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var machineRoot = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        return ResolveFor(fileName, Environment.UserInteractive, localRoot, machineRoot);
    }

    /// <summary>Pure path selection so the interactive/service split is unit-testable.</summary>
    public static string ResolveFor(
        string fileName,
        bool userInteractive,
        string localRoot,
        string machineRoot)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(fileName);
        ArgumentException.ThrowIfNullOrWhiteSpace(localRoot);
        ArgumentException.ThrowIfNullOrWhiteSpace(machineRoot);

        var local = Path.Combine(localRoot, DirectoryName, fileName);
        if (userInteractive)
        {
            return local;
        }

        var machine = Path.Combine(machineRoot, DirectoryName, fileName);
        if (!File.Exists(machine))
        {
            TryMigrateFromLocal(local, machine);
        }

        return machine;
    }

    private static void TryMigrateFromLocal(string localPath, string machinePath)
    {
        try
        {
            if (!File.Exists(localPath))
            {
                return;
            }

            var directory = Path.GetDirectoryName(machinePath);
            if (!string.IsNullOrEmpty(directory))
            {
                Directory.CreateDirectory(directory);
            }

            File.Copy(localPath, machinePath, overwrite: false);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // A failed migration must not stop the resolver; it starts with defaults instead.
        }
    }
}
