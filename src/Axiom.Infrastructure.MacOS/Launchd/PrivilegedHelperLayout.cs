// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Infrastructure.Unix.Install;
using Axiom.Infrastructure.Unix.Interop;

namespace Axiom.Infrastructure.MacOS.Launchd;

/// <summary>
/// Where the root daemon lives on macOS: <c>/Library/PrivilegedHelperTools/com.axiom.service</c>
/// (root:wheel, 0755 dirs, 0644 files, 0755 executables). The modes and the audit are the shared
/// Unix <see cref="ProtectedImageLayout"/>; this type keeps the macOS paths and forwards the rest
/// so launchd code and tests keep their names.
/// </summary>
public static class PrivilegedHelperLayout
{
    public const string HelperRoot = "/Library/PrivilegedHelperTools";

    public const string HelperDirectory = HelperRoot + "/" + MacServicePaths.LaunchdLabel;

    public const string DaemonFileName = ProtectedImageLayout.DaemonFileName;

    public const UnixFileMode DirectoryMode = ProtectedImageLayout.DirectoryMode;

    public const UnixFileMode ExecutableMode = ProtectedImageLayout.ExecutableMode;

    public const UnixFileMode FileMode = ProtectedImageLayout.FileMode;

    public const UnixFileMode AnyExecute = ProtectedImageLayout.AnyExecute;

    /// <summary>Daemon path inside the helper directory.</summary>
    public static string DaemonPath => Path.Combine(HelperDirectory, DaemonFileName);

    /// <inheritdoc cref="ProtectedImageLayout.ModeFor"/>
    public static UnixFileMode ModeFor(bool isDirectory, UnixFileMode sourceMode) =>
        ProtectedImageLayout.ModeFor(isDirectory, sourceMode);

    /// <inheritdoc cref="ProtectedImageLayout.Audit"/>
    public static IReadOnlyList<string> Audit(string helperDirectory, IReadOnlyList<UnixFileEntry> entries) =>
        ProtectedImageLayout.Audit(helperDirectory, entries);

    /// <inheritdoc cref="ProtectedImageLayout.EnumerateTree"/>
    public static IReadOnlyList<string> EnumerateTree(string directory) =>
        ProtectedImageLayout.EnumerateTree(directory);
}
