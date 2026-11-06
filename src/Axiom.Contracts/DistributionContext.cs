// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.Contracts;

/// <summary>
/// Process-wide distribution mode. The Desktop host sets this once from the Windows package API
/// before the WPF application starts; UI and service helpers can then avoid features that are not
/// part of the Microsoft Store (MSIX) package.
/// </summary>
public static class DistributionContext
{
    private static int _isPackaged;

    /// <summary>True when the current process has MSIX package identity.</summary>
    public static bool IsPackaged => Volatile.Read(ref _isPackaged) == 1;

    /// <summary>
    /// True for the Store/core-only distribution. A sideloaded MSIX package uses the same
    /// restrictions so the package never attempts optional third-party installers or agent hooks.
    /// </summary>
    public static bool IsStorePackage => IsPackaged;

    /// <summary>Called once by the Desktop composition root.</summary>
    public static void ConfigureForProcess(bool isPackaged) =>
        Volatile.Write(ref _isPackaged, isPackaged ? 1 : 0);
}
