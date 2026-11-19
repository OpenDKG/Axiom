// SPDX-License-Identifier: GPL-3.0-or-later
using System.Runtime.InteropServices;
using Axiom.Presentation;

namespace Axiom.Desktop.Avalonia.MacOS;

/// <summary>
/// The in-process activation path (review #4): <c>Contents/MacOS/libAxiomSysext.dylib</c> exports
/// the <c>axiom-sysext</c> operations as C functions returning the same JSON. Calling them from the
/// main <c>Axiom</c> executable makes the entitlements, the provisioning profile and
/// <c>Bundle.main</c> all belong to the one executable macOS vouches for.
/// </summary>
public interface ISysextLibrary
{
    /// <summary>Where the dylib is expected; logged so a support bundle shows which path ran.</summary>
    string Path { get; }

    /// <summary>True when the dylib file exists next to the executable.</summary>
    bool IsPresent { get; }

    /// <summary>
    /// Runs one command synchronously (blocks up to <paramref name="timeoutSeconds"/> + 5 s) and
    /// returns its JSON, or null when the library returned no string. Throws
    /// <see cref="DllNotFoundException"/>, <see cref="EntryPointNotFoundException"/> or
    /// <see cref="BadImageFormatException"/> when the dylib cannot be used; the caller falls back
    /// to the helper executable.
    /// </summary>
    string? Invoke(SysextLibraryCommand command, int timeoutSeconds);
}

public enum SysextLibraryCommand
{
    Status,
    Activate,
    Deactivate,
    Enable,
    Disable,
}

/// <summary>
/// P/Invoke binding of <c>libAxiomSysext.dylib</c> (macos/README.md "libAxiomSysext.dylib"). The
/// library is resolved from the executable's directory only (<c>Contents/MacOS</c>), never from
/// the default search path. Every call blocks the calling thread: the Swift side services the
/// <c>OSSystemExtensionRequest</c> / <c>NEFilterManager</c> callbacks on a private dispatch queue
/// and waits on a semaphore, so no main run loop is needed and the calls are safe from a worker
/// thread — which is where <see cref="FilterExtensionManager"/> runs them.
/// </summary>
public sealed class DylibSysextLibrary(string path) : ISysextLibrary
{
    private const string LibraryName = MacBundleLayout.SysextLibraryFileName;

    /// <summary>Activate: bit 1 = replace the installed extension, bit 2 = reset the filter configuration.</summary>
    public const int ForceNone = 0;

    public string Path { get; } = path;

    public bool IsPresent => File.Exists(Path);

    public string? Invoke(SysextLibraryCommand command, int timeoutSeconds)
    {
        var pointer = command switch
        {
            SysextLibraryCommand.Activate => Native.axiom_sysext_activate(ForceNone, 1, timeoutSeconds),
            SysextLibraryCommand.Deactivate => Native.axiom_sysext_deactivate(timeoutSeconds),
            SysextLibraryCommand.Enable => Native.axiom_sysext_set_filter(1, timeoutSeconds),
            SysextLibraryCommand.Disable => Native.axiom_sysext_set_filter(0, timeoutSeconds),
            _ => Native.axiom_sysext_status(timeoutSeconds),
        };

        if (pointer == IntPtr.Zero)
        {
            return null;
        }

        try
        {
            return Marshal.PtrToStringUTF8(pointer);
        }
        finally
        {
            Native.axiom_sysext_free(pointer);
        }
    }

    /// <summary>Contract version string of the loaded library (<c>axiom_sysext_version</c>), or null.</summary>
    public static string? TryGetVersion()
    {
        try
        {
            return Marshal.PtrToStringUTF8(Native.axiom_sysext_version());
        }
        catch (Exception exception) when (exception is DllNotFoundException or EntryPointNotFoundException or BadImageFormatException)
        {
            return null;
        }
    }

    private static class Native
    {
        static Native()
        {
            NativeLibrary.SetDllImportResolver(typeof(Native).Assembly, Resolve);
        }

        [DllImport(LibraryName, ExactSpelling = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory)]
        internal static extern IntPtr axiom_sysext_activate(int force, int waitForApproval, int timeoutSeconds);

        [DllImport(LibraryName, ExactSpelling = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory)]
        internal static extern IntPtr axiom_sysext_deactivate(int timeoutSeconds);

        [DllImport(LibraryName, ExactSpelling = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory)]
        internal static extern IntPtr axiom_sysext_set_filter(int enable, int timeoutSeconds);

        [DllImport(LibraryName, ExactSpelling = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory)]
        internal static extern IntPtr axiom_sysext_status(int timeoutSeconds);

        [DllImport(LibraryName, ExactSpelling = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory)]
        internal static extern void axiom_sysext_free(IntPtr json);

        [DllImport(LibraryName, ExactSpelling = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory)]
        internal static extern IntPtr axiom_sysext_version();

        /// <summary>
        /// Loads the dylib from the executable directory (<c>AppContext.BaseDirectory</c> is
        /// <c>Contents/MacOS</c> in the bundle). Returning zero lets the runtime raise
        /// <see cref="DllNotFoundException"/>, which the manager turns into the helper fallback.
        /// </summary>
        private static IntPtr Resolve(string libraryName, System.Reflection.Assembly assembly, DllImportSearchPath? searchPath)
        {
            if (!string.Equals(libraryName, LibraryName, StringComparison.Ordinal))
            {
                return IntPtr.Zero;
            }

            var candidate = System.IO.Path.Combine(AppContext.BaseDirectory, LibraryName);
            return File.Exists(candidate) && NativeLibrary.TryLoad(candidate, out var handle) ? handle : IntPtr.Zero;
        }
    }
}
