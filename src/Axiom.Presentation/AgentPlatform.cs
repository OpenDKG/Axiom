// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.Presentation;

/// <summary>
/// Platform naming rules shared by the agent protections, module installers and probes. Windows
/// results are the historical literals (<c>venv\Scripts\python.exe</c>, <c>name.exe</c>); macOS and
/// Linux use the POSIX layout (<c>venv/bin/python</c>, bare executable names).
/// </summary>
public static class AgentPlatform
{
    public static bool IsWindows => OperatingSystem.IsWindows();

    /// <summary>Python interpreter of a virtual environment rooted at <paramref name="root"/>.</summary>
    public static string VenvPython(string root) => VenvPython(root, IsWindows);

    public static string VenvPython(string root, bool windows) =>
        windows
            ? Path.Combine(root, "venv", "Scripts", "python.exe")
            : Path.Combine(root, "venv", "bin", "python");

    /// <summary>
    /// Interpreter used to start a background module without a console window. Windows: upstream's
    /// choice, <c>venv\\Scripts\\pythonw.exe</c> when it exists, otherwise <c>python.exe</c>. POSIX has
    /// no console-window variant: <c>venv/bin/python</c>.
    /// </summary>
    public static string VenvPythonNoConsole(string root) => VenvPythonNoConsole(root, IsWindows, File.Exists);

    public static string VenvPythonNoConsole(string root, bool windows, Func<string, bool> fileExists)
    {
        ArgumentNullException.ThrowIfNull(fileExists);
        if (!windows)
        {
            return VenvPython(root, windows: false);
        }

        var venvPythonW = Path.Combine(root, "venv", "Scripts", "pythonw.exe");
        var venvPython = Path.Combine(root, "venv", "Scripts", "python.exe");
        return fileExists(venvPythonW) ? venvPythonW : venvPython;
    }

    /// <summary>
    /// True when the virtual environment under <paramref name="root"/> has an interpreter. Windows:
    /// upstream's check, <c>venv\\Scripts\\python.exe</c> or <c>pythonw.exe</c>; POSIX: <c>venv/bin/python</c>.
    /// </summary>
    public static bool HasVenvPython(string root) => HasVenvPython(root, IsWindows, File.Exists);

    public static bool HasVenvPython(string root, bool windows, Func<string, bool> fileExists)
    {
        ArgumentNullException.ThrowIfNull(fileExists);
        return fileExists(VenvPython(root, windows)) || fileExists(VenvPythonNoConsole(root, windows, fileExists));
    }

    /// <summary>A console tool installed in a virtual environment (for example <c>hermes</c>).</summary>
    public static string VenvTool(string root, string name) => VenvTool(root, name, IsWindows);

    public static string VenvTool(string root, string name, bool windows) =>
        windows
            ? Path.Combine(root, "venv", "Scripts", name + ".exe")
            : Path.Combine(root, "venv", "bin", name);

    /// <summary><c>name.exe</c> on Windows, <c>name</c> elsewhere.</summary>
    public static string ExecutableName(string name) => ExecutableName(name, IsWindows);

    public static string ExecutableName(string name, bool windows) => windows ? name + ".exe" : name;

    /// <summary>npm's shim for a global/local package binary: <c>name.cmd</c> on Windows, <c>name</c> elsewhere.</summary>
    public static string NpmShimName(string name) => IsWindows ? name + ".cmd" : name;

    /// <summary>
    /// Extensions tried after the bare name when searching PATH. Windows uses PATHEXT; POSIX
    /// systems have no implicit extensions.
    /// </summary>
    public static IReadOnlyList<string> PathExtensions(bool windows, string? pathExt) =>
        windows
            ? (pathExt ?? ".EXE;.CMD;.BAT;.COM")
                .Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            : [];

    /// <summary>
    /// Extra directories to search on macOS, where GUI apps start with launchd's minimal PATH
    /// (<c>/usr/bin:/bin:/usr/sbin:/sbin</c>) and miss Homebrew, npm and user tool locations.
    /// </summary>
    public static IReadOnlyList<string> MacExtraSearchDirectories(string userProfile) =>
    [
        "/opt/homebrew/bin",
        "/usr/local/bin",
        Path.Combine(userProfile, ".local", "bin"),
        Path.Combine(userProfile, ".npm-global", "bin"),
        Path.Combine(userProfile, ".bun", "bin"),
        Path.Combine(userProfile, ".cargo", "bin"),
        Path.Combine(userProfile, "bin"),
    ];

    /// <summary>The evidence-path expression every generated Python hook script uses on Windows.</summary>
    public const string WindowsEvidenceRoot = "Path(os.environ.get(\"LOCALAPPDATA\", str(Path.home())))";

    /// <summary>
    /// POSIX equivalent of <see cref="WindowsEvidenceRoot"/>: the directory .NET reports as
    /// LocalApplicationData (<c>~/Library/Application Support</c> on macOS, <c>~/.local/share</c>
    /// elsewhere), so hooks write evidence where the desktop reads it.
    /// </summary>
    public const string PosixEvidenceRoot =
        "Path(os.environ.get(\"LOCALAPPDATA\") or str(Path.home() / \"Library\" / \"Application Support\" " +
        "if sys.platform == \"darwin\" else Path.home() / \".local\" / \"share\"))";

    /// <summary>Returns a generated hook script unchanged on Windows and with POSIX data paths elsewhere.</summary>
    public static string AdaptHookScript(string script) => AdaptHookScript(script, IsWindows);

    public static string AdaptHookScript(string script, bool windows)
    {
        ArgumentNullException.ThrowIfNull(script);
        return windows ? script : script.Replace(WindowsEvidenceRoot, PosixEvidenceRoot, StringComparison.Ordinal);
    }

    /// <summary>The user's macOS Applications folders.</summary>
    public static IReadOnlyList<string> MacApplicationDirectories(string userProfile) =>
    [
        "/Applications",
        Path.Combine(userProfile, "Applications"),
    ];
}
