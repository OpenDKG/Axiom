// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.Desktop.Avalonia.Linux;

/// <summary>
/// XDG locations of the desktop host (never the daemon's /var/lib/axiom): logs and the secret-key
/// fallback under <c>$XDG_STATE_HOME/axiom</c> (default <c>~/.local/state/axiom</c>), the
/// single-instance socket under <c>$XDG_RUNTIME_DIR</c>, autostart under
/// <c>$XDG_CONFIG_HOME/autostart</c>.
/// </summary>
internal static class LinuxPaths
{
    public const string AppId = "com.axiom.firewall";

    public const string DirectoryName = "axiom";

    public static string StateDirectory => StateDirectoryFor(
        Environment.GetEnvironmentVariable("XDG_STATE_HOME"),
        Environment.GetEnvironmentVariable("HOME"));

    public static string RuntimeDirectory => RuntimeDirectoryFor(
        Environment.GetEnvironmentVariable("XDG_RUNTIME_DIR"),
        StateDirectory);

    public static string AutostartDirectory => AutostartDirectoryFor(
        Environment.GetEnvironmentVariable("XDG_CONFIG_HOME"),
        Environment.GetEnvironmentVariable("HOME"));

    internal static string StateDirectoryFor(string? xdgStateHome, string? home) =>
        Path.Combine(
            !string.IsNullOrWhiteSpace(xdgStateHome) ? xdgStateHome
            : Path.Combine(HomeOrTemp(home), ".local", "state"),
            DirectoryName);

    /// <summary>XDG_RUNTIME_DIR (tmpfs, 0700, per session) or the state directory when a session has none.</summary>
    internal static string RuntimeDirectoryFor(string? xdgRuntimeDir, string fallback) =>
        !string.IsNullOrWhiteSpace(xdgRuntimeDir) && Directory.Exists(xdgRuntimeDir) ? xdgRuntimeDir : fallback;

    internal static string AutostartDirectoryFor(string? xdgConfigHome, string? home) =>
        Path.Combine(
            !string.IsNullOrWhiteSpace(xdgConfigHome) ? xdgConfigHome : Path.Combine(HomeOrTemp(home), ".config"),
            "autostart");

    private static string HomeOrTemp(string? home) =>
        !string.IsNullOrWhiteSpace(home) ? home : Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
}
