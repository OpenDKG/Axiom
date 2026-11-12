// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using Axiom.Infrastructure.Unix.Interop;
using Axiom.Infrastructure.Unix.Ipc;

namespace Axiom.Infrastructure.Unix.Install;

/// <summary>
/// Which local account installed the daemon. That account becomes the owner uid that may send
/// write commands over the IPC socket (the Unix counterpart of the Windows <c>AllowedSid</c>).
/// Detected from <c>SUDO_UID</c> (install over sudo), <c>PKEXEC_UID</c> (install through a polkit
/// prompt on Linux) or the owner of <c>/dev/console</c> (install from the macOS administrator
/// prompt, where the console user is the person who typed the password).
/// </summary>
public static class InstallOwner
{
    public const string SudoUidVariable = "SUDO_UID";

    public const string PkexecUidVariable = "PKEXEC_UID";

    public const string ConsoleDevice = "/dev/console";

    /// <summary>macOS decision: a console uid (>= 501) wins; system accounts are never owners.</summary>
    public static uint? Resolve(string? sudoUid, uint? consoleOwner) =>
        Resolve(sudoUid, null, consoleOwner, UnixAccountRange.MacOS);

    /// <summary>
    /// Pure decision: the first regular-user uid among <paramref name="sudoUid"/>,
    /// <paramref name="pkexecUid"/> and <paramref name="consoleOwner"/> wins.
    /// </summary>
    public static uint? Resolve(string? sudoUid, string? pkexecUid, uint? consoleOwner, UnixAccountRange range)
    {
        ArgumentNullException.ThrowIfNull(range);

        foreach (var text in new[] { sudoUid, pkexecUid })
        {
            if (uint.TryParse(text?.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out var uid) &&
                range.IsRegularUser(uid))
            {
                return uid;
            }
        }

        if (consoleOwner is { } owner && range.IsRegularUser(owner))
        {
            return owner;
        }

        return null;
    }

    /// <summary>macOS detection: <c>SUDO_UID</c>, then the owner of <c>/dev/console</c>.</summary>
    public static uint? Detect(IProcessRunner runner) => Resolve(
        Environment.GetEnvironmentVariable(SudoUidVariable),
        UnixFileStat.Stat(runner, ConsoleDevice)?.Uid);

    /// <summary>Linux detection: <c>SUDO_UID</c>, then <c>PKEXEC_UID</c> (no console owner).</summary>
    public static uint? DetectLinux() => Resolve(
        Environment.GetEnvironmentVariable(SudoUidVariable),
        Environment.GetEnvironmentVariable(PkexecUidVariable),
        null,
        UnixAccountRange.Linux);
}
