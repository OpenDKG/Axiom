// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using Axiom.Infrastructure.MacOS.Interop;
using Axiom.Infrastructure.MacOS.Ipc;

namespace Axiom.Infrastructure.MacOS.Launchd;

/// <summary>
/// Which local account installed the daemon. That account becomes the owner uid that may send
/// write commands over the IPC socket (the macOS counterpart of the Windows <c>AllowedSid</c>).
/// Detected from <c>SUDO_UID</c> (install over sudo) or the owner of <c>/dev/console</c> (install
/// from the app's administrator prompt, where the console user is the person who typed the password).
/// </summary>
public static class InstallOwner
{
    public const string SudoUidVariable = "SUDO_UID";

    public const string ConsoleDevice = "/dev/console";

    /// <summary>Pure decision: a console uid (>= 501) wins; system accounts are never owners.</summary>
    public static uint? Resolve(string? sudoUid, uint? consoleOwner)
    {
        if (uint.TryParse(sudoUid?.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out var uid) &&
            uid >= PeerAuthorization.FirstConsoleUid && uid != PeerAuthorization.NobodyUid)
        {
            return uid;
        }

        if (consoleOwner is { } owner && owner >= PeerAuthorization.FirstConsoleUid && owner != PeerAuthorization.NobodyUid)
        {
            return owner;
        }

        return null;
    }

    public static uint? Detect(IProcessRunner runner) => Resolve(
        Environment.GetEnvironmentVariable(SudoUidVariable),
        UnixFileStat.Stat(runner, ConsoleDevice)?.Uid);
}
