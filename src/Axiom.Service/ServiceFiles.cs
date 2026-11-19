// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.Service;

/// <summary>
/// Files the service writes are owner-only on Unix (0600): the root daemon's data directory is
/// shared with no one. Windows keeps its ACL-based layout; the call is a no-op there.
/// </summary>
internal static class ServiceFiles
{
    public const UnixFileMode OwnerOnly = UnixFileMode.UserRead | UnixFileMode.UserWrite;

    public static void SetOwnerOnly(string path)
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        try
        {
            File.SetUnixFileMode(path, OwnerOnly);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // The write itself succeeded; the startup sweep tightens the mode on the next start.
        }
    }
}
