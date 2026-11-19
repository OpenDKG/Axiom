// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.Service;

/// <summary>
/// Unix counterpart of the Windows <c>MachineStateSecurity</c> (ProgramData ACLs, protected
/// service image). On macOS the data root modes are enforced by
/// <c>MacDataDirectoryPermissions</c> and the root-owned helper copy by
/// <c>LaunchdServiceInstaller</c>; this type only keeps the path check the shared
/// <see cref="NetworkRecoveryController"/> relies on.
/// </summary>
internal static class MachineStateSecurity
{
    /// <summary>True when the path or any parent is a symbolic link.</summary>
    public static bool IsReparsePointInPath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        try
        {
            var current = Path.GetFullPath(path);
            while (!string.IsNullOrEmpty(current))
            {
                if (Directory.Exists(current) || File.Exists(current))
                {
                    var attributes = File.GetAttributes(current);
                    if ((attributes & FileAttributes.ReparsePoint) != 0)
                    {
                        return true;
                    }
                }

                current = Path.GetDirectoryName(current);
            }

            return false;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return true;
        }
    }
}
