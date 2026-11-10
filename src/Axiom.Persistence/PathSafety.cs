// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.Persistence;

/// <summary>
/// Rejects paths that traverse a junction or symbolic link. Legacy migration moves machine state
/// between directories, so following a link a standard user planted would import their files into
/// ProgramData with the user's ACL.
/// </summary>
internal static class PathSafety
{
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
                    if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
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
