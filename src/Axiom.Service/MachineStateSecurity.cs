// SPDX-License-Identifier: GPL-3.0-or-later
using System.Security.AccessControl;
using System.Security.Principal;

namespace Axiom.Service;

/// <summary>
/// Owns the machine-wide paths the SYSTEM service depends on. The service image must live where a
/// medium-integrity process cannot replace it, and ProgramData must not be plantable before the
/// service creates it. Both are enforced here with explicit ACLs and reparse-point rejection.
/// </summary>
internal static class MachineStateSecurity
{
    public static string ProgramDataDirectory => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "Axiom");

    public static string ServiceDirectory => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
        "Axiom",
        "Service");

    public static string ServiceImagePath => Path.Combine(ServiceDirectory, "Axiom.Service.exe");

    public static bool IsRunningAsSystem()
    {
        if (!OperatingSystem.IsWindows())
        {
            return false;
        }

        using var identity = WindowsIdentity.GetCurrent();
        return identity.User?.IsWellKnown(WellKnownSidType.LocalSystemSid) == true;
    }

    /// <summary>True when the path or any parent is a junction/symlink.</summary>
    public static bool IsReparsePointInPath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path) || !OperatingSystem.IsWindows())
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

    /// <summary>
    /// Creates or repairs %ProgramData%\Axiom as SYSTEM + Administrators only. Existing files
    /// inherit the tightened ACL, so a previous install's Users-read entries are removed.
    /// </summary>
    public static void HardenProgramData()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var directory = ProgramDataDirectory;
        if (IsReparsePointInPath(directory))
        {
            return;
        }

        EnsureDirectory(directory, usersMayRead: false);

        foreach (var file in Directory.EnumerateFiles(directory))
        {
            if (!IsReparsePointInPath(file))
            {
                EnsureFile(file, usersMayRead: false);
            }
        }
    }

    public static void EnsureServiceImage()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        if (IsReparsePointInPath(ServiceDirectory))
        {
            return;
        }

        EnsureDirectory(ServiceDirectory, usersMayRead: false);
        if (File.Exists(ServiceImagePath))
        {
            EnsureFile(ServiceImagePath, usersMayRead: false);
        }
    }

    public static void EnsureDirectory(string path, bool usersMayRead)
    {
        var info = new DirectoryInfo(path);
        if (!info.Exists)
        {
            info.Create();
        }

        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        AddFullControl(security, SystemSid(), InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit);
        AddFullControl(security, AdministratorsSid(), InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit);
        if (usersMayRead)
        {
            security.AddAccessRule(new FileSystemAccessRule(
                UsersSid(),
                FileSystemRights.ReadAndExecute,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow));
        }

        info.SetAccessControl(security);
    }

    public static void EnsureFile(string path, bool usersMayRead)
    {
        var info = new FileInfo(path);
        if (!info.Exists)
        {
            return;
        }

        var security = new FileSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        AddFullControl(security, SystemSid(), InheritanceFlags.None);
        AddFullControl(security, AdministratorsSid(), InheritanceFlags.None);
        if (usersMayRead)
        {
            security.AddAccessRule(new FileSystemAccessRule(
                UsersSid(),
                FileSystemRights.ReadAndExecute,
                AccessControlType.Allow));
        }

        info.SetAccessControl(security);
    }

    private static void AddFullControl(
        FileSystemSecurity security,
        SecurityIdentifier sid,
        InheritanceFlags inheritance)
    {
        security.AddAccessRule(new FileSystemAccessRule(
            sid,
            FileSystemRights.FullControl,
            inheritance,
            PropagationFlags.None,
            AccessControlType.Allow));
    }

    private static SecurityIdentifier SystemSid() =>
        new(WellKnownSidType.LocalSystemSid, null);

    private static SecurityIdentifier AdministratorsSid() =>
        new(WellKnownSidType.BuiltinAdministratorsSid, null);

    private static SecurityIdentifier UsersSid() =>
        new(WellKnownSidType.BuiltinUsersSid, null);
}
