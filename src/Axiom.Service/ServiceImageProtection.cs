// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics;
using System.Security.Cryptography;

namespace Axiom.Service;

/// <summary>
/// Keeps the registered service image under Program Files. A service installed from the user
/// profile can be replaced by any medium-integrity process of that user; this repairs such an
/// install on the first start after an update by copying the running image to the protected
/// directory and re-pointing the service registration at it.
/// </summary>
internal static class ServiceImageProtection
{
    public static void EnsureProtectedImage()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var current = Environment.ProcessPath;
        if (string.IsNullOrWhiteSpace(current))
        {
            return;
        }

        try
        {
            MachineStateSecurity.EnsureServiceImage();
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return;
        }

        var target = MachineStateSecurity.ServiceImagePath;
        if (string.Equals(current, target, StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        if (MachineStateSecurity.IsReparsePointInPath(MachineStateSecurity.ServiceDirectory))
        {
            return;
        }

        try
        {
            File.Copy(current, target, overwrite: true);
            MachineStateSecurity.EnsureFile(target, usersMayRead: false);
            if (!ServiceInstaller.FilesMatch(current, target))
            {
                return;
            }

            // The running process keeps its old image; the next start uses the protected copy.
            _ = ServiceInstaller.RunSc($"config {ServiceInfo.ServiceName} binPath= \"\\\"{target}\\\"\"");
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
        }
    }
}
