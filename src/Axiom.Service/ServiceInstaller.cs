// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Principal;
using System.ServiceProcess;
using Axiom.Core.Protection;

namespace Axiom.Service;

/// <summary>
/// Registers the worker as a Windows service so it can create machine-wide firewall rules.
/// This is the only elevation point in the product: the app asks for it once, with UAC, and the
/// service then runs as LocalSystem. The service image is copied out of the user profile into
/// Program Files with an administrator-only ACL, because a LocalSystem service that any
/// medium-integrity process can replace is a privilege-escalation path.
/// </summary>
internal static class ServiceInstaller
{
    public static int Install(string? allowedSid)
    {
        if (!IsAdministrator())
        {
            Console.Error.WriteLine("Axiom Shield setup requires administrator rights.");
            return 5;
        }

        // Harden ProgramData before writing the allowed SID, so a planted directory or a
        // pre-created protection.json.tmp cannot decide who may connect to the pipe.
        MachineStateSecurity.HardenProgramData();

        var store = new ProtectionSettingsStore();
        var sid = allowedSid?.Trim();
        if (string.IsNullOrWhiteSpace(sid))
        {
            using var identity = WindowsIdentity.GetCurrent();
            sid = identity.User?.Value;
        }

        if (!string.IsNullOrWhiteSpace(sid) &&
            !store.Save(store.Load() with { AllowedSid = sid }))
        {
            Console.Error.WriteLine("The shield settings could not be written to ProgramData.");
            return 6;
        }

        var source = Environment.ProcessPath
                     ?? Path.Combine(AppContext.BaseDirectory, "Axiom.Service.exe");
        var target = MachineStateSecurity.ServiceImagePath;

        try
        {
            StopExisting(TimeSpan.FromSeconds(30));
            MachineStateSecurity.EnsureDirectory(MachineStateSecurity.ServiceDirectory, usersMayRead: false);
            if (!string.Equals(source, target, StringComparison.OrdinalIgnoreCase))
            {
                CopyWithRetry(source, target);
            }

            MachineStateSecurity.EnsureFile(target, usersMayRead: false);
            if (!FilesMatch(source, target))
            {
                Console.Error.WriteLine("The protected service copy does not match the installer image.");
                return 7;
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            Console.Error.WriteLine($"The service image could not be protected: {exception.Message}");
            return 7;
        }

        var create = RunSc(
            $"create {ServiceInfo.ServiceName} binPath= \"\\\"{target}\\\"\" start= auto " +
            $"DisplayName= \"Axiom Service\"");

        if (create is not 0 and not 1073)
        {
            // 1073 = service already exists; keep going so install is idempotent.
            Console.Error.WriteLine($"sc create failed with exit code {create}.");
            return create;
        }

        // Existing installs keep their old binPath after sc create returns 1073.
        _ = RunSc($"config {ServiceInfo.ServiceName} binPath= \"\\\"{target}\\\"\"");
        _ = RunSc($"description {ServiceInfo.ServiceName} \"Axiom - Free Open-Source Network & AI Agent Security\"");
        _ = RunSc($"failure {ServiceInfo.ServiceName} reset= 86400 actions= restart/5000");
        var start = RunSc($"start {ServiceInfo.ServiceName}");

        // 1056 = already running.
        return start == 1056 ? 0 : start;
    }

    public static int Uninstall()
    {
        if (!IsAdministrator())
        {
            Console.Error.WriteLine("Axiom Shield removal requires administrator rights.");
            return 5;
        }

        StopExisting(TimeSpan.FromSeconds(30));
        var result = RunSc($"delete {ServiceInfo.ServiceName}");

        try
        {
            if (Directory.Exists(MachineStateSecurity.ServiceDirectory) &&
                !MachineStateSecurity.IsReparsePointInPath(MachineStateSecurity.ServiceDirectory))
            {
                Directory.Delete(MachineStateSecurity.ServiceDirectory, recursive: true);
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
        }

        return result;
    }

    public static bool IsAdministrator()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    internal static bool FilesMatch(string left, string right)
    {
        try
        {
            return string.Equals(Hash(left), Hash(right), StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    internal static int RunSc(string arguments)
    {
        using var process = Process.Start(new ProcessStartInfo
        {
            FileName = Path.Combine(Environment.SystemDirectory, "sc.exe"),
            Arguments = arguments,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        });

        if (process is null)
        {
            return 1;
        }

        process.WaitForExit(30_000);
        return process.ExitCode;
    }

    private static void StopExisting(TimeSpan timeout)
    {
        try
        {
            using var controller = new ServiceController(ServiceInfo.ServiceName);
            controller.Refresh();
            if (controller.Status == ServiceControllerStatus.Stopped)
            {
                return;
            }

            if (controller.Status != ServiceControllerStatus.StopPending)
            {
                controller.Stop();
            }

            controller.WaitForStatus(ServiceControllerStatus.Stopped, timeout);
        }
        catch (InvalidOperationException)
        {
            // Not installed yet.
        }
        catch (System.ServiceProcess.TimeoutException)
        {
            Console.Error.WriteLine("The existing Axiom service did not stop in time.");
        }
    }

    private static void CopyWithRetry(string source, string target)
    {
        for (var attempt = 1; ; attempt++)
        {
            try
            {
                File.Copy(source, target, overwrite: true);
                return;
            }
            catch (IOException) when (attempt < 10)
            {
                // The stopped image can stay mapped for a moment; Windows releases it shortly.
                Thread.Sleep(TimeSpan.FromSeconds(1));
            }
        }
    }

    private static string Hash(string path)
    {
        using var stream = File.OpenRead(path);
        return Convert.ToHexString(SHA256.HashData(stream));
    }
}
