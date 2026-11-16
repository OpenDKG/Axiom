// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Principal;
using System.ServiceProcess;
using Axiom.Contracts.Protection;
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
            ServiceInstallLog.Write($"install: source={source} target={target} sid={sid}");
            // A crashed service is restarted by its own recovery actions, which re-map the image
            // before the copy can replace it. Clear them first; they are re-applied below.
            ClearRecoveryActions();
            StopExisting(TimeSpan.FromSeconds(45));
            MachineStateSecurity.EnsureDirectory(MachineStateSecurity.ServiceDirectory, usersMayRead: false);
            if (!string.Equals(source, target, StringComparison.OrdinalIgnoreCase))
            {
                CopyWithRetry(source, target);
            }

            MachineStateSecurity.EnsureFile(target, usersMayRead: false);
            if (!FilesMatch(source, target))
            {
                Console.Error.WriteLine("The protected service copy does not match the installer image.");
                ServiceInstallLog.Write(
                    "install failed: service image does not match after copy " +
                    $"(source {Describe(source)}, target {Describe(target)})");
                return 7;
            }

            ServiceInstallLog.Write("install: service image replaced and verified");
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            Console.Error.WriteLine($"The service image could not be protected: {exception.Message}");
            ServiceInstallLog.Write($"install failed: {exception.GetType().Name}: {exception.Message}");
            return 7;
        }

        var create = RunSc(
            $"create {ServiceInfo.ServiceName} binPath= \"\\\"{target}\\\"\" start= auto " +
            $"DisplayName= \"Axiom Service\"");

        if (create is not 0 and not 1073)
        {
            // 1073 = service already exists; keep going so install is idempotent.
            Console.Error.WriteLine($"sc create failed with exit code {create}.");
            ServiceInstallLog.Write($"install failed: sc create returned {create}");
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
        ClearRecoveryActions();
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
            ServiceInstallLog.Write($"sc {arguments}: process did not start");
            return 1;
        }

        if (!process.WaitForExit(30_000))
        {
            // Reading ExitCode on a live process throws; report the timeout instead of crashing the
            // elevated installer with an unhandled exception.
            ServiceInstallLog.Write($"sc {arguments}: did not finish within 30 s");
            try
            {
                process.Kill(entireProcessTree: true);
            }
            catch (Exception exception) when (exception is InvalidOperationException or System.ComponentModel.Win32Exception)
            {
            }

            return 1460;
        }

        if (process.ExitCode != 0)
        {
            ServiceInstallLog.Write($"sc {arguments}: exit {process.ExitCode}");
        }

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
                ServiceInstallLog.Write("stop: existing service already stopped");
                return;
            }

            ServiceInstallLog.Write($"stop: existing service is {controller.Status}");
            if (controller.Status != ServiceControllerStatus.StopPending)
            {
                controller.Stop();
            }

            controller.WaitForStatus(ServiceControllerStatus.Stopped, timeout);
            ServiceInstallLog.Write("stop: existing service stopped");
        }
        catch (InvalidOperationException)
        {
            // Not installed yet.
            ServiceInstallLog.Write("stop: no existing service");
        }
        catch (System.ServiceProcess.TimeoutException)
        {
            Console.Error.WriteLine("The existing Axiom service did not stop in time.");
            ServiceInstallLog.Write($"stop: existing service still {SafeStatus()} after {timeout.TotalSeconds:0} s");
        }
    }

    /// <summary>
    /// Recovery actions restart a crashed service within seconds, which keeps the image mapped and
    /// makes the upgrade copy fail. Clear them for the duration of the install (issue #367); the
    /// failure actions are written again once the new image is in place.
    /// </summary>
    private static void ClearRecoveryActions()
    {
        var result = RunSc($"failure {ServiceInfo.ServiceName} reset= 0 actions= \"\"");
        if (result is not (0 or 1060))
        {
            // 1060 = no such service, which is normal on a first install.
            ServiceInstallLog.Write($"recovery: could not clear failure actions (sc exit {result})");
        }
    }

    private static string SafeStatus()
    {
        try
        {
            using var controller = new ServiceController(ServiceInfo.ServiceName);
            controller.Refresh();
            return controller.Status.ToString();
        }
        catch (Exception exception) when (exception is InvalidOperationException or UnauthorizedAccessException)
        {
            return "unknown";
        }
    }

    private static void CopyWithRetry(string source, string target)
    {
        const int attempts = 30;
        for (var attempt = 1; ; attempt++)
        {
            try
            {
                File.Copy(source, target, overwrite: true);
                if (attempt > 1)
                {
                    ServiceInstallLog.Write($"copy: succeeded on attempt {attempt}");
                }

                return;
            }
            catch (IOException exception) when (attempt < attempts)
            {
                // The stopped image can stay mapped for a moment, especially after a crash loop.
                if (attempt is 1 or 10 or 20)
                {
                    ServiceInstallLog.Write($"copy: attempt {attempt} blocked ({exception.Message}); retrying");
                }

                Thread.Sleep(TimeSpan.FromSeconds(1));
            }
            catch (IOException exception)
            {
                ServiceInstallLog.Write($"copy: failed after {attempts} attempts ({exception.Message})");
                throw;
            }
        }
    }

    private static string Describe(string path)
    {
        try
        {
            var info = new FileInfo(path);
            return info.Exists
                ? $"{info.Length} B, {Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)))[..12]}"
                : "missing";
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return "unreadable";
        }
    }

    private static string Hash(string path)
    {
        using var stream = File.OpenRead(path);
        return Convert.ToHexString(SHA256.HashData(stream));
    }
}
