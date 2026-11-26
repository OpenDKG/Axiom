// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics;
using System.Runtime.InteropServices;
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
        string? elevatedSid;
        using (var identity = WindowsIdentity.GetCurrent())
        {
            elevatedSid = identity.User?.Value;
        }

        var decision = ResolveAllowedSid(
            allowedSid,
            elevatedSid,
            string.IsNullOrWhiteSpace(allowedSid) ? InteractiveConsoleUserSid() : null);
        if (decision.Error is not null)
        {
            Console.Error.WriteLine(decision.Error);
            ServiceInstallLog.Write($"install failed: {decision.Error}");
            return 2;
        }

        var sid = decision.Sid;
        ServiceInstallLog.Write($"install: pipe client bound to sid={sid ?? "(none)"} source={decision.Source}");
        if (decision.Warning is not null)
        {
            Console.Error.WriteLine(decision.Warning);
            ServiceInstallLog.Write($"install warning: {decision.Warning}");
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

    public static int Uninstall(bool removeData = false)
    {
        if (!IsAdministrator())
        {
            Console.Error.WriteLine("Axiom Shield removal requires administrator rights.");
            return 5;
        }

        StopExisting(TimeSpan.FromSeconds(30));
        ClearRecoveryActions();

        var cleanupFailed = false;
        try
        {
            using var firewall = new Infrastructure.Windows.Firewall.WindowsFirewallPolicyAdapter();
            var ownedRules = firewall.ListOwnedRulesAsync(CancellationToken.None).GetAwaiter().GetResult();
            foreach (var rule in ownedRules)
            {
                try
                {
                    var removed = firewall
                        .RemoveCapturedOwnedRuleAsync(rule.ManagedRuleId, rule.Spec.Direction, CancellationToken.None)
                        .GetAwaiter()
                        .GetResult();
                    if (!removed.Success)
                    {
                        cleanupFailed = true;
                        ServiceInstallLog.Write($"uninstall: could not remove firewall rule {rule.OsRuleName}: {removed.ErrorMessage}");
                    }
                }
                catch (Exception exception)
                {
                    cleanupFailed = true;
                    ServiceInstallLog.Write($"uninstall: failed removing firewall rule {rule.OsRuleName}: {exception.Message}");
                }
            }
        }
        catch (Exception exception)
        {
            cleanupFailed = true;
            ServiceInstallLog.Write($"uninstall: firewall rule cleanup failed: {exception.Message}");
        }

        try
        {
            _ = PrivacyDnsFailSafe.RestoreIfNeeded();
        }
        catch (Exception exception)
        {
            ServiceInstallLog.Write($"uninstall: DNS restore check failed: {exception.Message}");
        }

        var result = RunSc($"delete {ServiceInfo.ServiceName}");
        var serviceRemoved = result is 0 or 1060;

        try
        {
            if (Directory.Exists(MachineStateSecurity.ServiceDirectory) &&
                !MachineStateSecurity.IsReparsePointInPath(MachineStateSecurity.ServiceDirectory))
            {
                DeleteUnlockedEntries(MachineStateSecurity.ServiceDirectory);
                if (Directory.Exists(MachineStateSecurity.ServiceDirectory))
                {
                    Directory.Delete(MachineStateSecurity.ServiceDirectory, recursive: true);
                }
            }

            var parentDir = Path.GetDirectoryName(MachineStateSecurity.ServiceDirectory);
            if (!string.IsNullOrWhiteSpace(parentDir) &&
                Directory.Exists(parentDir) &&
                !MachineStateSecurity.IsReparsePointInPath(parentDir) &&
                !Directory.EnumerateFileSystemEntries(parentDir).Any())
            {
                Directory.Delete(parentDir);
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            ServiceInstallLog.Write($"uninstall: could not delete service directory immediately ({exception.Message})");
            if (Directory.Exists(MachineStateSecurity.ServiceDirectory) &&
                !ScheduleDirectoryCleanupOnReboot(MachineStateSecurity.ServiceDirectory))
            {
                cleanupFailed = true;
                ServiceInstallLog.Write("uninstall: could not schedule delayed cleanup for locked service directory");
            }
        }

        if (removeData)
        {
            try
            {
                if (Directory.Exists(MachineStateSecurity.ProgramDataDirectory) &&
                    !MachineStateSecurity.IsReparsePointInPath(MachineStateSecurity.ProgramDataDirectory))
                {
                    Directory.Delete(MachineStateSecurity.ProgramDataDirectory, recursive: true);
                }
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                cleanupFailed = true;
                ServiceInstallLog.Write($"uninstall: could not delete ProgramData directory: {exception.Message}");
            }
        }

        if (!serviceRemoved)
        {
            return result;
        }

        return cleanupFailed ? 9 : 0;
    }

    /// <summary>
    /// Chooses the one SID the service pipe accepts. The non-elevated caller passes its own SID with
    /// <c>--allowed-sid</c>, because with over-the-shoulder UAC the elevated token belongs to the
    /// approving administrator, not to the desktop user. Without it, the elevated identity is used
    /// as before, but never silently when it differs from the interactive console user.
    /// </summary>
    internal static AllowedSidDecision ResolveAllowedSid(string? requestedSid, string? elevatedSid, string? interactiveSid)
    {
        var requested = requestedSid?.Trim();
        if (!string.IsNullOrEmpty(requested))
        {
            return IsWellFormedSid(requested)
                ? new AllowedSidDecision(requested, "caller", null, null)
                : new AllowedSidDecision(null, "caller", null, $"--allowed-sid '{requested}' is not a valid SID.");
        }

        var interactive = interactiveSid?.Trim();
        var warning = !string.IsNullOrEmpty(elevatedSid) && !string.IsNullOrEmpty(interactive) &&
                      !string.Equals(elevatedSid, interactive, StringComparison.OrdinalIgnoreCase)
            ? $"No --allowed-sid was passed, so the service pipe is bound to the elevated account {elevatedSid}, " +
              $"not the interactive user {interactive}. That user's desktop app cannot connect until setup is " +
              "re-run from their account or with --allowed-sid."
            : null;
        return new AllowedSidDecision(elevatedSid, "elevated-fallback", warning, null);
    }

    internal static bool IsWellFormedSid(string value) =>
        System.Text.RegularExpressions.Regex.IsMatch(
            value,
            "^S-1-[0-9]{1,14}(-[0-9]{1,10}){1,15}$",
            System.Text.RegularExpressions.RegexOptions.CultureInvariant,
            TimeSpan.FromSeconds(1));

    private static string? InteractiveConsoleUserSid()
    {
        var session = WTSGetActiveConsoleSessionId();
        if (session == uint.MaxValue)
        {
            return null;
        }

        var user = QuerySessionString(session, WtsUserName);
        if (string.IsNullOrEmpty(user))
        {
            return null;
        }

        try
        {
            var domain = QuerySessionString(session, WtsDomainName);
            var account = string.IsNullOrEmpty(domain) ? new NTAccount(user) : new NTAccount(domain, user);
            return account.Translate(typeof(SecurityIdentifier)).Value;
        }
        catch (Exception exception) when (exception is IdentityNotMappedException or SystemException)
        {
            return null;
        }
    }

    private static string? QuerySessionString(uint session, int infoClass)
    {
        if (!WTSQuerySessionInformationW(IntPtr.Zero, session, infoClass, out var buffer, out _))
        {
            return null;
        }

        try
        {
            return Marshal.PtrToStringUni(buffer);
        }
        finally
        {
            WTSFreeMemory(buffer);
        }
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

        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();

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

        _ = stdout.Wait(500);
        _ = stderr.Wait(500);

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

    private static void DeleteUnlockedEntries(string directory)
    {
        foreach (var file in Directory.EnumerateFiles(directory))
        {
            try
            {
                File.Delete(file);
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
            }
        }

        foreach (var subDirectory in Directory.EnumerateDirectories(directory))
        {
            if (MachineStateSecurity.IsReparsePointInPath(subDirectory))
            {
                continue;
            }

            DeleteUnlockedEntries(subDirectory);
            try
            {
                if (!Directory.EnumerateFileSystemEntries(subDirectory).Any())
                {
                    Directory.Delete(subDirectory);
                }
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
            }
        }
    }

    private static bool ScheduleDirectoryCleanupOnReboot(string directory)
    {
        try
        {
            var allScheduled = true;
            foreach (var file in Directory.EnumerateFiles(directory, "*", SearchOption.AllDirectories))
            {
                if (!MoveFileEx(file, null, MoveFileDelayUntilReboot))
                {
                    allScheduled = false;
                }
            }

            foreach (var subDirectory in Directory.EnumerateDirectories(directory, "*", SearchOption.AllDirectories)
                         .OrderByDescending(path => path.Length))
            {
                if (!MoveFileEx(subDirectory, null, MoveFileDelayUntilReboot))
                {
                    allScheduled = false;
                }
            }

            if (!MoveFileEx(directory, null, MoveFileDelayUntilReboot))
            {
                allScheduled = false;
            }

            if (allScheduled)
            {
                ServiceInstallLog.Write($"uninstall: scheduled delayed removal of '{directory}' on reboot");
            }

            return allScheduled;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    private const uint MoveFileDelayUntilReboot = 0x4;
    private const int WtsUserName = 5;
    private const int WtsDomainName = 7;

    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("kernel32.dll")]
    private static extern uint WTSGetActiveConsoleSessionId();

    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("wtsapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WTSQuerySessionInformationW(
        IntPtr hServer,
        uint sessionId,
        int infoClass,
        out IntPtr buffer,
        out uint bytesReturned);

    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("wtsapi32.dll")]
    private static extern void WTSFreeMemory(IntPtr memory);

    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool MoveFileEx(string lpExistingFileName, string? lpNewFileName, uint dwFlags);
}

/// <summary>Which SID the service pipe is bound to, where it came from, and any warning or error.</summary>
internal sealed record AllowedSidDecision(string? Sid, string Source, string? Warning, string? Error);
