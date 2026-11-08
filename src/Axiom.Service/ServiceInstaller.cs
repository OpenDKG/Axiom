// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics;
using System.Security.Principal;
using Axiom.Core.Protection;

namespace Axiom.Service;

/// <summary>
/// Registers the worker as a Windows service so it can create machine-wide firewall rules.
/// This is the only elevation point in the product: the app asks for it once, with UAC, and the
/// service then runs as LocalSystem. The interactive user's SID is persisted so the pipe DACL
/// still accepts exactly that user.
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

        if (!string.IsNullOrWhiteSpace(allowedSid))
        {
            var store = new ProtectionSettingsStore();
            _ = store.Save(store.Load() with { AllowedSid = allowedSid.Trim() });
        }
        else
        {
            using var identity = WindowsIdentity.GetCurrent();
            var sid = identity.User?.Value;
            if (!string.IsNullOrWhiteSpace(sid))
            {
                var store = new ProtectionSettingsStore();
                _ = store.Save(store.Load() with { AllowedSid = sid });
            }
        }

        var executable = Environment.ProcessPath
                         ?? Path.Combine(AppContext.BaseDirectory, "Axiom.Service.exe");

        var create = RunSc(
            $"create {ServiceInfo.ServiceName} binPath= \"\\\"{executable}\\\"\" start= auto " +
            $"DisplayName= \"Axiom Service\"");

        if (create is not 0 and not 1073)
        {
            // 1073 = service already exists; keep going so install is idempotent.
            Console.Error.WriteLine($"sc create failed with exit code {create}.");
            return create;
        }

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

        _ = RunSc($"stop {ServiceInfo.ServiceName}");
        return RunSc($"delete {ServiceInfo.ServiceName}");
    }

    public static bool IsAdministrator()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    private static int RunSc(string arguments)
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
}
