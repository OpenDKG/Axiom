// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;

namespace Axiom.Presentation;

/// <summary>Headless commands used by the Unix installer, before the desktop single-instance check.</summary>
public static class UnixAgentSetup
{
    public static bool TryHandle(string[] args, out int exitCode)
    {
        exitCode = 0;
        if (args.Length == 0 || args[0] != "--axiom-unix-agent-setup")
        {
            return false;
        }

        var localData = Environment.GetFolderPath(
            Environment.SpecialFolder.LocalApplicationData,
            Environment.SpecialFolderOption.DoNotVerify);
        var runtime = Path.Combine(localData, "Axiom", "modules", "blackbox", "agent-blackbox");
        if (!Path.IsPathFullyQualified(runtime) || StorageSafety.IsReparsePointInPath(runtime))
        {
            Console.Error.WriteLine("Axiom agent setup requires a local application data directory without symbolic links.");
            exitCode = 1;
            return true;
        }

        if (args is [_, "path"])
        {
            Console.WriteLine(runtime);
        }
        else if (args is [_, "refresh"] && AgentPlatform.HasVenvPython(runtime))
        {
            AgentHookMaintenance.ProvisionDetectedHooks();
        }
        else
        {
            Console.Error.WriteLine("Axiom agent setup requires a working Axiom-managed Blackbox runtime to refresh hooks.");
            exitCode = 1;
        }

        return true;
    }
}
