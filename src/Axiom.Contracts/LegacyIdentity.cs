// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.Contracts;

/// <summary>
/// Old product names that remain only as one-time migration inputs. Runtime code uses Axiom names;
/// this is the single compatibility boundary.
/// </summary>
public static class LegacyIdentity
{
    public const string ProductName = "Netpetra";

    public const string DataDirectoryName = "Netpetra";

    public const string DatabaseFileName = "netpetra.db";

    public const string ServiceName = "Netpetra";

    public const string PipeName = "Netpetra.Service.v1";

    public const string RulePrefix = "Netpetra::";

    public const string HookMarker = "Managed by Netpetra";

    public const string StarterFeedUrl = "netpetra://starter";

    public const string InstallDirectoryName = "Netpetra";

    public const string ShortcutName = "Netpetra.lnk";

    public const string AutostartValueName = "Netpetra";

    public const string CopilotHookFileName = "netpetra.json";

    public const string OpenCodePluginName = "netpetra-blackbox";

    public const string OpenCodeV1PluginFileName = "netpetra-blackbox.ts";

    public const string GuardBridgeFileName = "netpetra-guard-bridge.py";

    public static string ScriptName(string axiomName) =>
        axiomName.Replace("axiom-", "netpetra-", StringComparison.OrdinalIgnoreCase);
}
