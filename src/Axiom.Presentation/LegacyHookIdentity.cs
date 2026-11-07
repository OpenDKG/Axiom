// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts;

namespace Axiom.Presentation;

/// <summary>Small, shared legacy checks used only to remove or replace pre-rename Axiom hooks.</summary>
public static class LegacyHookIdentity
{
    public const string DataDirectoryName = LegacyIdentity.DataDirectoryName;

    public static string ScriptName(string axiomName) => LegacyIdentity.ScriptName(axiomName);

    public static bool IsLegacyCommand(string? command) =>
        !string.IsNullOrWhiteSpace(command) &&
        (command.Contains("netpetra-", StringComparison.OrdinalIgnoreCase) ||
         command.Contains("\\" + LegacyIdentity.DataDirectoryName + "\\", StringComparison.OrdinalIgnoreCase) ||
         command.Contains(LegacyIdentity.CopilotHookFileName, StringComparison.OrdinalIgnoreCase));

    public static bool IsLegacyManagedText(string? text) =>
        text?.Contains(LegacyIdentity.HookMarker, StringComparison.Ordinal) == true;
}
