// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Axiom.UI.Services;

/// <summary>The installation profile the user chose in Axiom Setup.</summary>
public enum InstallProfile
{
    Light,
    Complete,
}

/// <summary>One provisioning step for the optional protection modules.</summary>
public sealed record ModuleProvisioningStep(string Id, string Title);

/// <summary>
/// Decides what a profile needs. The light profile leaves module installation to the user's
/// buttons; the complete profile provisions prerequisites, both modules, configuration and hooks
/// on first launch. Keeping the decision pure makes the contract testable without running a
/// third-party installer.
/// </summary>
public static class ModuleProvisioningPlanner
{
    public const string BlockMode = "block";
    public const string AuditMode = "audit";

    /// <summary>The Blackbox mode a profile targets. Community sharing stays opt-in either way.</summary>
    public static string TargetMode(InstallProfile profile) =>
        profile == InstallProfile.Complete ? BlockMode : AuditMode;

    /// <summary>
    /// Steps to run for the profile. A complete install with missing prerequisites stops at that
    /// step: installing npm packages without Node, or a Python venv without Python, cannot work.
    /// </summary>
    public static IReadOnlyList<ModuleProvisioningStep> Plan(
        InstallProfile profile,
        bool prerequisitesMissing,
        bool blackboxInstalled,
        bool dkgInstalled,
        bool hooksInstalled)
    {
        if (profile != InstallProfile.Complete)
        {
            return [];
        }

        var steps = new List<ModuleProvisioningStep>();
        if (prerequisitesMissing)
        {
            steps.Add(new ModuleProvisioningStep("prerequisites", "Install Node.js, Python and Git"));
            return steps;
        }

        if (!dkgInstalled)
        {
            steps.Add(new ModuleProvisioningStep("dkg", "Install the OriginTrail DKG node"));
        }

        if (!blackboxInstalled)
        {
            steps.Add(new ModuleProvisioningStep("blackbox", "Install Blackbox"));
        }

        steps.Add(new ModuleProvisioningStep("configure", "Set block mode and keep sharing off"));

        if (!hooksInstalled)
        {
            steps.Add(new ModuleProvisioningStep("hooks", "Install agent hooks"));
        }

        steps.Add(new ModuleProvisioningStep("self-test", "Verify a protected-path read is blocked"));
        return steps;
    }

    /// <summary>
    /// Rewrites the plugin mode in a Hermes config, preserving every other line. Returns the
    /// original text when the block has no mode line.
    /// </summary>
    public static string ApplyMode(string configYaml, string mode)
    {
        if (string.IsNullOrEmpty(configYaml))
        {
            return configYaml;
        }

        var replaced = System.Text.RegularExpressions.Regex.Replace(
            configYaml,
            @"(?m)^(\s*)mode:\s*(audit|block|flag)\s*$",
            "${1}mode: " + mode);
        return replaced;
    }
}

/// <summary>Reads the persisted install profile.</summary>
public static class InstallProfileStore
{
    public static InstallProfile Read(string? localAppData = null)
    {
        var root = localAppData ?? Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var path = Path.Combine(root, "Axiom", "install-profile.json");
        try
        {
            if (!File.Exists(path))
            {
                return InstallProfile.Light;
            }

            var node = JsonNode.Parse(File.ReadAllText(path));
            var profile = node?["profile"]?.GetValue<string>();
            return string.Equals(profile, "complete", StringComparison.OrdinalIgnoreCase)
                ? InstallProfile.Complete
                : InstallProfile.Light;
        }
        catch (Exception exception) when (exception is IOException or JsonException or InvalidOperationException)
        {
            return InstallProfile.Light;
        }
    }
}
