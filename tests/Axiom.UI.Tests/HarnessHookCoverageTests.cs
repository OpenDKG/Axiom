// SPDX-License-Identifier: GPL-3.0-or-later
using System.Reflection;
using Axiom.UI.Services;
using Xunit;

namespace Axiom.UI.Tests;

/// <summary>
/// The WPF assembly ships the same user-level Cline, Copilot CLI and Cursor hooks as the Avalonia
/// build, so its templates must carry the shared command guard and each host's deny shape too.
/// Issue #362: these copies previously installed the vendor-only hook body.
/// </summary>
public sealed class HarnessHookCoverageTests
{
    private static string BuildScript(Type type, bool isStatic)
    {
        var method = type.GetMethod(
            "BuildHookScript",
            BindingFlags.NonPublic | (isStatic ? BindingFlags.Static : BindingFlags.Instance))!;
        object? target = null;
        if (!isStatic)
        {
            var ctor = type.GetConstructor([typeof(string), typeof(string)])
                ?? throw new InvalidOperationException($"{type.Name} has no (string, string) constructor");
            target = ctor.Invoke([null, null]);
        }

        return (string)method.Invoke(target, null)!;
    }

    [Fact]
    public void Cline_hook_carries_the_shared_guard_and_cancel_shape()
    {
        var hook = BuildScript(typeof(ClineProtection), isStatic: false);

        Assert.Contains("_check_command_safety", hook, StringComparison.Ordinal);
        Assert.Contains("_sensitive_store", hook, StringComparison.Ordinal);
        Assert.Contains("_axiom_injection", hook, StringComparison.Ordinal);
        Assert.Contains("\"cancel\": True", hook, StringComparison.Ordinal);
        Assert.Contains("errorMessage", hook, StringComparison.Ordinal);
    }

    [Fact]
    public void Copilot_hook_carries_the_shared_guard_and_permission_decision_shape()
    {
        var hook = BuildScript(typeof(CopilotProtection), isStatic: true);

        Assert.Contains("_check_command_safety", hook, StringComparison.Ordinal);
        Assert.Contains("_sensitive_store", hook, StringComparison.Ordinal);
        Assert.Contains("_axiom_injection", hook, StringComparison.Ordinal);
        Assert.Contains("\"permissionDecision\": \"deny\"", hook, StringComparison.Ordinal);
        Assert.Contains("\"permissionDecision\": \"allow\"", hook, StringComparison.Ordinal);
    }

    [Fact]
    public void Cursor_hook_carries_the_shared_guard_and_permission_shape()
    {
        var hook = BuildScript(typeof(CursorProtection), isStatic: true);

        Assert.Contains("_check_command_safety", hook, StringComparison.Ordinal);
        Assert.Contains("_sensitive_store", hook, StringComparison.Ordinal);
        Assert.Contains("_axiom_injection", hook, StringComparison.Ordinal);
        Assert.Contains("\"permission\": \"deny\"", hook, StringComparison.Ordinal);
        Assert.Contains("\"permission\": \"allow\"", hook, StringComparison.Ordinal);
    }
}
