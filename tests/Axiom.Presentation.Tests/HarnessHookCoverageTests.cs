// SPDX-License-Identifier: GPL-3.0-or-later
using System.Reflection;
using Axiom.Presentation;
using Xunit;

namespace Axiom.Presentation.Tests;

/// <summary>
/// Every user-level hook we ship for a harness must carry the shared Axiom command guard and the
/// deny shape that harness understands. Cline, Copilot CLI and Cursor were verified live in the lab;
/// these assertions keep the generated scripts from regressing to the vendor-only path.
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