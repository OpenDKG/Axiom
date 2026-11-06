// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using Axiom.UI.Services;
using Xunit;

namespace Axiom.UI.Tests;

public sealed class OpenCodeLifecycleTests
{
    [Fact]
    public void Generated_plugins_observe_sessions_and_prevent_duplicate_registration()
    {
        using var temp = new TempTree();
        Directory.CreateDirectory(Path.Combine(temp.Root, ".config", "opencode"));
        var python = Path.Combine(
            temp.Root,
            "Axiom",
            "modules",
            "blackbox",
            "agent-blackbox",
            "venv",
            "Scripts",
            "python.exe");
        Directory.CreateDirectory(Path.GetDirectoryName(python)!);
        File.WriteAllText(python, string.Empty);

        var protection = new OpenCodeProtection(temp.Root, temp.Root, temp.Root);
        Assert.True(protection.EnsureInstalled());

        var v2 = File.ReadAllText(protection.PluginPath);
        var v1 = File.ReadAllText(protection.V1PluginPath);
        var bridge = File.ReadAllText(protection.BridgePath);

        Assert.Contains("startLifecycle", v2, StringComparison.Ordinal);
        Assert.Contains("session.step.started", v2, StringComparison.Ordinal);
        Assert.Contains("pre_api_request", v2, StringComparison.Ordinal);
        Assert.Contains("__axiomBlackboxHooksInstalled", v2, StringComparison.Ordinal);
        Assert.Contains("startLifecycle", v1, StringComparison.Ordinal);
        Assert.Contains("event == \"session_start\"", bridge, StringComparison.Ordinal);
        Assert.Contains("event == \"pre_api_request\"", bridge, StringComparison.Ordinal);
    }

    private sealed class TempTree : IDisposable
    {
        public TempTree()
        {
            Root = Path.Combine(Path.GetTempPath(), $"axiom-opencode-{Guid.NewGuid():N}");
            Directory.CreateDirectory(Root);
        }

        public string Root { get; }

        public void Dispose()
        {
            try
            {
                Directory.Delete(Root, recursive: true);
            }
            catch (IOException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }
        }
    }
}
