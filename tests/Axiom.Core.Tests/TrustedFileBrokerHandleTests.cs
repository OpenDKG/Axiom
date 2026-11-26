// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics;
using Axiom.Contracts.Firewall;
using Axiom.Core.Enforcement;
using Xunit;

namespace Axiom.Core.Tests;

/// <summary>
/// The broker opens the file once without following a final-component link, decides policy on the
/// path resolved from that handle, reads from the same handle, and compares file identity. Each test
/// passes a path checker that misses the link or swap, so only the handle-based checks can catch it.
/// </summary>
public sealed class TrustedFileBrokerHandleTests : IDisposable
{
    private static readonly DateTimeOffset Observed = new(2026, 11, 25, 12, 0, 0, TimeSpan.Zero);

    private readonly string _root = Directory.CreateTempSubdirectory("axiom-broker-handle-").FullName;

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    [Fact]
    public void Final_component_symlink_is_not_followed_even_when_the_path_check_misses_it()
    {
        var secret = Write("secret.env", "SECRET=1");
        var link = Path.Combine(_root, "notes.txt");
        File.CreateSymbolicLink(link, secret);
        var broker = new TrustedFileBroker(Evaluator(protectedScope: Final(secret)), _ => false);

        var result = broker.OpenRead("opencode", "req-link", link, Observed);

        Assert.Equal(BrokerAccessDecision.DeniedReparseOrSymlink, result.Decision);
        Assert.Null(result.ContentBytes);
    }

    [Fact]
    public void Policy_is_decided_on_the_path_resolved_from_the_handle()
    {
        var realDir = Directory.CreateDirectory(Path.Combine(_root, "real")).FullName;
        var secret = Write(Path.Combine("real", "secret.env"), "SECRET=1");
        var alias = Path.Combine(_root, "alias");
        Directory.CreateSymbolicLink(alias, realDir);
        var broker = new TrustedFileBroker(Evaluator(protectedScope: Final(secret)), _ => false);

        var result = broker.OpenRead("opencode", "req-alias", Path.Combine(alias, "secret.env"), Observed);

        Assert.Equal(BrokerAccessDecision.DeniedByPolicy, result.Decision);
        Assert.Null(result.ContentBytes);
    }

    [Fact]
    public void A_swap_of_the_path_during_the_read_is_detected_or_prevented()
    {
        var work = Write("work.txt", "original");
        var protectedScope = Write("unrelated.env", "x");
        var calls = 0;
        var swapped = false;
        var broker = new TrustedFileBroker(
            Evaluator(protectedScope: Final(protectedScope)),
            _ =>
            {
                if (++calls == 2)
                {
                    try
                    {
                        File.Move(work, work + ".old");
                        File.WriteAllText(work, "replaced");
                        swapped = true;
                    }
                    catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
                    {
                        // Windows: the broker's handle does not share delete access, so the file
                        // cannot be renamed while it is being read.
                    }
                }

                return false;
            });

        var result = broker.OpenRead("opencode", "req-swap", work, Observed);

        if (swapped)
        {
            Assert.Equal(BrokerAccessDecision.DeniedToctouMismatch, result.Decision);
            Assert.Null(result.ContentBytes);
        }
        else
        {
            Assert.True(OperatingSystem.IsWindows(), "only Windows share modes may block the swap");
            Assert.Equal(BrokerAccessDecision.Allowed, result.Decision);
            Assert.Equal("original", System.Text.Encoding.UTF8.GetString(result.ContentBytes!));
        }
    }

    [Fact]
    public void Directories_and_missing_files_are_denied_without_throwing()
    {
        var broker = new TrustedFileBroker(Evaluator(protectedScope: Final(Write("unrelated.env", "x"))), _ => false);
        var directory = Directory.CreateDirectory(Path.Combine(_root, "folder")).FullName;

        var forDirectory = broker.OpenRead("opencode", "req-dir", directory, Observed);
        var forMissing = broker.OpenRead("opencode", "req-missing", Path.Combine(_root, "missing.txt"), Observed);

        Assert.Equal(BrokerAccessDecision.DeniedUnsafePath, forDirectory.Decision);
        Assert.Equal(BrokerAccessDecision.DeniedUnsafePath, forMissing.Decision);
        Assert.Null(forDirectory.ContentBytes);
        Assert.Null(forMissing.ContentBytes);
    }

    [Fact]
    public async Task Fifo_is_refused_promptly_instead_of_blocking_the_open()
    {
        if (OperatingSystem.IsWindows())
        {
            return; // Windows has no filesystem FIFOs.
        }

        var fifo = Path.Combine(_root, "pipe.txt");
        using (var mkfifo = Process.Start("mkfifo", [fifo]))
        {
            await mkfifo.WaitForExitAsync();
            Assert.Equal(0, mkfifo.ExitCode);
        }

        var broker = new TrustedFileBroker(Evaluator(protectedScope: Final(Write("unrelated.env", "x"))), _ => false);
        var work = Task.Run(() => (
            Result: broker.OpenRead("opencode", "req-fifo", fifo, Observed),
            Resolved: TrustedFileBroker.TryResolveFinalPath(fifo, out _)));

        if (await Task.WhenAny(work, Task.Delay(TimeSpan.FromSeconds(10))) != work)
        {
            // Release the blocked reader so the test host can exit: opening read/write never blocks on a FIFO.
            using var release = new FileStream(fifo, FileMode.Open, FileAccess.ReadWrite);
            Assert.Fail("Opening a FIFO blocked the broker.");
        }

        var outcome = await work;
        Assert.Equal(BrokerAccessDecision.DeniedUnsafePath, outcome.Result.Decision);
        Assert.Null(outcome.Result.ContentBytes);
        Assert.False(outcome.Resolved);
    }

    [Fact]
    public void Regular_file_is_read_from_the_handle()
    {
        var work = Write("work.txt", "hello-handle");
        var broker = new TrustedFileBroker(Evaluator(protectedScope: Final(Write("unrelated.env", "x"))), _ => false);

        var result = broker.OpenRead("opencode", "req-ok", work, Observed);

        Assert.Equal(BrokerAccessDecision.Allowed, result.Decision);
        Assert.Equal("hello-handle", System.Text.Encoding.UTF8.GetString(result.ContentBytes!));
    }

    private string Write(string relativePath, string content)
    {
        var path = Path.Combine(_root, relativePath);
        File.WriteAllText(path, content);
        return path;
    }

    private static string Final(string path)
    {
        Assert.True(TrustedFileBroker.TryResolveFinalPath(path, out var finalPath));
        return finalPath;
    }

    private EnforcementPolicyEvaluator Evaluator(string protectedScope) =>
        new(new EnforcementPolicy
        {
            Version = "1",
            ProtectedResources =
            [
                new ProtectedResource
                {
                    ResourceId = "res-secret",
                    Kinds = [AgentActionKind.ReadFile],
                    Scope = protectedScope,
                },
            ],
            Agents =
            [
                new AgentEnforcementPolicy
                {
                    AgentId = "opencode",
                    Mode = EnforcementMode.ProtectSelectedOperations,
                    Rules =
                    [
                        new EnforcementRule
                        {
                            RuleId = "allow-work",
                            Effect = EnforcementRuleEffect.Allow,
                            Kind = AgentActionKind.ReadFile,
                            TargetScope = Path.GetDirectoryName(Final(Write("anchor.txt", "a")))!,
                        },
                    ],
                },
            ],
        });
}
