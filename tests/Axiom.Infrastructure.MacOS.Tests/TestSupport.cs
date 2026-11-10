// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Firewall;
using Axiom.Infrastructure.MacOS.Interop;

namespace Axiom.Infrastructure.MacOS.Tests;

internal sealed class ManualTimeProvider(DateTimeOffset start) : TimeProvider
{
    public DateTimeOffset Now { get; set; } = start;

    public override DateTimeOffset GetUtcNow() => Now;

    public void Advance(TimeSpan by) => Now += by;
}

internal sealed class TempDirectory : IDisposable
{
    public TempDirectory()
    {
        Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "axiom-mac-tests-" + Guid.NewGuid().ToString("N")[..12]);
        Directory.CreateDirectory(Path);
    }

    public string Path { get; }

    public void Dispose()
    {
        try
        {
            Directory.Delete(Path, recursive: true);
        }
        catch (IOException)
        {
        }
    }
}

/// <summary>Scripted process runner: answers by "tool arg0 arg1..." prefix and records calls.</summary>
internal sealed class FakeRunner : IProcessRunner
{
    private readonly List<(string Prefix, Func<IReadOnlyList<string>, ProcessResult> Answer)> _answers = [];

    public List<string> Calls { get; } = [];

    public FakeRunner On(string prefix, Func<IReadOnlyList<string>, ProcessResult> answer)
    {
        _answers.Insert(0, (prefix, answer));
        return this;
    }

    public FakeRunner On(string prefix, string stdout, int exitCode = 0) =>
        On(prefix, _ => new ProcessResult(exitCode, stdout, string.Empty));

    public ProcessResult Run(string fileName, IReadOnlyList<string> arguments, TimeSpan timeout)
    {
        var line = string.Join(' ', new[] { System.IO.Path.GetFileName(fileName) }.Concat(arguments));
        Calls.Add(line);
        foreach (var (prefix, answer) in _answers)
        {
            if (line.StartsWith(prefix, StringComparison.Ordinal))
            {
                return answer(arguments);
            }
        }

        return new ProcessResult(0, string.Empty, string.Empty);
    }
}

internal static class Specs
{
    public static RuleSpec Block(string appPath, Guid? id = null) => new()
    {
        ManagedRuleId = id ?? Guid.NewGuid(),
        AppPath = appPath,
        Direction = FirewallDirection.Outbound,
        Action = FirewallAction.Block,
        CreatedBy = "uid:501",
    };
}
