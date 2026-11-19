// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts;

namespace Axiom.Infrastructure.Unix.Interop;

/// <summary>Result of a helper tool invocation.</summary>
public sealed record ProcessResult(int ExitCode, string StandardOutput, string StandardError)
{
    public bool Succeeded => ExitCode == 0;
}

/// <summary>Runs a system tool with an argument list (no shell), bounded output and a timeout.</summary>
public interface IProcessRunner
{
    ProcessResult Run(string fileName, IReadOnlyList<string> arguments, TimeSpan timeout);
}

/// <summary>Production runner over the shared <see cref="ToolProcess"/> implementation.</summary>
public sealed class ProcessRunner : IProcessRunner
{
    public static ProcessRunner Instance { get; } = new();

    public ProcessResult Run(string fileName, IReadOnlyList<string> arguments, TimeSpan timeout)
    {
        var result = ToolProcess.Run(fileName, arguments, timeout);
        return new ProcessResult(result.ExitCode, result.StandardOutput, result.StandardError);
    }
}
