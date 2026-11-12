// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.Contracts.Modules;

/// <summary>
/// How far the local listener could be tied to the expected module. <see cref="ProcessObserved"/>
/// is evidence, not proof: a process name and command line can be imitated by the same user.
/// </summary>
public enum ModuleEndpointIdentityLevel
{
    /// <summary>No owning process could be inspected, or the host has no inspector.</summary>
    Unverified = 0,

    /// <summary>The port is owned by the module runtime and the command line or path names the module.</summary>
    ProcessObserved = 1,

    /// <summary>The port is owned by an unrelated process; the endpoint is not the module.</summary>
    ProcessMismatch = 2,
}

/// <summary>Owning process of a listening loopback port, as reported by a platform inspector.</summary>
public sealed record ModuleListenerOwner(
    int ProcessId,
    string ProcessName,
    string ExecutablePath,
    string CommandLine);

/// <summary>Read-only lookup of the process that listens on a loopback endpoint.</summary>
public interface ILoopbackListenerInspector
{
    /// <summary>Returns the owner, or <c>null</c> when it cannot be resolved without elevation.</summary>
    ModuleListenerOwner? FindOwner(Uri endpoint);
}

/// <summary>Portable identity result attached to a module probe.</summary>
public sealed record ModuleEndpointIdentity
{
    public required ModuleEndpointIdentityLevel Level { get; init; }

    /// <summary>Short, UI-safe description. Never contains a command line or full path.</summary>
    public required string Detail { get; init; }

    public int ProcessId { get; init; }

    public string ProcessName { get; init; } = string.Empty;
}
