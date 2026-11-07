// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.Presentation;

/// <summary>
/// Host process control. Axiom only calls this after an explicit confirmation on the Applications
/// page; it never runs for an automatic or background action.
/// </summary>
public interface IProcessActions
{
    /// <summary>Ends each accessible process. Returns how many were ended.</summary>
    int EndProcesses(IReadOnlyList<int> processIds);
}
