// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.Presentation;

/// <summary>Host without process control: ends nothing instead of pretending it succeeded.</summary>
public sealed class UnsupportedProcessActions : IProcessActions
{
    public int EndProcesses(IReadOnlyList<int> processIds) => 0;
}
