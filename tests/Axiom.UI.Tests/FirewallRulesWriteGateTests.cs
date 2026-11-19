// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.UI.ViewModels;
using Xunit;

namespace Axiom.UI.Tests;

/// <summary>
/// The WPF rule hint must follow the live service write gate: no stale "disabled" text after the
/// gate opens, and no stale "enabled" state after a failed probe. Windows-only test (WPF target).
/// </summary>
public sealed class FirewallRulesWriteGateTests
{
    [Fact]
    public void Write_hint_tracks_the_gate_and_clears_on_a_failed_probe()
    {
        using var viewModel = new FirewallRulesViewModel(serviceMode: false);
        var changed = new List<string?>();
        viewModel.PropertyChanged += (_, e) => changed.Add(e.PropertyName);

        viewModel.WriteGateKnown = true;
        Assert.Contains("disabled by design", viewModel.NewRuleWriteHint, StringComparison.Ordinal);

        changed.Clear();
        viewModel.WritesEnabled = true;
        Assert.Contains(nameof(FirewallRulesViewModel.NewRuleWriteHint), changed);
        Assert.Contains("Writes are enabled", viewModel.NewRuleWriteHint, StringComparison.Ordinal);
        Assert.DoesNotContain("disabled", viewModel.NewRuleWriteHint, StringComparison.Ordinal);

        viewModel.ApplyQueryFailure("Service offline", "pipe closed", "pipe closed");
        Assert.False(viewModel.WritesEnabled);
        Assert.False(viewModel.WriteGateKnown);
        Assert.Contains(nameof(FirewallRulesViewModel.NewRuleWriteHint), changed);
        Assert.Contains("could not be read", viewModel.NewRuleWriteHint, StringComparison.Ordinal);
        Assert.DoesNotContain("Writes are enabled", viewModel.NewRuleWriteHint, StringComparison.Ordinal);
    }
}
