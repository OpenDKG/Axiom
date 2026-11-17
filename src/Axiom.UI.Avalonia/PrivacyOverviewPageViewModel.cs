// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Presentation;
using CommunityToolkit.Mvvm.Input;

namespace Axiom.UI.Avalonia;

/// <summary>
/// Live DNS filtering overview and monitoring dashboard. Reuses the single-owner
/// <see cref="PrivacyShieldPageViewModel"/> so resolver polling, blocked history,
/// adapter checks and allow/block mutations stay consistent with Privacy Shield settings.
/// </summary>
public sealed partial class PrivacyOverviewPageViewModel : PageViewModel, IActivatablePage
{
    private readonly Action? _openSettings;

    public PrivacyOverviewPageViewModel(
        PrivacyShieldPageViewModel privacyShield,
        Action? openSettings = null)
        : base("Privacy Dashboard", "Live DNS filtering metrics, blocked activity and resolver health", "\uE72E")
    {
        PrivacyShield = privacyShield ?? throw new ArgumentNullException(nameof(privacyShield));
        _openSettings = openSettings;
    }

    public PrivacyShieldPageViewModel PrivacyShield { get; }

    public void Activate() => PrivacyShield.Activate();

    public void Deactivate() => PrivacyShield.Deactivate();

    [RelayCommand]
    private void OpenSettings() => _openSettings?.Invoke();
}
