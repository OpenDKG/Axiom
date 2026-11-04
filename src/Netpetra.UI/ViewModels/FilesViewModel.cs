// SPDX-License-Identifier: GPL-3.0-or-later
using CommunityToolkit.Mvvm.Input;

namespace Netpetra.UI.ViewModels;

/// <summary>
/// File tracking page. Background folder watching is not enabled in this build; the working local
/// SHA-256 scan lives on the Security page. The page states that explicitly and links there.
/// </summary>
public sealed partial class FilesViewModel : PageViewModel
{
    private readonly Action _openSecurity;

    public FilesViewModel(Action openSecurity)
        : base("Files", "File tracking · local scan lives on Security", "\uE8A5")
    {
        _openSecurity = openSecurity ?? throw new ArgumentNullException(nameof(openSecurity));
    }

    public string StatusTitle => "Local file scan is on Security";

    public string StatusText =>
        "Use Security → Local file scan to choose a folder and calculate SHA-256 locally. " +
        "Background folder watching, quarantine and automatic upload are not enabled in this build.";

    public IReadOnlyList<string> PlannedCapabilities { get; } =
    [
        "Watch only the folders the user selects (for example Downloads and Desktop).",
        "Calculate SHA-256 in the background with size limits and cancellation.",
        "Read Authenticode signer metadata for PE files without network lookups.",
        "Show local provenance, first/last seen and an explicit unknown status.",
        "Never delete, quarantine or upload a file automatically.",
    ];

    [RelayCommand]
    private void OpenSecurity() => _openSecurity();
}
