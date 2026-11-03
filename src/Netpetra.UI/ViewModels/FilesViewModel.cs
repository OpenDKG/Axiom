// SPDX-License-Identifier: GPL-3.0-or-later
namespace Netpetra.UI.ViewModels;

/// <summary>
/// File tracking page. The module is not enabled: no folder is watched, no file is hashed and no
/// file is uploaded. The page states that explicitly instead of showing a fake scanner.
/// </summary>
public sealed class FilesViewModel : PageViewModel
{
    public FilesViewModel()
        : base("Files", "File tracking · optional module, not enabled", "\uE8A5")
    {
    }

    public string StatusTitle => "File tracking is not enabled";

    public string StatusText =>
        "No folder is watched, no SHA-256 is calculated and no file is scanned, uploaded or quarantined.";

    public IReadOnlyList<string> PlannedCapabilities { get; } =
    [
        "Watch only the folders the user selects (for example Downloads and Desktop).",
        "Calculate SHA-256 in the background with size limits and cancellation.",
        "Read Authenticode signer metadata for PE files without network lookups.",
        "Show local provenance, first/last seen and an explicit unknown status.",
        "Never delete, quarantine or upload a file automatically.",
    ];

    public bool IsAvailable => false;
}
