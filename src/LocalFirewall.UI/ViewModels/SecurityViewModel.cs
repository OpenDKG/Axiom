// SPDX-License-Identifier: GPL-3.0-or-later
namespace LocalFirewall.UI.ViewModels;

/// <summary>Status of one optional security or intelligence module.</summary>
public sealed record SecurityModule(
    string Name,
    string Status,
    string Detail,
    string Glyph);

/// <summary>
/// Security page. Every optional module is off; the page reports that state instead of showing a
/// fake scanner, feed or agent connection.
/// </summary>
public sealed class SecurityViewModel : PageViewModel
{
    public SecurityViewModel()
        : base("Security", "Optional intelligence and protection modules", "\uE8D7")
    {
        Modules =
        [
            new SecurityModule(
                "Reputation provider",
                "NOT CONFIGURED",
                "No external reputation lookup is enabled. Unknown is shown as unknown.",
                "\uE9D9"),
            new SecurityModule(
                "Blackbox",
                "NOT INSTALLED",
                "No Blackbox process is started, queried or controlled.",
                "\uE7BA"),
            new SecurityModule(
                "OriginTrail DKG",
                "NOT CONNECTED",
                "No DKG node, wallet, token or feed is used by the standard build.",
                "\uE968"),
            new SecurityModule(
                "Community feed",
                "NOT CONFIGURED",
                "No community report is fetched, verified or published.",
                "\uE774"),
            new SecurityModule(
                "File scanning",
                "NOT ENABLED",
                "No file is scanned, uploaded, quarantined or deleted.",
                "\uE8A5"),
        ];
    }

    public IReadOnlyList<SecurityModule> Modules { get; }

    public string StatusTitle => "All optional modules are off";

    public string StatusText =>
        "The standard build works fully offline. No background module, account, wallet or external " +
        "service is active. Enabling one later is an explicit, separate choice.";
}
