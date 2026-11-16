// SPDX-License-Identifier: GPL-3.0-or-later
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Primitives;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Media.Imaging;
using Avalonia.Platform;
using Axiom.Presentation;

namespace Axiom.UI.Avalonia;

/// <summary>
/// First-run component picker. Nothing is downloaded or installed until the operator accepts the
/// terms and presses Apply; Skip changes no component and only records the onboarding decision.
/// </summary>
public sealed class FirstRunDialog : Window
{
    private static IBrush BackgroundBrush => AxiomDialogTheme.WindowBackground;
    private static IBrush SurfaceBrush => AxiomDialogTheme.Surface;
    private static IBrush BorderBrushStatic => AxiomDialogTheme.Border;
    private static IBrush ForegroundBrush => AxiomDialogTheme.TextPrimary;
    private static IBrush MutedBrush => AxiomDialogTheme.TextMuted;

    private readonly CheckBox _dkg = new() { Content = "OriginTrail DKG testnet (npm package, local node)", Foreground = ForegroundBrush };
    private readonly CheckBox _blackbox = new() { Content = "Blackbox (Umanitek official installer; large third-party download)", Foreground = ForegroundBrush };
    private readonly CheckBox _community = new() { Content = "Axiom starter community feed (bundled, offline)", IsChecked = true, Foreground = ForegroundBrush };
    private readonly CheckBox _accept = new()
    {
        Content = new TextBlock
        {
            Text = "I understand this is a development build and accept the third-party terms and changes above.",
            Foreground = ForegroundBrush,
            TextWrapping = TextWrapping.Wrap,
        },
    };
    private readonly Button _apply = new()
    {
        Content = "Apply",
        IsEnabled = false,
        Padding = new Thickness(14, 7),
        Classes = { "primary" },
    };
    private readonly IApiKeyProtector _protector;
    private bool _accepted;

    public FirstRunDialog(IApiKeyProtector protector)
    {
        _protector = protector ?? throw new ArgumentNullException(nameof(protector));
        Title = "Set up Axiom";
        Width = 720;
        Height = 680;
        CanResize = false;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        Background = BackgroundBrush;
        Foreground = ForegroundBrush;

        _accept.IsCheckedChanged += (_, _) => _apply.IsEnabled = _accept.IsChecked == true;
        _apply.Click += (_, _) =>
        {
            _accepted = true;
            Close();
        };
        var skip = new Button
        {
            Content = "Skip for now",
            Padding = new Thickness(14, 7),
            Background = AxiomDialogTheme.SurfaceAlt,
            Foreground = ForegroundBrush,
            BorderBrush = BorderBrushStatic,
            BorderThickness = new Thickness(1),
            CornerRadius = new CornerRadius(6),
        };
        skip.Click += (_, _) => Close();

        Content = BuildContent(skip);
    }

    public bool Accepted => _accepted;

    public static async Task<bool> ShowAsync(Window owner, IApiKeyProtector protector)
    {
        var dialog = new FirstRunDialog(protector);
        await dialog.ShowDialog(owner).ConfigureAwait(true);
        if (!dialog.Accepted)
        {
            OnboardingStore.Save(new OnboardingSettings(true, true, false, false));
            return false;
        }

        var settings = new OnboardingSettings(
            Completed: true,
            Skipped: false,
            Dkg: dialog._dkg.IsChecked == true,
            Blackbox: dialog._blackbox.IsChecked == true);
        OnboardingStore.Save(settings);

        if (dialog._community.IsChecked == true)
        {
            try
            {
                new CommunityFeedSettingsStore(protector).Save(new CommunityFeedSettings(
                    Enabled: true,
                    Url: CommunityFeedSettingsStore.StarterFeedUrl,
                    Token: string.Empty));
            }
            catch (NotSupportedException)
            {
                // The starter feed has no token; a host without a protector can still skip it.
            }
        }

        var installer = new OptionalModuleInstaller();
        if (settings.Dkg)
        {
            installer.InstallDkg();
        }

        if (settings.Blackbox)
        {
            installer.InstallBlackbox();
        }

        return true;
    }

    private ScrollViewer BuildContent(Button skip)
    {
        var panel = new StackPanel { Spacing = 12, Margin = new Thickness(24) };
        panel.Children.Add(new Image
        {
            Source = new Bitmap(AssetLoader.Open(new Uri("avares://Axiom.UI.Avalonia/Assets/axiom-lockup.png"))),
            Width = 220,
            HorizontalAlignment = HorizontalAlignment.Left,
            Margin = new Thickness(0, 0, 0, 4),
        });
        panel.Children.Add(new SelectableTextBlock
        {
            Text = "Set up Axiom",
            FontSize = 22,
            FontWeight = FontWeight.SemiBold,
            Foreground = ForegroundBrush,
        });
        panel.Children.Add(new SelectableTextBlock
        {
            Text = "Axiom core is already installed. Choose optional components below. Nothing is downloaded or installed until you click Apply and accept the terms.",
            Foreground = MutedBrush,
            FontSize = 12,
            TextWrapping = TextWrapping.Wrap,
        });
        panel.Children.Add(Card(
            "Components (Modify)",
            new SelectableTextBlock { Text = "Local service — history, firewall inventory and secure IPC (built in)", Foreground = MutedBrush, FontSize = 11, TextWrapping = TextWrapping.Wrap },
            new SelectableTextBlock { Text = "Local file scanner — SHA-256 on demand, no upload (built in)", Foreground = MutedBrush, FontSize = 11, TextWrapping = TextWrapping.Wrap },
            _dkg,
            _blackbox,
            _community));
        panel.Children.Add(Card(
            "Before you apply",
            new SelectableTextBlock
            {
                Text = "Selected installers run in a visible PowerShell window. They may download hundreds of MB, " +
                       "create a local testnet wallet/config and a scheduled task, and may ask for UAC or third-party terms. " +
                       "Axiom does not hide, bundle or vouch for third-party code.",
                Foreground = MutedBrush,
                FontSize = 11,
                TextWrapping = TextWrapping.Wrap,
            }));
        panel.Children.Add(_accept);
        panel.Children.Add(new StackPanel
        {
            Orientation = Orientation.Horizontal,
            HorizontalAlignment = HorizontalAlignment.Right,
            Spacing = 8,
            Children = { skip, _apply },
        });

        return new ScrollViewer { Content = panel, VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
    }

    private static Border Card(string title, params Control[] children)
    {
        var panel = new StackPanel { Spacing = 8 };
        panel.Children.Add(new SelectableTextBlock { Text = title, Foreground = ForegroundBrush, FontSize = 13, FontWeight = FontWeight.SemiBold, TextWrapping = TextWrapping.Wrap });
        foreach (var child in children)
        {
            panel.Children.Add(child);
        }

        return new Border
        {
            Background = SurfaceBrush,
            BorderBrush = BorderBrushStatic,
            BorderThickness = new Thickness(1),
            CornerRadius = new CornerRadius(8),
            Padding = new Thickness(14),
            Child = panel,
        };
    }
}

