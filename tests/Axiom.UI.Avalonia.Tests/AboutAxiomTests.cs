// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Monitoring;
using Axiom.Presentation;
using Axiom.UI.Avalonia;
using Xunit;

namespace Axiom.UI.Avalonia.Tests;

public sealed class AboutAxiomTests
{
    [Fact]
    public void Bundled_documents_are_available_offline()
    {
        Assert.Contains("GNU GENERAL PUBLIC LICENSE", AxiomDocuments.License, StringComparison.Ordinal);
        Assert.Contains("Copyright (C) 2026 The Axiom contributors", AxiomDocuments.Notice, StringComparison.Ordinal);
        Assert.Contains("The Axiom contributors", AxiomDocuments.Authors, StringComparison.Ordinal);
        Assert.Contains("affiliated with the OpenDKG initiative", AxiomDocuments.Authors, StringComparison.Ordinal);
        Assert.False(string.IsNullOrWhiteSpace(AxiomDocuments.ThirdPartyNotices));
        Assert.StartsWith(AxiomDocuments.Notice, AxiomDocuments.LicenseBundle, StringComparison.Ordinal);
    }

    [Fact]
    public void About_reports_the_real_version_and_license()
    {
        var page = CreatePage(new RecordingInteraction());
        try
        {
            var version = typeof(SettingsPageViewModel).Assembly.GetName().Version?.ToString(3);
            Assert.Equal($"v{version}", page.AppVersion);
            Assert.Contains("GPL-3.0-or-later", page.AboutLicense, StringComparison.Ordinal);
            Assert.Equal("a-51-50", page.AboutCreatedBy);
            Assert.Contains("dreddster", page.AboutContributors, StringComparison.Ordinal);
            Assert.Contains("brxtrac", page.AboutContributors, StringComparison.Ordinal);
            var hottogo = Assert.Single(page.AboutSpecialThanks, role => role.GitHubHandle == "hottogo");
            Assert.Equal("https://github.com/hottogo", hottogo.ProfileUrl);
            Assert.Equal("OpenDKG Initiative", page.AboutAffiliationLabel);
            Assert.Equal("https://opendkg.org", AxiomDocuments.AffiliationUrl);
            Assert.Equal("Axiom is an independent open-source project affiliated with the OpenDKG initiative.", page.AboutAffiliation);
            Assert.Equal("https://github.com/OpenDKG/Axiom", page.AboutSource);
            Assert.Contains("2026 The Axiom contributors", page.AboutCopyright, StringComparison.Ordinal);
        }
        finally
        {
            page.Dispose();
        }
    }

    [Fact]
    public async Task About_actions_open_the_bundled_documents_and_the_repository()
    {
        var interaction = new RecordingInteraction();
        var page = CreatePage(interaction);
        try
        {
            await page.ViewLicenseCommand.ExecuteAsync(null);
            await page.ViewThirdPartyNoticesCommand.ExecuteAsync(null);
            await page.ViewContributorsCommand.ExecuteAsync(null);
            await page.OpenSourceCommand.ExecuteAsync(null);
            await page.OpenAffiliationCommand.ExecuteAsync(null);

            Assert.Equal(3, interaction.Documents.Count);
            Assert.Contains("GNU GENERAL PUBLIC LICENSE", interaction.Documents[0].Text, StringComparison.Ordinal);
            Assert.Equal("Third-party notices", interaction.Documents[1].Title);
            Assert.Equal("Axiom contributors", interaction.Documents[2].Title);
            Assert.Equal(2, interaction.OpenedUrls.Count);
            Assert.Equal("https://github.com/OpenDKG/Axiom", interaction.OpenedUrls[0]);
            Assert.Equal("https://opendkg.org", interaction.OpenedUrls[1]);
        }
        finally
        {
            page.Dispose();
        }
    }

    [Fact]
    public void Settings_tracks_active_theme_and_visual_effects_flags()
    {
        var theme = new MutableThemeService();
        var effects = new MutableVisualEffectsService();
        var monitor = new ConnectionMonitor(new FakeSource(), new NoOpTimerFactory());
        using var page = new SettingsPageViewModel(
            monitor,
            serviceMode: false,
            theme: theme,
            autostart: new UnsupportedAutostartService(),
            userInteraction: new RecordingInteraction(),
            visualEffects: effects);

        Assert.True(page.IsGlassDarkTheme);
        Assert.False(page.IsGlassLightTheme);
        Assert.True(page.IsAutoEffects);
        Assert.False(page.IsReducedEffects);

        page.UseGlassLightThemeCommand.Execute(null);
        Assert.False(page.IsGlassDarkTheme);
        Assert.True(page.IsGlassLightTheme);
        Assert.Equal("Axiom Glass Light", page.CurrentThemeText);

        page.UseDarkMidnightThemeCommand.Execute(null);
        Assert.False(page.IsGlassLightTheme);
        Assert.True(page.IsDarkMidnightTheme);
        Assert.Equal("Dark Midnight", page.CurrentThemeText);

        page.UseReducedEffectsCommand.Execute(null);
        Assert.False(page.IsAutoEffects);
        Assert.True(page.IsReducedEffects);
    }

    [Fact]
    public async Task Events_context_commands_inspect_and_copy_event_details()
    {
        var interaction = new RecordingInteraction();
        using var eventsPage = new EventsPageViewModel(null, new NoOpTimerFactory(), interaction);
        var row = new EventRowView(new Axiom.Contracts.History.HistoryRow
        {
            AppDisplayName = "curl.exe",
            AppPath = @"C:\Windows\System32\curl.exe",
            ProcessId = 4120,
            Protocol = "TCP",
            LocalEndpoint = "10.0.0.5:51234",
            RemoteEndpoint = "93.184.216.34:443",
            Direction = "Outbound",
            State = "Established",
            Quality = "Exact",
            FirstSeenUtc = new DateTimeOffset(2026, 11, 12, 0, 10, 0, TimeSpan.Zero),
            LastSeenUtc = new DateTimeOffset(2026, 11, 12, 0, 11, 0, TimeSpan.Zero),
        });

        await eventsPage.InspectEventCommand.ExecuteAsync(row);
        await eventsPage.CopyEventDetailsCommand.ExecuteAsync(row);
        await eventsPage.CopyEventRemoteCommand.ExecuteAsync(row);

        Assert.Single(interaction.Messages);
        Assert.Contains("curl.exe", interaction.Messages[0].Title, StringComparison.Ordinal);
        Assert.Contains("93.184.216.34:443", interaction.Messages[0].Message, StringComparison.Ordinal);
        Assert.Equal(2, interaction.CopiedTexts.Count);
        Assert.Contains("C:\\Windows\\System32\\curl.exe", interaction.CopiedTexts[0], StringComparison.Ordinal);
        Assert.Equal("93.184.216.34:443", interaction.CopiedTexts[1]);
    }

    private sealed class MutableThemeService : IThemeService
    {
        public UiTheme Current { get; private set; } = UiTheme.GlassDark;

        public event EventHandler? Changed;

        public void Apply(UiTheme theme)
        {
            Current = theme;
            Changed?.Invoke(this, EventArgs.Empty);
        }
    }

    private sealed class MutableVisualEffectsService : IVisualEffectsService
    {
        public VisualEffects Current { get; private set; } = VisualEffects.Auto;

        public string BackdropStatus { get; private set; } = "AcrylicBlur (native backdrop active)";

        public event EventHandler? Changed;

        public void Apply(VisualEffects value)
        {
            Current = value;
            Changed?.Invoke(this, EventArgs.Empty);
        }

        public void ReportBackdrop(string status)
        {
            BackdropStatus = status;
            Changed?.Invoke(this, EventArgs.Empty);
        }
    }


    private static SettingsPageViewModel CreatePage(IUserInteraction interaction)
    {
        var monitor = new ConnectionMonitor(new FakeSource(), new NoOpTimerFactory());
        return new SettingsPageViewModel(
            monitor,
            serviceMode: false,
            theme: new FixedThemeService(),
            autostart: new UnsupportedAutostartService(),
            userInteraction: interaction);
    }

    private sealed class RecordingInteraction : IUserInteraction
    {
        public List<(string Title, string Text)> Documents { get; } = [];

        public List<(string Title, string Message)> Messages { get; } = [];

        public List<string> CopiedTexts { get; } = [];

        public List<string> OpenedUrls { get; } = [];

        public Task<bool> ConfirmAsync(
            string title,
            string message,
            string confirmLabel,
            bool destructive,
            CancellationToken cancellationToken) => Task.FromResult(false);

        public Task ShowMessageAsync(string title, string message, CancellationToken cancellationToken)
        {
            Messages.Add((title, message));
            return Task.CompletedTask;
        }

        public Task ShowDocumentAsync(string title, string document, CancellationToken cancellationToken)
        {
            Documents.Add((title, document));
            return Task.CompletedTask;
        }

        public Task<string?> PickSaveFileAsync(
            string suggestedFileName,
            string extension,
            string typeName,
            CancellationToken cancellationToken) => Task.FromResult<string?>(null);

        public Task<string?> PickOpenFileAsync(
            string title,
            string extension,
            string typeName,
            CancellationToken cancellationToken) => Task.FromResult<string?>(null);

        public Task<string?> PickFolderAsync(string title, CancellationToken cancellationToken) =>
            Task.FromResult<string?>(null);

        public Task CopyTextAsync(string text, CancellationToken cancellationToken)
        {
            CopiedTexts.Add(text);
            return Task.CompletedTask;
        }

        public Task OpenExternalAsync(string url, CancellationToken cancellationToken)
        {
            OpenedUrls.Add(url);
            return Task.CompletedTask;
        }
    }

    private sealed class FakeSource : IConnectionSnapshotSource
    {
        public string Name => "demo";

        public TimeSpan PollInterval => TimeSpan.FromSeconds(1);

        public Task<ConnectionSnapshot> CaptureAsync(CancellationToken cancellationToken) =>
            Task.FromResult(new ConnectionSnapshot
            {
                CapturedUtc = DateTimeOffset.UtcNow,
                Connections = [],
                ProcessCount = 0,
                SourceName = "demo",
            });
    }

    private sealed class NoOpTimerFactory : IUiTimerFactory
    {
        public IUiTimer Create(TimeSpan interval) => new NoOpTimer();

        private sealed class NoOpTimer : IUiTimer
        {
            public TimeSpan Interval { get; set; } = TimeSpan.FromSeconds(1);

            public bool IsEnabled { get; private set; }

            public event EventHandler? Tick
            {
                add { }
                remove { }
            }

            public void Start() => IsEnabled = true;

            public void StopTimer() => IsEnabled = false;

            public void Dispose()
            {
            }
        }
    }
}
