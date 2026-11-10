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
            Assert.Equal("OpenDKG Initiative", page.AboutAffiliationLabel);
            Assert.Equal("https://opendkg.org", AxiomDocuments.AffiliationUrl);
            Assert.Equal("Axiom is an independent open-source project affiliated with the OpenDKG initiative.", page.AboutAffiliation);
            Assert.Equal("https://github.com/a-51-50/Axiom", page.AboutSource);
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
            Assert.Equal("https://github.com/a-51-50/Axiom", interaction.OpenedUrls[0]);
            Assert.Equal("https://opendkg.org", interaction.OpenedUrls[1]);
        }
        finally
        {
            page.Dispose();
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

        public List<string> OpenedUrls { get; } = [];

        public Task<bool> ConfirmAsync(
            string title,
            string message,
            string confirmLabel,
            bool destructive,
            CancellationToken cancellationToken) => Task.FromResult(false);

        public Task ShowMessageAsync(string title, string message, CancellationToken cancellationToken) =>
            Task.CompletedTask;

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

        public Task CopyTextAsync(string text, CancellationToken cancellationToken) => Task.CompletedTask;

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
