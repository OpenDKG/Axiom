// SPDX-License-Identifier: GPL-3.0-or-later
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Axiom.Contracts.Ai;
using Axiom.Contracts.Monitoring;
using Axiom.Presentation;
using Xunit;

namespace Axiom.UI.Avalonia.Tests;

public sealed class AiAnalystComplianceUiTests
{
    [Fact]
    public void Providers_list_matches_compliance_presets_with_local_and_official_providers_first()
    {
        var timers = new FakeTimerFactory();
        using var monitor = new ConnectionMonitor(new FakeSnapshotSource(), timers);
        using var viewModel = new AiAnalystPageViewModel(
            monitor,
            new FakeApiKeyProtector(),
            timers,
            new FakeUserInteraction());

        var presets = AiProviderCompliancePolicy.GetPresets();
        Assert.Equal(10, presets.Count);
        Assert.Equal(presets.Count, viewModel.Providers.Count);
        Assert.Equal(
            presets.Select(p => (p.Kind, p.Label)),
            viewModel.Providers.Select(p => (p.Value, p.Label)));

        Assert.NotEqual(AiProviderKind.OpenChamberLocal, viewModel.Providers[0].Value);
        Assert.Equal(AiProviderKind.LocalOpenAiCompatible, viewModel.Providers[0].Value);
        Assert.Contains(viewModel.Providers, p => p.Value == AiProviderKind.GoogleGemini);
        Assert.Contains(viewModel.Providers, p => p.Value == AiProviderKind.OpenRouter);
    }

    [Theory]
    [InlineData(AiProviderKind.Anthropic)]
    [InlineData(AiProviderKind.GoogleGemini)]
    [InlineData(AiProviderKind.OpenRouter)]
    [InlineData(AiProviderKind.LocalOpenAiCompatible)]
    [InlineData(AiProviderKind.OpenChamberLocal)]
    public void Switching_provider_updates_endpoint_model_and_compliance_note_and_notifies(AiProviderKind targetKind)
    {
        var timers = new FakeTimerFactory();
        using var monitor = new ConnectionMonitor(new FakeSnapshotSource(), timers);
        using var viewModel = new AiAnalystPageViewModel(
            monitor,
            new FakeApiKeyProtector(),
            timers,
            new FakeUserInteraction());

        // Move away from targetKind first so setting targetKind always triggers a change.
        var initial = viewModel.Providers.First(p => p.Value != targetKind);
        viewModel.Provider = initial;

        var changedProperties = new List<string?>();
        viewModel.PropertyChanged += (_, args) => changedProperties.Add(args.PropertyName);

        var target = viewModel.Providers.Single(p => p.Value == targetKind);
        viewModel.Provider = target;

        Assert.True(AiProviderCompliancePolicy.TryGetPreset(targetKind, out var preset));
        Assert.Equal(preset.Endpoint, viewModel.Endpoint);
        Assert.Equal(preset.DefaultModel, viewModel.Model);
        Assert.Equal(AiProviderCompliancePolicy.GetComplianceNote(targetKind), viewModel.ProviderComplianceText);
        Assert.Contains(nameof(AiAnalystPageViewModel.ProviderComplianceText), changedProperties);
        Assert.Contains(nameof(AiAnalystPageViewModel.CredentialsText), changedProperties);

        if (targetKind == AiProviderKind.OpenChamberLocal)
        {
            Assert.Contains("Third-party consumer logins", viewModel.CredentialsText, StringComparison.Ordinal);
            Assert.Contains("blocked", viewModel.CredentialsText, StringComparison.OrdinalIgnoreCase);
        }
    }

    [Fact]
    public void Agent_setup_prompt_uses_safe_mcp_or_official_api_or_local_model_guidance()
    {
        var timers = new FakeTimerFactory();
        using var monitor = new ConnectionMonitor(new FakeSnapshotSource(), timers);
        using var viewModel = new AiAnalystPageViewModel(
            monitor,
            new FakeApiKeyProtector(),
            timers,
            new FakeUserInteraction());

        var prompt = viewModel.AgentSetupPrompt;
        Assert.Contains("MCP", prompt, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("API key", prompt, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Ollama", prompt, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("OpenChamber Local", prompt, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("this agent's own local login", prompt, StringComparison.OrdinalIgnoreCase);
    }

    private sealed class FakeSnapshotSource : IConnectionSnapshotSource
    {
        public string Name => "fake";
        public TimeSpan PollInterval => TimeSpan.FromSeconds(1);

        public Task<ConnectionSnapshot> CaptureAsync(CancellationToken cancellationToken) =>
            Task.FromResult(new ConnectionSnapshot
            {
                CapturedUtc = DateTimeOffset.UtcNow,
                Connections = [],
                ProcessCount = 0,
                SourceName = "fake",
            });
    }

    private sealed class FakeTimerFactory : IUiTimerFactory
    {
        public IUiTimer Create(TimeSpan interval) => new FakeTimer(interval);

        private sealed class FakeTimer(TimeSpan interval) : IUiTimer
        {
            public TimeSpan Interval { get; set; } = interval;
            public bool IsEnabled { get; private set; }
            public event EventHandler? Tick
            {
                add { }
                remove { }
            }

            public void Start() => IsEnabled = true;
            public void StopTimer() => IsEnabled = false;
            public void Dispose() => StopTimer();
        }
    }

    private sealed class FakeApiKeyProtector : IApiKeyProtector
    {
        public string Protect(string plaintext) => plaintext;
        public string Unprotect(string ciphertext) => ciphertext;
    }

    private sealed class FakeUserInteraction : IUserInteraction
    {
        public Task<bool> ConfirmAsync(string title, string message, string confirmLabel, bool destructive, CancellationToken cancellationToken) =>
            Task.FromResult(false);

        public Task ShowMessageAsync(string title, string message, CancellationToken cancellationToken) =>
            Task.CompletedTask;

        public Task ShowDocumentAsync(string title, string document, CancellationToken cancellationToken) =>
            Task.CompletedTask;

        public Task<string?> PickSaveFileAsync(string suggestedFileName, string extension, string typeName, CancellationToken cancellationToken) =>
            Task.FromResult<string?>(null);

        public Task<string?> PickOpenFileAsync(string title, string extension, string typeName, CancellationToken cancellationToken) =>
            Task.FromResult<string?>(null);

        public Task<string?> PickFolderAsync(string title, CancellationToken cancellationToken) =>
            Task.FromResult<string?>(null);

        public Task CopyTextAsync(string text, CancellationToken cancellationToken) =>
            Task.CompletedTask;

        public Task OpenExternalAsync(string url, CancellationToken cancellationToken) =>
            Task.CompletedTask;
    }
}
