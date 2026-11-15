// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using System.Security.Cryptography;
using Avalonia.Controls;
using Avalonia.Threading;
using Avalonia.VisualTree;
using Axiom.Contracts.Files;
using Axiom.Presentation;
using Axiom.UI.Avalonia.Views;
using Xunit;

namespace Axiom.UI.Avalonia.Tests;

public sealed class SecurityFileScanTests
{
    [Fact]
    public void FileScanRow_marks_initial_verdict_as_VirusTotal_unchecked()
    {
        var hashed = new FileScanRow(new FileScanEntry(@"C:\temp\sample.exe", 128, new string('A', 64), null));
        var skipped = new FileScanRow(new FileScanEntry(@"C:\temp\huge.bin", 999, null, "Too large"));

        Assert.Equal("VT: Not checked", hashed.VerdictText);
        Assert.Equal("Skipped", skipped.VerdictText);
    }

    [Fact]
    public void Local_scan_reports_community_feed_check_when_hashes_loaded()
    {
        var folder = Path.Combine(Path.GetTempPath(), $"axiom-scan-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(folder);
        try
        {
            var payload = "dummy-binary-payload"u8.ToArray();
            var exePath = Path.Combine(folder, "tool.exe");
            File.WriteAllBytes(exePath, payload);
            var exeHash = Convert.ToHexString(SHA256.HashData(payload));

            _ = typeof(SecurityPageViewModel).Assembly;
            TestAppBuilder.RunOnUiThread(() =>
            {
                using var vm = new SecurityPageViewModel(
                    new FolderPickingInteraction(folder),
                    new UnsupportedSecurityDialogs(),
                    new UnsupportedApiKeyProtector(),
                    new TestTimerFactory(),
                    new UnsupportedShellActions());

                PumpUntil(() => !vm.IsFetchingCommunity);

                vm.CommunityEntries.Clear();
                vm.CommunityEntries.Add(new CommunityFeedRow(new string('0', 64), "other", "malware", "test"));

                var scanTask = vm.ScanFilesCommand.ExecuteAsync(null);
                PumpUntil(() => scanTask.IsCompleted);
                scanTask.GetAwaiter().GetResult();

                Assert.Single(vm.FileScanResults);
                Assert.False(vm.HasCommunityMatches);
                Assert.True(vm.HasScanCommunityNotice);
                Assert.Contains("0 matches", vm.CommunityMatchesText, StringComparison.Ordinal);
                Assert.Contains("VT Check", vm.CommunityMatchesText, StringComparison.Ordinal);
                Assert.Contains("0 matches in 1 community hashes", vm.FileScanStatus, StringComparison.Ordinal);
                Assert.Equal("VT: Not checked", vm.FileScanResults[0].VerdictText);

                // Re-scan with matching SHA-256 in the loaded community feed.
                vm.CommunityEntries.Clear();
                vm.CommunityEntries.Add(new CommunityFeedRow(exeHash, "tool.exe", "malware", "test"));

                var secondScan = vm.ScanFilesCommand.ExecuteAsync(null);
                PumpUntil(() => secondScan.IsCompleted);
                secondScan.GetAwaiter().GetResult();

                Assert.True(vm.HasCommunityMatches);
                Assert.False(vm.HasScanCommunityNotice);
                Assert.True(vm.FileScanResults[0].IsCommunityMatch);
                Assert.True(vm.FileScanResults[0].CanBlockFromCommunity);
                Assert.Contains("1 match(es) in 1 community hashes", vm.FileScanStatus, StringComparison.Ordinal);

                var view = new SecurityView { DataContext = vm };
                var window = new Window { Width = 1100, Height = 800, Content = view };
                window.Show();
                Dispatcher.UIThread.RunJobs();

                var vtButtons = view.GetVisualDescendants()
                    .OfType<Button>()
                    .Where(button => Equals(button.Content, "VT Check"))
                    .ToList();
                Assert.Single(vtButtons);

                window.Close();
            });
        }
        finally
        {
            if (Directory.Exists(folder))
            {
                Directory.Delete(folder, recursive: true);
            }
        }
    }

    private static void PumpUntil(Func<bool> condition)
    {
        var deadline = DateTime.UtcNow.AddSeconds(10);
        while (!condition() && DateTime.UtcNow < deadline)
        {
            Dispatcher.UIThread.RunJobs();
            Thread.Sleep(15);
        }

        Dispatcher.UIThread.RunJobs();
        Assert.True(condition());
    }

    private sealed class FolderPickingInteraction(string folder) : IUserInteraction
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
            Task.FromResult<string?>(folder);

        public Task CopyTextAsync(string text, CancellationToken cancellationToken) =>
            Task.CompletedTask;

        public Task OpenExternalAsync(string url, CancellationToken cancellationToken) =>
            Task.CompletedTask;
    }

    private sealed class TestTimerFactory : IUiTimerFactory
    {
        public IUiTimer Create(TimeSpan interval) => new TestTimer(interval);

        private sealed class TestTimer(TimeSpan interval) : IUiTimer
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

            public void Dispose()
            {
            }
        }
    }
}
