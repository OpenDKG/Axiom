// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Infrastructure.Linux;
using Xunit;

namespace Axiom.Infrastructure.Linux.Tests;

public sealed class LinuxAiAnalystSettingsTests : IDisposable
{
    private readonly string _directory = Path.Combine(
        Path.GetTempPath(),
        $"axiom-ai-{Guid.NewGuid():N}");

    public LinuxAiAnalystSettingsTests() => Directory.CreateDirectory(_directory);

    public void Dispose() => Directory.Delete(_directory, recursive: true);

    [Fact]
    public void Concurrent_saves_publish_one_complete_document_without_temporary_files()
    {
        var path = Path.Combine(_directory, "ai-analyst.json");
        var settings = new LinuxAiAnalystSettings(path);

        Parallel.For(0, 20, index =>
            settings.Save(new Axiom.Contracts.Ai.AiAnalystSettings
            {
                Enabled = true,
                Model = $"model-{index}",
                Endpoint = "http://127.0.0.1:18080/v1",
            }));

        var loaded = settings.Load();
        Assert.StartsWith("model-", loaded.Model, StringComparison.Ordinal);
        Assert.Equal("http://127.0.0.1:18080/v1", loaded.Endpoint);
        Assert.Empty(Directory.GetFiles(_directory, "*.tmp"));
    }
}
