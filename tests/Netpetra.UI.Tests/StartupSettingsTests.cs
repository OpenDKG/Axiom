// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using Netpetra.UI.Services;
using Xunit;

namespace Netpetra.UI.Tests;

public sealed class StartupSettingsTests
{
    [Fact]
    public void Missing_settings_default_to_autostart_off()
    {
        using var temp = new TempTree();
        var store = new StartupSettingsStore(Path.Combine(temp.Root, "startup.json"));

        var settings = store.Load();

        Assert.False(settings.StartWithWindows);
        Assert.False(settings.StartMinimized);
    }

    [Fact]
    public void Startup_settings_round_trip()
    {
        using var temp = new TempTree();
        var store = new StartupSettingsStore(Path.Combine(temp.Root, "startup.json"));
        var expected = new StartupSettings(
            StartWithWindows: true,
            StartMinimized: true,
            LastKnownExecutablePath: @"C:\Program Files\Netpetra\Netpetra.Desktop.exe",
            UpdatedUtc: DateTimeOffset.UtcNow);

        store.Save(expected);
        var actual = store.Load();

        Assert.True(actual.StartWithWindows);
        Assert.True(actual.StartMinimized);
        Assert.Equal(expected.LastKnownExecutablePath, actual.LastKnownExecutablePath);
    }

    [Fact]
    public void Corrupt_settings_fall_back_to_off()
    {
        using var temp = new TempTree();
        var path = Path.Combine(temp.Root, "startup.json");
        File.WriteAllText(path, "{not json");

        var settings = new StartupSettingsStore(path).Load();

        Assert.False(settings.StartWithWindows);
        Assert.False(settings.StartMinimized);
    }

    [Fact]
    public void Autostart_command_points_at_the_current_executable()
    {
        const string path = @"C:\Program Files\Netpetra\Netpetra.Desktop.exe";

        var command = AutostartRegistration.BuildCommand(path);

        Assert.Equal($"\"{path}\" --autostart", command);
    }

    private sealed class TempTree : IDisposable
    {
        public TempTree()
        {
            Root = Path.Combine(Path.GetTempPath(), $"netpetra-startup-{Guid.NewGuid():N}");
            Directory.CreateDirectory(Root);
        }

        public string Root { get; }

        public void Dispose()
        {
            try
            {
                Directory.Delete(Root, recursive: true);
            }
            catch (IOException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }
        }
    }
}
