// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Infrastructure.Linux;
using Xunit;

namespace Axiom.Infrastructure.Linux.Tests;

public sealed class LinuxAutostartTests : IDisposable
{
    private readonly string _configHome = Path.Combine(
        Path.GetTempPath(),
        $"axiom-autostart-{Guid.NewGuid():N}");

    [Fact]
    public void Enable_writes_a_marked_desktop_entry_with_an_absolute_exec()
    {
        var executable = TestBinaries.ExistingExecutable();

        LinuxAutostart.Enable(executable, _configHome);

        var path = LinuxAutostart.ResolvePath(_configHome);
        Assert.True(File.Exists(path));
        var content = File.ReadAllText(path);
        Assert.Contains("Type=Application", content, StringComparison.Ordinal);
        Assert.Contains(LinuxAutostart.Marker, content, StringComparison.Ordinal);
        Assert.Contains($"Exec=\"{executable}\"", content, StringComparison.Ordinal);
        Assert.True(LinuxAutostart.IsEnabled(_configHome));
    }

    [Fact]
    public void Disable_removes_only_an_entry_axiom_owns()
    {
        var path = LinuxAutostart.ResolvePath(_configHome);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, "[Desktop Entry]\nName=Other");

        LinuxAutostart.Disable(_configHome);

        Assert.True(File.Exists(path));
        Assert.False(LinuxAutostart.IsEnabled(_configHome));
    }

    [Fact]
    public void Enable_refuses_to_overwrite_an_unowned_entry()
    {
        var path = LinuxAutostart.ResolvePath(_configHome);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, "[Desktop Entry]\nName=Other");

        Assert.Throws<IOException>(() => LinuxAutostart.Enable(TestBinaries.ExistingExecutable(), _configHome));
        Assert.Equal("[Desktop Entry]\nName=Other", File.ReadAllText(path));
    }

    [Fact]
    public void Enable_refuses_a_symlinked_entry()
    {
        var path = LinuxAutostart.ResolvePath(_configHome);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var target = Path.Combine(_configHome, "target.desktop");
        File.WriteAllText(target, LinuxAutostart.Marker);
        File.CreateSymbolicLink(path, target);

        Assert.Throws<IOException>(() => LinuxAutostart.Enable(TestBinaries.ExistingExecutable(), _configHome));
    }

    [Fact]
    public void Enable_requires_an_absolute_existing_executable()
    {
        Assert.Throws<ArgumentException>(() => LinuxAutostart.Enable("relative/tool", _configHome));
        Assert.Throws<FileNotFoundException>(() => LinuxAutostart.Enable("/definitely/not/here", _configHome));
    }

    public void Dispose()
    {
        if (Directory.Exists(_configHome))
        {
            Directory.Delete(_configHome, recursive: true);
        }
    }
}
