// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Infrastructure.MacOS.Filter;

namespace Axiom.Infrastructure.MacOS.Tests;

public sealed class DataDirectoryPermissionsTests
{
    private const UnixFileMode Mode700 = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;

    private const UnixFileMode Mode755 = Mode700 | UnixFileMode.GroupRead | UnixFileMode.GroupExecute | UnixFileMode.OtherRead | UnixFileMode.OtherExecute;

    private const UnixFileMode Mode600 = UnixFileMode.UserRead | UnixFileMode.UserWrite;

    private const UnixFileMode Mode644 = Mode600 | UnixFileMode.GroupRead | UnixFileMode.OtherRead;

    [Theory]
    [InlineData("", true, Mode700)]
    [InlineData("filter", true, Mode755)]
    [InlineData("filter/rules.json", false, Mode644)]
    [InlineData("filter/managed-rules.json", false, Mode600)]
    [InlineData("axiom.db", false, Mode600)]
    [InlineData("axiom.db-wal", false, Mode600)]
    [InlineData("axiom.db-shm", false, Mode600)]
    [InlineData("threat-share.json", false, Mode600)]
    [InlineData("privacy-shield-settings.json", false, Mode600)]
    [InlineData("privacy-shield-blocked.jsonl", false, Mode600)]
    [InlineData("privacy-shield-dns-backup.json", false, Mode600)]
    [InlineData("protection.json", false, Mode600)]
    [InlineData("other", true, Mode700)]
    public void ExpectedModeMap(string relative, bool isDirectory, UnixFileMode expected)
    {
        const string root = "/Library/Application Support/Axiom";
        var path = relative.Length == 0 ? root : Path.Combine(root, relative);

        Assert.Equal(expected, MacDataDirectoryPermissions.ExpectedMode(root, path, isDirectory));
    }

    [Fact]
    public void EnforceTightensExistingFilesAndIsIdempotent()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        using var temp = new TempDirectory();
        var root = Path.Combine(temp.Path, "Axiom");
        Directory.CreateDirectory(Path.Combine(root, "filter"));
        File.SetUnixFileMode(root, Mode755);
        File.SetUnixFileMode(Path.Combine(root, "filter"), Mode755);
        var db = Path.Combine(root, "axiom.db");
        var wal = Path.Combine(root, "axiom.db-wal");
        var rules = Path.Combine(root, "filter", "rules.json");
        var managed = Path.Combine(root, "filter", "managed-rules.json");
        foreach (var file in new[] { db, wal, rules, managed })
        {
            File.WriteAllText(file, "x");
            File.SetUnixFileMode(file, Mode644);
        }

        var changed = MacDataDirectoryPermissions.Enforce(root);

        Assert.Equal(Mode700, File.GetUnixFileMode(root));
        Assert.Equal(Mode755, File.GetUnixFileMode(Path.Combine(root, "filter")));
        Assert.Equal(Mode600, File.GetUnixFileMode(db));
        Assert.Equal(Mode600, File.GetUnixFileMode(wal));
        Assert.Equal(Mode644, File.GetUnixFileMode(rules));
        Assert.Equal(Mode600, File.GetUnixFileMode(managed));
        Assert.Equal([root, db, wal, managed], changed.Order(StringComparer.Ordinal).ToList().Order(StringComparer.Ordinal));
        Assert.Empty(MacDataDirectoryPermissions.Enforce(root));
    }

    [Fact]
    public void AtomicWritesUseTheRequestedMode()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        using var temp = new TempDirectory();
        var published = Path.Combine(temp.Path, "rules.json");
        var secret = Path.Combine(temp.Path, "backup.json");

        FilterRulesFile.WriteAtomic(published, "{}");
        FilterRulesFile.WriteAtomic(secret, "{}", FilterRulesFile.PrivateMode);

        Assert.Equal(Mode644, File.GetUnixFileMode(published));
        Assert.Equal(Mode600, File.GetUnixFileMode(secret));
        Assert.Empty(Directory.GetFiles(temp.Path, ".*.tmp"));
    }
}
