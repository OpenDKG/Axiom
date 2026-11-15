// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Protection;
using Xunit;

namespace Axiom.Contracts.Tests;

public sealed class ServiceInstallLogTests : IDisposable
{
    private readonly string _path = Path.Combine(
        Path.GetTempPath(),
        "axiom-service-install-" + Guid.NewGuid().ToString("N") + ".log");

    public void Dispose()
    {
        try
        {
            File.Delete(_path);
        }
        catch (IOException)
        {
        }
    }

    [Fact]
    public void Tail_returns_only_the_last_lines_oldest_first()
    {
        File.WriteAllLines(_path, ["one", "two", "three", "four"]);

        var lines = ServiceInstallLog.Tail(2, _path);

        Assert.Equal(["three", "four"], lines);
    }

    [Fact]
    public void Tail_returns_empty_for_a_missing_file_or_non_positive_count()
    {
        Assert.Empty(ServiceInstallLog.Tail(5, _path));
        File.WriteAllText(_path, "one" + Environment.NewLine);
        Assert.Empty(ServiceInstallLog.Tail(0, _path));
    }

    [Fact]
    public void Tail_reads_a_file_another_process_is_still_writing()
    {
        using (var writer = new FileStream(_path, FileMode.Create, FileAccess.Write, FileShare.ReadWrite))
        using (var text = new StreamWriter(writer))
        {
            text.WriteLine("first");
            text.Flush();

            Assert.Equal(["first"], ServiceInstallLog.Tail(10, _path));
        }
    }

    [Fact]
    public void Default_path_lives_under_machine_state_logs()
    {
        Assert.EndsWith(Path.Combine("Axiom", "logs", "service-install.log"), ServiceInstallLog.Path);
    }
}
