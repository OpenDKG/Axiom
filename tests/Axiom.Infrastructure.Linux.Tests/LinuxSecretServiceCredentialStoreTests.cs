// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Infrastructure.Linux;
using Xunit;

namespace Axiom.Infrastructure.Linux.Tests;

public sealed class LinuxSecretServiceCredentialStoreTests : IDisposable
{
    private readonly string _directory = Path.Combine(
        Path.GetTempPath(),
        $"axiom-secret-{Guid.NewGuid():N}");

    private readonly string _store;

    private readonly string? _previousBus;

    public LinuxSecretServiceCredentialStoreTests()
    {
        Directory.CreateDirectory(_directory);
        _store = Path.Combine(_directory, "credential.txt");
        var tool = Path.Combine(_directory, "secret-tool");
        File.WriteAllText(tool, $"""
            #!/bin/sh
            store='{_store}'
            case "$1" in
              lookup) [ -f "$store" ] && cat "$store" ;;
              store) cat > "$store" ;;
              clear) rm -f "$store" ;;
            esac
            """);
        File.SetUnixFileMode(
            tool,
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);

        _previousBus = Environment.GetEnvironmentVariable("DBUS_SESSION_BUS_ADDRESS");
        Environment.SetEnvironmentVariable("DBUS_SESSION_BUS_ADDRESS", "unix:path=/tmp/test-bus");

        Tool = tool;
    }

    private string Tool { get; }

    public void Dispose()
    {
        Environment.SetEnvironmentVariable("DBUS_SESSION_BUS_ADDRESS", _previousBus);
        if (Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);
        }
    }

    [Fact]
    public async Task Round_trips_a_secret_through_the_secret_service_backend()
    {
        var store = new LinuxSecretServiceCredentialStore(Tool);

        Assert.True(store.IsAvailable);
        await store.SetAsync("virustotal", "not-a-real-key", CancellationToken.None);
        Assert.Equal("not-a-real-key", await store.GetAsync("virustotal", CancellationToken.None));

        await store.DeleteAsync("virustotal", CancellationToken.None);
        Assert.Null(await store.GetAsync("virustotal", CancellationToken.None));
    }

    [Fact]
    public async Task Missing_backend_refuses_to_store_in_plaintext()
    {
        var store = new LinuxSecretServiceCredentialStore(Path.Combine(_directory, "missing"));

        Assert.False(store.IsAvailable);
        await Assert.ThrowsAsync<NotSupportedException>(
            () => store.SetAsync("virustotal", "secret", CancellationToken.None));
        Assert.Null(await store.GetAsync("virustotal", CancellationToken.None));
        Assert.False(File.Exists(_store));
    }

    [Fact]
    public async Task Deleting_without_a_backend_is_reported_instead_of_faked()
    {
        var store = new LinuxSecretServiceCredentialStore(Path.Combine(_directory, "missing"));

        await Assert.ThrowsAsync<NotSupportedException>(
            () => store.DeleteAsync("virustotal", CancellationToken.None));
    }

    [Fact]
    public async Task Failed_backend_deletion_is_reported()
    {
        var failing = Path.Combine(_directory, "failing-secret-tool");
        File.WriteAllText(failing, "#!/bin/sh\nexit 1\n");
        File.SetUnixFileMode(
            failing,
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);

        var store = new LinuxSecretServiceCredentialStore(failing);

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => store.DeleteAsync("virustotal", CancellationToken.None));
    }

    [Fact]
    public async Task No_session_bus_is_reported_and_rejected()
    {
        Environment.SetEnvironmentVariable("DBUS_SESSION_BUS_ADDRESS", null);
        var store = new LinuxSecretServiceCredentialStore(Tool);

        Assert.False(store.IsAvailable);
        await Assert.ThrowsAsync<NotSupportedException>(
            () => store.SetAsync("virustotal", "secret", CancellationToken.None));
    }

    [Theory]
    [InlineData("../escape")]
    [InlineData("UPPER")]
    [InlineData("")]
    [InlineData("name with space")]
    public async Task Invalid_names_are_rejected_before_any_process_starts(string name)
    {
        var store = new LinuxSecretServiceCredentialStore(Tool);

        await Assert.ThrowsAnyAsync<ArgumentException>(
            () => store.SetAsync(name, "secret", CancellationToken.None));
    }

    [Fact]
    public void Unavailable_store_is_explicit()
    {
        var unavailable = new Axiom.Contracts.Security.UnavailableCredentialStore("no keyring");

        Assert.False(unavailable.IsAvailable);
        Assert.Equal("no keyring", unavailable.Reason);
    }
}
