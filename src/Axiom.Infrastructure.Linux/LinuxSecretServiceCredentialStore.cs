// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics;
using System.Text.RegularExpressions;
using Axiom.Contracts.Security;

namespace Axiom.Infrastructure.Linux;

/// <summary>
/// Secret Service storage through the libsecret <c>secret-tool</c> CLI. A session bus and an
/// unlocked keyring are required; without them writes fail and no plaintext file is created.
/// Only fixed arguments are passed (no shell), and the secret is written on stdin.
/// </summary>
public sealed partial class LinuxSecretServiceCredentialStore : ICredentialStore
{
    private const string Service = "axiom";

    private readonly string _tool;

    private readonly TimeSpan _timeout;

    public LinuxSecretServiceCredentialStore(string? tool = null, TimeSpan? timeout = null)
    {
        _tool = tool ?? "secret-tool";
        _timeout = timeout ?? TimeSpan.FromSeconds(10);
    }

    public string Backend => "Secret Service (secret-tool)";

    public bool IsAvailable => ResolveTool() is not null && HasSessionBus();

    public async Task<string?> GetAsync(string name, CancellationToken cancellationToken)
    {
        ValidateName(name);
        var tool = ResolveTool();
        if (tool is null || !HasSessionBus())
        {
            return null;
        }

        var result = await RunAsync(
            tool,
            ["lookup", "service", Service, "key", name],
            stdin: null,
            cancellationToken).ConfigureAwait(false);

        return result.ExitCode == 0 ? result.Output.TrimEnd('\n') : null;
    }

    public async Task SetAsync(string name, string secret, CancellationToken cancellationToken)
    {
        ValidateName(name);
        ArgumentNullException.ThrowIfNull(secret);
        var tool = ResolveTool() ?? throw Unavailable();

        if (!HasSessionBus())
        {
            throw Unavailable();
        }

        var result = await RunAsync(
            tool,
            ["store", "--label", $"Axiom {name}", "service", Service, "key", name],
            stdin: secret,
            cancellationToken).ConfigureAwait(false);

        if (result.ExitCode != 0)
        {
            throw new InvalidOperationException(
                $"secret-tool could not store the credential (exit {result.ExitCode}); " +
                "is the keyring unlocked and the session bus reachable?");
        }
    }

    public async Task DeleteAsync(string name, CancellationToken cancellationToken)
    {
        ValidateName(name);
        var tool = ResolveTool() ?? throw Unavailable();

        if (!HasSessionBus())
        {
            throw Unavailable();
        }

        var result = await RunAsync(
            tool,
            ["clear", "service", Service, "key", name],
            stdin: null,
            cancellationToken).ConfigureAwait(false);

        if (result.ExitCode != 0)
        {
            throw new InvalidOperationException(
                $"secret-tool could not delete the credential (exit {result.ExitCode}); the stored " +
                "secret may still be present.");
        }
    }

    internal static void ValidateName(string name)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        if (!NamePattern().IsMatch(name))
        {
            throw new ArgumentException(
                "Credential names are limited to 1-64 characters of a-z, 0-9, '.', '_' or '-'.",
                nameof(name));
        }
    }

    private static NotSupportedException Unavailable() => new(
        "No Secret Service backend is available (secret-tool and an unlocked session bus are " +
        "required). Refusing to store the credential in plaintext.");

    private string? ResolveTool()
    {
        if (Path.IsPathFullyQualified(_tool))
        {
            return File.Exists(_tool) ? _tool : null;
        }

        var path = Environment.GetEnvironmentVariable("PATH") ?? string.Empty;
        foreach (var directory in path.Split(':', StringSplitOptions.RemoveEmptyEntries))
        {
            var candidate = Path.Combine(directory, _tool);
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }

        return null;
    }

    private static bool HasSessionBus() =>
        !string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("DBUS_SESSION_BUS_ADDRESS"));

    private async Task<(int ExitCode, string Output)> RunAsync(
        string tool,
        string[] arguments,
        string? stdin,
        CancellationToken cancellationToken)
    {
        var startInfo = new ProcessStartInfo(tool)
        {
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        foreach (var argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        using var process = Process.Start(startInfo) ?? throw Unavailable();
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(_timeout);

        try
        {
            if (stdin is not null)
            {
                await process.StandardInput.WriteAsync(stdin.AsMemory(), timeout.Token).ConfigureAwait(false);
            }

            process.StandardInput.Close();
            var output = await process.StandardOutput.ReadToEndAsync(timeout.Token).ConfigureAwait(false);
            await process.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
            return (process.ExitCode, output);
        }
        catch (OperationCanceledException)
        {
            try
            {
                process.Kill(entireProcessTree: true);
            }
            catch (InvalidOperationException)
            {
                // The process already exited.
            }

            throw new TimeoutException("secret-tool did not answer in time.");
        }
    }

    [GeneratedRegex("^[a-z0-9._-]{1,64}$", RegexOptions.CultureInvariant)]
    private static partial Regex NamePattern();
}
