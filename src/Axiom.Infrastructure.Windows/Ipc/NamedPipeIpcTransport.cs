// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Service.Hosting.Ipc;

namespace Axiom.Infrastructure.Windows.Ipc;

/// <summary>
/// The SID the pipe accepts. <paramref name="Pending"/> means the intended user could not be
/// resolved yet, so <paramref name="Sid"/> is the service account and resolution is worth retrying.
/// </summary>
public sealed record AllowedPipeSid(string Sid, bool Pending = false);

/// <summary>
/// Windows IPC transport: the ACL-protected named pipe with the client-SID check of
/// <see cref="PipeServer"/>. The allowed SID is resolved when the service worker starts. Right after
/// boot, Windows may not resolve a domain or Entra ID user yet; then the pipe starts for the service
/// account only and resolution is retried with backoff for about five minutes. Waiting for a client
/// instead would not work: the pipe ACL stops the user before the server sees them.
/// </summary>
public sealed class NamedPipeIpcTransport : IIpcTransport
{
    /// <summary>Waits between attempts: 5 minutes in total.</summary>
    internal static readonly IReadOnlyList<TimeSpan> DefaultRetryDelays =
        new[] { 2, 4, 8, 16, 30, 60, 60, 60, 60 }.Select(seconds => TimeSpan.FromSeconds(seconds)).ToArray();

    private readonly Func<AllowedPipeSid> _resolve;
    private readonly IReadOnlyList<TimeSpan> _retryDelays;
    private readonly Func<TimeSpan, CancellationToken, Task> _delay;
    private readonly Func<string, IpcRequestDispatcher, Action<string>, CancellationToken, Task> _serve;
    private AllowedPipeSid? _allowed;

    public NamedPipeIpcTransport(string pipeName, Func<AllowedPipeSid> resolveAllowedSid)
        : this(pipeName, resolveAllowedSid, DefaultRetryDelays, Task.Delay, serve: null)
    {
    }

    internal NamedPipeIpcTransport(
        string pipeName,
        Func<AllowedPipeSid> resolveAllowedSid,
        IReadOnlyList<TimeSpan> retryDelays,
        Func<TimeSpan, CancellationToken, Task> delay,
        Func<string, IpcRequestDispatcher, Action<string>, CancellationToken, Task>? serve)
    {
        Endpoint = pipeName;
        _resolve = resolveAllowedSid;
        _retryDelays = retryDelays;
        _delay = delay;
        _serve = serve ?? ((sid, dispatcher, log, cancellationToken) =>
            new PipeServer(Endpoint, sid, dispatcher, log).RunAsync(cancellationToken));
    }

    public string Endpoint { get; }

    public string Prepare() => (_allowed ??= _resolve()).Sid;

    public async Task RunAsync(IpcRequestDispatcher dispatcher, Action<string> log, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(dispatcher);
        ArgumentNullException.ThrowIfNull(log);
        _ = Prepare();
        var allowed = _allowed!;
        if (!allowed.Pending)
        {
            await _serve(allowed.Sid, dispatcher, log, cancellationToken).ConfigureAwait(false);
            return;
        }

        using var firstServer = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        using var retry = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var serving = _serve(allowed.Sid, dispatcher, log, firstServer.Token);
        var retrying = RetryAsync(allowed.Sid, log, retry.Token);
        if (await Task.WhenAny(serving, retrying).ConfigureAwait(false) == serving)
        {
            await retry.CancelAsync().ConfigureAwait(false);
            _ = await retrying.ConfigureAwait(false);
            await serving.ConfigureAwait(false);
            return;
        }

        var resolved = await retrying.ConfigureAwait(false);
        if (resolved is null)
        {
            await serving.ConfigureAwait(false);
            return;
        }

        // All instances of a named pipe share the first instance's security descriptor, so the old
        // server must close completely before a server with the new ACL starts.
        await firstServer.CancelAsync().ConfigureAwait(false);
        try
        {
            await serving.ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
        }

        if (cancellationToken.IsCancellationRequested)
        {
            return;
        }

        _allowed = resolved;
        log($"Pipe {Endpoint} now allows SID {resolved.Sid}.");
        await _serve(resolved.Sid, dispatcher, log, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>The newly resolved SID, or null when there is nothing to change.</summary>
    private async Task<AllowedPipeSid?> RetryAsync(string servingSid, Action<string> log, CancellationToken cancellationToken)
    {
        for (var attempt = 0; attempt < _retryDelays.Count; attempt++)
        {
            try
            {
                await _delay(_retryDelays[attempt], cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return null;
            }

            var allowed = _resolve();
            if (!allowed.Pending)
            {
                return string.Equals(allowed.Sid, servingSid, StringComparison.OrdinalIgnoreCase) ? null : allowed;
            }
        }

        log($"Pipe {Endpoint}: the allowed user still cannot be resolved after {_retryDelays.Count} retries. Restart the service to try again.");
        return null;
    }
}
