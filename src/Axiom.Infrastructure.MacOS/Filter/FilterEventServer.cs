// SPDX-License-Identifier: GPL-3.0-or-later
using System.Net.Sockets;
using System.Runtime.Versioning;
using Axiom.Infrastructure.MacOS.Interop;
using Axiom.Infrastructure.MacOS.Monitoring;

namespace Axiom.Infrastructure.MacOS.Filter;

/// <summary>
/// Listens on <c>/var/run/axiom/filter.sock</c> (root, 0600) for the AxiomFilter extension and
/// feeds its NDJSON flow events into <see cref="FlowTable"/> and <see cref="FilterStatus"/>. The
/// filter is a client that reconnects every 2 s; the daemon never writes to it. Garbage, unknown
/// types and oversized lines are counted and skipped, never fatal.
/// </summary>
[UnsupportedOSPlatform("windows")]
public sealed class FilterEventServer
{
    public const int MaxLineBytes = 16 * 1024;

    private const int MaxConcurrentClients = 4;

    private readonly MacServicePaths _paths;

    private readonly FlowTable _flows;

    private readonly FilterStatus _status;

    private readonly Func<uint?, bool> _authorizePeer;

    private readonly TimeProvider _time;

    private long _rejectedLines;

    private long _acceptedEvents;

    public FilterEventServer(MacServicePaths paths, FlowTable flows, FilterStatus status)
        : this(paths, flows, status, uid => uid == 0, TimeProvider.System)
    {
    }

    public FilterEventServer(
        MacServicePaths paths,
        FlowTable flows,
        FilterStatus status,
        Func<uint?, bool> authorizePeer,
        TimeProvider time)
    {
        _paths = paths ?? throw new ArgumentNullException(nameof(paths));
        _flows = flows ?? throw new ArgumentNullException(nameof(flows));
        _status = status ?? throw new ArgumentNullException(nameof(status));
        _authorizePeer = authorizePeer ?? throw new ArgumentNullException(nameof(authorizePeer));
        _time = time ?? throw new ArgumentNullException(nameof(time));
    }

    /// <summary>
    /// Runs after every accepted filter connection. The daemon uses it to republish the rule table
    /// so the extension reloads and sends a fresh <c>filter.rules</c> acknowledgement on the new
    /// connection (the extension only reports rules after a reload, the hello on connect is not an
    /// acknowledgement). Failures are logged, never fatal.
    /// </summary>
    public Func<CancellationToken, Task>? ClientConnectedAsync { get; set; }

    /// <summary>
    /// Runs after every accepted filter connection with the peer's process identity (pid + start
    /// time; null when it cannot be read). The daemon uses it to reset mDNSResponder once per new
    /// filter instance (<see cref="ResolverResetCoordinator"/>).
    /// </summary>
    public Action<FilterInstanceIdentity?>? FilterInstanceConnected { get; set; }

    public long RejectedLines => Interlocked.Read(ref _rejectedLines);

    public long AcceptedEvents => Interlocked.Read(ref _acceptedEvents);

    public string SocketPath => _paths.FilterSocketPath;

    public async Task RunAsync(Action<string> log, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(log);

        var active = 0;
        while (!cancellationToken.IsCancellationRequested)
        {
            Socket listener;
            try
            {
                listener = UnixSocketListener.Create(SocketPath, UnixSocketListener.PrivateSocketMode);
            }
            catch (Exception exception) when (exception is
                         SocketException or IOException or UnauthorizedAccessException)
            {
                log($"Filter socket {SocketPath} could not start: {exception.Message}");
                await Task.Delay(TimeSpan.FromSeconds(2), cancellationToken).ConfigureAwait(false);
                continue;
            }

            log($"Filter event socket listening on {SocketPath}");

            try
            {
                while (!cancellationToken.IsCancellationRequested)
                {
                    var client = await listener.AcceptAsync(cancellationToken).ConfigureAwait(false);
                    if (Interlocked.Increment(ref active) > MaxConcurrentClients)
                    {
                        Interlocked.Decrement(ref active);
                        client.Dispose();
                        continue;
                    }

                    _ = Task.Run(
                        async () =>
                        {
                            try
                            {
                                await ServeAsync(client, log, cancellationToken).ConfigureAwait(false);
                            }
                            finally
                            {
                                Interlocked.Decrement(ref active);
                            }
                        },
                        CancellationToken.None);
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                break;
            }
            catch (SocketException exception)
            {
                log($"Filter socket accept failed: {exception.Message}");
            }
            finally
            {
                listener.Dispose();
                UnixSocketListener.TryDelete(SocketPath);
            }
        }
    }

    /// <summary>Consumes one filter connection (also used directly by tests with any stream).</summary>
    public async Task ConsumeAsync(Stream stream, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);

        var reader = new BoundedLineReader(stream, MaxLineBytes);
        var droppedBefore = 0L;
        while (!cancellationToken.IsCancellationRequested)
        {
            var line = await reader.ReadLineAsync(cancellationToken).ConfigureAwait(false);
            if (reader.DroppedLines != droppedBefore)
            {
                Interlocked.Add(ref _rejectedLines, reader.DroppedLines - droppedBefore);
                droppedBefore = reader.DroppedLines;
            }

            if (line is null)
            {
                return;
            }

            if (line.Length == 0)
            {
                continue;
            }

            var flowEvent = FlowEventParser.TryParse(line);
            if (flowEvent is null)
            {
                Interlocked.Increment(ref _rejectedLines);
                continue;
            }

            Accept(flowEvent);
        }
    }

    /// <summary>Applies one parsed event.</summary>
    public void Accept(FlowEvent flowEvent)
    {
        ArgumentNullException.ThrowIfNull(flowEvent);

        var now = _time.GetUtcNow();
        Interlocked.Increment(ref _acceptedEvents);
        if (flowEvent.Type == FlowEventType.Hello)
        {
            _status.Hello(flowEvent.Version, flowEvent.Generation, flowEvent.Dropped, now);
            return;
        }

        if (flowEvent.Type == FlowEventType.Rules)
        {
            _status.RulesReported(flowEvent, now);
            return;
        }

        _status.EventSeen(now);
        _flows.Apply(flowEvent, now);
    }

    private async Task ServeAsync(Socket client, Action<string> log, CancellationToken cancellationToken)
    {
        using (client)
        {
            uint? uid = UnixPeerCredentials.TryGetPeerUid(client, out var peerUid) ? peerUid : null;
            if (!_authorizePeer(uid))
            {
                log($"Rejected filter socket client uid {uid?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "unknown"}.");
                return;
            }

            _status.ClientConnected();
            log("AxiomFilter connected to the flow-event socket.");
            try
            {
                FilterInstanceConnected?.Invoke(FilterInstanceIdentity.TryRead(client));

                if (ClientConnectedAsync is { } onConnected)
                {
                    try
                    {
                        await onConnected(cancellationToken).ConfigureAwait(false);
                    }
                    catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
                    {
                        log($"Could not republish the rule table for the new filter connection: {exception.Message}");
                    }
                }

                var stream = new NetworkStream(client, ownsSocket: false);
                await using (stream.ConfigureAwait(false))
                {
                    await ConsumeAsync(stream, cancellationToken).ConfigureAwait(false);
                }
            }
            catch (Exception exception) when (exception is
                         IOException or SocketException or ObjectDisposedException or OperationCanceledException)
            {
                // Filter restarted or daemon stopping; the filter reconnects on its own.
            }
            finally
            {
                _status.ClientDisconnected();
                log("AxiomFilter disconnected from the flow-event socket.");
            }
        }
    }
}
