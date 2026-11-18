// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Presentation;

namespace Axiom.UI.Avalonia;

/// <summary>
/// Wraps the shell's service client so every call any page makes also tells the shell whether the
/// daemon was reached. The shell turns the first unreachable answer into one shared "unknown"
/// state for the header, the footer lamp, Network Control, Simple home and Mini, instead of each
/// page waiting for its own poll; the first answer after that brings them back together.
/// Used off Windows only.
/// </summary>
internal sealed class ServiceReachabilityClient(IServiceRequestClient inner) : IServiceRequestClient
{
    /// <summary>The service answered (with a result or with its own error).</summary>
    public event EventHandler? Answered;

    /// <summary>The service could not be reached (no socket, refused, denied, timed out).</summary>
    public event EventHandler? Unreachable;

    public async Task<T> SendAsync<T>(string command, object? payload, CancellationToken cancellationToken)
    {
        T result;
        try
        {
            result = await inner.SendAsync<T>(command, payload, cancellationToken).ConfigureAwait(true);
        }
        catch (ServiceUnavailableException exception)
        {
            (exception.ServiceResponded ? Answered : Unreachable)?.Invoke(this, EventArgs.Empty);
            throw;
        }

        Answered?.Invoke(this, EventArgs.Empty);
        return result;
    }
}
