// SPDX-License-Identifier: GPL-3.0-or-later
using Microsoft.Extensions.Hosting;

using Axiom.Infrastructure.Linux.Systemd;

namespace Axiom.Service;

/// <summary>
/// Sends <c>READY=1</c> once the host has started (every hosted service, including the IPC socket
/// listener, is running) and <c>STOPPING=1</c> on shutdown, so <c>Type=notify</c> units report
/// the real state. A no-op outside systemd.
/// </summary>
public sealed class SystemdReadyNotifier : IHostedService
{
    private readonly IHostApplicationLifetime _lifetime;

    private readonly Func<string, bool> _send;

    public SystemdReadyNotifier(IHostApplicationLifetime lifetime)
        : this(lifetime, SdNotify.Send)
    {
    }

    public SystemdReadyNotifier(IHostApplicationLifetime lifetime, Func<string, bool> send)
    {
        _lifetime = lifetime ?? throw new ArgumentNullException(nameof(lifetime));
        _send = send ?? throw new ArgumentNullException(nameof(send));
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        _lifetime.ApplicationStarted.Register(() => _send(SdNotify.Ready));
        _lifetime.ApplicationStopping.Register(() => _send(SdNotify.Stopping));
        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
