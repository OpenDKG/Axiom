// SPDX-License-Identifier: GPL-3.0-or-later
using System.Text.Json;

namespace LocalFirewall.Contracts.Ipc;

/// <summary>
/// Wire envelope for every UI to service message. The protocol is local-only (Named Pipes in
/// FND-003); FND-001 defines the shape and guards only.
/// </summary>
public sealed record IpcEnvelope
{
    public int Version { get; init; } = IpcProtocol.CurrentVersion;

    public Guid Id { get; init; } = Guid.NewGuid();

    /// <summary>One of <see cref="IpcCommandTypes"/>.</summary>
    public required string Type { get; init; }

    public DateTimeOffset RequestedAtUtc { get; init; } = DateTimeOffset.UtcNow;

    public JsonElement? Payload { get; init; }
}
