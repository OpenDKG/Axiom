// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.Contracts.Security;

/// <summary>
/// Stores small secrets (API keys) for optional modules. Implementations must never fall back to
/// plaintext: when no OS secret service is available the store reports itself unavailable and
/// refuses writes so the caller can tell the user instead of persisting a key in the clear.
/// </summary>
public interface ICredentialStore
{
    /// <summary>Short backend name for diagnostics, never a secret.</summary>
    string Backend { get; }

    bool IsAvailable { get; }

    Task<string?> GetAsync(string name, CancellationToken cancellationToken);

    Task SetAsync(string name, string secret, CancellationToken cancellationToken);

    Task DeleteAsync(string name, CancellationToken cancellationToken);
}

/// <summary>Explicit no-backend implementation; writes fail closed and reads return nothing.</summary>
public sealed class UnavailableCredentialStore(string reason) : ICredentialStore
{
    public string Backend => "unavailable";

    public bool IsAvailable => false;

    public string Reason { get; } = reason;

    public Task<string?> GetAsync(string name, CancellationToken cancellationToken) =>
        Task.FromResult<string?>(null);

    public Task SetAsync(string name, string secret, CancellationToken cancellationToken) =>
        throw new NotSupportedException(Reason);

    public Task DeleteAsync(string name, CancellationToken cancellationToken) =>
        throw new NotSupportedException(Reason);
}
