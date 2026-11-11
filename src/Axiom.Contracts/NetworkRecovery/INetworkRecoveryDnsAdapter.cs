// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.Contracts.NetworkRecovery;

/// <summary>
/// Windows DNS surface used by network recovery. Reads are side-effect free; <see cref="ApplyDns"/>
/// changes one captured adapter only. Implementations must throw
/// <see cref="NetworkRecoveryPlatformException"/> with a safe code when the operating system
/// rejects the operation, and must never invent servers.
/// </summary>
public interface INetworkRecoveryDnsAdapter
{
    IReadOnlyList<NetworkAdapterDnsState> CaptureDns();

    void ApplyDns(NetworkAdapterDnsState state);

    void FlushDnsCache();

    bool AnyAdapterUsesLoopbackDns();
}

/// <summary>Safe, coded platform failure for recovery diagnostics and UI messages.</summary>
public sealed class NetworkRecoveryPlatformException(string code, string message, Exception? inner = null)
    : Exception(message, inner)
{
    public string Code { get; } = code;
}
