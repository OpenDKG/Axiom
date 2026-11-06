// SPDX-License-Identifier: GPL-3.0-or-later
namespace Netpetra.Contracts.Agents;

/// <summary>Privacy-safe view of one host-owned agent session. Raw host session ids never leave the reader.</summary>
public sealed record AgentSessionInfo(
    string Framework,
    string SessionKey,
    string Title,
    string Workspace,
    DateTimeOffset LastSeenUtc,
    bool HostLive);

/// <summary>Read-only source for Claude/Codex host session descriptors and thread metadata.</summary>
public interface IAgentSessionSource
{
    IReadOnlyList<AgentSessionInfo> Read();
}
