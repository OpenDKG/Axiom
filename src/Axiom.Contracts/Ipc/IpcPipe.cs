// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.Contracts.Ipc;

public static class IpcPipe
{
    /// <summary>Local-only pipe name; the server applies an explicit DACL and SID check.</summary>
    public const string Name = "Axiom.Service.v1";
}

public static class IpcErrorCodes
{
    public const string UnknownCommand = "unknown_command";
    public const string NotSupported = "not_supported";
    public const string MessageTooLarge = "message_too_large";
    public const string InvalidRequest = "invalid_request";
    public const string Unauthorized = "unauthorized";
    public const string InternalError = "internal_error";
    public const string ServiceUnavailable = "service_unavailable";
}
