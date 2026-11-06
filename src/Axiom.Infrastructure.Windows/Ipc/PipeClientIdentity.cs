// SPDX-License-Identifier: GPL-3.0-or-later
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace Axiom.Infrastructure.Windows.Ipc;

/// <summary>
/// Reads the SID of the process on the other end of a pipe. This is the identity check used after
/// the DACL: the DACL decides who may connect, this decides who actually did.
/// </summary>
public static class PipeClientIdentity
{
    private const uint ProcessQueryLimitedInformation = 0x1000;

    private const uint TokenQuery = 0x0008;

    private const int TokenUserInformation = 1;

    public static string? TryGetClientSid(SafePipeHandle pipe)
    {
        ArgumentNullException.ThrowIfNull(pipe);

        if (!GetNamedPipeClientProcessId(pipe, out var processId))
        {
            return null;
        }

        using var process = OpenProcess(ProcessQueryLimitedInformation, false, processId);
        if (process.IsInvalid)
        {
            return null;
        }

        if (!OpenProcessToken(process, TokenQuery, out var token))
        {
            return null;
        }

        using (token)
        {
            GetTokenInformation(token, TokenUserInformation, IntPtr.Zero, 0, out var required);
            if (required <= 0)
            {
                return null;
            }

            var buffer = Marshal.AllocHGlobal(required);
            try
            {
                if (!GetTokenInformation(token, TokenUserInformation, buffer, required, out _))
                {
                    return null;
                }

                // TOKEN_USER { SID_AND_ATTRIBUTES { PSID Sid; DWORD Attributes; } }
                var sidPointer = Marshal.ReadIntPtr(buffer);
                return sidPointer == IntPtr.Zero ? null : new SecurityIdentifier(sidPointer).Value;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetNamedPipeClientProcessId(SafePipeHandle pipe, out uint clientProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern SafeProcessHandle OpenProcess(uint desiredAccess, bool inheritHandle, uint processId);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(
        SafeProcessHandle processHandle,
        uint desiredAccess,
        out SafeAccessTokenHandle tokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetTokenInformation(
        SafeAccessTokenHandle tokenHandle,
        int tokenInformationClass,
        IntPtr tokenInformation,
        int tokenInformationLength,
        out int returnLength);
}
