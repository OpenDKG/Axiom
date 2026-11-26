// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text.RegularExpressions;

namespace Axiom.Service;

/// <summary>Account type Windows reports for a SID (<c>SID_NAME_USE</c>).</summary>
internal enum SidNameUse
{
    User = 1,
    Group = 2,
    Domain = 3,
    Alias = 4,
    WellKnownGroup = 5,
    DeletedAccount = 6,
    Invalid = 7,
    Unknown = 8,
    Computer = 9,
    Label = 10,
    LogonSession = 11,
}

/// <summary>
/// Decides whether a SID may be granted access to the service pipe. Only an account that Windows
/// reports as a user qualifies; this covers local, domain and Microsoft Entra ID
/// (<c>S-1-12-1-...</c>) users. The SID text alone cannot tell a user from a group.
/// </summary>
internal static class AccountSid
{
    /// <summary>Format pre-check only. It says nothing about what kind of account the SID names.</summary>
    public static bool IsWellFormed(string value) =>
        Regex.IsMatch(
            value,
            @"\AS-1-[0-9]{1,14}(-[0-9]{1,10}){1,15}\z",
            RegexOptions.CultureInvariant,
            TimeSpan.FromSeconds(1));

    /// <summary>False when the SID is malformed, cannot be resolved, or is not a user.</summary>
    public static bool IsUser(string value, Func<string, SidNameUse?> lookup) =>
        IsWellFormed(value) && lookup(value) == SidNameUse.User;

    /// <summary><c>LookupAccountSid</c> on this machine, or null when the SID cannot be resolved.</summary>
    public static SidNameUse? Lookup(string value)
    {
        byte[] sid;
        try
        {
            var identifier = new SecurityIdentifier(value);
            sid = new byte[identifier.BinaryLength];
            identifier.GetBinaryForm(sid, 0);
        }
        catch (ArgumentException)
        {
            return null;
        }

        uint nameLength = 0;
        uint domainLength = 0;
        _ = LookupAccountSidW(null, sid, null, ref nameLength, null, ref domainLength, out _);
        if (Marshal.GetLastPInvokeError() != ErrorInsufficientBuffer)
        {
            return null;
        }

        var name = new char[nameLength.ToInt32Checked()];
        var domain = new char[domainLength.ToInt32Checked()];
        return LookupAccountSidW(null, sid, name, ref nameLength, domain, ref domainLength, out var use)
            ? (SidNameUse)use
            : null;
    }

    private static int ToInt32Checked(this uint value) => Convert.ToInt32(value, CultureInfo.InvariantCulture);

    private const int ErrorInsufficientBuffer = 122;

    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool LookupAccountSidW(
        string? lpSystemName,
        byte[] sid,
        [Out] char[]? name,
        ref uint cchName,
        [Out] char[]? referencedDomainName,
        ref uint cchReferencedDomainName,
        out int peUse);
}
