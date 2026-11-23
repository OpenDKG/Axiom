// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using System.Text;

namespace Axiom.Contracts.Blackbox;

/// <summary>Determines how cooperative agent hooks behave when the Blackbox guard cannot answer.</summary>
public enum AgentGuardFailureMode
{
    FailOpen = 0,
    FailClosed = 1,
}

/// <summary>
/// Persists the operator's opt-in agent guard failure policy (`fail-open` default vs `fail-closed`
/// strict refusal) under `<c>LocalApplicationData\Axiom\guard-failure-policy.txt</c>` so Python
/// and JS/TS hook adapters can read it directly with zero service round-trips.
/// </summary>
public static class AgentGuardFailurePolicyStore
{
    public const string FileName = "guard-failure-policy.txt";
    public const string FailOpenToken = "fail-open";
    public const string FailClosedToken = "fail-closed";

    public static string ResolvePath(string? localAppData = null)
    {
        var root = string.IsNullOrWhiteSpace(localAppData)
            ? Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)
            : localAppData;
        return Path.Combine(root, "Axiom", FileName);
    }

    public static AgentGuardFailureMode Read(string? localAppData = null)
    {
        try
        {
            var path = ResolvePath(localAppData);
            if (!File.Exists(path))
            {
                return AgentGuardFailureMode.FailOpen;
            }

            var value = File.ReadAllText(path).Trim();
            return value.Equals(FailClosedToken, StringComparison.OrdinalIgnoreCase) ||
                   value.Equals("fail_closed", StringComparison.OrdinalIgnoreCase) ||
                   value.Equals("strict", StringComparison.OrdinalIgnoreCase) ||
                   value.Equals("true", StringComparison.OrdinalIgnoreCase) ||
                   value.Equals("1", StringComparison.OrdinalIgnoreCase)
                ? AgentGuardFailureMode.FailClosed
                : AgentGuardFailureMode.FailOpen;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return AgentGuardFailureMode.FailOpen;
        }
    }

    public static bool IsFailClosed(string? localAppData = null) =>
        Read(localAppData) == AgentGuardFailureMode.FailClosed;

    public static bool Write(AgentGuardFailureMode mode, string? localAppData = null)
    {
        try
        {
            var path = ResolvePath(localAppData);
            var directory = Path.GetDirectoryName(path);
            if (!string.IsNullOrWhiteSpace(directory))
            {
                Directory.CreateDirectory(directory);
            }

            var token = mode == AgentGuardFailureMode.FailClosed ? FailClosedToken : FailOpenToken;
            File.WriteAllText(path, token + Environment.NewLine, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
            return true;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    public static bool SetFailClosed(bool failClosed, string? localAppData = null) =>
        Write(failClosed ? AgentGuardFailureMode.FailClosed : AgentGuardFailureMode.FailOpen, localAppData);
}
