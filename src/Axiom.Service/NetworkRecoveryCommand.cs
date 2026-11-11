// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Axiom.Contracts.NetworkRecovery;
using Axiom.Infrastructure.Windows.Firewall;
using Axiom.Infrastructure.Windows.Network;
using Axiom.Persistence;
using Microsoft.Extensions.Logging.Abstractions;

namespace Axiom.Service;

/// <summary>
/// Explicit administrator recovery when the service or desktop cannot run. It reads only the
/// validated machine snapshot, prints a dry-run plan by default, and applies only with
/// <c>--apply</c> from an elevated prompt while the service is stopped. It accepts no adapter,
/// server or rule names from the command line.
/// </summary>
internal static class NetworkRecoveryCommand
{
    private const string ApplyArgument = "--apply";

    private const string ServiceProcessName = "Axiom.Service";

    private const uint AttachParentProcess = 0xFFFFFFFF;

    public static int Run(string[] arguments) =>
        Run(arguments, NetworkRecoverySnapshotStore.DefaultPath);

    internal static int Run(string[] arguments, string snapshotPath)
    {
        _ = AttachConsole(AttachParentProcess);

        var path = snapshotPath;
        var apply = arguments.Any(argument =>
            string.Equals(argument, ApplyArgument, StringComparison.OrdinalIgnoreCase));

        Write("Axiom network recovery");
        Write($"Snapshot: {path}");

        var read = NetworkRecoverySnapshotStore.Read(path);
        switch (read.Status)
        {
            case NetworkRecoverySnapshotReadStatus.Missing:
                Write("No saved network state is available. Nothing was changed.");
                return ExitCodes.NoSnapshot;

            case NetworkRecoverySnapshotReadStatus.Corrupt:
                Write($"Refusing to act: {read.Error}");
                return ExitCodes.SnapshotRefused;

            case NetworkRecoverySnapshotReadStatus.Unreadable:
                Write($"Refusing to act: {read.Error}");
                return ExitCodes.SnapshotRefused;
        }

        var snapshot = read.Snapshot!;
        PrintPlan(snapshot);

        if (!apply)
        {
            Write("Dry run: no change was made.");
            Write("Run this command from an elevated prompt with --apply to restore the saved state.");
            return ExitCodes.PlanOnly;
        }

        if (!ServiceInstaller.IsAdministrator())
        {
            Write("Restore requires administrator rights. Re-run from an elevated prompt. Nothing was changed.");
            return ExitCodes.NotAdministrator;
        }

        var runningProcesses = Process.GetProcessesByName(ServiceProcessName);
        try
        {
            if (runningProcesses.Any(process => process.Id != Environment.ProcessId))
            {
                Write(
                    "The Axiom service is running. Stop it before the offline recovery, or use " +
                    "Settings > Restore network settings in the app. Nothing was changed.");
                return ExitCodes.ServiceRunning;
            }
        }
        finally
        {
            foreach (var process in runningProcesses)
            {
                process.Dispose();
            }
        }

        using var firewall = new WindowsFirewallPolicyAdapter();
        var dns = new WindowsDnsRecoveryAdapter();
        HistoryStore? history = null;
        try
        {
            // The service is non-interactive and audits into ProgramData; the emergency command
            // must use the same database even though its own console is interactive.
            history = new HistoryStore(DatabasePaths.DefaultDatabasePath);
        }
        catch (Exception exception) when (exception is InvalidOperationException or IOException or UnauthorizedAccessException)
        {
            Write($"Audit database unavailable; recovery continues without an audit row: {exception.Message}");
        }

        using var controller = new NetworkRecoveryController(
            dns,
            firewall,
            () => true,
            () => snapshot.ProtectionWasActive,
            path,
            history,
            NullLogger<NetworkRecoveryController>.Instance);

        var actor = CurrentActor();
        NetworkRecoveryRestoreResult result;
        try
        {
            result = controller.RestoreAsync(actor, CancellationToken.None).GetAwaiter().GetResult();
        }
        catch (Exception exception) when (exception is
                     InvalidOperationException or UnauthorizedAccessException or IOException)
        {
            Write($"Recovery failed before it could complete: {exception.Message}");
            return ExitCodes.PartialFailure;
        }

        Write($"Result: {result.Status}; verified: {(result.Verified ? "yes" : "no")}");
        Write(
            $"Adapters restored: {result.AdaptersRestored} (verified {result.AdaptersVerified}); " +
            $"Axiom rules removed: {result.RulesRemoved}; already absent: {result.RulesVerifiedAbsent}.");
        foreach (var problem in result.Problems)
        {
            Write($"- {problem.Code}: {problem.Message}");
        }

        if (!result.Verified)
        {
            Write("Recovery did not complete. Review the messages above; nothing else was changed.");
            return ExitCodes.PartialFailure;
        }

        Write("Recovery completed and was verified.");
        return ExitCodes.Success;
    }

    private static void PrintPlan(NetworkRecoverySnapshot snapshot)
    {
        Write(
            $"Captured: {snapshot.CapturedUtc.ToLocalTime().ToString("g", CultureInfo.CurrentCulture)}; " +
            $"protection was {(snapshot.ProtectionWasActive ? "active" : "inactive")}.");

        if (snapshot.Adapters.Count == 0 && snapshot.Rules.Count == 0)
        {
            Write("The saved state contains nothing to restore.");
            return;
        }

        foreach (var adapter in snapshot.Adapters)
        {
            Write(
                $"- Adapter {adapter.InterfaceAlias} ({adapter.AdapterId:D}): " +
                $"IPv4 {ModeText(adapter.Ipv4Mode, adapter.Ipv4Servers)}, " +
                $"IPv6 {ModeText(adapter.Ipv6Mode, adapter.Ipv6Servers)}");
        }

        foreach (var rule in snapshot.Rules)
        {
            Write(
                $"- Axiom rule {rule.ManagedRuleId:D} " +
                $"{(rule.Direction == Axiom.Contracts.Firewall.FirewallDirection.Outbound ? "OUT" : "IN")} " +
                $"(group '{rule.OwnershipGroup}')");
        }
    }

    private static string ModeText(NetworkDnsMode mode, IReadOnlyList<string> servers) =>
        mode == NetworkDnsMode.Automatic
            ? "automatic (DHCP)"
            : "static " + string.Join(", ", servers);

    private static string CurrentActor()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            return identity.Name ?? "administrator";
        }
        catch (Exception exception) when (exception is InvalidOperationException or UnauthorizedAccessException)
        {
            return "administrator";
        }
    }

    private static void Write(string message) => Console.WriteLine(message);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AttachConsole(uint processId);

    internal static class ExitCodes
    {
        public const int Success = 0;
        public const int PlanOnly = 1;
        public const int NoSnapshot = 2;
        public const int SnapshotRefused = 3;
        public const int NotAdministrator = 4;
        public const int PartialFailure = 5;
        public const int ServiceRunning = 6;
    }
}
