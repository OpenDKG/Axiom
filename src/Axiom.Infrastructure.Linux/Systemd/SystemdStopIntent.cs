// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using Axiom.Infrastructure.Unix.Interop;

namespace Axiom.Infrastructure.Linux.Systemd;

/// <summary>
/// Tells a restart from a stop when the daemon is asked to stop (docs/LINUX_EBPF.md §12). A restart
/// (<c>systemctl restart</c>, a pending start) or a package upgrade (the installer leaves
/// <see cref="MarkerFileName"/> in the runtime directory before it stops the unit) keeps the
/// connect-time BPF layer attached for the next daemon; a plain <c>systemctl stop</c>,
/// <c>disable --now</c> or shutdown detaches it. When the answer cannot be read the layer is kept
/// (fail closed): package removal still detaches through <c>bpf-pins.sh</c>.
/// </summary>
public sealed class SystemdStopIntent
{
    /// <summary>One-shot marker the installer writes into the runtime directory before an upgrade stop.</summary>
    public const string MarkerFileName = "bpf-handover";

    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(5);

    private readonly IProcessRunner _runner;
    private readonly string _markerPath;
    private readonly Action<string> _log;
    private readonly string _unit;

    public SystemdStopIntent(IProcessRunner runner, string markerPath, Action<string> log, string? unit = null)
    {
        _runner = runner ?? throw new ArgumentNullException(nameof(runner));
        ArgumentException.ThrowIfNullOrWhiteSpace(markerPath);
        _markerPath = markerPath;
        _log = log ?? throw new ArgumentNullException(nameof(log));
        _unit = unit ?? SystemdServiceInstaller.ServiceTarget;
    }

    /// <summary>Marker path under the daemon's runtime directory (<c>$RUNTIME_DIRECTORY</c>, else /run/axiom).</summary>
    public static string DefaultMarkerPath()
    {
        var runtime = Environment.GetEnvironmentVariable(LinuxServicePaths.SystemdRuntimeDirectoryVariable)?.Split(':')[0];
        return Path.Combine(string.IsNullOrWhiteSpace(runtime) ? LinuxServicePaths.DefaultRunDirectory : runtime, MarkerFileName);
    }

    /// <summary>True = hand the layer over (restart, upgrade, or unknown); false = detach (a real stop).</summary>
    public bool KeepEnforcementAcrossStop()
    {
        if (File.Exists(_markerPath))
        {
            try
            {
                File.Delete(_markerPath);
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                _log($"BPF layer: could not remove the hand-over marker {_markerPath}: {exception.Message}");
            }

            _log("BPF layer: the package installer asked for a hand-over (upgrade); keeping connect-time enforcement attached for the next daemon.");
            return true;
        }

        ProcessResult jobs;
        try
        {
            jobs = _runner.Run(SystemdServiceInstaller.Systemctl, ["list-jobs", "--no-legend", "--plain", "--full", _unit], Timeout);
        }
        catch (Exception exception) when (exception is System.ComponentModel.Win32Exception or IOException or InvalidOperationException or UnauthorizedAccessException)
        {
            jobs = new ProcessResult(127, string.Empty, exception.Message);
        }

        var restart = jobs.Succeeded ? Classify(jobs.StandardOutput, _unit) : null;
        if (restart is null)
        {
            _log(string.Create(CultureInfo.InvariantCulture, $"BPF layer: cannot tell a restart from a stop (systemctl list-jobs exited {jobs.ExitCode}: {(jobs.StandardError + jobs.StandardOutput).Trim()}); keeping connect-time enforcement attached (fail closed)."));
            return true;
        }

        if (restart.Value)
        {
            _log($"BPF layer: systemd is restarting {_unit}; keeping connect-time enforcement attached for the next daemon.");
        }

        return restart.Value;
    }

    /// <summary>
    /// Parses <c>systemctl list-jobs --no-legend --plain --full &lt;unit&gt;</c> (<c>JOB UNIT TYPE STATE</c>):
    /// true when the unit's job restarts or starts it again, false for a stop or when it has no job,
    /// null when its line cannot be read.
    /// </summary>
    public static bool? Classify(string listJobs, string unit)
    {
        ArgumentNullException.ThrowIfNull(listJobs);
        foreach (var line in listJobs.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var tokens = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (tokens.Length < 2 || !long.TryParse(tokens[0], NumberStyles.None, CultureInfo.InvariantCulture, out _) || !string.Equals(tokens[1], unit, StringComparison.Ordinal))
            {
                continue;
            }

            if (tokens.Length < 3)
            {
                return null;
            }

            return tokens[2] switch
            {
                "restart" or "try-restart" or "reload-or-restart" or "start" or "reload-or-start" => true,
                "stop" => false,
                _ => null,
            };
        }

        return false;
    }
}
