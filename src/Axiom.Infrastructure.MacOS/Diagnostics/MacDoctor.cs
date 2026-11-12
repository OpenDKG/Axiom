// SPDX-License-Identifier: GPL-3.0-or-later
using System.Text.Json;
using System.Text.Json.Serialization;
using Axiom.Core.Protection;
using Axiom.Infrastructure.MacOS.Dns;
using Axiom.Infrastructure.MacOS.Interop;
using Axiom.Infrastructure.MacOS.Launchd;

namespace Axiom.Infrastructure.MacOS.Diagnostics;

/// <summary>Everything the doctor needs to look at (production paths by default; tests use a temp root).</summary>
public sealed record DoctorTargets(
    string PlistPath,
    string HelperDirectory,
    string MachineDataDirectory,
    string IpcSocketPath,
    string FilterSocketPath,
    string DnsBackupPath,
    string ProtectionSettingsPath,
    string PrivacyShieldSettingsPath)
{
    public static DoctorTargets Default { get; } = new(
        MacServicePaths.LaunchDaemonPlistPath,
        PrivilegedHelperLayout.HelperDirectory,
        MacServicePaths.Default.MachineDataDirectory,
        MacServicePaths.Default.IpcSocketPath,
        MacServicePaths.Default.FilterSocketPath,
        MacServicePaths.Default.DnsBackupFile,
        ProtectionSettingsStore.DefaultPath,
        Path.Combine(MacServicePaths.Default.MachineDataDirectory, "privacy-shield.json"));
}

/// <summary>
/// <c>axiomd --doctor [--json]</c>: launchd job state, plist target, helper directory ownership,
/// socket and data-directory modes, DNS per network service and backup, Privacy Shield state and
/// the filter extension status. Exit code 0 when nothing is WARN/FAIL. Root-only checks are
/// reported as SKIP for a normal user. Pure inspection: nothing is changed.
/// </summary>
public sealed class MacDoctor
{
    private const string Launchctl = "/bin/launchctl";

    private const string SystemExtensionsCtl = "/usr/bin/systemextensionsctl";

    private static readonly TimeSpan ToolTimeout = TimeSpan.FromSeconds(30);

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    private readonly IProcessRunner _runner;

    private readonly DoctorTargets _targets;

    private readonly bool _isRoot;

    public MacDoctor(IProcessRunner runner, DoctorTargets targets, bool isRoot)
    {
        _runner = runner ?? throw new ArgumentNullException(nameof(runner));
        _targets = targets ?? throw new ArgumentNullException(nameof(targets));
        _isRoot = isRoot;
    }

    public static int Run(string[] args, TextWriter output)
    {
        ArgumentNullException.ThrowIfNull(args);
        var json = args.Any(argument => string.Equals(argument, "--json", StringComparison.OrdinalIgnoreCase));
        var doctor = new MacDoctor(ProcessRunner.Instance, DoctorTargets.Default, Environment.IsPrivilegedProcess);
        var checks = doctor.Collect();
        doctor.Write(checks, json, output);
        return checks.Any(check => check.IsProblem) ? 1 : 0;
    }

    public void Write(IReadOnlyList<DoctorCheck> checks, bool json, TextWriter output)
    {
        ArgumentNullException.ThrowIfNull(checks);
        ArgumentNullException.ThrowIfNull(output);

        var problems = checks.Count(check => check.IsProblem);
        if (json)
        {
            output.WriteLine(JsonSerializer.Serialize(
                new
                {
                    root = _isRoot,
                    ok = problems == 0,
                    problems,
                    skipped = checks.Count(check => check.Status == DoctorCheck.Skip),
                    checks,
                },
                JsonOptions));
            return;
        }

        output.WriteLine($"axiomd doctor ({(_isRoot ? "root" : "unprivileged; root-only checks skipped")})");
        foreach (var check in checks)
        {
            output.WriteLine(check.ToString());
        }

        output.WriteLine(problems == 0 ? "Result: all checks passed." : $"Result: {problems} problem(s).");
    }

    public IReadOnlyList<DoctorCheck> Collect()
    {
        var checks = new List<DoctorCheck>();
        CheckLaunchd(checks);
        CheckPlist(checks);
        CheckHelper(checks);
        CheckSocket(checks, "axiom.sock", _targets.IpcSocketPath, 0x1B6, root: true);
        CheckSocket(checks, "filter.sock", _targets.FilterSocketPath, 0x180, root: true);
        CheckDataDirectory(checks);
        CheckDns(checks);
        CheckPrivacyShield(checks);
        CheckFilterExtension(checks);
        return checks;
    }

    private void CheckLaunchd(List<DoctorCheck> checks)
    {
        var result = _runner.Run(Launchctl, ["print", LaunchdServiceInstaller.ServiceTarget], ToolTimeout);
        if (!result.Succeeded)
        {
            var detail = (result.StandardError + result.StandardOutput).Trim();
            checks.Add(!_isRoot && detail.Contains("not permitted", StringComparison.OrdinalIgnoreCase)
                ? new DoctorCheck(DoctorCheck.Skip, "launchd job", "launchctl print needs root")
                : new DoctorCheck(DoctorCheck.Fail, "launchd job", $"{LaunchdServiceInstaller.ServiceTarget} not loaded ({Shorten(detail)})"));
            return;
        }

        var state = ReadField(result.StandardOutput, "state");
        var program = ReadField(result.StandardOutput, "program");
        var running = string.Equals(state, "running", StringComparison.Ordinal);
        var fromHelper = program is not null &&
                         program.StartsWith(_targets.HelperDirectory + "/", StringComparison.Ordinal);
        checks.Add(new DoctorCheck(
            running ? DoctorCheck.Pass : DoctorCheck.Fail,
            "launchd job",
            $"{LaunchdServiceInstaller.ServiceTarget} state={state ?? "?"}"));
        checks.Add(new DoctorCheck(
            program is null ? DoctorCheck.Warn : fromHelper ? DoctorCheck.Pass : DoctorCheck.Fail,
            "launchd program",
            program is null
                ? "launchctl did not report the program path"
                : fromHelper ? program : $"{program} (expected under {_targets.HelperDirectory})"));
    }

    private void CheckPlist(List<DoctorCheck> checks)
    {
        if (!File.Exists(_targets.PlistPath))
        {
            checks.Add(new DoctorCheck(DoctorCheck.Fail, "plist", $"{_targets.PlistPath} is missing"));
            return;
        }

        string text;
        try
        {
            text = File.ReadAllText(_targets.PlistPath);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            checks.Add(new DoctorCheck(DoctorCheck.Fail, "plist", $"{_targets.PlistPath}: {exception.Message}"));
            return;
        }

        var program = ReadProgramArgument(text);
        var expected = Path.Combine(_targets.HelperDirectory, PrivilegedHelperLayout.DaemonFileName);
        checks.Add(new DoctorCheck(
            program == expected ? DoctorCheck.Pass : DoctorCheck.Fail,
            "plist",
            $"{_targets.PlistPath} -> {program ?? "(no ProgramArguments)"}" +
            (program == expected ? string.Empty : $" (expected {expected})")));

        var entry = UnixFileStat.Stat(_runner, _targets.PlistPath);
        if (entry is not null)
        {
            var ok = entry.IsRootOwned && !entry.IsGroupOrWorldWritable;
            checks.Add(new DoctorCheck(ok ? DoctorCheck.Pass : DoctorCheck.Fail, "plist owner", entry.Describe()));
        }
    }

    private void CheckHelper(List<DoctorCheck> checks)
    {
        if (!Directory.Exists(_targets.HelperDirectory))
        {
            checks.Add(new DoctorCheck(DoctorCheck.Fail, "helper dir", $"{_targets.HelperDirectory} is missing (run axiomd --install-service)"));
            return;
        }

        IReadOnlyList<string> paths;
        try
        {
            paths = PrivilegedHelperLayout.EnumerateTree(_targets.HelperDirectory);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            checks.Add(new DoctorCheck(DoctorCheck.Fail, "helper dir", $"{_targets.HelperDirectory}: {exception.Message}"));
            return;
        }

        var entries = UnixFileStat.List(_runner, paths);
        var problems = PrivilegedHelperLayout.Audit(_targets.HelperDirectory, entries).ToList();
        if (entries.Count != paths.Count)
        {
            problems.Add($"stat listed {entries.Count} of {paths.Count} entries");
        }

        var directory = entries.FirstOrDefault(entry => entry.Path == _targets.HelperDirectory);
        checks.Add(new DoctorCheck(
            problems.Count == 0 ? DoctorCheck.Pass : DoctorCheck.Fail,
            "helper dir",
            $"{_targets.HelperDirectory} {directory?.Describe() ?? "(not listed)"}, {entries.Count} entries" +
            (problems.Count == 0 ? ", all root-owned and not group/world-writable" : "; " + string.Join("; ", problems.Take(5)))));
    }

    private void CheckSocket(List<DoctorCheck> checks, string name, string path, int expectedMode, bool root)
    {
        var entry = UnixFileStat.Stat(_runner, path);
        if (entry is null)
        {
            checks.Add(new DoctorCheck(DoctorCheck.Fail, name, $"{path} is missing"));
            return;
        }

        var ok = entry.IsSocket && entry.Permissions == expectedMode && (!root || entry.IsRootOwned);
        checks.Add(new DoctorCheck(
            ok ? DoctorCheck.Pass : DoctorCheck.Fail,
            name,
            $"{path} {entry.Describe()}" + (ok ? string.Empty : $" (expected socket mode {Convert.ToString(expectedMode, 8)}, uid 0)")));
    }

    private void CheckDataDirectory(List<DoctorCheck> checks)
    {
        var root = _targets.MachineDataDirectory;
        var rootEntry = UnixFileStat.Stat(_runner, root);
        if (rootEntry is null)
        {
            checks.Add(new DoctorCheck(DoctorCheck.Fail, "data root", $"{root} is missing"));
            return;
        }

        var expectedRoot = (int)UnixDataDirectoryPermissions.PrivateDirectoryMode;
        var rootOk = rootEntry.IsDirectory && rootEntry.IsRootOwned && rootEntry.Permissions == expectedRoot;
        checks.Add(new DoctorCheck(rootOk ? DoctorCheck.Pass : DoctorCheck.Fail, "data root", $"{root} {rootEntry.Describe()}" + (rootOk ? string.Empty : " (expected uid 0 mode 700)")));

        if (!_isRoot)
        {
            checks.Add(new DoctorCheck(DoctorCheck.Skip, "data files", "listing the data directory needs root"));
            return;
        }

        IReadOnlyList<string> paths;
        try
        {
            paths = Directory.EnumerateFileSystemEntries(root, "*", SearchOption.AllDirectories)
                .Order(StringComparer.Ordinal)
                .ToList();
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            checks.Add(new DoctorCheck(DoctorCheck.Fail, "data files", exception.Message));
            return;
        }

        foreach (var entry in UnixFileStat.List(_runner, paths))
        {
            if (entry.IsSocket)
            {
                continue;
            }

            var expected = (int)UnixDataDirectoryPermissions.ExpectedMode(root, entry.Path, entry.IsDirectory);
            var ok = entry.IsRootOwned && entry.Permissions == expected;
            checks.Add(new DoctorCheck(
                ok ? DoctorCheck.Pass : DoctorCheck.Warn,
                "data file",
                $"{entry.Path} {entry.Describe()}" + (ok ? string.Empty : $" (expected uid 0 mode {Convert.ToString(expected, 8)})")));
        }
    }

    private void CheckDns(List<DoctorCheck> checks)
    {
        var configurator = new MacDnsConfigurator(_runner, _targets.DnsBackupPath);
        var backupExists = _isRoot ? File.Exists(_targets.DnsBackupPath) : (bool?)null;
        var backup = backupExists == true ? configurator.ReadBackup() : null;
        foreach (var service in configurator.ListServices().Where(service => service.Enabled))
        {
            var servers = configurator.GetDnsServers(service.Name);
            var text = servers is null ? "unreadable" : servers.Count == 0 ? "automatic" : string.Join(' ', servers);
            var redirected = servers is not null && MacDnsConfigurator.IsLoopbackOnly(servers);
            var status = servers is null ? DoctorCheck.Warn
                : redirected && backupExists == false ? DoctorCheck.Warn
                : DoctorCheck.Pass;
            checks.Add(new DoctorCheck(
                status,
                "dns",
                $"'{service.Name}' = {text}" +
                (redirected ? backupExists == false ? " (loopback without a backup file)" : " (Privacy Shield)" : string.Empty)));
        }

        checks.Add(backupExists is null
            ? new DoctorCheck(DoctorCheck.Skip, "dns backup", "reading the backup needs root")
            : new DoctorCheck(
                DoctorCheck.Pass,
                "dns backup",
                backupExists == true
                    ? $"{_targets.DnsBackupPath} present" + (backup is null ? " (unreadable)" : $" ({backup.Services.Count} service(s), saved {backup.SavedUtc:u})")
                    : "none (system DNS not redirected by Axiom)"));
    }

    private void CheckPrivacyShield(List<DoctorCheck> checks)
    {
        if (!_isRoot)
        {
            checks.Add(new DoctorCheck(DoctorCheck.Skip, "privacy shield", "reading the settings needs root"));
            return;
        }

        try
        {
            if (!File.Exists(_targets.PrivacyShieldSettingsPath))
            {
                checks.Add(new DoctorCheck(DoctorCheck.Pass, "privacy shield", "not configured (defaults)"));
                return;
            }

            using var document = JsonDocument.Parse(File.ReadAllText(_targets.PrivacyShieldSettingsPath));
            var enabled = document.RootElement.TryGetProperty("enabled", out var value) && value.ValueKind == JsonValueKind.True;
            checks.Add(new DoctorCheck(DoctorCheck.Pass, "privacy shield", enabled ? "enabled" : "disabled"));
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or JsonException)
        {
            checks.Add(new DoctorCheck(DoctorCheck.Warn, "privacy shield", $"{_targets.PrivacyShieldSettingsPath}: {exception.Message}"));
        }
    }

    private void CheckFilterExtension(List<DoctorCheck> checks)
    {
        var result = _runner.Run(SystemExtensionsCtl, ["list"], ToolTimeout);
        var line = result.StandardOutput
            .Split('\n')
            .FirstOrDefault(candidate => candidate.Contains("com.axiom.firewall.filter", StringComparison.Ordinal));
        if (line is null)
        {
            checks.Add(new DoctorCheck(DoctorCheck.Warn, "filter extension", "com.axiom.firewall.filter is not listed by systemextensionsctl"));
            return;
        }

        var state = line[(line.LastIndexOf('[') is var start && start >= 0 ? start : 0)..].Trim();
        var active = state.Contains("activated enabled", StringComparison.Ordinal);
        checks.Add(new DoctorCheck(active ? DoctorCheck.Pass : DoctorCheck.Warn, "filter extension", $"com.axiom.firewall.filter {state}"));
    }

    /// <summary>First string of <c>ProgramArguments</c> in a launchd plist (null when absent).</summary>
    public static string? ReadProgramArgument(string plistText)
    {
        ArgumentNullException.ThrowIfNull(plistText);
        var key = plistText.IndexOf("<key>ProgramArguments</key>", StringComparison.Ordinal);
        if (key < 0)
        {
            return null;
        }

        var start = plistText.IndexOf("<string>", key, StringComparison.Ordinal);
        var end = start < 0 ? -1 : plistText.IndexOf("</string>", start, StringComparison.Ordinal);
        return start < 0 || end < 0
            ? null
            : System.Net.WebUtility.HtmlDecode(plistText[(start + "<string>".Length)..end]).Trim();
    }

    /// <summary>Value of a <c>name = value</c> line in <c>launchctl print</c> output.</summary>
    public static string? ReadField(string output, string name)
    {
        ArgumentNullException.ThrowIfNull(output);
        foreach (var raw in output.Split('\n'))
        {
            var line = raw.Trim();
            if (line.StartsWith(name + " = ", StringComparison.Ordinal))
            {
                return line[(name.Length + 3)..].Trim();
            }
        }

        return null;
    }

    private static string Shorten(string text) =>
        text.Length <= 120 ? text : text[..120] + "…";
}
