// SPDX-License-Identifier: GPL-3.0-or-later
using System.ComponentModel;
using System.Diagnostics;

namespace Axiom.Contracts.Modules;

/// <summary>
/// External tools the optional modules need before their installers can run. The installers are
/// third-party scripts: DKG is installed with npm, and Blackbox clones its repository with git and
/// builds a Python virtual environment.
/// </summary>
public enum ModuleTool
{
    Node,
    Npm,
    Python,
    Git,
}

/// <summary>One tool and where it was found, if anywhere.</summary>
public sealed record ModuleToolStatus(
    ModuleTool Tool,
    string DisplayName,
    string? Directory,
    string? Executable,
    string? Version = null)
{
    public bool IsAvailable => Directory is not null;
}

/// <summary>
/// Result of looking for the optional-module prerequisites.
/// </summary>
/// <remarks>
/// Discovery deliberately searches the well-known install folders in addition to PATH. The running
/// desktop process keeps the PATH it started with, so a tool the user installed after Axiom started
/// would otherwise stay invisible until the next launch.
/// </remarks>
public sealed class ModulePrerequisiteReport
{
    public ModulePrerequisiteReport(
        IReadOnlyList<ModuleToolStatus> tools,
        IReadOnlyList<string>? rejectedPythonVersions = null)
    {
        Tools = tools;
        RejectedPythonVersions = rejectedPythonVersions ?? [];
    }

    public IReadOnlyList<ModuleToolStatus> Tools { get; }

    /// <summary>Python versions that were found but are outside Blackbox's 3.11-3.13 window.</summary>
    public IReadOnlyList<string> RejectedPythonVersions { get; }

    public IReadOnlyList<ModuleToolStatus> Missing =>
        Tools.Where(tool => !tool.IsAvailable).ToArray();

    public bool IsSatisfied => Missing.Count == 0;

    /// <summary>The found tool folders, ready to be prepended to PATH for a child script.</summary>
    public IReadOnlyList<string> SearchDirectories =>
        Tools
            .Where(tool => tool.Directory is not null)
            // Python first: the vendor installer resolves `python` from PATH and must see the
            // compatible interpreter even when an incompatible one comes earlier in the user PATH.
            .OrderBy(tool => tool.Tool == ModuleTool.Python ? 0 : 1)
            .Select(tool => tool.Directory!)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

    public string MissingSummary =>
        string.Join(", ", Missing.Select(tool => tool.DisplayName));

    /// <summary>
    /// A PowerShell snippet that makes the found tools visible to the installer script.
    /// </summary>
    public string BuildPathPreamble()
    {
        var directories = SearchDirectories;
        if (directories.Count == 0)
        {
            return string.Empty;
        }

        var joined = string.Join(";", directories.Select(Escape));
        return $"$env:PATH = '{joined};' + $env:PATH";
    }

    /// <summary>
    /// A POSIX shell snippet that makes the found tools visible to the installer script.
    /// </summary>
    public string BuildUnixPathPreamble()
    {
        var directories = SearchDirectories;
        if (directories.Count == 0)
        {
            return string.Empty;
        }

        var joined = string.Join(":", directories.Select(static value => value.Replace("\"", "\\\"", StringComparison.Ordinal)));
        return $"export PATH=\"{joined}:$PATH\"";
    }

    private static string Escape(string value) => value.Replace("'", "''", StringComparison.Ordinal);
}

/// <summary>
/// Finds the tools the optional Blackbox and DKG installers need, and builds the bootstrap scripts
/// that install missing prerequisites on Windows (winget), Linux (apt), and macOS (Homebrew).
/// </summary>
public static class ModulePrerequisites
{
    private const string VcRedistPackageId = "Microsoft.VCRedist.2015+.x64";

    /// <summary>Blackbox supports Python 3.11 to 3.13; 3.12 is the version Axiom installs.</summary>
    public const int MinPythonMinor = 11;

    public const int MaxPythonMinor = 13;

    public const int PreferredPythonMinor = 12;

    public const string PythonDisplayName = "Python 3.11-3.13";

    private static readonly (ModuleTool Tool, string DisplayName, string[] FileNames)[] WindowsDefinitions =
    [
        (ModuleTool.Node, "Node.js", ["node.exe"]),
        (ModuleTool.Npm, "npm", ["npm.cmd"]),
        (ModuleTool.Python, PythonDisplayName, ["python.exe"]),
        (ModuleTool.Git, "Git", ["git.exe"]),
    ];

    private static readonly (ModuleTool Tool, string DisplayName, string[] FileNames)[] UnixDefinitions =
    [
        (ModuleTool.Node, "Node.js", ["node", "node.exe"]),
        (ModuleTool.Npm, "npm", ["npm", "npm.cmd"]),
        (ModuleTool.Python, PythonDisplayName, ["python3.12", "python3.13", "python3.11", "python3", "python", "python.exe"]),
        (ModuleTool.Git, "Git", ["git", "git.exe"]),
    ];

    private static (ModuleTool Tool, string DisplayName, string[] FileNames)[] Definitions =>
        OperatingSystem.IsWindows() ? WindowsDefinitions : UnixDefinitions;

    /// <summary>Winget package ids used by the bootstrap, in installation order.</summary>
    internal static readonly (ModuleTool Tool, string PackageId, string[] ExtraArguments)[] Bootstrap =
    [
        (ModuleTool.Node, "OpenJS.NodeJS.LTS", []),
        (ModuleTool.Python, "Python.Python.3.12", ["--scope", "user"]),
        (ModuleTool.Git, "Git.Git", []),
    ];

    /// <summary>Probes the current process environment.</summary>
    public static ModulePrerequisiteReport Probe() =>
        Probe(Environment.GetEnvironmentVariable("PATH"), File.Exists, ReadPythonVersion);

    /// <summary>
    /// Probes the given PATH plus the well-known per-user and per-machine install folders.
    /// <paramref name="fileExists"/> is injectable so the discovery rules stay unit-testable.
    /// <paramref name="readPythonVersion"/> returns "3.12" for a candidate interpreter, or null when
    /// it cannot be run. Python outside 3.11-3.13 is reported as missing so Setup installs 3.12.
    /// </summary>
    public static ModulePrerequisiteReport Probe(
        string? pathValue,
        Func<string, bool> fileExists,
        Func<string, string?>? readPythonVersion = null)
    {
        ArgumentNullException.ThrowIfNull(fileExists);
        var searchDirectories = BuildSearchDirectories(pathValue);
        var readVersion = readPythonVersion ?? (_ => null);
        var rejected = new List<string>();

        var statuses = Definitions.Select(definition =>
        {
            foreach (var directory in searchDirectories)
            {
                foreach (var fileName in definition.FileNames)
                {
                    var candidate = Path.Combine(directory, fileName);
                    if (!fileExists(candidate))
                    {
                        continue;
                    }

                    if (definition.Tool != ModuleTool.Python)
                    {
                        return new ModuleToolStatus(definition.Tool, definition.DisplayName, directory, candidate);
                    }

                    var version = readVersion(candidate);
                    if (IsSupportedPython(version))
                    {
                        return new ModuleToolStatus(
                            definition.Tool,
                            definition.DisplayName,
                            directory,
                            candidate,
                            version);
                    }

                    // A 3.10 or 3.15 interpreter is not a usable prerequisite: Blackbox's own
                    // installer refuses it, so keep searching for a compatible one.
                    rejected.Add(version ?? candidate);
                }
            }

            return new ModuleToolStatus(definition.Tool, definition.DisplayName, null, null);
        }).ToArray();

        return new ModulePrerequisiteReport(statuses, rejected);
    }

    public static bool IsSupportedPython(string? version)
    {
        if (string.IsNullOrWhiteSpace(version))
        {
            return false;
        }

        var parts = version.Split('.');
        return parts.Length >= 2 &&
               int.TryParse(parts[0], out var major) &&
               int.TryParse(parts[1], out var minor) &&
               major == 3 &&
               minor is >= MinPythonMinor and <= MaxPythonMinor;
    }

    /// <summary>Runs one candidate interpreter and returns "3.12" (or null when it does not run).</summary>
    public static string? ReadPythonVersion(string executable)
    {
        try
        {
            var startInfo = new ProcessStartInfo(executable, "-c \"import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')\"")
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                WindowStyle = ProcessWindowStyle.Hidden,
            };
            using var process = Process.Start(startInfo);
            if (process is null)
            {
                return null;
            }

            var stdoutTask = process.StandardOutput.ReadToEndAsync();
            var stderrTask = process.StandardError.ReadToEndAsync();
            if (!process.WaitForExit(4000))
            {
                try
                {
                    process.Kill(entireProcessTree: true);
                }
                catch (Exception exception) when (exception is InvalidOperationException or Win32Exception)
                {
                }

                return null;
            }

            Task.WaitAll([stdoutTask, stderrTask], 500);
            var output = stdoutTask.IsCompletedSuccessfully ? stdoutTask.Result.Trim() : string.Empty;
            return process.ExitCode == 0 && output.Length > 0 ? output : null;
        }
        catch (Exception exception) when (exception is
                     Win32Exception or InvalidOperationException or IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    /// <summary>
    /// PATH entries followed by the default install folders, skipping the Microsoft Store
    /// application-execution aliases: <c>python.exe</c> there only opens the Store page.
    /// </summary>
    internal static IReadOnlyList<string> BuildSearchDirectories(string? pathValue)
    {
        var directories = new List<string>();

        if (!string.IsNullOrWhiteSpace(pathValue))
        {
            directories.AddRange(pathValue
                .Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries)
                .Select(entry => entry.Trim().Trim('"'))
                .Where(entry => entry.Length > 0));
        }

        if (OperatingSystem.IsWindows())
        {
            var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            var programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);

            foreach (var candidate in new[]
                     {
                         Path.Combine(programFiles, "nodejs"),
                         Path.Combine(programFilesX86, "nodejs"),
                         Path.Combine(localAppData, "Programs", "nodejs"),
                         Path.Combine(programFiles, "Git", "cmd"),
                         Path.Combine(localAppData, "Programs", "Git", "cmd"),
                         Path.Combine(localAppData, "Programs", "Python", "Python313"),
                         Path.Combine(localAppData, "Programs", "Python", "Python312"),
                         Path.Combine(localAppData, "Programs", "Python", "Python311"),
                         Path.Combine(localAppData, "Programs", "Python", "Python310"),
                         Path.Combine(programFiles, "Python313"),
                         Path.Combine(programFiles, "Python312"),
                         Path.Combine(programFiles, "Python311"),
                     })
            {
                directories.Add(candidate);
            }

            return directories
                .Where(directory => !IsStoreAliasDirectory(directory))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();
        }

        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        foreach (var candidate in new[]
                 {
                     "/opt/homebrew/bin",
                     "/usr/local/bin",
                     "/usr/bin",
                     "/bin",
                     Path.Combine(home, ".local", "bin"),
                     Path.Combine(home, ".npm-global", "bin"),
                     Path.Combine(home, ".bun", "bin"),
                     Path.Combine(home, "bin"),
                 })
        {
            if (!string.IsNullOrWhiteSpace(candidate))
            {
                directories.Add(candidate);
            }
        }

        return directories
            .Distinct(StringComparer.Ordinal)
            .ToArray();
    }

    private static bool IsStoreAliasDirectory(string directory) =>
        directory.Contains(@"\WindowsApps", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Builds the visible PowerShell script that installs the missing tools through winget.
    /// </summary>
    public static string BuildBootstrapScript(
        ModulePrerequisiteReport report,
        bool includeVcRedist = false,
        bool interactive = true)
    {
        ArgumentNullException.ThrowIfNull(report);

        var missing = report.Missing.Select(tool => tool.Tool).ToHashSet();
        var steps = new List<string>();

        if (includeVcRedist)
        {
            steps.Add(BuildWingetStep("Visual C++ 2015-2022 Redistributable", VcRedistPackageId, []));
        }

        foreach (var step in Bootstrap)
        {
            var needed = missing.Contains(step.Tool) ||
                         (step.Tool == ModuleTool.Node && missing.Contains(ModuleTool.Npm));
            if (needed)
            {
                steps.Add(BuildWingetStep(PackageLabel(step.Tool), step.PackageId, step.ExtraArguments));
            }
        }

        if (interactive)
        {
            return $$"""
                $ErrorActionPreference = 'Stop'
                $winget = Get-Command winget -ErrorAction SilentlyContinue
                if (-not $winget) {
                  Write-Host 'winget is not available. Install Node.js, Python 3.11-3.13 and Git manually, then click Check again.' -ForegroundColor Red
                  Write-Host 'https://nodejs.org/en/download  https://www.python.org/downloads/windows/  https://git-scm.com/download/win'
                  Read-Host 'Press Enter to close'
                  exit 2
                }

                {{string.Join("\n\n", steps)}}

                Write-Host 'All prerequisites are installed. Return to Axiom and click Check again.' -ForegroundColor Green
                Read-Host 'Press Enter to close'
                """;
        }

        return $$"""
            $ErrorActionPreference = 'Stop'
            $winget = Get-Command winget -ErrorAction SilentlyContinue
            if (-not $winget) {
              Write-Warning 'winget is not available; skipping automatic prerequisite installation.'
              exit 2
            }

            {{string.Join("\n\n", steps)}}

            Write-Host 'Prerequisite installation finished.' -ForegroundColor Green
            exit 0
            """;
    }

    private static string BuildWingetStep(string label, string packageId, string[] extraArguments)
    {
        var arguments = string.Join(" ", new[]
        {
            "install",
            "--id", packageId,
            "--silent",
            "--accept-package-agreements",
            "--accept-source-agreements",
            "--disable-interactivity",
        }.Concat(extraArguments));

        return "Write-Host 'Installing " + label + "...' -ForegroundColor Cyan\n" +
               "winget " + arguments + "\n" +
               "if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne -1978335189) { throw \"winget failed for " + packageId + " with exit code $LASTEXITCODE\" }";
    }

    private static string PackageLabel(ModuleTool tool) => tool switch
    {
        ModuleTool.Node => "Node.js LTS",
        ModuleTool.Npm => "npm",
        ModuleTool.Python => "Python 3.12",
        ModuleTool.Git => "Git",
        _ => tool.ToString(),
    };

    /// <summary>
    /// Builds a shell script that installs missing prerequisites on Linux (apt) or macOS (Homebrew).
    /// </summary>
    public static string BuildUnixBootstrapScript(ModulePrerequisiteReport report)
    {
        ArgumentNullException.ThrowIfNull(report);
        var missing = report.Missing.Select(tool => tool.Tool).ToHashSet();
        var aptPackages = new List<string>();
        var brewPackages = new List<string>();

        if (missing.Contains(ModuleTool.Git))
        {
            aptPackages.Add("git");
            brewPackages.Add("git");
        }

        if (missing.Contains(ModuleTool.Node) || missing.Contains(ModuleTool.Npm))
        {
            aptPackages.Add("nodejs");
            aptPackages.Add("npm");
            brewPackages.Add("node");
        }

        if (missing.Contains(ModuleTool.Python))
        {
            aptPackages.Add("python3");
            aptPackages.Add("python3-venv");
            aptPackages.Add("python3-pip");
            brewPackages.Add("python@3.12");
        }

        var aptLine = aptPackages.Count == 0 ? "true" : $"sudo apt-get update && sudo apt-get install -y {string.Join(' ', aptPackages)}";
        var brewLine = brewPackages.Count == 0 ? "true" : $"brew install {string.Join(' ', brewPackages)}";
        return $$"""
            #!/usr/bin/env bash
            set -euo pipefail
            if [ "$(uname -s)" = "Darwin" ]; then
              if ! command -v brew >/dev/null 2>&1; then
                echo "Homebrew is required to auto-install prerequisites on macOS: https://brew.sh"
                exit 2
              fi
              {{brewLine}}
            else
              if ! command -v apt-get >/dev/null 2>&1; then
                echo "apt-get not found; install Git, Node.js/npm and Python 3.11-3.13 manually."
                exit 2
              fi
              {{aptLine}}
            fi
            echo "Prerequisite installation finished. Return to Axiom and click Check again."
            """;
    }
}
