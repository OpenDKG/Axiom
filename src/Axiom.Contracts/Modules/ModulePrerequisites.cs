// SPDX-License-Identifier: GPL-3.0-or-later
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
public sealed record ModuleToolStatus(ModuleTool Tool, string DisplayName, string? Directory, string? Executable)
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
    public ModulePrerequisiteReport(IReadOnlyList<ModuleToolStatus> tools)
    {
        Tools = tools;
    }

    public IReadOnlyList<ModuleToolStatus> Tools { get; }

    public IReadOnlyList<ModuleToolStatus> Missing =>
        Tools.Where(tool => !tool.IsAvailable).ToArray();

    public bool IsSatisfied => Missing.Count == 0;

    /// <summary>The found tool folders, ready to be prepended to PATH for a child script.</summary>
    public IReadOnlyList<string> SearchDirectories =>
        Tools
            .Where(tool => tool.Directory is not null)
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

    private static string Escape(string value) => value.Replace("'", "''", StringComparison.Ordinal);
}

/// <summary>
/// Finds the tools the optional Blackbox and DKG installers need, and builds the bootstrap scripts
/// that install missing prerequisites through winget.
/// </summary>
public static class ModulePrerequisites
{
    private const string VcRedistPackageId = "Microsoft.VCRedist.2015+.x64";

    private static readonly (ModuleTool Tool, string DisplayName, string[] FileNames)[] Definitions =
    [
        (ModuleTool.Node, "Node.js", ["node.exe"]),
        (ModuleTool.Npm, "npm", ["npm.cmd"]),
        (ModuleTool.Python, "Python 3", ["python.exe"]),
        (ModuleTool.Git, "Git", ["git.exe"]),
    ];

    /// <summary>Winget package ids used by the bootstrap, in installation order.</summary>
    internal static readonly (ModuleTool Tool, string PackageId, string[] ExtraArguments)[] Bootstrap =
    [
        (ModuleTool.Node, "OpenJS.NodeJS.LTS", []),
        (ModuleTool.Python, "Python.Python.3.12", ["--scope", "user"]),
        (ModuleTool.Git, "Git.Git", []),
    ];

    /// <summary>Probes the current process environment.</summary>
    public static ModulePrerequisiteReport Probe() =>
        Probe(Environment.GetEnvironmentVariable("PATH"), File.Exists);

    /// <summary>
    /// Probes the given PATH plus the well-known per-user and per-machine install folders.
    /// <paramref name="fileExists"/> is injectable so the discovery rules stay unit-testable.
    /// </summary>
    public static ModulePrerequisiteReport Probe(string? pathValue, Func<string, bool> fileExists)
    {
        ArgumentNullException.ThrowIfNull(fileExists);
        var searchDirectories = BuildSearchDirectories(pathValue);

        var statuses = Definitions.Select(definition =>
        {
            foreach (var directory in searchDirectories)
            {
                foreach (var fileName in definition.FileNames)
                {
                    var candidate = Path.Combine(directory, fileName);
                    if (fileExists(candidate))
                    {
                        return new ModuleToolStatus(definition.Tool, definition.DisplayName, directory, candidate);
                    }
                }
            }

            return new ModuleToolStatus(definition.Tool, definition.DisplayName, null, null);
        }).ToArray();

        return new ModulePrerequisiteReport(statuses);
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
                  Write-Host 'winget is not available. Install Node.js, Python 3 and Git manually, then click Check again.' -ForegroundColor Red
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
}
