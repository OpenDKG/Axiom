// SPDX-License-Identifier: GPL-3.0-or-later
using System.Reflection;
using Axiom.Presentation;
using Xunit;

namespace Axiom.Presentation.Tests;

public sealed class OptionalModuleInstallerTests
{
    [Fact]
    public void Blackbox_script_checks_vcpp_runtime_before_choosing_oxigraph_backend()
    {
        var installer = new OptionalModuleInstaller();
        var build = typeof(OptionalModuleInstaller).GetMethod(
            "BuildBlackboxScript",
            BindingFlags.NonPublic | BindingFlags.Instance)!;
        var script = (string)build.Invoke(installer, null)!;

        Assert.Contains("vcruntime140.dll", script, StringComparison.Ordinal);
        Assert.Contains("msvcp140.dll", script, StringComparison.Ordinal);
        Assert.Contains("-StoreBackend $storeBackend", script, StringComparison.Ordinal);
        Assert.Contains("'auto'", script, StringComparison.Ordinal);
        Assert.DoesNotContain("oxigraph-worker", script, StringComparison.Ordinal);
    }

    [Fact]
    public void Store_backend_defaults_to_auto_when_vcpp_runtime_is_absent()
    {
        Assert.Equal("oxigraph", OptionalModuleInstaller.SelectBlackboxStoreBackend(hasVcRuntime: true));
        Assert.Equal("auto", OptionalModuleInstaller.SelectBlackboxStoreBackend(hasVcRuntime: false));
    }

    [Fact]
    public void Resolve_npm_executable_finds_path_or_standard_node_locations_and_null_when_missing()
    {
        Assert.Null(OptionalModuleInstaller.ResolveNpmExecutable(
            pathVariable: @"C:\Windows\System32",
            fileExists: _ => false,
            programFiles: @"C:\Program Files",
            programFilesX86: @"C:\Program Files (x86)",
            localAppData: @"C:\Users\test\AppData\Local"));

        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        const string standardNpm = @"C:\Program Files\nodejs\npm.cmd";
        Assert.Equal(
            standardNpm,
            OptionalModuleInstaller.ResolveNpmExecutable(
                pathVariable: @"C:\Windows\System32",
                fileExists: p => string.Equals(p, standardNpm, StringComparison.OrdinalIgnoreCase),
                programFiles: @"C:\Program Files",
                programFilesX86: @"C:\Program Files (x86)",
                localAppData: @"C:\Users\test\AppData\Local"));

        var preamble = OptionalModuleInstaller.BuildNodePathPreamble(
            pathVariable: @"C:\Windows\System32",
            fileExists: p => string.Equals(p, standardNpm, StringComparison.OrdinalIgnoreCase),
            programFiles: @"C:\Program Files",
            programFilesX86: @"C:\Program Files (x86)",
            localAppData: @"C:\Users\test\AppData\Local");
        Assert.Equal(@"$env:PATH = 'C:\Program Files\nodejs;' + $env:PATH", preamble);
    }

    [Fact]
    public void Dkg_script_checks_npm_prerequisite_before_invoking_npm_ci()
    {
        var installer = new OptionalModuleInstaller();
        var build = typeof(OptionalModuleInstaller).GetMethod(
            "BuildDkgScript",
            BindingFlags.NonPublic | BindingFlags.Instance)!;
        var script = (string)build.Invoke(installer, null)!;

        Assert.Contains("Get-Command npm", script, StringComparison.Ordinal);
        Assert.Contains("DKG prerequisite missing: npm", script, StringComparison.Ordinal);
    }

    [Fact]
    public void PowerShell_resolution_prefers_pwsh_7_over_windows_powershell()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        const string pwshInPath = @"C:\Tools\pwsh\pwsh.exe";
        Assert.Equal(
            pwshInPath,
            OptionalModuleInstaller.ResolvePowerShellExecutable(
                pathVariable: @"C:\Tools\pwsh;C:\Windows\System32\WindowsPowerShell\v1.0",
                fileExists: p => string.Equals(p, pwshInPath, StringComparison.OrdinalIgnoreCase),
                programFiles: @"C:\Program Files"));

        const string standardPwsh = @"C:\Program Files\PowerShell\7\pwsh.exe";
        Assert.Equal(
            standardPwsh,
            OptionalModuleInstaller.ResolvePowerShellExecutable(
                pathVariable: @"C:\Windows\System32",
                fileExists: p => string.Equals(p, standardPwsh, StringComparison.OrdinalIgnoreCase),
                programFiles: @"C:\Program Files"));

        Assert.Equal(
            "powershell.exe",
            OptionalModuleInstaller.ResolvePowerShellExecutable(
                pathVariable: @"C:\Windows\System32",
                fileExists: _ => false,
                programFiles: @"C:\Program Files"));
    }

    [Fact]
    public void Installer_scripts_guard_native_stderr_against_ps51_terminating_errors_and_crlf_drift()
    {
        var installer = new OptionalModuleInstaller();
        var buildDkg = typeof(OptionalModuleInstaller).GetMethod(
            "BuildDkgScript",
            BindingFlags.NonPublic | BindingFlags.Instance)!;
        var buildBlackbox = typeof(OptionalModuleInstaller).GetMethod(
            "BuildBlackboxScript",
            BindingFlags.NonPublic | BindingFlags.Instance)!;

        var dkgScript = (string)buildDkg.Invoke(installer, null)!;
        var blackboxScript = (string)buildBlackbox.Invoke(installer, null)!;

        Assert.Contains("$ErrorActionPreference = 'Continue'", dkgScript, StringComparison.Ordinal);
        Assert.DoesNotContain("*> $null", blackboxScript, StringComparison.Ordinal);
        Assert.Contains("-c core.autocrlf=false", blackboxScript, StringComparison.Ordinal);
        Assert.Contains("$ErrorActionPreference = 'Continue'", blackboxScript, StringComparison.Ordinal);
    }

    [Fact]
    public void Blackbox_script_switches_to_continue_before_vendor_installer_and_wraps_try()
    {
        var installer = new OptionalModuleInstaller();
        var buildBlackbox = typeof(OptionalModuleInstaller).GetMethod(
            "BuildBlackboxScript",
            BindingFlags.NonPublic | BindingFlags.Instance)!;

        var script = ((string)buildBlackbox.Invoke(installer, null)!)
            .Replace("\r\n", "\n", StringComparison.Ordinal);

        var continueIndex = script.IndexOf("$ErrorActionPreference = 'Continue'\n$vendorExit = 0", StringComparison.Ordinal);
        var installerIndex = script.IndexOf("& $installer -StoreBackend $storeBackend", StringComparison.Ordinal);
        Assert.True(continueIndex >= 0, "Expected $ErrorActionPreference = 'Continue' immediately before vendor installer try block.");
        Assert.True(installerIndex > continueIndex);
        Assert.Contains("try {\n  & $installer -StoreBackend $storeBackend", script, StringComparison.Ordinal);
    }

    [Fact]
    public void Blackbox_script_installs_python_packages_only_from_the_hash_lock()
    {
        var buildBlackbox = typeof(OptionalModuleInstaller).GetMethod(
            "BuildBlackboxScript",
            BindingFlags.NonPublic | BindingFlags.Instance)!;
        var script = (string)buildBlackbox.Invoke(new OptionalModuleInstaller(), null)!;

        var installs = script.Split('\n')
            .Where(line => line.Contains("-m pip install", StringComparison.Ordinal))
            .Select(line => line.Trim())
            .ToArray();

        Assert.Equal(
            ["& $venv -m pip install --disable-pip-version-check --require-hashes --no-deps -r $requirements"],
            installs);
        Assert.Contains("$requirements = Join-Path $dir 'axiom-requirements.lock.txt'", script, StringComparison.Ordinal);
    }

    [Fact]
    public void Blackbox_dependency_repair_arguments_name_no_packages()
    {
        var arguments = OptionalModuleInstaller.BuildBlackboxPipArguments(@"C:\Users\a b\lock.txt");

        Assert.Equal(
            "-m pip install --disable-pip-version-check --quiet --require-hashes --no-deps -r \"C:\\Users\\a b\\lock.txt\"",
            arguments);
    }

    [Fact]
    public void Blackbox_requirements_are_exact_versions_with_hashes()
    {
        using var stream = typeof(OptionalModuleInstaller).Assembly
            .GetManifestResourceStream(OptionalModuleInstaller.BlackboxRequirementsResource);
        Assert.NotNull(stream);
        using var reader = new StreamReader(stream);
        var text = reader.ReadToEnd().Replace("\r\n", "\n", StringComparison.Ordinal)
            .Replace("\\\n", " ", StringComparison.Ordinal); // join continued lines

        var requirements = text.Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Select(line => line.Trim())
            .Where(line => line.Length > 0 && !line.StartsWith('#'))
            .ToArray();

        Assert.All(requirements, line =>
        {
            Assert.Matches(@"^[a-z0-9-]+==[0-9][0-9a-z.]*( ;[^-]*)?\s+--hash=sha256:[0-9a-f]{64}", line);
        });
        var names = requirements.Select(line => line[..line.IndexOf("==", StringComparison.Ordinal)]).ToHashSet();
        foreach (var required in new[]
                 {
                     "cryptography", "cffi", "psutil", "fastapi", "uvicorn", "ruamel-yaml", "pyyaml",
                     "python-dotenv", "rich", "aiohttp", "pywin32",
                 })
        {
            Assert.Contains(required, names);
        }

        Assert.Single(requirements, line => line.StartsWith("pywin32==", StringComparison.Ordinal) &&
                                            line.Contains("sys_platform == 'win32'", StringComparison.Ordinal));
    }

    [Fact]
    public void Blackbox_dashboard_launcher_guards_null_stdio_for_pythonw()
    {
        Assert.Contains("if sys.stdout is None:", OptionalModuleInstaller.BlackboxDashboardLauncherCode, StringComparison.Ordinal);
        Assert.Contains("if sys.stderr is None:", OptionalModuleInstaller.BlackboxDashboardLauncherCode, StringComparison.Ordinal);
        Assert.Contains("os.devnull", OptionalModuleInstaller.BlackboxDashboardLauncherCode, StringComparison.Ordinal);
        Assert.Contains("CREATE_NO_WINDOW", OptionalModuleInstaller.BlackboxDashboardLauncherCode, StringComparison.Ordinal);
        Assert.Contains("STARTF_USESHOWWINDOW", OptionalModuleInstaller.BlackboxDashboardLauncherCode, StringComparison.Ordinal);
        Assert.Contains("subprocess.Popen.__init__", OptionalModuleInstaller.BlackboxDashboardLauncherCode, StringComparison.Ordinal);
        Assert.Contains("os.system", OptionalModuleInstaller.BlackboxDashboardLauncherCode, StringComparison.Ordinal);

        var installer = new OptionalModuleInstaller();
        var buildBlackbox = typeof(OptionalModuleInstaller).GetMethod(
            "BuildBlackboxScript",
            BindingFlags.NonPublic | BindingFlags.Instance)!;
        var script = (string)buildBlackbox.Invoke(installer, null)!;

        Assert.Contains("if sys.stdout is None:", script, StringComparison.Ordinal);
        Assert.Contains("if sys.stderr is None:", script, StringComparison.Ordinal);
        Assert.Contains("os.devnull", script, StringComparison.Ordinal);
        Assert.Contains("CREATE_NO_WINDOW", script, StringComparison.Ordinal);
        Assert.Contains("STARTF_USESHOWWINDOW", script, StringComparison.Ordinal);
    }

    [Fact]
    public void Should_upgrade_running_launcher_detects_outdated_script_and_matches_current()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "axiom-launcher-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        try
        {
            var launcher = Path.Combine(tempDir, "start-dashboard.py");
            Assert.False(OptionalModuleInstaller.ShouldUpgradeRunningLauncher(launcher));

            File.WriteAllText(launcher, "from plugins.blackbox.dashboard import cmd_dashboard\n");
            Assert.True(OptionalModuleInstaller.ShouldUpgradeRunningLauncher(launcher));

            File.WriteAllText(launcher, OptionalModuleInstaller.BlackboxDashboardLauncherCode.Replace("\n", "\r\n", StringComparison.Ordinal));
            Assert.False(OptionalModuleInstaller.ShouldUpgradeRunningLauncher(launcher));
        }
        finally
        {
            try
            {
                Directory.Delete(tempDir, recursive: true);
            }
            catch (IOException)
            {
            }
        }
    }
}
