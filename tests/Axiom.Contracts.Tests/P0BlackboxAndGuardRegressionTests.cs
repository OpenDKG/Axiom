// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Text;
using Axiom.Contracts.Blackbox;
using Xunit;

namespace Axiom.Contracts.Tests;

public sealed class P0BlackboxAndGuardRegressionTests : IDisposable
{
    private readonly string _tempDir;

    public P0BlackboxAndGuardRegressionTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "axiom-p0-contracts-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(_tempDir, recursive: true);
        }
        catch
        {
            // Best effort cleanup
        }
    }

    [Fact]
    public async Task BlackboxDashboardClient_accepts_already_used_injected_HttpClient()
    {
        using var handler = new StubHandler(req =>
        {
            if (req.RequestUri!.AbsolutePath == "/api/session")
            {
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent("""{"token":"tok"}""", Encoding.UTF8, "application/json"),
                };
            }

            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("""{"mode":"block"}""", Encoding.UTF8, "application/json"),
            };
        });

        using var http = new HttpClient(handler);
        // Simulate an already-started HttpClient whose Timeout/BaseAddress can no longer be mutated
        using var warmResp = await http.GetAsync(new Uri("http://127.0.0.1:9700/api/session"));
        Assert.Equal(HttpStatusCode.OK, warmResp.StatusCode);

        using var client = new BlackboxDashboardClient(http, new Uri("http://127.0.0.1:9700/"));
        var settings = await client.GetSettingsAsync(CancellationToken.None);
        Assert.Equal("block", settings["mode"]?.GetValue<string>());
    }

    [Fact]
    public async Task Python_guard_helpers_limit_recursion_and_honor_xdg_local_share_fail_closed()
    {
        var pythonExe = FindPython();
        if (pythonExe is null)
        {
            return;
        }

        // The helper reads %LOCALAPPDATA%\Axiom on Windows and the XDG ~/.local/share/Axiom elsewhere,
        // so the persisted policy is written where the current platform looks for it.
        var fakeHome = Path.Combine(_tempDir, "home");
        var localAppData = Path.Combine(fakeHome, "AppData", "Local");
        var policyDir = OperatingSystem.IsWindows()
            ? Path.Combine(localAppData, "Axiom")
            : Path.Combine(fakeHome, ".local", "share", "Axiom");
        Directory.CreateDirectory(policyDir);
        await File.WriteAllTextAsync(Path.Combine(policyDir, "guard-failure-policy.txt"), "fail-closed\n");

        var scriptPath = Path.Combine(_tempDir, "test_guard.py");
        var script = "import os\nfrom pathlib import Path\n\n"
            + AgentCommandGuard.PythonHelpers.Replace("\r\n", "\n", StringComparison.Ordinal)
            + """

import os
from pathlib import Path

cmd = "echo ok"
for _ in range(30):
    cmd = f'sh -c "{cmd}"'
segs = _split_shell_segments(cmd)
assert isinstance(segs, list) and len(segs) <= _MAX_SHELL_UNWRAP_DEPTH + 1, f"unexpected segments: {len(segs)}"

assert _is_fail_closed() is True, "expected fail-closed from the persisted guard-failure-policy.txt"
os.environ["AXIOM_GUARD_FAIL_CLOSED"] = "0"
assert _is_fail_closed() is True, "env downgrade must not override persisted fail-closed policy"
print("PY_GUARD_OK")
""";
        await File.WriteAllTextAsync(scriptPath, script, Encoding.UTF8);

        var psi = new ProcessStartInfo
        {
            FileName = pythonExe,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        psi.ArgumentList.Add(scriptPath);
        psi.Environment["HOME"] = fakeHome;
        psi.Environment["USERPROFILE"] = fakeHome;
        if (OperatingSystem.IsWindows())
        {
            psi.Environment["LOCALAPPDATA"] = localAppData;
        }
        else
        {
            psi.Environment.Remove("LOCALAPPDATA");
        }

        psi.Environment.Remove("XDG_DATA_HOME");
        psi.Environment.Remove("AXIOM_GUARD_FAIL_CLOSED");

        using var proc = Process.Start(psi)!;
        var stdout = await proc.StandardOutput.ReadToEndAsync();
        var stderr = await proc.StandardError.ReadToEndAsync();
        await proc.WaitForExitAsync();

        Assert.True(proc.ExitCode == 0, $"python failed ({proc.ExitCode}): {stderr}\n{stdout}");
        Assert.Contains("PY_GUARD_OK", stdout, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Python_guard_blocks_shell_nesting_it_cannot_inspect()
    {
        var pythonExe = FindPython();
        if (pythonExe is null)
        {
            return;
        }

        var scriptPath = Path.Combine(_tempDir, "test_nesting.py");
        var script = "import os\nfrom pathlib import Path\n\n"
            + AgentCommandGuard.PythonHelpers.Replace("\r\n", "\n", StringComparison.Ordinal)
            + """

protected = ["/home/x/protected"]

def escaped(command, levels, wrapper):
    for _ in range(levels):
        command = wrapper + ' "' + command.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return command

def unescaped(command, levels, wrapper):
    for _ in range(levels):
        command = f'{wrapper} "{command}"'
    return command

def verdict(command):
    result = _check_command_safety({"command": command}, protected)
    return result[0] if result else "allowed"

failures = []
for leaf, wrapper in (("rm -rf /home/x/protected", "sh -c"), ("del /f /q /home/x/protected", "cmd /c")):
    for nest, levels, expected in ((escaped, 9, "nesting"), (unescaped, 3, "nesting"), (unescaped, 9, "nesting"),
                                   (escaped, 3, "delete")):  # escaped quoting can be followed to the command
        got = verdict(nest(leaf, levels, wrapper))
        if got != expected:
            failures.append(f"{nest.__name__} {wrapper} x{levels}: {got}")
    for nest in (escaped, unescaped):
        for levels in (1, 2):
            got = verdict(nest(leaf, levels, wrapper))
            if got != "delete":
                failures.append(f"{nest.__name__} {wrapper} x{levels}: {got}")

for command in ('bash -c "echo hi"', 'grep -r "bash -c" .', 'echo "sh -c sh -c"',
                "sh -c 'sh -c \"echo ok\"'", 'bash -c bash', 'sh -c a && sh -c b && sh -c c'):
    if verdict(command) != "allowed":
        failures.append(f"false positive: {command}: {verdict(command)}")

# Two wrappers with escaped quotes around a command, in every combination.
wrappers = ("sh -c", "bash -c", "cmd /c", "powershell -Command", "pwsh -c", "zsh -c", "python -c")
for leaf in ("rm -rf /home/x/protected", "cat /home/x/protected/id", "sc stop axiom.service",
             "net stop axiom.service", "taskkill /f /im axiom.service", "systemctl stop axiomd",
             "systemctl disable axiomd"):
    if verdict(leaf) == "allowed":
        failures.append(f"direct form not blocked: {leaf}")
    for outer in wrappers:
        for inner in wrappers:
            if verdict(escaped(escaped(leaf, 1, inner), 1, outer)) == "allowed":
                failures.append(f"{outer} > {inner}: {leaf} allowed")

# The recursion limit itself fails closed.
if _UNINSPECTABLE_SEGMENT not in _split_shell_segments('sh -c "echo ok"', _MAX_SHELL_UNWRAP_DEPTH):
    failures.append("no block marker at the depth limit")

assert not failures, "\n".join(failures)
print("PY_NESTING_OK")
""";
        await File.WriteAllTextAsync(scriptPath, script, Encoding.UTF8);

        var psi = new ProcessStartInfo
        {
            FileName = pythonExe,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        psi.ArgumentList.Add(scriptPath);
        using var proc = Process.Start(psi)!;
        var stdout = await proc.StandardOutput.ReadToEndAsync();
        var stderr = await proc.StandardError.ReadToEndAsync();
        await proc.WaitForExitAsync();

        Assert.True(proc.ExitCode == 0, $"python failed ({proc.ExitCode}): {stderr}\n{stdout}");
        Assert.Contains("PY_NESTING_OK", stdout, StringComparison.Ordinal);
    }

    /// <summary>Commands judged against the protected path ~/.ssh/*: true must be blocked.</summary>
    public static TheoryData<string, bool> WrappedShellForms => new()
    {
        { @"bash -lc ""rm -rf ~/.ssh""", true },
        { @"bash -ic ""rm -rf ~/.ssh""", true },
        { @"sh -ec ""rm -rf ~/.ssh""", true },
        { @"dash -c ""rm -rf ~/.ssh""", true },
        { @"/bin/bash -lc ""rm -rf ~/.ssh""", true },
        { @"zsh -c ""rm -rf ~/.ssh""", true },
        { @"ksh -c ""rm -rf ~/.ssh""", true },
        { @"mksh -c ""rm -rf ~/.ssh""", true },
        { @"fish -c ""rm -rf ~/.ssh""", true },
        { @"busybox sh -c ""rm -rf ~/.ssh""", true },
        { @"bash -o pipefail -c ""rm -rf ~/.ssh""", true },
        { @"sudo sh -c ""rm -rf ~/.ssh""", true },
        { @"sudo -u root bash -c ""rm -rf ~/.ssh""", true },
        { @"sudo sh -c sh -c ""rm -rf ~/.ssh""", true },
        { @"sudo -E -u root -- bash -lc ""rm -rf ~/.ssh""", true },
        { @"eval ""rm -rf ~/.ssh""", true },
        { @"eval 'rm -rf ~/.ssh'", true },
        { @"echo `rm -rf ~/.ssh`", true },
        { @"echo ""$(rm -rf ~/.ssh)""", true },
        { @"r\m -rf ~/.ssh", true },
        { @"find ~/.ssh -delete", true },
        { @"find ~/.ssh -type f -exec rm {} +", true },
        { @"shred -u ~/.ssh/id_rsa", true },
        { @"truncate -s 0 ~/.ssh/id_rsa", true },
        { @"rsync -a --delete /tmp/empty/ ~/.ssh/", true },
        { @"python3 -c ""import shutil; shutil.rmtree('/home/u/.ssh')""", true },
        { @"python3 -c ""import os; os.remove('/home/u/.ssh/id_rsa')""", true },
        { @"node -e ""require('fs').rmSync('/home/u/.ssh', {recursive: true})""", true },
        { @"ruby -e ""require 'fileutils'; FileUtils.rm_rf('/home/u/.ssh')""", true },
        { @"perl -e ""unlink('/home/u/.ssh/id_rsa')""", true },
        { @"bash -lc ""cat ~/.ssh/id_rsa""", true },
        { @"bash -lc ""systemctl stop axiomd""", true },
        { @"eval ""systemctl stop axiomd""", true },
        { @"doas sh -c 'rm -rf ~/.ssh'", true },
        { @"nice -n 5 bash -lc 'rm -rf ~/.ssh'", true },
        { @"env FOO=1 bash -c 'rm -rf ~/.ssh'", true },
        { @"timeout -s KILL 5 sh -c 'rm -rf ~/.ssh'", true },
        { @"nohup stdbuf -oL ionice -c 3 chrt -i 0 taskset -c 0 time exec rm -rf ~/.ssh", true },
        { @"command builtin rm -rf ~/.ssh", true },
        { @"ls | xargs -I {} -P 4 sh -c 'rm -rf ~/.ssh'", true },
        { @"env -S 'rm -rf ~/.ssh'", true },
        { @"sudo --unknown-option sh -c ""echo hi""", true },
        { @"pwsh -Command:""Remove-Item ~/.ssh -Recurse""", true },
        { @"powershell -NoProfile -ExecutionPolicy Bypass -Com ""Remove-Item ~/.ssh -Recurse""", true },
        { @"powershell -enc UgBlAG0AbwB2AGUALQBJAHQAZQBtACAAfgAvAC4AcwBzAGgAIAAtAFIAZQBjAHUAcgBzAGUA", true },
        { @"pwsh -e UgBlAG0AbwB2AGUALQBJAHQAZQBtACAAfgAvAC4AcwBzAGgAIAAtAFIAZQBjAHUAcgBzAGUA", true },
        { @"powershell -EncodedCommand UgBlAG0AbwB2AGUALQBJAHQAZQBtACAAfgAvAC4AcwBzAGgAIAAtAFIAZQBjAHUAcgBzAGUA", true },
        { @"powershell -enc not*base64", true },
        { @"cmd /k ""del /f /q C:\Users\u\.ssh""", true },
        { @"cmd /d /r del C:\Users\u\.ssh", true },
        { @"bash -lc ""$(printf 'rm -rf x')""", true },
        { @"bash -c ""$CMD""", true },
        { @"bash -c", true },
        { @"echo $(rm -rf ~/.ssh", true },
        { @"echo `date", true },
        { @"bash -lc ""npm test""", false },
        { @"sudo apt-get update", false },
        { @"eval ""$(ssh-agent -s)""", false },
        { @"find . -name '*.log' -delete", false },
        { @"echo `date`", false },
        { @"bash -c ""echo \""hello world\""""", false },
        { @"sh -c ""sh -c \""echo ok\""""", false },
        { @"cmd /c ""dir \Users"" /b", false },
        { @"grep -r ""bash -c"" .", false },
        { @"echo ""sh -c sh -c""", false },
        { @"bash -c bash", false },
        { @"sh -c a && sh -c b && sh -c c", false },
        { @"sudo -n -E env PATH=/usr/bin make build", false },
        { @"timeout 30 npm run build", false },
        { @"nice -n 10 make -j4", false },
        { @"xargs -0 -n 1 echo", false },
        { @"command -v git", false },
        { @"time -p cargo test", false },
        { @"env", false },
        { @"sudo -v", false },
        { @"bash script.sh --clean", false },
        { @"bash -o pipefail -c ""npm test | tee log""", false },
        { @"python3 -c ""print(1)""", false },
        { @"python3 -m pytest -q", false },
        { @"node -e ""console.log(1)""", false },
        { @"pwsh -NoProfile -File build.ps1", false },
        { @"powershell -Command ""Get-ChildItem C:\Temp""", false },
        { @"powershell -Command ""Write-Host 'a`tb'""", false },
        { @"echo ""$(date) $(whoami)""", false },
        { @"echo '$(not run'", false },
        { @"rsync -a src/ dst/", false },
        { @"find . -name ""*.tmp"" -exec rm {} \;", false },
        { @"cat README.md", false },
        { @"type C:\Temp\notes.txt", false },
        { @"git commit -m ""describe the sh -c handling""", false },
        { @"sh -c ""sh -c \""rm -rf ~/.ssh\""""", true }, // three levels, escaped quotes
        { "Write-Output \"a`tb\"", false },
        { "Get-ChildItem C:\\src `\n  -Recurse", false },
        { "cat > notes.md <<'EOF'\nit's one ` backtick and $( open\nEOF", false },
    };

    [Theory]
    [MemberData(nameof(WrappedShellForms))]
    public async Task Guard_inspects_wrapped_shell_forms(string command, bool blocked)
    {
        var pythonExe = FindPython();
        if (pythonExe is null)
        {
            return;
        }

        var scriptPath = Path.Combine(_tempDir, "test_wrapped.py");
        var script = "import os\nimport sys\nfrom pathlib import Path\n\n"
            + AgentCommandGuard.PythonHelpers.Replace("\r\n", "\n", StringComparison.Ordinal)
            + """

result = _check_command_safety({"command": sys.argv[1]}, ["~/.ssh/*"])
print("BLOCKED " + result[0] if result else "ALLOWED")
""";
        await File.WriteAllTextAsync(scriptPath, script, Encoding.UTF8);

        var psi = new ProcessStartInfo
        {
            FileName = pythonExe,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        psi.ArgumentList.Add(scriptPath);
        psi.ArgumentList.Add(command);
        using var proc = Process.Start(psi)!;
        var stdout = await proc.StandardOutput.ReadToEndAsync();
        var stderr = await proc.StandardError.ReadToEndAsync();
        await proc.WaitForExitAsync();

        Assert.True(proc.ExitCode == 0, $"python failed ({proc.ExitCode}): {stderr}");
        Assert.Empty(stderr.Trim()); // hooks must stay quiet
        Assert.StartsWith(blocked ? "BLOCKED" : "ALLOWED", stdout, StringComparison.Ordinal);
    }

    private static string? FindPython()
    {
        foreach (var candidate in new[] { "python3", "python" })
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = candidate,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                };
                psi.ArgumentList.Add("--version");
                using var p = Process.Start(psi);
                p?.WaitForExit(2000);
                if (p?.ExitCode == 0)
                {
                    return candidate;
                }
            }
            catch
            {
                // Try next candidate
            }
        }
        return null;
    }

    private sealed class StubHandler(Func<HttpRequestMessage, HttpResponseMessage> responder) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(responder(request));
    }
}
