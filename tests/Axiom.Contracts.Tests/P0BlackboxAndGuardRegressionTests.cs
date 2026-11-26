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
