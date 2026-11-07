// SPDX-License-Identifier: GPL-3.0-or-later
using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Text;
using Xunit;

namespace Axiom.Infrastructure.Linux.Tests;

/// <summary>
/// Runs the real loopback UI host on an ephemeral port against a fake <c>secret-tool</c> on PATH, so
/// the credential routes are exercised end to end without reading or writing the developer's keyring.
/// It covers the token gate on every credential route, key validation, non-disclosure of a stored
/// key, and the cache policy that keeps a stale app.js from surviving an update.
/// </summary>
public sealed class DesktopLinuxUiTests
{
    private const string StoredKey = "dummy-stored-vt-key";

    [Fact]
    public async Task Credential_routes_are_token_gated_validated_and_never_echo_a_key()
    {
        if (!OperatingSystem.IsLinux())
        {
            return;
        }

        var tools = CreateFakeSecretTool();
        try
        {
            await using var host = await UiHost.StartAsync(tools);
            using var http = new HttpClient { BaseAddress = host.BaseAddress };
            var token = host.Token;

            // Every credential route rejects a missing token.
            foreach (var (method, path, body) in new[]
            {
                (HttpMethod.Get, "/api/reputation", (string?)null),
                (HttpMethod.Post, "/api/reputation/key", "{\"key\":\"x\"}"),
                (HttpMethod.Delete, "/api/reputation/key", (string?)null),
            })
            {
                var response = await SendAsync(http, method, path, body, token: null);
                Assert.True(response.StatusCode == HttpStatusCode.Unauthorized, $"{method} {path} accepted a request without a token.");
            }

            // ... and a wrong token, so authentication is really compared and not just non-empty.
            foreach (var (method, path, body) in new[]
            {
                (HttpMethod.Get, "/api/reputation", (string?)null),
                (HttpMethod.Post, "/api/reputation/key", "{\"key\":\"x\"}"),
                (HttpMethod.Delete, "/api/reputation/key", (string?)null),
            })
            {
                var response = await SendAsync(http, method, path, body, new string('A', token.Length));
                Assert.True(response.StatusCode == HttpStatusCode.Unauthorized, $"{method} {path} accepted a wrong token.");
            }

            var statusResponse = await SendAsync(http, HttpMethod.Get, "/api/reputation", null, token);
            Assert.Equal(HttpStatusCode.OK, statusResponse.StatusCode);
            var statusBody = await statusResponse.Content.ReadAsStringAsync();
            Assert.Contains("\"hasKey\":true", statusBody, StringComparison.Ordinal);
            Assert.True(!statusBody.Contains(StoredKey, StringComparison.Ordinal), "The credential status leaked the stored key.");
            Assert.True(!statusBody.Contains(token, StringComparison.Ordinal), "The credential status leaked the session token.");

            // A key that passes validation is stored through the fake backend and never echoed back.
            const string newKey = "dummy-new-vt-key";
            var stored = await SendAsync(http, HttpMethod.Post, "/api/reputation/key", $"{{\"key\":\"{newKey}\"}}", token);
            Assert.Equal(HttpStatusCode.OK, stored.StatusCode);
            var storedBody = await stored.Content.ReadAsStringAsync();
            Assert.True(!storedBody.Contains(newKey, StringComparison.Ordinal), "Storing a key echoed it back.");
            var deleted = await SendAsync(http, HttpMethod.Delete, "/api/reputation/key", null, token);
            Assert.Equal(HttpStatusCode.OK, deleted.StatusCode);

            // An oversized key is refused before the backend is touched, and never echoed back.
            var oversizedKey = new string('k', 5000);
            var oversized = await SendAsync(http, HttpMethod.Post, "/api/reputation/key", $"{{\"key\":\"{oversizedKey}\"}}", token);
            Assert.Equal(HttpStatusCode.BadRequest, oversized.StatusCode);
            var oversizedBody = await oversized.Content.ReadAsStringAsync();
            Assert.True(!oversizedBody.Contains(oversizedKey, StringComparison.Ordinal), "A rejected key was echoed back.");

            var empty = await SendAsync(http, HttpMethod.Post, "/api/reputation/key", "{}", token);
            Assert.Equal(HttpStatusCode.BadRequest, empty.StatusCode);

            foreach (var path in new[] { "/api/reputation/key", "/api/ai/key", "/api/ai/settings", "/api/autostart", "/api/reputation" })
            {
                var malformed = await SendAsync(http, HttpMethod.Post, path, "{", token);
                Assert.Equal(HttpStatusCode.BadRequest, malformed.StatusCode);
                Assert.Contains("invalid-request", await malformed.Content.ReadAsStringAsync(), StringComparison.Ordinal);
            }

            // Static assets must revalidate so an updated app.js replaces the cached one; API data is never cached.
            foreach (var asset in new[] { "/", "/app.js", "/style.css" })
            {
                var response = await http.GetAsync(asset);
                Assert.Equal("no-cache", response.Headers.CacheControl?.ToString());
            }

            Assert.Equal("no-store", statusResponse.Headers.CacheControl?.ToString());
        }
        finally
        {
            Directory.Delete(tools, recursive: true);
        }
    }

    private static string CreateFakeSecretTool()
    {
        var directory = Directory.CreateTempSubdirectory("axiom-fake-secret-tool-");
        var path = Path.Combine(directory.FullName, "secret-tool");
        File.WriteAllText(
            path,
            "#!/bin/sh\n" +
            "case \"$1\" in\n" +
            $"  lookup) printf '%s' '{StoredKey}' ;;\n" +
            "  store) cat > /dev/null ;;\n" +
            "esac\n" +
            "exit 0\n");
        File.SetUnixFileMode(
            path,
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        return directory.FullName;
    }

    private static async Task<HttpResponseMessage> SendAsync(
        HttpClient http,
        HttpMethod method,
        string path,
        string? json,
        string? token)
    {
        using var request = new HttpRequestMessage(method, path);
        if (json is not null)
        {
            request.Content = new StringContent(json, Encoding.UTF8, "application/json");
        }

        if (token is not null)
        {
            request.Headers.Add("X-Axiom-Token", token);
        }

        return await http.SendAsync(request).ConfigureAwait(false);
    }

    private sealed class UiHost : IAsyncDisposable
    {
        private readonly Process _process;

        private UiHost(Process process, Uri baseAddress, string token)
        {
            _process = process;
            BaseAddress = baseAddress;
            Token = token;
        }

        public Uri BaseAddress { get; }

        public string Token { get; }

        public static async Task<UiHost> StartAsync(string fakeCredentialToolDirectory)
        {
            var executable = LocateExecutable();
            var startInfo = new ProcessStartInfo(executable)
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
            };
            startInfo.ArgumentList.Add("--no-browser");
            startInfo.ArgumentList.Add("--port");
            startInfo.ArgumentList.Add("0");
            startInfo.ArgumentList.Add("--socket");
            startInfo.ArgumentList.Add(Path.Combine(Path.GetTempPath(), "axiom-absent-" + Guid.NewGuid().ToString("N") + ".sock"));

            // Isolate the credential backend: our fake tool first on PATH, and a bus address that is
            // only used to pass the store's availability check. The real keyring is never contacted.
            startInfo.Environment["PATH"] = fakeCredentialToolDirectory + ":" +
                (Environment.GetEnvironmentVariable("PATH") ?? "/usr/bin:/bin");
            startInfo.Environment["DBUS_SESSION_BUS_ADDRESS"] = "unix:path=/tmp/axiom-test-no-bus";

            var process = Process.Start(startInfo)
                ?? throw new InvalidOperationException("The UI host did not start.");

            try
            {
                using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
                while (true)
                {
                    var line = await process.StandardOutput.ReadLineAsync(timeout.Token).ConfigureAwait(false)
                        ?? throw new InvalidOperationException("The UI host exited before printing its URL.");
                    var marker = line.IndexOf("Axiom UI: ", StringComparison.Ordinal);
                    if (marker < 0)
                    {
                        continue;
                    }

                    var url = new Uri(line[(marker + "Axiom UI: ".Length)..].Trim());
                    var token = url.Fragment.StartsWith("#t=", StringComparison.Ordinal)
                        ? url.Fragment[3..]
                        : throw new InvalidOperationException("The UI URL did not carry a token fragment.");
                    return new UiHost(process, new Uri(url.GetLeftPart(UriPartial.Authority)), token);
                }
            }
            catch
            {
                process.Kill(entireProcessTree: true);
                process.Dispose();
                throw;
            }
        }

        public ValueTask DisposeAsync()
        {
            try
            {
                if (!_process.HasExited)
                {
                    _process.Kill(entireProcessTree: true);
                    _process.WaitForExit(5000);
                }
            }
            catch (InvalidOperationException)
            {
            }

            _process.Dispose();
            return ValueTask.CompletedTask;
        }

        private static string LocateExecutable()
        {
            // .../tests/Axiom.Infrastructure.Linux.Tests/bin/<Configuration>/net10.0
            var configuration = new DirectoryInfo(AppContext.BaseDirectory).Parent?.Name
                ?? throw new InvalidOperationException("Cannot determine the build configuration.");
            var root = new DirectoryInfo(AppContext.BaseDirectory);
            while (root is not null && !File.Exists(Path.Combine(root.FullName, "Axiom.Linux.slnf")))
            {
                root = root.Parent;
            }

            if (root is null)
            {
                throw new InvalidOperationException("Cannot locate the repository root from the test output.");
            }

            var candidate = Path.Combine(
                root.FullName, "src", "Axiom.Desktop.Linux", "bin", configuration, "net10.0",
                OperatingSystem.IsWindows() ? "Axiom.Desktop.Linux.exe" : "Axiom.Desktop.Linux");
            return File.Exists(candidate)
                ? candidate
                : throw new FileNotFoundException(
                    "Build src/Axiom.Desktop.Linux before running this test; the UI host is missing.", candidate);
        }
    }
}
