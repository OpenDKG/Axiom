// SPDX-License-Identifier: GPL-3.0-or-later
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json.Nodes;
using Netpetra.Contracts.Blackbox;
using Xunit;

namespace Netpetra.Contracts.Tests;

public sealed class BlackboxDashboardClientTests
{
    [Fact]
    public async Task Save_sends_session_token_and_only_the_requested_patch()
    {
        string? tokenHeader = null;
        string? body = null;

        var handler = new StubHandler(request =>
        {
            if (request.RequestUri!.AbsolutePath == "/api/session")
            {
                return Json(HttpStatusCode.OK, """{"token":"session-token"}""");
            }

            if (request.Method == HttpMethod.Post && request.RequestUri.AbsolutePath == "/api/settings")
            {
                tokenHeader = request.Headers.TryGetValues("X-Blackbox-Token", out var values)
                    ? values.Single()
                    : null;
                body = request.Content!.ReadAsStringAsync().GetAwaiter().GetResult();
                return Json(HttpStatusCode.OK, """{"ok":true}""");
            }

            return Json(HttpStatusCode.OK, """{"mode":"block"}""");
        });

        using var http = new HttpClient(handler);
        using var client = new BlackboxDashboardClient(http);
        var result = await client.SaveSettingsAsync(
            new JsonObject { ["mode"] = "block" },
            CancellationToken.None);

        Assert.True(result.Ok);
        Assert.Equal("session-token", tokenHeader);
        Assert.NotNull(body);
        var patch = JsonNode.Parse(body!)!.AsObject();
        Assert.Equal("block", patch["mode"]!.GetValue<string>());
        Assert.False(patch.ContainsKey("protected_paths"));
        Assert.Equal("block", result.Settings!["mode"]!.GetValue<string>());
    }

    [Fact]
    public async Task Save_returns_server_errors_without_claiming_success()
    {
        var handler = new StubHandler(request =>
            request.RequestUri!.AbsolutePath == "/api/session"
                ? Json(HttpStatusCode.OK, """{"token":"session-token"}""")
                : Json(HttpStatusCode.BadRequest, """{"ok":false,"errors":["invalid mode: nope"]}"""));

        using var http = new HttpClient(handler);
        using var client = new BlackboxDashboardClient(http);
        var result = await client.SaveSettingsAsync(
            new JsonObject { ["mode"] = "nope" },
            CancellationToken.None);

        Assert.False(result.Ok);
        Assert.Contains("invalid mode", result.Errors[0], StringComparison.Ordinal);
        Assert.Null(result.Settings);
    }

    [Fact]
    public async Task Audit_parser_distinguishes_blocked_and_flagged()
    {
        var handler = new StubHandler(_ => Json(HttpStatusCode.OK, """
            {
              "total": 2,
              "entries": [
                {
                  "iso": "2026-11-04T08:23:31Z",
                  "event": "pre_tool_call",
                  "framework": "codex",
                  "severity": "high",
                  "detail": {
                    "tool_name": "shell",
                    "session_id": "ses_123456789",
                    "decision": "block",
                    "identifier": "dep:npm:evil@1.0.0",
                    "args": { "command": "do-not-display-this" }
                  }
                },
                {
                  "iso": "2026-11-04T08:23:30Z",
                  "event": "pre_tool_call",
                  "framework": "hermes",
                  "severity": "medium",
                  "detail": {
                    "tool_name": "read",
                    "session_id": "ses_987654321",
                    "decision": "flag",
                    "args": { "path": "C:\\secret\\.env" }
                  }
                }
              ]
            }
            """));

        using var http = new HttpClient(handler);
        using var client = new BlackboxDashboardClient(http);
        var page = await client.GetAuditAsync(100, 0, CancellationToken.None);

        Assert.Equal(2, page.Total);
        Assert.True(page.Entries[0].IsBlocked);
        Assert.Equal("codex", page.Entries[0].Agent);
        Assert.Equal("Shell command (redacted)", page.Entries[0].Action);
        Assert.DoesNotContain("do-not-display-this", page.Entries[0].Action);
        Assert.True(page.Entries[1].IsFlagged);
        Assert.Contains(".env", page.Entries[1].Action, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Malformed_settings_json_throws_invalid_data()
    {
        var handler = new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("{not-json", Encoding.UTF8, "application/json"),
        });

        using var http = new HttpClient(handler);
        using var client = new BlackboxDashboardClient(http);

        await Assert.ThrowsAsync<InvalidDataException>(() =>
            client.GetSettingsAsync(CancellationToken.None));
    }

    [Fact]
    public void Non_loopback_base_address_is_rejected()
    {
        using var http = new HttpClient(new StubHandler(_ => Json(HttpStatusCode.OK, "{}")));
        Assert.Throws<ArgumentException>(() =>
            new BlackboxDashboardClient(http, new Uri("http://example.com/")));
    }

    private static HttpResponseMessage Json(HttpStatusCode status, string json) => new(status)
    {
        Content = new StringContent(json, Encoding.UTF8, "application/json"),
    };

    private sealed class StubHandler(Func<HttpRequestMessage, HttpResponseMessage> respond) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken) =>
            Task.FromResult(respond(request));
    }
}
