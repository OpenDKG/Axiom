// SPDX-License-Identifier: GPL-3.0-or-later
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json.Nodes;
using Axiom.Contracts.Blackbox;
using Xunit;

namespace Axiom.Contracts.Tests;

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
        Assert.Equal("do-not-display-this", page.Entries[0].Action);
        Assert.Equal("do-not-display-this", page.Entries[0].Detail!.Command);
        Assert.Equal("Tool call", page.Entries[0].EventLabel);
        Assert.Equal("tools", page.Entries[0].Category);
        Assert.Equal("ses_123456789", page.Entries[0].SessionFull);
        Assert.Equal("BLOCKED", page.Entries[0].SecurityOutcome);
        Assert.True(page.Entries[0].IsSecurityThreat);
        Assert.True(page.Entries[1].IsFlagged);
        Assert.Equal("FLAGGED", page.Entries[1].SecurityOutcome);
        Assert.Contains(".env", page.Entries[1].Action, StringComparison.Ordinal);
        Assert.Equal("C:\\secret\\.env", page.Entries[1].Detail!.Path);
    }

    [Fact]
    public async Task Audit_parser_keeps_session_api_and_install_details()
    {
        var handler = new StubHandler(_ => Json(HttpStatusCode.OK, """
            {
              "total": 4,
              "entries": [
                {
                  "iso": "2026-11-04T08:23:31Z",
                  "event": "session_start",
                  "framework": "opencode",
                  "detail": { "session_id": "ses_session_1" }
                },
                {
                  "iso": "2026-11-04T08:23:30Z",
                  "event": "pre_api_request",
                  "framework": "codex",
                  "detail": {
                    "session_id": "ses_session_2",
                    "provider": "openai",
                    "model": "gpt-5"
                  }
                },
                {
                  "iso": "2026-11-04T08:23:29Z",
                  "event": "dependency_install",
                  "framework": "hermes",
                  "ecosystem": "npm",
                  "name": "left-pad",
                  "version": "1.3.0",
                  "tool": "shell"
                },
                {
                  "iso": "2026-11-04T08:23:28Z",
                  "event": "post_tool_call",
                  "framework": "hermes",
                  "detail": {
                    "tool_name": "shell",
                    "session_id": "ses_session_3",
                    "tool_call_id": "call_1",
                    "result": { "exit_code": 0 },
                    "duration_ms": 1250
                  }
                }
              ]
            }
            """));

        using var http = new HttpClient(handler);
        using var client = new BlackboxDashboardClient(http);
        var page = await client.GetAuditAsync(100, 0, CancellationToken.None);

        Assert.Equal("sessions", page.Entries[0].Category);
        Assert.Equal("Session started", page.Entries[0].EventLabel);
        Assert.Equal("ses_session_1", page.Entries[0].Detail!.SessionId);
        Assert.Equal("PASSED", page.Entries[0].SecurityOutcome);
        Assert.False(page.Entries[0].IsSecurityThreat);

        Assert.Equal("api", page.Entries[1].Category);
        Assert.Equal("API request", page.Entries[1].EventLabel);
        Assert.Equal("openai gpt-5", page.Entries[1].Action);
        Assert.Equal("openai", page.Entries[1].Detail!.Provider);
        Assert.Equal("gpt-5", page.Entries[1].Detail!.Model);

        Assert.Equal("installs", page.Entries[2].Category);
        Assert.Equal("Package install", page.Entries[2].EventLabel);
        Assert.Equal("npm:left-pad@1.3.0", page.Entries[2].Action);
        Assert.Equal("npm", page.Entries[2].Detail!.Ecosystem);

        Assert.Equal("tools", page.Entries[3].Category);
        Assert.Equal("exit 0", page.Entries[3].Detail!.ResultStatus);
        Assert.Equal(1250L, page.Entries[3].Detail!.DurationMs!.Value);
    }

    [Fact]
    public async Task Audit_action_summary_masks_secret_values()
    {
        var handler = new StubHandler(_ => Json(HttpStatusCode.OK, """
            {
              "total": 1,
              "entries": [
                {
                  "iso": "2026-11-04T08:23:31Z",
                  "event": "pre_tool_call",
                  "framework": "hermes",
                  "detail": {
                    "tool_name": "shell",
                    "args": { "command": "tool --api_key=supersecretvalue" }
                  }
                }
              ]
            }
            """));

        using var http = new HttpClient(handler);
        using var client = new BlackboxDashboardClient(http);
        var page = await client.GetAuditAsync(100, 0, CancellationToken.None);

        Assert.DoesNotContain("supersecretvalue", page.Entries[0].ActionSummary, StringComparison.Ordinal);
        Assert.Contains("[redacted]", page.Entries[0].ActionSummary, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Verified_sync_parser_preserves_unknown_values()
    {
        var handler = new StubHandler(_ => Json(HttpStatusCode.OK, """
            {
              "state": "unavailable",
              "graph_assets": null,
              "downloaded_assets": null,
              "downloaded_triples": null,
              "compiled_assets": null,
              "verified_rules": 0,
              "percent_downloaded": null,
              "percent_compiled": null,
              "checked_at": "",
              "lookups": {
                "state": "unknown",
                "label": "Node not answering",
                "text": "The local DKG node is not answering."
              },
              "phase": "",
              "phase_text": "",
              "running_since": null,
              "last_progress": null
            }
            """));

        using var http = new HttpClient(handler);
        using var client = new BlackboxDashboardClient(http);
        var sync = await client.GetVerifiedSyncAsync(CancellationToken.None);

        Assert.Equal("unavailable", sync.State);
        Assert.True(sync.IsOffline);
        Assert.Null(sync.GraphAssets);
        Assert.Null(sync.DownloadedAssets);
        Assert.Null(sync.PercentCompiled);
        Assert.Equal(0, sync.VerifiedRules);
        Assert.Equal(0, sync.DisplayPercent);
        Assert.Equal("Node not answering", sync.Lookups.Label);
    }

    [Fact]
    public async Task Verified_sync_parser_reads_compiled_progress()
    {
        var handler = new StubHandler(_ => Json(HttpStatusCode.OK, """
            {
              "state": "synced",
              "graph_assets": 120,
              "downloaded_assets": 120,
              "downloaded_triples": 3456,
              "compiled_assets": 110,
              "verified_rules": 42,
              "percent_downloaded": 100,
              "percent_compiled": 91.7,
              "checked_at": "2026-11-07T10:00:00Z",
              "lookups": {
                "state": "live",
                "label": "live",
                "text": "Verified answers are served from the graph store."
              },
              "phase": "compile",
              "phase_text": "Compiling verified rules",
              "running_since": "2026-11-07T09:59:00Z",
              "last_progress": "110/120"
            }
            """));

        using var http = new HttpClient(handler);
        using var client = new BlackboxDashboardClient(http);
        var sync = await client.GetVerifiedSyncAsync(CancellationToken.None);

        Assert.Equal("synced", sync.State);
        Assert.False(sync.IsOffline);
        Assert.Equal(120, sync.GraphAssets);
        Assert.Equal(3456L, sync.DownloadedTriples);
        Assert.Equal(42, sync.VerifiedRules);
        Assert.Equal(91.7, sync.DisplayPercent);
        Assert.Equal("Compiling verified rules", sync.PhaseText);
        Assert.NotNull(sync.RunningSince);
    }

    [Fact]
    public async Task Verified_graph_parser_reads_public_threat_page()
    {
        string? path = null;
        var handler = new StubHandler(request =>
        {
            path = request.RequestUri!.PathAndQuery;
            return Json(HttpStatusCode.OK, """
                {
                  "tier": "public",
                  "threats": [
                    {
                      "identifier": "dep:npm:evil@1.0.0",
                      "name": "evil-package",
                      "category": "dependency",
                      "severity": "critical",
                      "ecosystems": ["npm"],
                      "source": "verified"
                    },
                    {
                      "identifier": "ioc:example",
                      "category": "ioc",
                      "severity": "high"
                    }
                  ],
                  "total": 2,
                  "partial": false
                }
                """);
        });

        using var http = new HttpClient(handler);
        using var client = new BlackboxDashboardClient(http);
        var page = await client.GetVerifiedGraphAsync(16, 0, CancellationToken.None);

        Assert.Equal("/api/graph?tier=public&limit=16&offset=0", path);
        Assert.Equal(2, page.Total);
        Assert.False(page.Partial);
        Assert.Equal(2, page.Threats.Count);
        Assert.Equal("evil-package", page.Threats[0].DisplayName);
        Assert.Equal("Dependency", page.Threats[0].CategoryLabel);
        Assert.Equal("Critical", page.Threats[0].SeverityLabel);
        Assert.Equal("npm", page.Threats[0].Ecosystems);
        Assert.Equal("ioc:example", page.Threats[1].DisplayName);
        Assert.Equal("IOC", page.Threats[1].CategoryLabel);
    }

    [Fact]
    public async Task Sync_request_posts_session_token()
    {
        string? tokenHeader = null;
        string? body = null;
        string? path = null;

        var handler = new StubHandler(request =>
        {
            if (request.RequestUri!.AbsolutePath == "/api/session")
            {
                return Json(HttpStatusCode.OK, """{"token":"session-token"}""");
            }

            if (request.Method == HttpMethod.Post && request.RequestUri.AbsolutePath == "/api/sync")
            {
                path = request.RequestUri.AbsolutePath;
                tokenHeader = request.Headers.TryGetValues("X-Blackbox-Token", out var values)
                    ? values.Single()
                    : null;
                body = request.Content!.ReadAsStringAsync().GetAwaiter().GetResult();
                return Json(HttpStatusCode.OK, """{"ok":true,"message":"Sync requested"}""");
            }

            return Json(HttpStatusCode.NotFound, """{"ok":false}""");
        });

        using var http = new HttpClient(handler);
        using var client = new BlackboxDashboardClient(http);
        var result = await client.RequestSyncAsync(CancellationToken.None);

        Assert.True(result.Ok);
        Assert.Equal("Sync requested", result.Message);
        Assert.Equal("/api/sync", path);
        Assert.Equal("session-token", tokenHeader);
        Assert.Equal("{}", body);
    }

    [Fact]
    public async Task Sync_request_reports_dashboard_rejection()
    {
        var handler = new StubHandler(request =>
            request.RequestUri!.AbsolutePath == "/api/session"
                ? Json(HttpStatusCode.OK, """{"token":"session-token"}""")
                : Json(HttpStatusCode.ServiceUnavailable, """{"ok":false,"errors":["DKG node offline"]}"""));

        using var http = new HttpClient(handler);
        using var client = new BlackboxDashboardClient(http);
        var result = await client.RequestSyncAsync(CancellationToken.None);

        Assert.False(result.Ok);
        Assert.Contains("DKG node offline", result.Message, StringComparison.Ordinal);
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
