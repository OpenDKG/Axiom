// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using Axiom.UI.Services;
using Xunit;

namespace Axiom.UI.Tests;

public sealed class AgentEvidenceStoreTests
{
    [Fact]
    public void Latest_ignores_evidence_older_than_the_requested_lifetime()
    {
        var path = Path.Combine(Path.GetTempPath(), $"axiom-evidence-{Guid.NewGuid():N}.jsonl");
        try
        {
            var old = DateTimeOffset.UtcNow - TimeSpan.FromHours(2);
            var recent = DateTimeOffset.UtcNow - TimeSpan.FromMinutes(1);
            File.WriteAllLines(path,
            [
                $"{{\"timestampUtc\":\"{old:O}\",\"framework\":\"codex\",\"eventType\":\"GUARD_ALLOWED\",\"tool\":\"old\",\"decision\":\"allowed\",\"guardStatus\":\"allowed\",\"durationMs\":1}}",
                $"{{\"timestampUtc\":\"{recent:O}\",\"framework\":\"codex\",\"eventType\":\"PROMPT_SCANNED\",\"tool\":\"new\",\"decision\":\"allowed\",\"guardStatus\":\"ok\",\"durationMs\":2}}",
            ]);

            var store = new AgentEvidenceStore(path);

            Assert.Equal("new", store.Latest("codex", TimeSpan.FromMinutes(5))?.Tool);
            Assert.Equal("new", store.Latest("codex")?.Tool);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Evidence_preserves_session_and_call_for_framework_attribution()
    {
        var path = Path.Combine(Path.GetTempPath(), $"axiom-evidence-{Guid.NewGuid():N}.jsonl");
        try
        {
            File.WriteAllText(
                path,
                $"{{\"timestampUtc\":\"{DateTimeOffset.UtcNow:O}\",\"framework\":\"opencode\",\"eventType\":\"GUARD_ALLOWED\",\"tool\":\"shell\",\"session\":\"ses_test\",\"call\":\"call_test\"}}");

            var item = Assert.Single(new AgentEvidenceStore(path).ReadRecent());

            Assert.Equal("opencode", item.Framework);
            Assert.Equal("ses_test", item.Session);
            Assert.Equal("call_test", item.Call);
        }
        finally
        {
            File.Delete(path);
        }
    }
}
