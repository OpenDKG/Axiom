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

    [Fact]
    public void ReadRecent_reads_tail_and_invalidates_cache_when_file_grows()
    {
        var path = Path.Combine(Path.GetTempPath(), $"axiom-evidence-{Guid.NewGuid():N}.jsonl");
        try
        {
            var now = DateTimeOffset.UtcNow;
            var lines = Enumerable.Range(1, 600)
                .Select(index =>
                    $"{{\"timestampUtc\":\"{now.AddSeconds(-600 + index):O}\",\"framework\":\"codex\",\"eventType\":\"GUARD_ALLOWED\",\"tool\":\"tool-{index}\",\"decision\":\"allowed\",\"guardStatus\":\"ok\",\"durationMs\":1}}")
                .ToArray();
            File.WriteAllLines(path, lines);

            var store = new AgentEvidenceStore(path);
            var initial = store.ReadRecent(10);
            Assert.Equal(10, initial.Count);
            Assert.Equal("tool-600", initial[^1].Tool);

            File.AppendAllLines(path,
            [
                $"{{\"timestampUtc\":\"{now.AddSeconds(1):O}\",\"framework\":\"codex\",\"eventType\":\"GUARD_ALLOWED\",\"tool\":\"tool-601\",\"decision\":\"allowed\",\"guardStatus\":\"ok\",\"durationMs\":1}}",
            ]);

            Assert.Equal("tool-601", store.Latest("codex")?.Tool);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Evidence_exposes_explicit_or_fallback_effective_channel()
    {
        var path = Path.Combine(Path.GetTempPath(), $"axiom-evidence-{Guid.NewGuid():N}.jsonl");
        try
        {
            var now = DateTimeOffset.UtcNow;
            File.WriteAllLines(path,
            [
                $"{{\"timestampUtc\":\"{now:O}\",\"framework\":\"claude\",\"eventType\":\"GUARD_BLOCKED\",\"tool\":\"bash\",\"decision\":\"block\",\"guardStatus\":\"blocked\",\"channel\":\"host_deny_verified\"}}",
                $"{{\"timestampUtc\":\"{now.AddSeconds(1):O}\",\"framework\":\"codex\",\"eventType\":\"GUARD_BLOCKED\",\"tool\":\"bash\",\"decision\":\"block\",\"guardStatus\":\"blocked\"}}",
                $"{{\"timestampUtc\":\"{now.AddSeconds(2):O}\",\"framework\":\"gemini\",\"eventType\":\"GUARD_ALLOWED\",\"tool\":\"read_file\",\"decision\":\"allowed\",\"guardStatus\":\"allowed\"}}",
                $"{{\"timestampUtc\":\"{now.AddSeconds(3):O}\",\"framework\":\"cursor\",\"eventType\":\"GUARD_FAILED\",\"tool\":\"bash\",\"decision\":\"\",\"guardStatus\":\"error\"}}",
            ]);

            var events = new AgentEvidenceStore(path).ReadRecent();

            Assert.Equal("HOST_DENY_VERIFIED", events[0].EffectiveChannel);
            Assert.Equal("HOST_DENY_SENT", events[1].EffectiveChannel);
            Assert.Equal("DETECTOR_ONLY", events[2].EffectiveChannel);
            Assert.Equal("FAILED_OPEN", events[3].EffectiveChannel);
        }
        finally
        {
            File.Delete(path);
        }
    }
}
