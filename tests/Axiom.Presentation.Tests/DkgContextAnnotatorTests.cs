// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Blackbox;
using Axiom.Presentation;
using Xunit;

namespace Axiom.Presentation.Tests;

public sealed class DkgContextAnnotatorTests
{
    private static readonly DateTimeOffset SnapshotTime =
        new(2026, 11, 14, 1, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Annotates_verified_community_unknown_and_local_false_positive_without_enforcing()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), $"axiom-dkg-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);
        var fpPath = Path.Combine(tempDir, "fp.json");

        try
        {
            var threats = new[]
            {
                new BlackboxGraphThreat("c2.verified.example", "Verified C2", "ioc", "high", "", "verified"),
                new BlackboxGraphThreat("sighting.community.example", "Comm", "ioc", "medium", "", "community"),
            };

            var annotator = new DkgContextAnnotator(threats, SnapshotTime, fpPath);

            var verified = annotator.Annotate("c2.verified.example", SnapshotTime.AddMinutes(10));
            Assert.Equal(DkgContextTier.Verified, verified.Tier);
            Assert.Equal("Verified threat", verified.BadgeLabel);
            Assert.False(verified.EnforcesBlock);
            Assert.False(verified.IsStaleCache);

            var community = annotator.Annotate("sighting.community.example", SnapshotTime.AddMinutes(10));
            Assert.Equal(DkgContextTier.Community, community.Tier);
            Assert.Equal("Community sighting", community.BadgeLabel);
            Assert.Equal(1, community.DistinctReporters);
            Assert.False(community.EnforcesBlock);

            var unknown = annotator.Annotate("benign.unknown.example", SnapshotTime.AddHours(8));
            Assert.Equal(DkgContextTier.Unknown, unknown.Tier);
            Assert.Equal("Unknown", unknown.BadgeLabel);
            Assert.DoesNotContain("Clean", unknown.BadgeLabel, StringComparison.OrdinalIgnoreCase);
            Assert.True(unknown.IsStaleCache);
            Assert.False(unknown.EnforcesBlock);

            annotator.MarkLocalFalsePositive("sighting.community.example", "Internal lab endpoint");
            var reloaded = new DkgContextAnnotator(threats, SnapshotTime, fpPath);
            var fp = reloaded.Annotate("sighting.community.example", SnapshotTime.AddMinutes(5));
            Assert.Equal(DkgContextTier.LocalFalsePositive, fp.Tier);
            Assert.Equal("Marked false positive (local)", fp.BadgeLabel);
            Assert.Equal("Internal lab endpoint", fp.LocalNote);
        }
        finally
        {
            if (Directory.Exists(tempDir))
            {
                Directory.Delete(tempDir, recursive: true);
            }
        }
    }

    [Fact]
    public void Batch_lookup_deduplicates_and_respects_bound()
    {
        var annotator = new DkgContextAnnotator(
            [new BlackboxGraphThreat("bad.example", "Bad", "ioc", "high", "", "verified")],
            SnapshotTime);

        var batch = annotator.AnnotateBatch(
            ["bad.example", "BAD.EXAMPLE", "one.example", "two.example"],
            maxBatch: 2,
            now: SnapshotTime);

        Assert.Equal(2, batch.Count);
        Assert.Equal(DkgContextTier.Verified, batch[0].Tier);
        Assert.Equal(DkgContextTier.Unknown, batch[1].Tier);
    }
}
