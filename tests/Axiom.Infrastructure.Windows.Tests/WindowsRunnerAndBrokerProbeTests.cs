// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Infrastructure.Windows.Enforcement;
using Xunit;

namespace Axiom.Infrastructure.Windows.Tests;

public sealed class WindowsRunnerAndBrokerProbeTests
{
    [Fact]
    public void Probe_current_host_reports_job_object_support_and_explicit_limitations()
    {
        var report = WindowsRunnerAndBrokerProbe.ProbeCurrentHost();

        Assert.True(report.JobObjectAvailable);
        Assert.True(report.ReparsePointDefenseAvailable);
        Assert.Equal("HOST_DENY_VERIFIED", report.DefaultClaimedBoundary);
        Assert.NotEmpty(report.RuntimeLimitations);
    }

    [Fact]
    public void Ancestry_reparse_probe_allows_normal_file_and_fails_closed_on_device_paths()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), $"axiom-probe-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);
        var cleanFile = Path.Combine(tempDir, "clean.txt");
        File.WriteAllText(cleanFile, "ok");

        try
        {
            Assert.False(WindowsRunnerAndBrokerProbe.HasReparsePointInAncestry(cleanFile));
            Assert.True(WindowsRunnerAndBrokerProbe.HasReparsePointInAncestry(@"\\?\C:\clean.txt"));
            Assert.True(WindowsRunnerAndBrokerProbe.HasReparsePointInAncestry(null));
        }
        finally
        {
            if (Directory.Exists(tempDir))
            {
                Directory.Delete(tempDir, recursive: true);
            }
        }
    }
}
