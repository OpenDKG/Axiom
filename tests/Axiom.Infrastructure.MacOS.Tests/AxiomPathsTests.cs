// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts;
using Axiom.Contracts.Ipc;

namespace Axiom.Infrastructure.MacOS.Tests;

public sealed class AxiomPathsTests
{
    [Fact]
    public void MachineDataDirectoryIsPerPlatform()
    {
        Assert.Equal(
            Path.Combine(@"C:\ProgramData", "Axiom"),
            AxiomPaths.MachineDataDirectoryFor(AxiomPlatform.Windows, @"C:\ProgramData"));
        Assert.Equal(
            "/Library/Application Support/Axiom",
            AxiomPaths.MachineDataDirectoryFor(AxiomPlatform.MacOS, "/usr/share"));
        Assert.Equal("/var/lib/axiom", AxiomPaths.MachineDataDirectoryFor(AxiomPlatform.Linux, "/usr/share"));
    }

    [Theory]
    [InlineData(AxiomPlatform.Windows, false, null, 0u, true)]
    [InlineData(AxiomPlatform.Windows, true, "1", 0u, false)]
    [InlineData(AxiomPlatform.MacOS, true, "1", 501u, true)]
    [InlineData(AxiomPlatform.MacOS, true, null, 0u, true)]
    [InlineData(AxiomPlatform.MacOS, true, null, 501u, false)]
    [InlineData(AxiomPlatform.MacOS, false, "0", 501u, false)]
    [InlineData(AxiomPlatform.Linux, true, " 1 ", 1000u, true)]
    public void ServiceDetectionFollowsPlatformRules(
        AxiomPlatform platform,
        bool userInteractive,
        string? variable,
        uint euid,
        bool expected) =>
        Assert.Equal(expected, AxiomPaths.IsServiceProcessFor(platform, userInteractive, variable, euid));

    [Fact]
    public void IpcEndpointIsPipeNameOnWindowsAndSocketOnUnix()
    {
        Assert.Equal(IpcPipe.Name, IpcPipe.EndpointFor(true, "/tmp/ignored.sock"));
        Assert.Equal(IpcPipe.UnixSocketPath, IpcPipe.EndpointFor(false, null));
        Assert.Equal("/tmp/x.sock", IpcPipe.EndpointFor(false, " /tmp/x.sock "));
    }

    [Fact]
    public void ServicePrivateDataIsMachineRootOnlyForUnixService()
    {
        const string local = "/home/u/.local/share";
        const string machine = "/Library/Application Support/Axiom";

        Assert.Equal(machine, AxiomPaths.ServicePrivateDataDirectoryFor(AxiomPlatform.MacOS, true, local, machine));
        Assert.Equal(Path.Combine(local, "Axiom"), AxiomPaths.ServicePrivateDataDirectoryFor(AxiomPlatform.MacOS, false, local, machine));
        Assert.Equal(machine, AxiomPaths.ServicePrivateDataDirectoryFor(AxiomPlatform.Linux, true, local, machine));

        // Windows keeps the service account's own LocalAppData even as a service.
        Assert.Equal(Path.Combine(local, "Axiom"), AxiomPaths.ServicePrivateDataDirectoryFor(AxiomPlatform.Windows, true, local, machine));
    }

    [Fact]
    public void MacServicePathsFollowTheContract()
    {
        var paths = new MacServicePaths("/Library/Application Support/Axiom", "/var/run/axiom", "/var/run/axiom/axiom.sock");
        Assert.Equal("/Library/Application Support/Axiom/filter/rules.json", paths.RulesFile);
        Assert.Equal("/Library/Application Support/Axiom/filter/managed-rules.json", paths.ManagedRulesFile);
        Assert.Equal("/var/run/axiom/filter.sock", paths.FilterSocketPath);
    }
}
