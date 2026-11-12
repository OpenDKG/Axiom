// SPDX-License-Identifier: GPL-3.0-or-later
using System.Reflection;
using Axiom.Contracts.Ipc;
using Axiom.Service.Hosting.Ipc;

namespace Axiom.Infrastructure.MacOS.Tests;

public sealed class IpcCommandAccessTests
{
    /// <summary>Every command constant of the IPC contract must be classified exactly once.</summary>
    [Fact]
    public void EveryCommandIsClassifiedExactlyOnce()
    {
        var commands = typeof(IpcCommandTypes)
            .GetFields(BindingFlags.Public | BindingFlags.Static)
            .Where(field => field.IsLiteral && field.FieldType == typeof(string))
            .Select(field => (string)field.GetRawConstantValue()!)
            .ToList();

        Assert.NotEmpty(commands);
        Assert.Equal(commands.Order(StringComparer.Ordinal), IpcCommandTypes.All.Order(StringComparer.Ordinal));

        foreach (var command in commands)
        {
            var listed = (IpcCommandAccess.PublicReadCommands.Contains(command) ? 1 : 0)
                + (IpcCommandAccess.PrivateReadCommands.Contains(command) ? 1 : 0)
                + (IpcCommandAccess.WriteCommands.Contains(command) ? 1 : 0);
            Assert.True(listed == 1, $"'{command}' must be in exactly one of PublicRead/PrivateRead/WriteCommands (found in {listed}).");
            Assert.Equal(IpcCommandAccess.ReadOnlyCommands.Contains(command), !IpcCommandAccess.IsWrite(command));
        }

        Assert.Equal(
            commands.Count,
            IpcCommandAccess.PublicReadCommands.Count + IpcCommandAccess.PrivateReadCommands.Count + IpcCommandAccess.WriteCommands.Count);
    }

    /// <summary>The public set is exactly the two health commands; everything that shows activity is private.</summary>
    [Theory]
    [InlineData("serviceHealth", IpcCommandClass.PublicRead)]
    [InlineData("capabilities", IpcCommandClass.PublicRead)]
    [InlineData("snapshot", IpcCommandClass.PrivateRead)]
    [InlineData("live.events", IpcCommandClass.PrivateRead)]
    [InlineData("history.query", IpcCommandClass.PrivateRead)]
    [InlineData("traffic.history", IpcCommandClass.PrivateRead)]
    [InlineData("diagnostics.export", IpcCommandClass.PrivateRead)]
    [InlineData("privacy.status", IpcCommandClass.PrivateRead)]
    [InlineData("threatshare.status", IpcCommandClass.PrivateRead)]
    [InlineData("protection.status", IpcCommandClass.PrivateRead)]
    [InlineData("config.get", IpcCommandClass.PrivateRead)]
    [InlineData("rules.query", IpcCommandClass.PrivateRead)]
    [InlineData("rule.verify", IpcCommandClass.PrivateRead)]
    [InlineData("rule.apply", IpcCommandClass.Write)]
    [InlineData("privacy.configure", IpcCommandClass.Write)]
    [InlineData("networkRecovery.restore", IpcCommandClass.Write)]
    [InlineData("something.new", IpcCommandClass.Write)]
    [InlineData(null, IpcCommandClass.Write)]
    public void Classification(string? command, IpcCommandClass expected)
    {
        Assert.Equal(expected, IpcCommandAccess.Classify(command));
    }

    [Fact]
    public void PublicSetIsOnlyTheHealthCommands()
    {
        Assert.Equal(["capabilities", "serviceHealth"], IpcCommandAccess.PublicReadCommands.Order(StringComparer.Ordinal));
    }

    [Fact]
    public void CallerFlagsGateTheClasses()
    {
        var publicOnly = new IpcCaller("uid:502", false, "no writes", false, "no private reads");
        Assert.True(publicOnly.Permits(IpcCommandClass.PublicRead));
        Assert.False(publicOnly.Permits(IpcCommandClass.PrivateRead));
        Assert.False(publicOnly.Permits(IpcCommandClass.Write));
        Assert.Equal("no private reads", publicOnly.DenialMessage(IpcCommandClass.PrivateRead, "snapshot"));
        Assert.Equal("no writes", publicOnly.DenialMessage(IpcCommandClass.Write, "rule.apply"));

        var readOnly = new IpcCaller("uid:503", false, null, true);
        Assert.True(readOnly.Permits(IpcCommandClass.PrivateRead));
        Assert.False(readOnly.Permits(IpcCommandClass.Write));
        Assert.Equal("Command 'rule.apply' is not allowed for uid:503.", readOnly.DenialMessage(IpcCommandClass.Write, "rule.apply"));

        var full = IpcCaller.FullAccess("S-1-5-21-1");
        Assert.True(full.Permits(IpcCommandClass.Write));
        Assert.True(full.Permits(IpcCommandClass.PrivateRead));
    }

    [Theory]
    [InlineData("serviceHealth", false)]
    [InlineData("capabilities", false)]
    [InlineData("snapshot", false)]
    [InlineData("rules.query", false)]
    [InlineData("history.query", false)]
    [InlineData("privacy.status", false)]
    [InlineData("protection.status", false)]
    [InlineData("rule.apply", true)]
    [InlineData("rule.remove", true)]
    [InlineData("privacy.configure", true)]
    [InlineData("privacy.sources.update", true)]
    [InlineData("protection.enable", true)]
    [InlineData("protection.disable", true)]
    [InlineData("config.set", true)]
    [InlineData("threatshare.enqueue", true)]
    [InlineData("something.new", true)]
    [InlineData(null, true)]
    public void WriteClassification(string? command, bool isWrite)
    {
        Assert.Equal(isWrite, IpcCommandAccess.IsWrite(command));
    }
}
