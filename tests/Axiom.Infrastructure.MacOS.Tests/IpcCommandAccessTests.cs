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
            var readOnly = IpcCommandAccess.ReadOnlyCommands.Contains(command);
            var write = IpcCommandAccess.WriteCommands.Contains(command);
            Assert.True(readOnly ^ write, $"'{command}' must be in exactly one of ReadOnlyCommands/WriteCommands.");
        }

        Assert.Equal(commands.Count, IpcCommandAccess.ReadOnlyCommands.Count + IpcCommandAccess.WriteCommands.Count);
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
