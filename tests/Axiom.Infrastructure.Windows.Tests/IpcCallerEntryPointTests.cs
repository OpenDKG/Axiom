// SPDX-License-Identifier: GPL-3.0-or-later
using System.Reflection;
using Axiom.Infrastructure.Windows.Ipc;
using Axiom.Service.Hosting.Ipc;
using Xunit;

namespace Axiom.Infrastructure.Windows.Tests;

/// <summary>
/// Gate for the dispatcher's entry points: the portable layer must not offer a way to serve a
/// connection, or to build a caller, from a bare actor string. "Full access because the transport
/// already authenticated the user" is a property of the Windows pipe (its DACL admits one SID) and
/// must be spelled out in the Windows project, so a Unix transport cannot pick it by accident.
/// </summary>
public sealed class IpcCallerEntryPointTests
{
    private const BindingFlags Exposed =
        BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly;

    /// <summary>Every connection entry point of the dispatcher takes an explicit <see cref="IpcCaller"/>.</summary>
    [Fact]
    public void DispatcherServesConnectionsOnlyForAnExplicitCaller()
    {
        var entryPoints = typeof(IpcRequestDispatcher)
            .GetMethods(Exposed)
            .Where(method => !method.IsPrivate && method.GetParameters().Any(parameter => parameter.ParameterType == typeof(Stream)))
            .ToList();

        Assert.NotEmpty(entryPoints);
        Assert.All(entryPoints, method =>
        {
            var parameters = method.GetParameters().Select(parameter => parameter.ParameterType).ToList();
            Assert.True(parameters.Contains(typeof(IpcCaller)), $"{method} must take an IpcCaller.");
            Assert.False(parameters.Contains(typeof(string)), $"{method} must not take a bare actor string.");
        });
    }

    /// <summary>
    /// No visible member of the portable hosting assembly turns a string into an
    /// <see cref="IpcCaller"/>; the only way to get one there is the record constructor, where
    /// <c>CanWrite</c> has no default and must be written out.
    /// </summary>
    [Fact]
    public void PortableLayerHasNoCallerFactoryFromAnActorString()
    {
        var factories = typeof(IpcCaller).Assembly.GetTypes()
            .SelectMany(type => type.GetMethods(Exposed))
            .Where(method => !method.IsPrivate
                && !method.IsSpecialName
                && method.ReturnType == typeof(IpcCaller)
                && method.GetParameters().Any(parameter => parameter.ParameterType == typeof(string))
                && method.Name != "<Clone>$")
            .Select(method => $"{method.DeclaringType!.Name}.{method.Name}")
            .ToList();

        Assert.Empty(factories);

        var constructor = Assert.Single(typeof(IpcCaller).GetConstructors(), ctor => ctor.GetParameters().Length > 1);
        var canWrite = Assert.Single(constructor.GetParameters(), parameter => parameter.Name == nameof(IpcCaller.CanWrite));
        Assert.False(canWrite.HasDefaultValue);
    }

    /// <summary>
    /// The Windows pipe names its caller itself: same actor (the SID that goes to the audit trail)
    /// and the same access the removed string overload gave, i.e. every command class.
    /// </summary>
    [Fact]
    public void WindowsPipeCallerIsTheAuthenticatedSidWithEveryClass()
    {
        var factory = typeof(PipeServer).Assembly
            .GetType("Axiom.Infrastructure.Windows.Ipc.WindowsPipeCaller")
            ?.GetMethod("Authenticated", BindingFlags.Public | BindingFlags.Static, [typeof(string)]);
        Assert.NotNull(factory);

        var caller = Assert.IsType<IpcCaller>(factory!.Invoke(null, ["S-1-5-21-1"]));

        Assert.Equal(new IpcCaller("S-1-5-21-1", CanWrite: true), caller);
        Assert.Equal("S-1-5-21-1", caller.Actor);
        Assert.All(Enum.GetValues<IpcCommandClass>(), commandClass => Assert.True(caller.Permits(commandClass)));
        Assert.Null(caller.WriteDenialReason);
        Assert.Null(caller.ReadDenialReason);

        var blank = Assert.Throws<TargetInvocationException>(() => factory.Invoke(null, [" "]));
        Assert.IsAssignableFrom<ArgumentException>(blank.InnerException);
    }
}
