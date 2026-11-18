// SPDX-License-Identifier: GPL-3.0-or-later
using Xunit.Abstractions;
using Xunit.Sdk;

[assembly: Xunit.TestFramework(
    "Axiom.UI.Avalonia.Tests.HeadlessTestFramework",
    "Axiom.UI.Avalonia.Tests")]

namespace Axiom.UI.Avalonia.Tests;

/// <summary>
/// The standard xUnit framework, plus the headless Avalonia UI thread set up before the first
/// test of the assembly runs. Tests that construct Avalonia objects on an xUnit worker thread can
/// then never become the owner of <c>Dispatcher.UIThread</c>, whatever order the parallel test
/// classes start in (see <see cref="TestAppBuilder"/>).
/// </summary>
public sealed class HeadlessTestFramework : XunitTestFramework
{
    public HeadlessTestFramework(IMessageSink messageSink)
        : base(messageSink)
    {
        TestAppBuilder.StartUiThread();
    }
}
