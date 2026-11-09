// SPDX-License-Identifier: GPL-3.0-or-later
using Axiom.Contracts.Monitoring;
using Axiom.Contracts.Protection;
using Axiom.Presentation;

namespace Axiom.UI.Avalonia;

/// <summary>
/// Adds live connection context to a Shield pending application. The service may run an older
/// build without remote endpoints, so the UI fills them from the same snapshot it is displaying.
/// </summary>
internal static class ProtectionAlertContext
{
    public static ProtectionPendingApp Enrich(
        ProtectionPendingApp app,
        IEnumerable<ConnectionRow>? connections)
    {
        ArgumentNullException.ThrowIfNull(app);
        if (app.RemoteEndpoints.Count > 0 || connections is null)
        {
            return app;
        }

        var endpoints = connections
            .Where(row =>
                !row.IsLoopback &&
                row.Source.Direction == ConnectionDirection.Outbound &&
                string.Equals(row.Source.AppPath, app.AppPath, StringComparison.OrdinalIgnoreCase))
            .Select(row => row.RemoteEndpoint)
            .Where(endpoint =>
                !string.IsNullOrWhiteSpace(endpoint) &&
                !string.Equals(endpoint, "—", StringComparison.Ordinal))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(5)
            .ToList();

        return endpoints.Count == 0 ? app : app with { RemoteEndpoints = endpoints };
    }
}
