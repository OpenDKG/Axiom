// SPDX-License-Identifier: GPL-3.0-or-later
using System.Text.Json.Nodes;
using Axiom.Contracts;
using Axiom.Contracts.Blackbox;

namespace Axiom.Presentation;

/// <summary>
/// Persists the one-time installer/first-run consent to enable Blackbox automatic community
/// sharing by default after installation, and applies it to the local Blackbox dashboard once.
/// Once applied (or explicitly changed by the operator), Axiom never overrides the operator's
/// later on/off choice.
/// </summary>
public static class BlackboxAutomaticSharingProvisioner
{
    private const string PendingMarker = "pending-v1";
    private const string AppliedMarker = "applied-v1";

    public static string DefaultMarkerPath => Path.Combine(
        AxiomPaths.UserDataDirectory,
        "blackbox-automatic-sharing-default");

    public static bool IsPending(string? path = null) =>
        string.Equals(ReadMarker(path), PendingMarker, StringComparison.Ordinal);

    public static bool IsApplied(string? path = null) =>
        string.Equals(ReadMarker(path), AppliedMarker, StringComparison.Ordinal);

    public static bool TryMarkPending(string? path = null) =>
        WriteMarker(PendingMarker, path);

    public static bool TryMarkApplied(string? path = null) =>
        WriteMarker(AppliedMarker, path);

    /// <summary>
    /// Enables Blackbox automatic sharing (<c>report: true</c>) through the local loopback
    /// dashboard so Blackbox records its own reporter-terms consent receipt and config flag.
    /// Marks the one-time default as applied only after the dashboard confirms <c>report == true</c>.
    /// </summary>
    public static async Task<bool> TryApplyToDashboardAsync(
        BlackboxDashboardClient client,
        CancellationToken cancellationToken,
        string? markerPath = null)
    {
        ArgumentNullException.ThrowIfNull(client);

        try
        {
            var result = await client
                .SaveSettingsAsync(new JsonObject { ["report"] = true }, cancellationToken)
                .ConfigureAwait(false);
            if (!result.Ok)
            {
                return false;
            }

            var settings = result.Settings ?? await client.GetSettingsAsync(cancellationToken).ConfigureAwait(false);
            var enabled = settings["report"] is JsonValue value &&
                          value.TryGetValue<bool>(out var report) &&
                          report;
            if (!enabled)
            {
                return false;
            }

            TryMarkApplied(markerPath);
            return true;
        }
        catch (Exception exception) when (exception is
                     HttpRequestException or TaskCanceledException or InvalidDataException or System.Text.Json.JsonException)
        {
            return false;
        }
    }

    private static string? ReadMarker(string? path)
    {
        try
        {
            var target = path ?? DefaultMarkerPath;
            return File.Exists(target) ? File.ReadAllText(target).Trim() : null;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    private static bool WriteMarker(string content, string? path)
    {
        var target = path ?? DefaultMarkerPath;
        var temporary = target + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            if (Path.GetDirectoryName(target) is { Length: > 0 } directory)
            {
                Directory.CreateDirectory(directory);
            }

            File.WriteAllText(temporary, content);
            File.Move(temporary, target, overwrite: true);
            return true;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return false;
        }
        finally
        {
            try
            {
                File.Delete(temporary);
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
            }
        }
    }
}
