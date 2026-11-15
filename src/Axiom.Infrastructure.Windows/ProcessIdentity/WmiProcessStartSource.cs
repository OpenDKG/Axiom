// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;
using System.Management;
using Axiom.Core.Enforcement;

namespace Axiom.Infrastructure.Windows.ProcessIdentity;

/// <summary>
/// Windows process-start feed backed by WMI's <c>Win32_ProcessStartTrace</c>. The trace gives the
/// image name only, so an optional resolver (normally a <c>Win32_Process</c> lookup) supplies the
/// executable paths the policy needs for the download/staging check.
/// </summary>
public sealed class WmiProcessStartSource : IProcessStartSource
{
    private readonly Func<int, string?>? _imagePathResolver;
    private ManagementEventWatcher? _watcher;

    public WmiProcessStartSource(Func<int, string?>? imagePathResolver = null)
    {
        _imagePathResolver = imagePathResolver;
    }

    public event EventHandler<ProcessSpawnEvent>? ProcessStarted;

    public void Start()
    {
        if (_watcher is not null)
        {
            return;
        }

        var watcher = new ManagementEventWatcher(
            new WqlEventQuery("SELECT * FROM Win32_ProcessStartTrace"));
        watcher.EventArrived += OnEventArrived;
        watcher.Start();
        _watcher = watcher;
    }

    public void Dispose()
    {
        var watcher = _watcher;
        if (watcher is null)
        {
            return;
        }

        _watcher = null;
        watcher.EventArrived -= OnEventArrived;
        try
        {
            watcher.Stop();
        }
        catch (ManagementException)
        {
        }

        watcher.Dispose();
    }

    private void OnEventArrived(object sender, EventArrivedEventArgs e)
    {
        try
        {
            var spawn = Map(
                Convert.ToUInt32(e.NewEvent["ProcessID"], CultureInfo.InvariantCulture),
                Convert.ToUInt32(e.NewEvent["ParentProcessID"], CultureInfo.InvariantCulture),
                e.NewEvent["ProcessName"] as string,
                _imagePathResolver,
                DateTimeOffset.UtcNow);
            if (spawn is not null)
            {
                ProcessStarted?.Invoke(this, spawn);
            }
        }
        catch (Exception exception) when (exception is ManagementException or FormatException or InvalidCastException)
        {
            // A malformed event must not stop the feed.
        }
    }

    /// <summary>Maps a trace event to a spawn observation; returns null for an unusable event.</summary>
    public static ProcessSpawnEvent? Map(
        uint processId,
        uint parentProcessId,
        string? processName,
        Func<int, string?>? imagePathResolver,
        DateTimeOffset at)
    {
        if (processId == 0)
        {
            return null;
        }

        var image = imagePathResolver?.Invoke((int)processId);
        if (string.IsNullOrWhiteSpace(image))
        {
            image = (processName ?? string.Empty).Trim();
        }

        var parent = imagePathResolver?.Invoke((int)parentProcessId) ?? string.Empty;
        if (string.IsNullOrWhiteSpace(image) && string.IsNullOrWhiteSpace(parent))
        {
            return null;
        }

        return new ProcessSpawnEvent((int)processId, (int)parentProcessId, image, parent, at);
    }
}
