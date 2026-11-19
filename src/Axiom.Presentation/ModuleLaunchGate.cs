// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.Presentation;

/// <summary>Serializes Axiom's launch requests while a detached module is binding its port.</summary>
internal sealed class ModuleLaunchGate(TimeSpan startupWindow, TimeProvider? timeProvider = null)
{
    private readonly object _lock = new();
    private readonly TimeProvider _timeProvider = timeProvider ?? TimeProvider.System;
    private long? _lastLaunch;

    public bool Start(Func<bool> isListening, Func<bool> launch, Func<bool>? prepare = null)
    {
        lock (_lock)
        {
            if (prepare is not null && !prepare())
            {
                return false;
            }

            if (isListening())
            {
                _lastLaunch = null;
                return true;
            }

            if (_lastLaunch is { } timestamp && _timeProvider.GetElapsedTime(timestamp) < startupWindow)
            {
                return true;
            }

            if (!launch())
            {
                return false;
            }

            _lastLaunch = _timeProvider.GetTimestamp();
            return true;
        }
    }

    public bool Stop(Func<bool> stop)
    {
        lock (_lock)
        {
            if (!stop())
            {
                return false;
            }

            _lastLaunch = null;
            return true;
        }
    }
}
