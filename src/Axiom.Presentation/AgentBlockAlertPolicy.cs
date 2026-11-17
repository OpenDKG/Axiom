// SPDX-License-Identifier: GPL-3.0-or-later
namespace Axiom.Presentation;

public sealed record AgentBlockAlert(int Count, string Message);

/// <summary>
/// Rate-limits alerts for blocked agent actions so a busy guard cannot flood the user with one
/// toast per blocked tool call. The first observation after startup is a baseline and stays quiet;
/// later blocks produce at most one alert per <see cref="Cooldown"/>, counting what accumulated in
/// between.
/// </summary>
public sealed class AgentBlockAlertPolicy
{
    private int _pending;
    private DateTimeOffset _lastAlert = DateTimeOffset.MinValue;
    private bool _initialized;
    private bool _hasAlerted;

    public TimeSpan Cooldown { get; init; } = TimeSpan.FromMinutes(5);

    /// <summary>Marks the initial audit load as a baseline: history never raises an alert.</summary>
    public void MarkInitialized() => _initialized = true;

    public AgentBlockAlert? Observe(int blockedCount, DateTimeOffset now, string? sample = null)
    {
        if (blockedCount <= 0)
        {
            return null;
        }

        if (!_initialized)
        {
            _initialized = true;
            return null;
        }

        _pending += blockedCount;
        if (_hasAlerted && now - _lastAlert < Cooldown)
        {
            return null;
        }

        var count = _pending;
        _pending = 0;
        _lastAlert = now;
        _hasAlerted = true;

        var message = count == 1
            ? "Blackbox blocked an agent action" + (string.IsNullOrWhiteSpace(sample) ? "." : $": {sample}.")
            : $"Blackbox blocked {count} agent actions since the last alert" +
              (string.IsNullOrWhiteSpace(sample) ? "." : $" (for example: {sample}).");

        return new AgentBlockAlert(count, message);
    }
}
