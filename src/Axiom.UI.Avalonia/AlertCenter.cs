// SPDX-License-Identifier: GPL-3.0-or-later
using System.Collections.ObjectModel;
using System.Globalization;
using CommunityToolkit.Mvvm.ComponentModel;

namespace Axiom.UI.Avalonia;

/// <summary>One alert kept in the in-app notification history.</summary>
public sealed partial class AlertRecord : ObservableObject
{
    public AlertRecord(
        DateTimeOffset at,
        string title,
        string message,
        Type? page,
        IReadOnlyList<string>? focusApps = null)
    {
        At = at;
        Title = title;
        Message = message;
        Page = page;
        FocusApps = focusApps ?? [];
    }

    public DateTimeOffset At { get; }

    public string TimeText => At.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);

    public string Title { get; }

    public string Message { get; }

    public Type? Page { get; }

    /// <summary>Application paths the alert was about, used to highlight them after navigation.</summary>
    public IReadOnlyList<string> FocusApps { get; }

    public string ActionText => ActionTextFor(Page);

    [ObservableProperty]
    private bool _isRead;

    /// <summary>Label for the button that opens the page an alert belongs to.</summary>
    public static string ActionTextFor(Type? page) => page?.Name switch
    {
        nameof(SecurityPageViewModel) => "Open Security",
        nameof(FirewallPageViewModel) => "Open Firewall",
        nameof(AgentsPageViewModel) => "Open Agents",
        _ => "Open Axiom",
    };
}

/// <summary>
/// In-memory history of every alert Axiom raised, including ones that were suppressed because the
/// main window was active or notifications were off. The newest entry is first.
/// </summary>
public static class AlertCenter
{
    public const int MaxItems = 50;

    public static ObservableCollection<AlertRecord> Items { get; } = [];

    public static event EventHandler? Changed;

    public static int UnreadCount => Items.Count(item => !item.IsRead);

    public static void Record(
        string title,
        string message,
        Type? page,
        IReadOnlyList<string>? focusApps = null)
    {
        Items.Insert(0, new AlertRecord(DateTimeOffset.Now, title, message, page, focusApps));
        while (Items.Count > MaxItems)
        {
            Items.RemoveAt(Items.Count - 1);
        }

        Changed?.Invoke(null, EventArgs.Empty);
    }

    public static void MarkRead(AlertRecord item)
    {
        if (item.IsRead)
        {
            return;
        }

        item.IsRead = true;
        Changed?.Invoke(null, EventArgs.Empty);
    }

    public static void MarkAllRead()
    {
        var changed = false;
        foreach (var item in Items)
        {
            if (!item.IsRead)
            {
                item.IsRead = true;
                changed = true;
            }
        }

        if (changed)
        {
            Changed?.Invoke(null, EventArgs.Empty);
        }
    }

    public static void Clear()
    {
        if (Items.Count == 0)
        {
            return;
        }

        Items.Clear();
        Changed?.Invoke(null, EventArgs.Empty);
    }
}
