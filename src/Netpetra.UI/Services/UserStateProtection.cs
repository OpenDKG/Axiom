// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using System.Security.Cryptography;

namespace Netpetra.UI.Services;

public sealed record UserStateFile(
    string Path,
    bool Exists,
    long Length,
    DateTimeOffset? LastWriteUtc,
    string? Sha256,
    byte[]? Content);

public sealed record UserStateDirectoryEntry(
    string RelativePath,
    long Length,
    DateTimeOffset LastWriteUtc,
    string? Sha256);

public sealed record UserStateDirectory(
    string Path,
    bool Exists,
    bool Recursive,
    IReadOnlyDictionary<string, UserStateDirectoryEntry> Entries);

public sealed record UserStateChange(string Path, string Reason);

public sealed class UserStateSnapshot(
    IReadOnlyDictionary<string, UserStateFile> files,
    IReadOnlyDictionary<string, UserStateDirectory> directories)
{
    public IReadOnlyDictionary<string, UserStateFile> Files { get; } = files;

    public IReadOnlyDictionary<string, UserStateDirectory> Directories { get; } = directories;
}

/// <summary>
/// Captures a bounded hash snapshot of user-owned agent configuration and Netpetra settings, then
/// verifies that hook installation changed only the explicitly allowed paths. Small file content is
/// kept in memory so an unexpected change can be rolled back. Large files and history directories
/// are fingerprinted without loading their full contents.
/// </summary>
public sealed class UserStateProtection
{
    private const int MaxRestorableBytes = 1024 * 1024;

    private readonly string _userProfile;

    private readonly string _localAppData;

    private readonly bool _includeHermesSettings;

    public UserStateProtection(
        string? userProfile = null,
        string? localAppData = null,
        string? roamingAppData = null,
        bool includeHermesSettings = true)
    {
        _userProfile = userProfile ?? Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        _localAppData = localAppData ?? Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        _ = roamingAppData;
        _includeHermesSettings = includeHermesSettings;
    }

    public IReadOnlyList<string> ProtectedPaths
    {
        get
        {
            var paths = new List<string>
            {
                Path.Combine(_userProfile, ".config", "opencode", "opencode.json"),
                Path.Combine(_userProfile, ".config", "opencode", "config.json"),
                Path.Combine(_userProfile, ".config", "opencode", "auth.json"),
                Path.Combine(_userProfile, ".codex", "config.toml"),
                Path.Combine(_userProfile, ".codex", "hooks.json"),
                Path.Combine(_userProfile, ".claude", "settings.json"),
                Path.Combine(_userProfile, ".cursor", "hooks.json"),
                Path.Combine(_userProfile, ".copilot", "settings.json"),
                Path.Combine(_userProfile, ".gemini", "settings.json"),
                Path.Combine(_userProfile, ".gemini", "config", "config.json"),
                Path.Combine(_userProfile, ".gemini", "config", "mcp_config.json"),
                Path.Combine(_userProfile, ".gemini", "antigravity", "conversation_summaries.db"),
                Path.Combine(_userProfile, ".gemini", "antigravity", "antigravity_state.pbtxt"),
                Path.Combine(_userProfile, ".gemini", "antigravity", "installation_id"),
                Path.Combine(_userProfile, ".gemini", "antigravity-cli", "history.jsonl"),
                Path.Combine(_userProfile, ".gemini", "antigravity-cli", "cache", "last_conversations.json"),
                Path.Combine(_userProfile, ".gemini", "antigravity-cli", "settings.json"),
                Path.Combine(_userProfile, ".gemini", "antigravity-cli", "mcp_config.json"),
                Path.Combine(_localAppData, "Netpetra", "theme.txt"),
                Path.Combine(_localAppData, "Netpetra", "tray-notifications.txt"),
                Path.Combine(_localAppData, "Netpetra", "reputation.json"),
                Path.Combine(_localAppData, "Netpetra", "community-feed.json"),
                Path.Combine(_localAppData, "Netpetra", "onboarding.json"),
            };

            if (_includeHermesSettings)
            {
                paths.Add(Path.Combine(_userProfile, ".hermes", "config.yaml"));
            }

            return paths;
        }
    }

    public IReadOnlyList<(string Path, bool Recursive)> ProtectedDirectories =>
    [
        (Path.Combine(_userProfile, ".gemini", "antigravity"), false),
        (Path.Combine(_userProfile, ".gemini", "antigravity", "conversations"), true),
        (Path.Combine(_userProfile, ".gemini", "antigravity", "brain"), true),
        (Path.Combine(_userProfile, ".gemini", "antigravity", "annotations"), true),
        (Path.Combine(_userProfile, ".gemini", "antigravity", "chapter_titles"), true),
        (Path.Combine(_userProfile, ".gemini", "antigravity", "cache"), true),
        (Path.Combine(_userProfile, ".gemini", "antigravity-cli"), false),
        (Path.Combine(_userProfile, ".gemini", "antigravity-cli", "conversations"), true),
        (Path.Combine(_userProfile, ".gemini", "antigravity-cli", "brain"), true),
        (Path.Combine(_userProfile, ".gemini", "antigravity-cli", "cache"), true),
    ];

    public UserStateSnapshot Capture()
    {
        var files = new Dictionary<string, UserStateFile>(StringComparer.OrdinalIgnoreCase);
        foreach (var path in ProtectedPaths)
        {
            files[path] = CaptureFile(path);
        }

        var directories = new Dictionary<string, UserStateDirectory>(StringComparer.OrdinalIgnoreCase);
        foreach (var (path, recursive) in ProtectedDirectories)
        {
            directories[path] = CaptureDirectory(path, recursive);
        }

        return new UserStateSnapshot(files, directories);
    }

    public IReadOnlyList<UserStateChange> Verify(
        UserStateSnapshot snapshot,
        IEnumerable<string> allowedPaths)
    {
        var allowed = new HashSet<string>(
            allowedPaths.Select(Path.GetFullPath),
            StringComparer.OrdinalIgnoreCase);
        var changes = new List<UserStateChange>();

        foreach (var (path, before) in snapshot.Files)
        {
            if (allowed.Contains(Path.GetFullPath(path)))
            {
                continue;
            }

            var after = CaptureFile(path);
            if (before.Exists != after.Exists)
            {
                changes.Add(new UserStateChange(path, before.Exists ? "removed" : "created"));
            }
            else if (before.Exists &&
                     !string.Equals(before.Sha256, after.Sha256, StringComparison.OrdinalIgnoreCase))
            {
                changes.Add(new UserStateChange(path, "content changed"));
            }
        }

        foreach (var (path, before) in snapshot.Directories)
        {
            if (allowed.Contains(Path.GetFullPath(path)))
            {
                continue;
            }

            var after = CaptureDirectory(path, before.Recursive);
            if (before.Exists != after.Exists)
            {
                changes.Add(new UserStateChange(path, before.Exists ? "directory removed" : "directory created"));
                continue;
            }

            if (!before.Exists)
            {
                continue;
            }

            foreach (var (relativePath, beforeEntry) in before.Entries)
            {
                if (!after.Entries.TryGetValue(relativePath, out var afterEntry))
                {
                    changes.Add(new UserStateChange(
                        Path.Combine(path, relativePath),
                        "history file removed"));
                }
                else if (beforeEntry.Length != afterEntry.Length ||
                         beforeEntry.LastWriteUtc != afterEntry.LastWriteUtc ||
                         !string.Equals(beforeEntry.Sha256, afterEntry.Sha256, StringComparison.OrdinalIgnoreCase))
                {
                    changes.Add(new UserStateChange(
                        Path.Combine(path, relativePath),
                        "history file changed"));
                }
            }

            foreach (var relativePath in after.Entries.Keys.Except(before.Entries.Keys, StringComparer.OrdinalIgnoreCase))
            {
                changes.Add(new UserStateChange(
                    Path.Combine(path, relativePath),
                    "history file created"));
            }
        }

        return changes;
    }

    public IReadOnlyList<string> Restore(
        UserStateSnapshot snapshot,
        IEnumerable<UserStateChange> changes)
    {
        var failures = new List<string>();
        foreach (var change in changes)
        {
            if (!snapshot.Files.TryGetValue(change.Path, out var before))
            {
                // Directory manifests and nested history files are detected, not reconstructed.
                // Report them rather than pretending a missing Antigravity history was restored.
                failures.Add(change.Path);
                continue;
            }

            try
            {
                if (!before.Exists)
                {
                    if (File.Exists(change.Path))
                    {
                        File.Delete(change.Path);
                    }

                    continue;
                }

                if (before.Content is null)
                {
                    failures.Add(change.Path);
                    continue;
                }

                Directory.CreateDirectory(Path.GetDirectoryName(change.Path)!);
                File.WriteAllBytes(change.Path, before.Content);
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                failures.Add(change.Path);
            }
        }

        return failures;
    }

    private static UserStateFile CaptureFile(string path)
    {
        try
        {
            if (!File.Exists(path))
            {
                return new UserStateFile(path, false, 0, null, null, null);
            }

            var info = new FileInfo(path);
            var content = info.Length <= MaxRestorableBytes
                ? File.ReadAllBytes(path)
                : null;
            var hash = content is null
                ? ComputeFileHash(path)
                : Convert.ToHexString(SHA256.HashData(content));

            return new UserStateFile(
                path,
                true,
                info.Length,
                info.LastWriteTimeUtc,
                hash,
                content);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return new UserStateFile(path, false, 0, null, null, null);
        }
    }

    private static UserStateDirectory CaptureDirectory(string path, bool recursive)
    {
        if (!Directory.Exists(path))
        {
            return new UserStateDirectory(
                path,
                false,
                recursive,
                new Dictionary<string, UserStateDirectoryEntry>(StringComparer.OrdinalIgnoreCase));
        }

        var entries = new Dictionary<string, UserStateDirectoryEntry>(StringComparer.OrdinalIgnoreCase);
        try
        {
            var options = new EnumerationOptions
            {
                RecurseSubdirectories = recursive,
                IgnoreInaccessible = true,
                AttributesToSkip = FileAttributes.ReparsePoint,
                ReturnSpecialDirectories = false,
            };

            foreach (var file in Directory.EnumerateFiles(path, "*", options))
            {
                var info = new FileInfo(file);
                entries[Path.GetRelativePath(path, file)] = new UserStateDirectoryEntry(
                    Path.GetRelativePath(path, file),
                    info.Length,
                    info.LastWriteTimeUtc,
                    ComputeFileHash(file));
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return new UserStateDirectory(
                path,
                false,
                recursive,
                new Dictionary<string, UserStateDirectoryEntry>(StringComparer.OrdinalIgnoreCase));
        }

        return new UserStateDirectory(path, true, recursive, entries);
    }

    private static string? ComputeFileHash(string path)
    {
        try
        {
            using var stream = File.OpenRead(path);
            return Convert.ToHexString(SHA256.HashData(stream));
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }
}
