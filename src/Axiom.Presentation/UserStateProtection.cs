// SPDX-License-Identifier: GPL-3.0-or-later
using System.IO;
using System.Security.Cryptography;

namespace Axiom.Presentation;

public sealed record UserStateFileSpec(
    string Path,
    string Category,
    bool HashContent = true);

public sealed record UserStateDirectorySpec(
    string Path,
    string Category,
    bool Recursive = true,
    bool HashContent = false);

public sealed record UserStateFile(
    string Path,
    bool Exists,
    long Length,
    DateTimeOffset? LastWriteUtc,
    string? Sha256,
    byte[]? Content,
    bool IsReparsePoint,
    string? LinkTarget,
    bool CaptureFailed = false);

public sealed record UserStateDirectoryEntry(
    string RelativePath,
    bool IsDirectory,
    bool IsReparsePoint,
    string? LinkTarget,
    long Length,
    DateTimeOffset LastWriteUtc,
    string? Sha256);

public sealed record UserStateDirectory(
    string Path,
    bool Exists,
    bool Recursive,
    bool IsReparsePoint,
    string? LinkTarget,
    IReadOnlyDictionary<string, UserStateDirectoryEntry> Entries,
    bool CaptureFailed = false);

public sealed record UserStateChange(string Path, string Reason);

public sealed class UserStateSnapshot(
    IReadOnlyDictionary<string, UserStateFile> files,
    IReadOnlyDictionary<string, UserStateDirectory> directories)
{
    public IReadOnlyDictionary<string, UserStateFile> Files { get; } = files;

    public IReadOnlyDictionary<string, UserStateDirectory> Directories { get; } = directories;
}

/// <summary>
/// Captures a bounded fingerprint of user-owned agent configuration, sessions, projects,
/// credentials, databases, history and Axiom settings. Hook installation, setup and uninstall
/// must change only explicitly allowed Axiom-owned paths; unexpected changes are detected and
/// small files can be restored from memory. Large databases are fingerprinted by size and
/// last-write time so a multi-gigabyte agent database is never loaded or rehashed on every action.
/// </summary>
public sealed class UserStateProtection
{
    private const int MaxRestorableBytes = 1024 * 1024;

    private const int MaxHashBytes = 64 * 1024 * 1024;

    private readonly string _userProfile;

    private readonly string _localAppData;

    private readonly string _roamingAppData;

    private readonly bool _includeHermesSettings;

    public UserStateProtection(
        string? userProfile = null,
        string? localAppData = null,
        string? roamingAppData = null,
        bool includeHermesSettings = true)
    {
        _userProfile = userProfile ?? Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        _localAppData = localAppData ?? Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        _roamingAppData = roamingAppData ?? Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        _includeHermesSettings = includeHermesSettings;
    }

    public IReadOnlyList<UserStateFileSpec> ProtectedFiles
    {
        get
        {
            var files = new List<UserStateFileSpec>
            {
                // OpenCode / OpenChamber configuration, credentials and state.
                HomeFile(".config/opencode/opencode.json", "OpenCode config"),
                HomeFile(".config/opencode/opencode.jsonc", "OpenCode config"),
                HomeFile(".config/opencode/config.json", "OpenCode config"),
                HomeFile(".config/opencode/auth.json", "OpenCode credentials"),
                HomeFile(".config/opencode/service.json", "OpenCode service config"),
                HomeFile(".config/openchamber/settings.json", "OpenChamber settings"),
                HomeFile(".config/openchamber/preferences.json", "OpenChamber settings"),
                HomeFile(".config/openchamber/relay-identity.json", "OpenChamber credentials"),
                HomeFile(".config/openchamber/git-credential-endpoint.json", "OpenChamber credentials"),
                HomeFile(".config/openchamber/message-queue.json", "OpenChamber sessions"),
                HomeFile(".config/openchamber/opencode.managed.json", "OpenChamber config"),
                HomeFile(".config/openchamber/discovered-apps.json", "OpenChamber config"),
                HomeFile(".local/share/opencode/account.json", "OpenCode credentials"),
                HomeFile(".local/share/opencode/auth.json", "OpenCode credentials"),
                HomeFile(".local/share/opencode/opencode.db", "OpenCode database", HashContent: false),
                HomeFile(".local/share/opencode/opencode.db-shm", "OpenCode database", HashContent: false),
                HomeFile(".local/share/opencode/opencode.db-wal", "OpenCode database", HashContent: false),

                // Codex configuration, credentials and databases.
                HomeFile(".codex/config.toml", "Codex config"),
                HomeFile(".codex/hooks.json", "Codex hooks"),
                HomeFile(".codex/auth.json", "Codex credentials"),
                HomeFile(".codex/auth.lock", "Codex credentials"),
                HomeFile(".codex/installation_id", "Codex state"),
                HomeFile(".codex/session_index.jsonl", "Codex sessions"),
                HomeFile(".codex/.codex-global-state.json", "Codex state"),
                HomeFile(".codex/cap_sid", "Codex state"),
                HomeFile(".codex/sqlite/codex.db", "Codex database", HashContent: false),
                HomeFile(".codex/goals_1.sqlite", "Codex database", HashContent: false),
                HomeFile(".codex/logs_2.sqlite", "Codex database", HashContent: false),
                HomeFile(".codex/memories_1.sqlite", "Codex database", HashContent: false),
                HomeFile(".codex/queue_1.sqlite", "Codex database", HashContent: false),
                HomeFile(".codex/state_5.sqlite", "Codex database", HashContent: false),
                HomeFile(".codex/thread_history_1.sqlite", "Codex sessions", HashContent: false),

                // Claude Code.
                HomeFile(".claude/settings.json", "Claude config"),
                HomeFile(".claude/.credentials.json", "Claude credentials"),
                HomeFile(".claude/history.jsonl", "Claude sessions"),
                HomeFile(".claude.json", "Claude state"),

                // Cursor and Copilot.
                HomeFile(".cursor/hooks.json", "Cursor hooks"),
                HomeFile(".cursor/mcp.json", "Cursor MCP config"),
                HomeFile(".codeium/windsurf/hooks.json", "Windsurf hooks"),
                HomeFile("Documents/Cline/Hooks/PreToolUse.py", "Cline hooks"),
                HomeFile(".copilot/config.json", "Copilot config"),
                HomeFile(".copilot/mcp-config.json", "Copilot MCP config"),
                HomeFile(".copilot/hooks/axiom.json", "Copilot hooks"),

                // ZCode user configuration and hook bridge.
                HomeFile(".zcode/cli/config.json", "ZCode config"),
                HomeFile(".zcode/AGENTS.md", "ZCode instructions"),

                // DeepSeek Harness configuration and its Claude hook bridge mount.
                HomeFile(".dsh/hooks.json", "DeepSeek hooks"),
                HomeFile(".dsh/axiom-hooks.json", "DeepSeek hooks"),
                HomeFile(".dsh/cordis.yml", "DeepSeek config"),
                HomeFile(".dsh/cordis.patch.yml", "DeepSeek config"),
                HomeFile(".dsh/AGENTS.md", "DeepSeek instructions"),

                // Hermes user state and Blackbox-managed Hermes configuration.
                LocalFile("hermes/config.yaml", "Hermes config"),
                LocalFile("hermes/SOUL.md", "Hermes memory"),

                // Gemini / Antigravity.
                HomeFile(".gemini/settings.json", "Gemini config"),
                HomeFile(".gemini/config/config.json", "Gemini config"),
                HomeFile(".gemini/config/mcp_config.json", "Gemini MCP config"),
                HomeFile(".gemini/antigravity/conversation_summaries.db", "Antigravity history"),
                HomeFile(".gemini/antigravity/antigravity_state.pbtxt", "Antigravity state"),
                HomeFile(".gemini/antigravity/installation_id", "Antigravity state"),
                HomeFile(".gemini/antigravity-cli/history.jsonl", "Antigravity CLI history"),
                HomeFile(".gemini/antigravity-cli/cache/last_conversations.json", "Antigravity CLI history"),
                HomeFile(".gemini/antigravity-cli/settings.json", "Antigravity CLI config"),
                HomeFile(".gemini/antigravity-cli/mcp_config.json", "Antigravity CLI MCP config"),

                // Windows agent application credentials and session stores.
                RoamingFile("Antigravity/app_storage.json", "Antigravity app state"),
                RoamingFile("Antigravity/credential-user-scope", "Antigravity credentials"),
                RoamingFile("Antigravity/Preferences", "Antigravity app state"),
                RoamingFile("Antigravity/Local State", "Antigravity app state"),
                RoamingFile("Cursor/User/settings.json", "Cursor settings"),
                RoamingFile("Cursor/User/globalStorage/state.vscdb", "Cursor sessions", HashContent: false),

                // Axiom's own user settings.
                LocalFile("Axiom/theme.txt", "Axiom settings"),
                LocalFile("Axiom/tray-notifications.txt", "Axiom settings"),
                LocalFile("Axiom/reputation.json", "Axiom settings"),
                LocalFile("Axiom/community-feed.json", "Axiom settings"),
                LocalFile("Axiom/onboarding.json", "Axiom settings"),
                LocalFile("Axiom/startup.json", "Axiom settings"),
                LocalFile("Axiom/blackbox-auto-sync.json", "Axiom Blackbox auto-sync settings"),
                LocalFile("Axiom/privacy-shield.json", "Axiom Privacy Shield settings"),
                LocalFile("Axiom/privacy-shield-blocked.jsonl", "Axiom Privacy Shield blocked history"),
                LocalFile("Axiom/ai-analyst.json", "Axiom AI analyst settings"),
                LocalFile("Axiom/ai-findings.json", "Axiom AI findings"),
                LocalFile("Axiom/firewall-defaults.json", "Axiom firewall defaults"),
            };

            if (_includeHermesSettings)
            {
                files.Add(HomeFile(".hermes/config.yaml", "Hermes/Blackbox config"));
            }

            return files;
        }
    }

    public IReadOnlyList<UserStateDirectorySpec> ProtectedDirectories
    {
        get
        {
            var directories = new List<UserStateDirectorySpec>
            {
                // OpenCode / OpenChamber sessions, projects and caches.
                HomeDir(".config/opencode", "OpenCode config", Recursive: false),
                HomeDir(".config/opencode/plugins", "OpenCode plugins", HashContent: true),
                HomeDir(".config/opencode/plugin", "OpenCode plugins", HashContent: true),
                HomeDir(".config/opencode/agents", "OpenCode agents", HashContent: true),
                HomeDir(".config/opencode/skills", "OpenCode skills", HashContent: true),
                HomeDir(".config/openchamber", "OpenChamber config", Recursive: false),
                HomeDir(".config/openchamber/chats", "OpenChamber sessions"),
                HomeDir(".config/openchamber/projects", "OpenChamber projects"),
                HomeDir(".config/openchamber/goals", "OpenChamber projects"),
                HomeDir(".config/openchamber/agent-tool", "OpenChamber tools"),
                HomeDir(".local/share/opencode", "OpenCode state", Recursive: false),
                HomeDir(".local/share/opencode/storage", "OpenCode sessions"),
                HomeDir(".local/share/opencode/repos", "OpenCode projects"),
                HomeDir(".local/share/opencode/snapshot", "OpenCode sessions"),
                HomeDir(".local/share/opencode/tool-output", "OpenCode sessions"),
                HomeDir(".cache/opencode", "OpenCode cache"),

                // Codex state, sessions and databases.
                HomeDir(".codex", "Codex state", Recursive: false),
                HomeDir(".codex/sessions", "Codex sessions"),
                HomeDir(".codex/sqlite", "Codex database"),
                HomeDir(".codex/plugins", "Codex plugins", HashContent: true),
                HomeDir(".codex/skills", "Codex skills", HashContent: true),
                HomeDir(".codex/automations", "Codex automations"),
                HomeDir(".codex/generated_images", "Codex generated files"),
                HomeDir(".codex/visualizations", "Codex generated files"),
                HomeDir(".codex/.sandbox-secrets", "Codex credentials"),

                // Claude, Cursor and Copilot state.
                HomeDir(".claude", "Claude state"),
                HomeDir(".cursor", "Cursor state"),
                HomeDir(".copilot", "Copilot state"),
                HomeDir(".zcode", "ZCode state", Recursive: false),
                HomeDir(".zcode/cli", "ZCode config", Recursive: false),
                HomeDir(".dsh", "DeepSeek Harness state", Recursive: false),
                HomeDir(".dsh/profiles", "DeepSeek profiles", Recursive: false),

                // Hermes user state. Installer-owned plugin/bin directories are intentionally excluded.
                LocalDir("hermes", "Hermes state", Recursive: false),
                LocalDir("hermes/sessions", "Hermes sessions"),
                LocalDir("hermes/memories", "Hermes memory"),
                LocalDir("hermes/skills", "Hermes skills", HashContent: true),
                LocalDir("hermes/tools", "Hermes tools", HashContent: true),
                LocalDir("hermes/cron", "Hermes automation"),
                LocalDir("hermes/hooks", "Hermes hooks", HashContent: true),
                LocalDir("hermes/pairing", "Hermes credentials", HashContent: true),

                // Gemini / Antigravity history.
                HomeDir(".gemini", "Gemini state", Recursive: false),
                HomeDir(".gemini/antigravity", "Antigravity history", Recursive: false),
                HomeDir(".gemini/antigravity/conversations", "Antigravity conversations", HashContent: true),
                HomeDir(".gemini/antigravity/brain", "Antigravity brain", HashContent: true),
                HomeDir(".gemini/antigravity/annotations", "Antigravity history", HashContent: true),
                HomeDir(".gemini/antigravity/chapter_titles", "Antigravity history", HashContent: true),
                HomeDir(".gemini/antigravity/cache", "Antigravity cache", HashContent: true),
                HomeDir(".gemini/antigravity-cli", "Antigravity CLI state", Recursive: false),
                HomeDir(".gemini/antigravity-cli/conversations", "Antigravity CLI conversations", HashContent: true),
                HomeDir(".gemini/antigravity-cli/brain", "Antigravity CLI brain", HashContent: true),
                HomeDir(".gemini/antigravity-cli/cache", "Antigravity CLI cache", HashContent: true),

                // Windows agent application state.
                RoamingDir("OpenCode", "OpenCode app state", Recursive: false),
                RoamingDir("OpenChamber", "OpenChamber app state", Recursive: false),
                RoamingDir("Codex", "Codex app state", Recursive: false),
                RoamingDir("Cursor", "Cursor app state", Recursive: false),
                RoamingDir("Antigravity", "Antigravity app state", Recursive: false),
                LocalDir("Codex", "Codex app state", Recursive: false),
            };

            return directories;
        }
    }

    public IReadOnlyList<string> ProtectedPaths => ProtectedFiles.Select(file => file.Path).ToArray();

    public UserStateSnapshot Capture()
    {
        var files = new Dictionary<string, UserStateFile>(StringComparer.OrdinalIgnoreCase);
        foreach (var spec in ProtectedFiles)
        {
            files[spec.Path] = CaptureFile(spec);
        }

        var directories = new Dictionary<string, UserStateDirectory>(StringComparer.OrdinalIgnoreCase);
        foreach (var spec in ProtectedDirectories)
        {
            directories[spec.Path] = CaptureDirectory(spec);
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
            if (before.CaptureFailed ||
                allowed.Contains(Path.GetFullPath(path)) ||
                IsAxiomBackupPath(path))
            {
                continue;
            }

            var spec = ProtectedFiles.FirstOrDefault(file =>
                string.Equals(file.Path, path, StringComparison.OrdinalIgnoreCase));
            var after = CaptureFile(spec ?? new UserStateFileSpec(path, "unknown"));
            if (after.CaptureFailed)
            {
                continue;
            }

            if (before.Exists != after.Exists)
            {
                changes.Add(new UserStateChange(path, before.Exists ? "removed" : "created"));
            }
            else if (before.Exists && FileChanged(before, after))
            {
                changes.Add(new UserStateChange(path, "content changed"));
            }
        }

        foreach (var (path, before) in snapshot.Directories)
        {
            if (before.CaptureFailed || allowed.Contains(Path.GetFullPath(path)))
            {
                continue;
            }

            var spec = ProtectedDirectories.FirstOrDefault(directory =>
                string.Equals(directory.Path, path, StringComparison.OrdinalIgnoreCase));
            var after = CaptureDirectory(spec ?? new UserStateDirectorySpec(path, "unknown", before.Recursive));
            if (after.CaptureFailed)
            {
                continue;
            }

            if (before.Exists != after.Exists)
            {
                if (!before.Exists && IsAllowedAncestor(path, allowed))
                {
                    continue;
                }

                changes.Add(new UserStateChange(path, before.Exists ? "directory removed" : "directory created"));
                continue;
            }

            if (!before.Exists)
            {
                continue;
            }

            if (before.IsReparsePoint != after.IsReparsePoint ||
                !string.Equals(before.LinkTarget, after.LinkTarget, StringComparison.OrdinalIgnoreCase))
            {
                changes.Add(new UserStateChange(path, "directory link changed"));
                continue;
            }

            foreach (var (relativePath, beforeEntry) in before.Entries)
            {
                var entryPath = Path.Combine(path, relativePath);
                if (allowed.Contains(Path.GetFullPath(entryPath)) || IsAxiomBackupPath(entryPath))
                {
                    continue;
                }

                if (!after.Entries.TryGetValue(relativePath, out var afterEntry))
                {
                    changes.Add(new UserStateChange(
                        entryPath,
                        beforeEntry.IsDirectory ? "directory removed" : "file removed"));
                }
                else if (EntryChanged(beforeEntry, afterEntry))
                {
                    changes.Add(new UserStateChange(
                        entryPath,
                        beforeEntry.IsDirectory ? "directory changed" : "file changed"));
                }
            }

            foreach (var relativePath in after.Entries.Keys.Except(before.Entries.Keys, StringComparer.OrdinalIgnoreCase))
            {
                var entryPath = Path.Combine(path, relativePath);
                if (allowed.Contains(Path.GetFullPath(entryPath)) ||
                    IsAxiomBackupPath(entryPath) ||
                    (after.Entries[relativePath].IsDirectory && IsAllowedAncestor(entryPath, allowed)))
                {
                    continue;
                }

                changes.Add(new UserStateChange(
                    entryPath,
                    "file or directory created"));
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
                // Directory manifests and nested files are detected, not reconstructed.
                failures.Add(change.Path);
                continue;
            }

            try
            {
                if (before.CaptureFailed || before.IsReparsePoint)
                {
                    // Never delete a path that was only assumed absent because its state could not
                    // be read. An unreadable file may still be a user credential or session store.
                    failures.Add(change.Path);
                    continue;
                }

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

    private static string Normalize(string relativePath) =>
        relativePath.Replace('/', Path.DirectorySeparatorChar);

    private UserStateFileSpec HomeFile(string relativePath, string category, bool HashContent = true) =>
        new(Path.Combine(_userProfile, Normalize(relativePath)), category, HashContent);

    private UserStateFileSpec LocalFile(string relativePath, string category, bool HashContent = true) =>
        new(Path.Combine(_localAppData, Normalize(relativePath)), category, HashContent);

    private UserStateFileSpec RoamingFile(string relativePath, string category, bool HashContent = true) =>
        new(Path.Combine(_roamingAppData, Normalize(relativePath)), category, HashContent);

    private UserStateDirectorySpec HomeDir(
        string relativePath,
        string category,
        bool Recursive = true,
        bool HashContent = false) =>
        new(Path.Combine(_userProfile, Normalize(relativePath)), category, Recursive, HashContent);

    private UserStateDirectorySpec LocalDir(
        string relativePath,
        string category,
        bool Recursive = true,
        bool HashContent = false) =>
        new(Path.Combine(_localAppData, Normalize(relativePath)), category, Recursive, HashContent);

    private UserStateDirectorySpec RoamingDir(
        string relativePath,
        string category,
        bool Recursive = true,
        bool HashContent = false) =>
        new(Path.Combine(_roamingAppData, Normalize(relativePath)), category, Recursive, HashContent);

    private static UserStateFile CaptureFile(UserStateFileSpec spec)
    {
        var path = spec.Path;
        try
        {
            try
            {
                _ = File.GetAttributes(path);
            }
            catch (Exception exception) when (exception is FileNotFoundException or DirectoryNotFoundException)
            {
                return new UserStateFile(path, false, 0, null, null, null, false, null);
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                return new UserStateFile(
                    path,
                    Exists: false,
                    Length: 0,
                    LastWriteUtc: null,
                    Sha256: null,
                    Content: null,
                    IsReparsePoint: false,
                    LinkTarget: null,
                    CaptureFailed: true);
            }

            var info = new FileInfo(path);
            if (!info.Exists)
            {
                // The file existed a moment ago but could not be inspected. Treat this as an
                // unknown state, not as "absent", so restore never deletes it.
                return new UserStateFile(
                    path,
                    Exists: false,
                    Length: 0,
                    LastWriteUtc: null,
                    Sha256: null,
                    Content: null,
                    IsReparsePoint: false,
                    LinkTarget: null,
                    CaptureFailed: true);
            }

            var isReparsePoint = (info.Attributes & FileAttributes.ReparsePoint) != 0;
            if (isReparsePoint)
            {
                return new UserStateFile(
                    path,
                    true,
                    info.Length,
                    info.LastWriteTimeUtc,
                    null,
                    null,
                    true,
                    info.LinkTarget);
            }

            var content = spec.HashContent && info.Length <= MaxRestorableBytes
                ? File.ReadAllBytes(path)
                : null;
            var hash = spec.HashContent && info.Length <= MaxHashBytes
                ? content is null
                    ? ComputeFileHash(path)
                    : Convert.ToHexString(SHA256.HashData(content))
                : null;

            return new UserStateFile(
                path,
                true,
                info.Length,
                info.LastWriteTimeUtc,
                hash,
                content,
                false,
                null);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return new UserStateFile(
                path,
                Exists: false,
                Length: 0,
                LastWriteUtc: null,
                Sha256: null,
                Content: null,
                IsReparsePoint: false,
                LinkTarget: null,
                CaptureFailed: true);
        }
    }

    private static UserStateDirectory CaptureDirectory(UserStateDirectorySpec spec)
    {
        var path = spec.Path;
        try
        {
            try
            {
                _ = File.GetAttributes(path);
            }
            catch (Exception exception) when (exception is DirectoryNotFoundException)
            {
                return new UserStateDirectory(
                    path,
                    false,
                    spec.Recursive,
                    false,
                    null,
                    new Dictionary<string, UserStateDirectoryEntry>(StringComparer.OrdinalIgnoreCase));
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                return new UserStateDirectory(
                    path,
                    Exists: false,
                    Recursive: spec.Recursive,
                    IsReparsePoint: false,
                    LinkTarget: null,
                    Entries: new Dictionary<string, UserStateDirectoryEntry>(StringComparer.OrdinalIgnoreCase),
                    CaptureFailed: true);
            }

            var info = new DirectoryInfo(path);
            if (!info.Exists)
            {
                return new UserStateDirectory(
                    path,
                    Exists: false,
                    Recursive: spec.Recursive,
                    IsReparsePoint: false,
                    LinkTarget: null,
                    Entries: new Dictionary<string, UserStateDirectoryEntry>(StringComparer.OrdinalIgnoreCase),
                    CaptureFailed: true);
            }

            var isReparsePoint = (info.Attributes & FileAttributes.ReparsePoint) != 0;
            if (isReparsePoint)
            {
                return new UserStateDirectory(
                    path,
                    true,
                    spec.Recursive,
                    true,
                    info.LinkTarget,
                    new Dictionary<string, UserStateDirectoryEntry>(StringComparer.OrdinalIgnoreCase));
            }

            var entries = new Dictionary<string, UserStateDirectoryEntry>(StringComparer.OrdinalIgnoreCase);
            CaptureDirectoryEntries(
                path,
                path,
                spec,
                entries,
                new HashSet<string>(StringComparer.OrdinalIgnoreCase));
            return new UserStateDirectory(path, true, spec.Recursive, false, null, entries);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return new UserStateDirectory(
                path,
                Exists: false,
                Recursive: spec.Recursive,
                IsReparsePoint: false,
                LinkTarget: null,
                Entries: new Dictionary<string, UserStateDirectoryEntry>(StringComparer.OrdinalIgnoreCase),
                CaptureFailed: true);
        }
    }

    private static void CaptureDirectoryEntries(
        string root,
        string current,
        UserStateDirectorySpec spec,
        Dictionary<string, UserStateDirectoryEntry> entries,
        HashSet<string> visited)
    {
        if (!visited.Add(current))
        {
            return;
        }

        foreach (var entry in new DirectoryInfo(current).EnumerateFileSystemInfos(
                     "*",
                     new EnumerationOptions
                     {
                         IgnoreInaccessible = true,
                         AttributesToSkip = 0,
                         RecurseSubdirectories = false,
                         ReturnSpecialDirectories = false,
                     }))
        {
            var relativePath = Path.GetRelativePath(root, entry.FullName);
            var isReparsePoint = (entry.Attributes & FileAttributes.ReparsePoint) != 0;
            if (entry is DirectoryInfo directory)
            {
                entries[relativePath] = new UserStateDirectoryEntry(
                    relativePath,
                    true,
                    isReparsePoint,
                    isReparsePoint ? directory.LinkTarget : null,
                    0,
                    directory.LastWriteTimeUtc,
                    null);
                if (spec.Recursive && !isReparsePoint)
                {
                    CaptureDirectoryEntries(root, directory.FullName, spec, entries, visited);
                }

                continue;
            }

            if (entry is FileInfo file)
            {
                var hash = spec.HashContent && file.Length <= MaxHashBytes
                    ? ComputeFileHash(file.FullName)
                    : null;
                entries[relativePath] = new UserStateDirectoryEntry(
                    relativePath,
                    false,
                    isReparsePoint,
                    isReparsePoint ? file.LinkTarget : null,
                    file.Length,
                    file.LastWriteTimeUtc,
                    hash);
            }
        }
    }

    private static bool IsAxiomBackupPath(string path) =>
        Path.GetFileName(path).Contains(".axiom-backup-", StringComparison.Ordinal);

    private static bool IsAllowedAncestor(string directoryPath, HashSet<string> allowed)
    {
        var prefix = Path.GetFullPath(directoryPath)
            .TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        return allowed.Any(path => path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase));
    }

    private static bool FileChanged(UserStateFile before, UserStateFile after) =>
        before.IsReparsePoint != after.IsReparsePoint ||
        !string.Equals(before.LinkTarget, after.LinkTarget, StringComparison.OrdinalIgnoreCase) ||
        before.Length != after.Length ||
        before.LastWriteUtc != after.LastWriteUtc ||
        !string.Equals(before.Sha256, after.Sha256, StringComparison.OrdinalIgnoreCase);

    private static bool EntryChanged(UserStateDirectoryEntry before, UserStateDirectoryEntry after) =>
        before.IsDirectory != after.IsDirectory ||
        before.IsReparsePoint != after.IsReparsePoint ||
        !string.Equals(before.LinkTarget, after.LinkTarget, StringComparison.OrdinalIgnoreCase) ||
        (!before.IsDirectory &&
         (before.Length != after.Length ||
          before.LastWriteUtc != after.LastWriteUtc ||
          !string.Equals(before.Sha256, after.Sha256, StringComparison.OrdinalIgnoreCase)));

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
