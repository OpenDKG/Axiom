// SPDX-License-Identifier: GPL-3.0-or-later
using System.Globalization;

namespace Axiom.Infrastructure.Linux.ProcFs;

/// <summary>One process instance that owns a socket inode.</summary>
public readonly record struct SocketOwner(int ProcessId, long StartTimeTicks);

/// <summary>
/// Inode owners plus the inodes that more than one process shares. A shared socket cannot be
/// attributed to one process without guessing, so the capture reports it as partial.
/// </summary>
public sealed record SocketOwnershipMap(
    IReadOnlyDictionary<long, SocketOwner> Owners,
    IReadOnlySet<long> SharedInodes);

/// <summary>
/// Maps socket inodes to owning PIDs by walking <c>/proc/&lt;pid&gt;/fd</c>. Linux does not expose an
/// owner table; this is the documented user-space equivalent. Processes the caller may not inspect
/// are skipped and later shown as unattributed instead of being guessed.
/// </summary>
public sealed class ProcSocketInventory(string procRoot = "/proc")
{
    private readonly string _procRoot = procRoot;

    public SocketOwnershipMap BuildInodeOwnerMap(CancellationToken cancellationToken = default)
    {
        var owners = new Dictionary<long, SocketOwner>();
        var shared = new HashSet<long>();

        IEnumerable<string> directories;
        try
        {
            directories = Directory.EnumerateDirectories(_procRoot);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return new SocketOwnershipMap(owners, shared);
        }

        foreach (var directory in directories)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var name = Path.GetFileName(directory);
            if (!int.TryParse(name, NumberStyles.None, CultureInfo.InvariantCulture, out var pid) || pid <= 0)
            {
                continue;
            }

            var fdDirectory = Path.Combine(directory, "fd");
            IEnumerable<string> descriptors;
            try
            {
                descriptors = Directory.EnumerateFileSystemEntries(fdDirectory);
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                continue;
            }

            // Read the process instance identity before its descriptors. If the PID is recycled
            // while the fd list is being read, the start time lets the caller reject the stale
            // attribution instead of labelling the socket with an unrelated executable.
            var startTime = ProcProcessIdentityResolver.ReadStartTime(
                Path.Combine(directory, "stat"));

            try
            {
                foreach (var descriptor in descriptors)
                {
                    var target = TryReadLink(descriptor);
                    if (target is null)
                    {
                        continue;
                    }

                    if (!target.StartsWith("socket:[", StringComparison.Ordinal))
                    {
                        continue;
                    }

                    var inodeText = target.AsSpan("socket:[".Length);
                    if (inodeText.Length < 2 || inodeText[^1] != ']')
                    {
                        continue;
                    }

                    if (!long.TryParse(
                            inodeText[..^1],
                            NumberStyles.None,
                            CultureInfo.InvariantCulture,
                            out var inode))
                    {
                        continue;
                    }

                    if (owners.TryGetValue(inode, out var existing))
                    {
                        if (existing.ProcessId != pid)
                        {
                            shared.Add(inode);
                        }
                    }
                    else
                    {
                        owners.Add(inode, new SocketOwner(pid, startTime));
                    }
                }
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                // A process may exit mid-enumeration; its rows simply stay unattributed.
            }
        }

        return new SocketOwnershipMap(owners, shared);
    }

    private static string? TryReadLink(string path) => ProcLinkReader.Read(path);
}
