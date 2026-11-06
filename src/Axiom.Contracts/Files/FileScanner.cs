// SPDX-License-Identifier: GPL-3.0-or-later
using System.Security.Cryptography;

namespace Axiom.Contracts.Files;

/// <summary>Computes SHA-256 for a local file. No bytes leave the process.</summary>
public static class FileHasher
{
    public const long DefaultMaxFileBytes = 64L * 1024 * 1024;

    public static async Task<string> ComputeSha256Async(string path, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        await using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: 81920,
            FileOptions.Asynchronous | FileOptions.SequentialScan);

        var hash = await SHA256.HashDataAsync(stream, cancellationToken).ConfigureAwait(false);
        return Convert.ToHexString(hash);
    }
}

public sealed record FileScanEntry(
    string Path,
    long SizeBytes,
    string? Sha256,
    string? SkippedReason);

/// <summary>
/// Bounded local folder scan. It hashes regular files, skips reparse points and files over the
/// limit, and never uploads, deletes or quarantines anything.
/// </summary>
public sealed class FileScanner
{
    public const int DefaultMaxFiles = 200;

    public static async Task<IReadOnlyList<FileScanEntry>> ScanAsync(
        string root,
        int maxFiles = DefaultMaxFiles,
        long maxFileBytes = FileHasher.DefaultMaxFileBytes,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(root);
        if (!Directory.Exists(root))
        {
            throw new DirectoryNotFoundException($"Folder not found: {root}");
        }

        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxFiles);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxFileBytes);

        var options = new EnumerationOptions
        {
            RecurseSubdirectories = true,
            IgnoreInaccessible = true,
            AttributesToSkip = FileAttributes.ReparsePoint,
            ReturnSpecialDirectories = false,
        };

        var results = new List<FileScanEntry>();

        foreach (var path in Directory.EnumerateFiles(root, "*", options).Take(maxFiles))
        {
            cancellationToken.ThrowIfCancellationRequested();

            long size;
            try
            {
                size = new FileInfo(path).Length;
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                results.Add(new FileScanEntry(path, 0, null, "metadata unavailable"));
                continue;
            }

            if (size > maxFileBytes)
            {
                results.Add(new FileScanEntry(path, size, null, "larger than limit"));
                continue;
            }

            try
            {
                var hash = await FileHasher.ComputeSha256Async(path, cancellationToken).ConfigureAwait(false);
                results.Add(new FileScanEntry(path, size, hash, null));
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                results.Add(new FileScanEntry(path, size, null, "unreadable"));
            }
        }

        return results;
    }
}
