// SPDX-License-Identifier: GPL-3.0-or-later
using System.Collections.Concurrent;
using System.Runtime.Versioning;
using Axiom.Infrastructure.MacOS.Interop;

namespace Axiom.Infrastructure.MacOS.ProcessIdentity;

/// <summary>Who a process is, as far as macOS tells an unprivileged-free root daemon.</summary>
public sealed record MacProcessIdentity
{
    public required int ProcessId { get; init; }

    public required string Path { get; init; }

    public required string DisplayName { get; init; }

    public string BundlePath { get; init; } = string.Empty;

    public string BundleId { get; init; } = string.Empty;

    public string Version { get; init; } = string.Empty;

    public string SignerName { get; init; } = string.Empty;

    public string TeamId { get; init; } = string.Empty;

    public string SignatureStatus { get; init; } = "Unavailable";

    public int? ParentProcessId { get; init; }

    public string ParentProcessName { get; init; } = string.Empty;

    public string ParentChain { get; init; } = string.Empty;
}

/// <summary>
/// Resolves executable path (<c>proc_pidpath</c>), parent chain (<c>proc_bsdinfo</c>), bundle id /
/// name / version (enclosing <c>.app</c> Info.plist) and code signature (<c>codesign</c>, run in the
/// background once per path and cached). Pid entries are cached briefly because pids are reused.
/// </summary>
public sealed class MacProcessIdentityResolver : IProcessIdentitySource
{
    public static readonly TimeSpan PidCacheLifetime = TimeSpan.FromSeconds(30);

    private static readonly TimeSpan ToolTimeout = TimeSpan.FromSeconds(5);

    private readonly IProcessRunner _runner;

    private readonly Func<int, string> _pidPath;

    private readonly Func<int, LibProcBsdInfo?> _bsdInfo;

    private readonly TimeProvider _time;

    private readonly ConcurrentDictionary<int, (MacProcessIdentity Identity, DateTimeOffset Resolved)> _pids = new();

    private readonly ConcurrentDictionary<string, MacBundleInfo?> _bundles = new(StringComparer.Ordinal);

    private readonly ConcurrentDictionary<string, Lazy<Task<CodeSignatureInfo>>> _signatures = new(StringComparer.Ordinal);

    [SupportedOSPlatform("macos")]
    public MacProcessIdentityResolver()
        : this(ProcessRunner.Instance)
    {
    }

    [SupportedOSPlatform("macos")]
    public MacProcessIdentityResolver(IProcessRunner runner)
        : this(runner, LibProc.PidPath, LibProc.BsdInfo, TimeProvider.System)
    {
    }

    /// <summary>Testable wiring: libproc lookups and the clock are injected.</summary>
    public MacProcessIdentityResolver(
        IProcessRunner runner,
        Func<int, string> pidPath,
        Func<int, LibProcBsdInfo?> bsdInfo,
        TimeProvider time)
    {
        _runner = runner ?? throw new ArgumentNullException(nameof(runner));
        _pidPath = pidPath ?? throw new ArgumentNullException(nameof(pidPath));
        _bsdInfo = bsdInfo ?? throw new ArgumentNullException(nameof(bsdInfo));
        _time = time ?? throw new ArgumentNullException(nameof(time));
    }

    public MacProcessIdentity Resolve(int processId, string? knownPath)
    {
        var now = _time.GetUtcNow();
        if (_pids.TryGetValue(processId, out var cached) &&
            now - cached.Resolved < PidCacheLifetime &&
            (string.IsNullOrEmpty(knownPath) || string.Equals(cached.Identity.Path, knownPath, StringComparison.Ordinal)))
        {
            // Refresh the signature once the background check finished.
            return WithSignature(cached.Identity);
        }

        var path = string.IsNullOrEmpty(knownPath) && processId > 0 ? _pidPath(processId) : knownPath ?? string.Empty;
        var bsd = processId > 0 ? _bsdInfo(processId) : null;
        var bundlePath = MacBundleInfo.FindEnclosingBundle(path);
        var bundle = bundlePath is null ? null : _bundles.GetOrAdd(bundlePath, ReadBundle);

        var displayName = bundle?.Name is { Length: > 0 } bundleName
            ? bundleName
            : path.Length > 0
                ? System.IO.Path.GetFileName(path)
                : bsd?.Name is { Length: > 0 } name ? name : bsd?.Command ?? string.Empty;

        int? parent = bsd is { ParentProcessId: > 0 } ? bsd.ParentProcessId : null;
        var identity = new MacProcessIdentity
        {
            ProcessId = processId,
            Path = path,
            DisplayName = displayName,
            BundlePath = bundle?.BundlePath ?? string.Empty,
            BundleId = bundle?.BundleId ?? string.Empty,
            Version = bundle?.Version ?? string.Empty,
            ParentProcessId = parent,
            ParentProcessName = parent is { } parentPid ? ProcessName(parentPid) : string.Empty,
            ParentChain = ParentChain(parent),
        };

        _pids[processId] = (identity, now);
        if (_pids.Count > 4096)
        {
            foreach (var pair in _pids.Where(pair => now - pair.Value.Resolved > PidCacheLifetime).ToList())
            {
                _pids.TryRemove(pair.Key, out _);
            }
        }

        return WithSignature(identity);
    }

    /// <summary>Signature of <paramref name="path"/> if the background check has finished; else null.</summary>
    public CodeSignatureInfo? TryGetSignature(string path)
    {
        if (string.IsNullOrEmpty(path))
        {
            return null;
        }

        var lazy = _signatures.GetOrAdd(
            path,
            key => new Lazy<Task<CodeSignatureInfo>>(() => Task.Run(() => CheckSignature(key))));
        var task = lazy.Value;
        return task.IsCompletedSuccessfully ? task.Result : null;
    }

    private MacProcessIdentity WithSignature(MacProcessIdentity identity)
    {
        var target = identity.BundlePath.Length > 0 ? identity.BundlePath : identity.Path;
        var signature = TryGetSignature(target);
        return signature is null
            ? identity with { SignatureStatus = target.Length > 0 ? "Pending" : "Unavailable" }
            : identity with
            {
                SignerName = signature.SignerName,
                TeamId = signature.TeamId,
                SignatureStatus = signature.Status,
            };
    }

    private CodeSignatureInfo CheckSignature(string path)
    {
        var display = _runner.Run("/usr/bin/codesign", ["-dv", "--verbose=2", path], ToolTimeout);
        var text = display.StandardError + "\n" + display.StandardOutput;
        if (text.Contains("not signed at all", StringComparison.OrdinalIgnoreCase))
        {
            return CodeSignatureInfo.Parse(text, null);
        }

        if (!display.Succeeded)
        {
            return CodeSignatureInfo.Unavailable;
        }

        var verify = _runner.Run("/usr/bin/codesign", ["--verify", "--no-strict", path], ToolTimeout);
        return CodeSignatureInfo.Parse(text, verify.ExitCode is 0 or 1 ? verify.Succeeded : null);
    }

    private MacBundleInfo? ReadBundle(string bundlePath)
    {
        var plistPath = Path.Combine(bundlePath, "Contents", "Info.plist");
        try
        {
            if (!File.Exists(plistPath))
            {
                return null;
            }

            var text = File.ReadAllText(plistPath);
            var plist = MacBundleInfo.ParseXmlPlist(text);
            if (plist is null)
            {
                // Binary plist: let plutil convert it.
                var converted = _runner.Run("/usr/bin/plutil", ["-convert", "xml1", "-o", "-", plistPath], ToolTimeout);
                plist = converted.Succeeded ? MacBundleInfo.ParseXmlPlist(converted.StandardOutput) : null;
            }

            return plist is null ? null : MacBundleInfo.FromPlist(bundlePath, plist);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    private string ProcessName(int processId)
    {
        var path = _pidPath(processId);
        if (path.Length > 0)
        {
            return Path.GetFileName(path);
        }

        return _bsdInfo(processId)?.Command ?? string.Empty;
    }

    private string ParentChain(int? parent)
    {
        var names = new List<string>();
        var current = parent;
        for (var depth = 0; depth < 6 && current is > 1; depth++)
        {
            var info = _bsdInfo(current.Value);
            if (info is null)
            {
                break;
            }

            names.Add(info.Command);
            current = info.ParentProcessId == current ? null : info.ParentProcessId;
        }

        return string.Join(" < ", names);
    }
}
