// SPDX-License-Identifier: GPL-3.0-or-later
using System.Reflection;
using System.Runtime.InteropServices;
using Axiom.Contracts.Firewall;
using Axiom.Core.Firewall;
using Axiom.Infrastructure.Linux.Firewall.Bpf;

namespace Axiom.Infrastructure.Linux.Firewall;

/// <summary>
/// Per-executable firewall policy on Linux via eBPF cgroup socket hooks. nftables/iptables cannot
/// match an executable path, and UID-only or port-global rules would silently widen the user's
/// choice, so this adapter uses <c>cgroup/connect4|connect6|udp4_sendmsg|udp6_sendmsg|bind4|bind6</c>
/// programs that compare the calling task's executable identity with the policy maps.
/// <para>
/// Reads (capability, list, verify) never change the host. Writes require both
/// <c>AXIOM_ENABLE_FIREWALL_WRITES=1</c> and <c>AXIOM_FIREWALL_WRITE_CONFIRM=yes</c>, the same
/// gate as Windows. Rules are owned by this process; exiting or crashing detaches enforcement.
/// </para>
/// </summary>
public sealed class LinuxFirewallPolicyAdapter : IFirewallPolicyAdapter, IFirewallPolicyRestorer, IDisposable
{
    public const string WriteEnableVariable = "AXIOM_ENABLE_FIREWALL_WRITES";

    public const string WriteConfirmVariable = "AXIOM_FIREWALL_WRITE_CONFIRM";

    public const string CgroupVariable = "AXIOM_FIREWALL_CGROUP";

    private const string DefaultCgroupPath = "/sys/fs/cgroup";

    private const string ObjectResourceName =
        "Axiom.Infrastructure.Linux.Firewall.axiom_fw.bpf.o";

    private static readonly (string Name, int AttachType)[] Hooks =
    [
        ("np_connect4", 10),      // BPF_CGROUP_INET4_CONNECT
        ("np_connect6", 11),      // BPF_CGROUP_INET6_CONNECT
        ("np_udp4_sendmsg", 14),  // BPF_CGROUP_UDP4_SENDMSG
        ("np_udp6_sendmsg", 15),  // BPF_CGROUP_UDP6_SENDMSG
        ("np_bind4", 8),          // BPF_CGROUP_INET4_BIND
        ("np_bind6", 9),          // BPF_CGROUP_INET6_BIND
    ];

    private static readonly string[] MapNames =
    [
        "np_config",
        "np_exes",
        "np_rules",
        "np_name_scratch",
    ];

    private readonly string _cgroupPath;

    private readonly Func<bool> _writeGate;

    private readonly byte[]? _objectOverride;

    private readonly SemaphoreSlim _gate = new(1, 1);

    private readonly Dictionary<Guid, RuleSpec> _desired = [];

    private BpfObject? _object;

    private int _cgroupFd = -1;

    private readonly List<IntPtr> _links = [];

    private bool _attached;

    private string? _lastError;

    public LinuxFirewallPolicyAdapter(
        string? cgroupPath = null,
        Func<bool>? writeGate = null,
        byte[]? objectOverride = null)
    {
        _cgroupPath = cgroupPath ??
                      Environment.GetEnvironmentVariable(CgroupVariable) ??
                      DefaultCgroupPath;
        _writeGate = writeGate ?? (() => IsWriteGateOpen);
        _objectOverride = objectOverride;
    }

    public static bool IsWriteGateOpen =>
        string.Equals(Environment.GetEnvironmentVariable(WriteEnableVariable), "1", StringComparison.Ordinal) &&
        string.Equals(Environment.GetEnvironmentVariable(WriteConfirmVariable), "yes", StringComparison.OrdinalIgnoreCase);

    public async Task<FirewallCapabilityReport> GetCapabilitiesAsync(CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        await _gate.WaitAsync(ct).ConfigureAwait(false);

        try
        {
            EnsureLoaded();
            var gateOpen = _writeGate();

            return new FirewallCapabilityReport
            {
                Status = FirewallCapabilityStatus.Available,
                Reason = gateOpen
                    ? (_lastError is null ? null : _lastError)
                    : "Linux per-executable enforcement is available but writes are disabled " +
                      $"(set {WriteEnableVariable}=1 and {WriteConfirmVariable}=yes on an isolated test host).",
                FirewallServiceRunning = null,
                ManagedRulesReadable = true,
                ManagedRuleCount = _desired.Count,
            };
        }
        catch (Exception exception) when (exception is PlatformNotSupportedException or IOException or UnauthorizedAccessException)
        {
            return Unavailable(exception.Message);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<IReadOnlyList<ManagedRule>> ListOwnedRulesAsync(CancellationToken ct)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var rules = new List<ManagedRule>(_desired.Count);
            foreach (var spec in _desired.Values.OrderBy(spec => spec.ManagedRuleId))
            {
                var applied = false;
                try
                {
                    applied = _object is not null &&
                              ExecutableIdentity.TryResolve(spec.AppPath, out var identity, out _) &&
                              VerifyState(identity!, SpecsFor(identity!));
                }
                catch (Exception exception) when (exception is PlatformNotSupportedException or IOException)
                {
                    applied = false;
                }

                rules.Add(new ManagedRule
                {
                    ManagedRuleId = spec.ManagedRuleId,
                    OsRuleName = OwnedRuleName.Create(spec.ManagedRuleId, spec.Direction),
                    Spec = spec,
                    State = applied ? RuleState.Applied : RuleState.Desired,
                    LastVerifiedUtc = applied ? DateTimeOffset.UtcNow : null,
                });
            }

            return rules;
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<RuleApplyResult> UpsertOwnedRuleAsync(RuleSpec spec, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(spec);
        EnsureWriteGateOpen();
        await _gate.WaitAsync(ct).ConfigureAwait(false);

        RuleSpec? previous = null;
        try
        {
            if (!ExecutableIdentity.TryResolve(spec.AppPath, out var identity, out var identityError))
            {
                return Failed(spec.ManagedRuleId, "rule.path.invalid", identityError!);
            }

            _desired.TryGetValue(spec.ManagedRuleId, out previous);
            var previousIdentity = previous is not null &&
                                   ExecutableIdentity.TryResolve(previous.AppPath, out var oldIdentity, out _)
                ? oldIdentity
                : null;

            _desired[spec.ManagedRuleId] = spec;

            var affected = new List<ExecutableIdentity> { identity! };
            if (previousIdentity is not null && previousIdentity != identity)
            {
                affected.Add(previousIdentity);
            }

            var result = await RewriteAsync(spec.ManagedRuleId, affected, ct).ConfigureAwait(false);
            if (!result.Success)
            {
                if (previous is null)
                {
                    _desired.Remove(spec.ManagedRuleId);
                }
                else
                {
                    _desired[spec.ManagedRuleId] = previous;
                }
            }

            return result;
        }
        catch (FirewallPolicyException exception)
        {
            _lastError = exception.Message;
            if (previous is null)
            {
                _desired.Remove(spec.ManagedRuleId);
            }
            else
            {
                _desired[spec.ManagedRuleId] = previous;
            }

            return Failed(spec.ManagedRuleId, exception.Code, exception.Message);
        }
        catch (Exception exception) when (exception is PlatformNotSupportedException or IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            _lastError = exception.Message;
            if (previous is null)
            {
                _desired.Remove(spec.ManagedRuleId);
            }
            else
            {
                _desired[spec.ManagedRuleId] = previous;
            }

            return Failed(spec.ManagedRuleId, "rule.apply_failed", exception.Message);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<RuleApplyResult> RemoveOwnedRuleAsync(Guid managedRuleId, CancellationToken ct)
    {
        if (managedRuleId == Guid.Empty)
        {
            throw new ArgumentException("Managed rule id must not be empty.", nameof(managedRuleId));
        }

        EnsureWriteGateOpen();
        await _gate.WaitAsync(ct).ConfigureAwait(false);

        try
        {
            if (!_desired.TryGetValue(managedRuleId, out var previous))
            {
                return new RuleApplyResult
                {
                    Success = true,
                    ManagedRuleId = managedRuleId,
                    State = RuleState.Desired,
                    VerifiedUtc = DateTimeOffset.UtcNow,
                };
            }

            if (!ExecutableIdentity.TryResolve(previous.AppPath, out var identity, out var error))
            {
                // Keep the desired entry: the kernel slots still exist and the rule must stay
                // visible until its executable can be resolved again for a verified removal.
                return Failed(managedRuleId, "rule.path.invalid", error!);
            }

            _desired.Remove(managedRuleId);
            try
            {
                var result = await RewriteAsync(managedRuleId, [identity!], ct).ConfigureAwait(false);
                if (!result.Success)
                {
                    _desired[managedRuleId] = previous;
                }

                return result;
            }
            catch
            {
                // Any failure after the desired entry was dropped must keep the rule visible: the
                // kernel slots may still exist and a second removal would otherwise report success.
                _desired[managedRuleId] = previous;
                throw;
            }
        }
        catch (FirewallPolicyException exception)
        {
            _lastError = exception.Message;
            return Failed(managedRuleId, exception.Code, exception.Message);
        }
        catch (Exception exception) when (exception is PlatformNotSupportedException or IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            _lastError = exception.Message;
            return Failed(managedRuleId, "rule.remove_failed", exception.Message);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<EffectiveRuleReport> VerifyAsync(RuleSpec spec, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(spec);
        if (spec.ManagedRuleId == Guid.Empty)
        {
            throw new ArgumentException("Managed rule id must not be empty.", nameof(spec));
        }

        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (!ExecutableIdentity.TryResolve(spec.AppPath, out var identity, out var error))
            {
                return new EffectiveRuleReport
                {
                    ManagedRuleId = spec.ManagedRuleId,
                    PresentInOs = false,
                    MatchesSpec = false,
                    EffectiveAction = null,
                    Notes = [error!],
                };
            }

            EnsureLoaded();
            var specs = SpecsFor(identity!)
                .Where(item => item.ManagedRuleId != spec.ManagedRuleId)
                .Append(spec)
                .ToList();

            var present = VerifyState(identity!, specs);
            var notes = new List<string>();
            if (!present)
            {
                notes.Add(_attached
                    ? "The kernel policy does not contain this executable/rule combination."
                    : "Enforcement is not attached (write gate closed or no applied rules).");
            }

            return new EffectiveRuleReport
            {
                ManagedRuleId = spec.ManagedRuleId,
                PresentInOs = present,
                MatchesSpec = present,
                EffectiveAction = present ? spec.Action : null,
                Notes = notes,
            };
        }
        catch (Exception exception) when (exception is PlatformNotSupportedException or IOException or UnauthorizedAccessException)
        {
            return new EffectiveRuleReport
            {
                ManagedRuleId = spec.ManagedRuleId,
                PresentInOs = false,
                MatchesSpec = false,
                EffectiveAction = null,
                Notes = [exception.Message],
            };
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task RestoreAsync(IReadOnlyList<RuleSpec> specs, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(specs);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            _desired.Clear();
            foreach (var spec in specs)
            {
                _desired[spec.ManagedRuleId] = spec;
            }

            if (_desired.Count == 0 || !_writeGate())
            {
                return;
            }

            var identities = new List<ExecutableIdentity>();
            foreach (var spec in _desired.Values)
            {
                if (ExecutableIdentity.TryResolve(spec.AppPath, out var identity, out _) &&
                    identities.All(existing => existing != identity))
                {
                    identities.Add(identity!);
                }
            }

            // Reuse the normal apply path so a restored rule loads the object, attaches the
            // hooks, writes the maps and reads them back exactly like an interactive apply. Each
            // executable is restored independently: a persisted rule that is no longer expressible
            // (for example an inbound remote-port rule) must not stop unrelated valid rules from
            // being enforced after a restart.
            foreach (var identity in identities)
            {
                try
                {
                    var restored = await RewriteAsync(Guid.Empty, [identity], cancellationToken)
                        .ConfigureAwait(false);
                    if (!restored.Success)
                    {
                        _lastError = restored.ErrorMessage;
                    }
                }
                catch (FirewallPolicyException exception)
                {
                    _lastError = exception.Message;
                }
                catch (Exception exception) when (exception is PlatformNotSupportedException or IOException or UnauthorizedAccessException or InvalidOperationException)
                {
                    _lastError = exception.Message;
                }
            }
        }
        catch (Exception exception) when (exception is PlatformNotSupportedException or IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            _lastError = exception.Message;
        }
        finally
        {
            _gate.Release();
        }
    }

    public void Dispose()
    {
        try
        {
            Detach();
        }
        catch (Exception exception) when (exception is PlatformNotSupportedException or IOException)
        {
            // Process exit is not the place to throw; the link dies with the process anyway.
            _ = exception;
        }

        _object?.Dispose();
        _object = null;
        _gate.Dispose();
    }

    private async Task<RuleApplyResult> RewriteAsync(
        Guid managedRuleId,
        IReadOnlyList<ExecutableIdentity> identities,
        CancellationToken ct)
    {
        // Compile before touching the kernel so an unsupported spec fails with its own error code
        // instead of a load/attach error, and so a rejected rule never reaches the maps.
        var compiledStates = identities
            .Select(identity => CompileFor(identity))
            .ToList();

        EnsureLoaded();
        var snapshots = identities.ToDictionary(identity => identity, Snapshot);

        try
        {
            EnsureAttached();
            foreach (var compiled in compiledStates)
            {
                WriteExecutable(compiled);
            }

            foreach (var identity in identities)
            {
                var specs = SpecsFor(identity);
                if (!VerifyState(identity, specs))
                {
                    throw new InvalidOperationException("The kernel policy did not read back as written.");
                }
            }

            if (_desired.Count == 0)
            {
                Detach();
            }

            return new RuleApplyResult
            {
                Success = true,
                ManagedRuleId = managedRuleId,
                State = RuleState.Applied,
                OsRuleName = managedRuleId == Guid.Empty
                    ? null
                    : OwnedRuleName.Create(
                        managedRuleId,
                        _desired.TryGetValue(managedRuleId, out var spec) ? spec.Direction : FirewallDirection.Outbound),
                VerifiedUtc = DateTimeOffset.UtcNow,
            };
        }
        catch (FirewallPolicyException exception)
        {
            _lastError = exception.Message;
            return Failed(
                managedRuleId,
                exception.Code,
                Rollback(exception.Message, snapshots.Values));
        }
        catch (Exception exception) when (exception is PlatformNotSupportedException or IOException or InvalidOperationException)
        {
            _lastError = exception.Message;
            return Failed(
                managedRuleId,
                "rule.apply_failed",
                Rollback(exception.Message, snapshots.Values));
        }
    }

    private CompiledExecutable CompileFor(ExecutableIdentity identity)
    {
        var specs = SpecsFor(identity);
        if (!FirewallPolicyCompiler.TryCompile(identity, specs, out var compiled, out var error))
        {
            throw new FirewallPolicyException(error!.Code, error.Message);
        }

        return compiled!;
    }

    private RuleSpec[] SpecsFor(ExecutableIdentity identity) =>
        _desired.Values
            .Where(spec => ExecutableIdentity.TryResolve(spec.AppPath, out var candidate, out _) && candidate == identity)
            .OrderBy(spec => spec.ManagedRuleId)
            .ToArray();

    private void WriteExecutable(CompiledExecutable compiled)
    {
        var exeKey = FirewallPolicyLayout.ExeKey(compiled.Identity);
        var objectKey = _object!;

        for (var index = 0; index < compiled.Slots.Count; index++)
        {
            var ruleKey = FirewallPolicyLayout.RuleKey(compiled.Identity.HashHi, compiled.Identity.HashLo, index);
            var value = FirewallPolicyLayout.RuleValue(compiled.Slots[index]);
            if (objectKey.UpdateMap("np_rules", ruleKey, value) != 0)
            {
                throw new IOException($"Writing firewall rule slot {index} failed (errno {NativeBpf.LastErrno}).");
            }
        }

        for (var index = compiled.Slots.Count; index < FirewallPolicyLayout.MaxSlots; index++)
        {
            var ruleKey = FirewallPolicyLayout.RuleKey(compiled.Identity.HashHi, compiled.Identity.HashLo, index);
            _ = objectKey.DeleteMap("np_rules", ruleKey);
        }

        if (compiled.Slots.Count == 0)
        {
            _ = objectKey.DeleteMap("np_exes", exeKey);
            return;
        }

        var exeValue = FirewallPolicyLayout.ExeValue(compiled.AllowOut, compiled.AllowIn, compiled.Slots.Count);
        if (objectKey.UpdateMap("np_exes", exeKey, exeValue) != 0)
        {
            throw new IOException($"Writing the firewall executable policy failed (errno {NativeBpf.LastErrno}).");
        }
    }

    private bool VerifyState(ExecutableIdentity identity, IReadOnlyList<RuleSpec> specs)
    {
        if (_object is null)
        {
            return false;
        }

        if (!FirewallPolicyCompiler.TryCompile(identity, specs, out var compiled, out _))
        {
            return false;
        }

        var exeKey = FirewallPolicyLayout.ExeKey(identity);
        var exeValue = new byte[FirewallPolicyLayout.ExeValueSize];

        if (compiled!.Slots.Count == 0)
        {
            return !_object.TryLookupMap("np_exes", exeKey, exeValue);
        }

        if (!_object.TryLookupMap("np_exes", exeKey, exeValue))
        {
            return false;
        }

        var expectedExe = FirewallPolicyLayout.ExeValue(compiled.AllowOut, compiled.AllowIn, compiled.Slots.Count);
        if (!exeValue.AsSpan().SequenceEqual(expectedExe))
        {
            return false;
        }

        for (var index = 0; index < compiled.Slots.Count; index++)
        {
            var ruleKey = FirewallPolicyLayout.RuleKey(identity.HashHi, identity.HashLo, index);
            var actual = new byte[FirewallPolicyLayout.RuleValueSize];
            if (!_object.TryLookupMap("np_rules", ruleKey, actual) ||
                !actual.AsSpan().SequenceEqual(FirewallPolicyLayout.RuleValue(compiled.Slots[index])))
            {
                return false;
            }
        }

        return true;
    }

    private ExeSnapshot Snapshot(ExecutableIdentity identity)
    {
        var exeKey = FirewallPolicyLayout.ExeKey(identity);
        var exeValue = new byte[FirewallPolicyLayout.ExeValueSize];
        var hadExe = _object is not null && _object.TryLookupMap("np_exes", exeKey, exeValue);
        var slots = new Dictionary<int, byte[]>();

        if (_object is not null)
        {
            for (var index = 0; index < FirewallPolicyLayout.MaxSlots; index++)
            {
                var ruleKey = FirewallPolicyLayout.RuleKey(identity.HashHi, identity.HashLo, index);
                var value = new byte[FirewallPolicyLayout.RuleValueSize];
                if (_object.TryLookupMap("np_rules", ruleKey, value))
                {
                    slots[index] = value;
                }
            }
        }

        return new ExeSnapshot(identity, hadExe, exeValue, slots);
    }

    /// <summary>
    /// Restores every touched executable from its snapshot and reports a failure instead of
    /// returning the original error as if the previous policy were intact.
    /// </summary>
    private string Rollback(string originalMessage, IEnumerable<ExeSnapshot> snapshots)
    {
        var restored = true;
        foreach (var snapshot in snapshots)
        {
            restored &= RestoreSnapshot(snapshot);
        }

        return restored
            ? originalMessage
            : $"{originalMessage} (the previous firewall policy could not be verified after rollback; " +
              "enforcement may be incomplete until the service is restarted)";
    }

    private bool RestoreSnapshot(ExeSnapshot snapshot)
    {
        if (_object is null)
        {
            return true;
        }

        var exeKey = FirewallPolicyLayout.ExeKey(snapshot.Identity);
        if (!DeleteIfPresent("np_exes", exeKey))
        {
            return false;
        }

        for (var index = 0; index < FirewallPolicyLayout.MaxSlots; index++)
        {
            var ruleKey = FirewallPolicyLayout.RuleKey(snapshot.Identity.HashHi, snapshot.Identity.HashLo, index);
            if (!DeleteIfPresent("np_rules", ruleKey))
            {
                return false;
            }
        }

        foreach (var (index, value) in snapshot.Slots)
        {
            var ruleKey = FirewallPolicyLayout.RuleKey(snapshot.Identity.HashHi, snapshot.Identity.HashLo, index);
            if (_object.UpdateMap("np_rules", ruleKey, value) != 0)
            {
                return false;
            }
        }

        if (snapshot.HadExe && _object.UpdateMap("np_exes", exeKey, snapshot.ExeValue) != 0)
        {
            return false;
        }

        return SnapshotMatches(snapshot);
    }

    private bool DeleteIfPresent(string map, byte[] key)
    {
        if (_object is null)
        {
            return true;
        }

        if (_object.DeleteMap(map, key) == 0)
        {
            return true;
        }

        // bpf_map_delete_elem reports ENOENT for a slot that was already empty.
        return NativeBpf.LastErrno == 2;
    }

    private bool SnapshotMatches(ExeSnapshot snapshot)
    {
        if (_object is null)
        {
            return true;
        }

        var exeKey = FirewallPolicyLayout.ExeKey(snapshot.Identity);
        var exeValue = new byte[FirewallPolicyLayout.ExeValueSize];
        var hasExe = _object.TryLookupMap("np_exes", exeKey, exeValue);

        if (hasExe != snapshot.HadExe)
        {
            return false;
        }

        if (snapshot.HadExe && !exeValue.AsSpan().SequenceEqual(snapshot.ExeValue))
        {
            return false;
        }

        for (var index = 0; index < FirewallPolicyLayout.MaxSlots; index++)
        {
            var ruleKey = FirewallPolicyLayout.RuleKey(snapshot.Identity.HashHi, snapshot.Identity.HashLo, index);
            var value = new byte[FirewallPolicyLayout.RuleValueSize];
            var present = _object.TryLookupMap("np_rules", ruleKey, value);
            if (present != snapshot.Slots.TryGetValue(index, out var expected))
            {
                return false;
            }

            if (present && expected is not null && !value.AsSpan().SequenceEqual(expected))
            {
                return false;
            }
        }

        return true;
    }

    private void EnsureLoaded()
    {
        if (_object is not null)
        {
            return;
        }

        var bytes = _objectOverride ?? ReadObject();
        var loaded = BpfObject.Load(bytes, Hooks.Select(hook => hook.Name).ToArray(), MapNames);

        if (loaded.MapKeySize("np_exes") != FirewallPolicyLayout.ExeKeySize ||
            loaded.MapValueSize("np_exes") != FirewallPolicyLayout.ExeValueSize ||
            loaded.MapKeySize("np_rules") != FirewallPolicyLayout.RuleKeySize ||
            loaded.MapValueSize("np_rules") != FirewallPolicyLayout.RuleValueSize)
        {
            loaded.Dispose();
            throw new PlatformNotSupportedException(
                "The embedded firewall object does not match the expected map layout.");
        }

        _object = loaded;
        WriteConfig(enabled: false);
    }

    private static byte[] ReadObject()
    {
        var assembly = Assembly.GetExecutingAssembly();
        using var stream = assembly.GetManifestResourceStream(ObjectResourceName)
            ?? throw new PlatformNotSupportedException(
                "The embedded firewall eBPF object is missing from this build.");
        using var buffer = new MemoryStream();
        stream.CopyTo(buffer);
        return buffer.ToArray();
    }

    private void EnsureAttached()
    {
        if (_attached)
        {
            return;
        }

        if (!_writeGate())
        {
            throw new NotSupportedException(
                $"Firewall writes are disabled. Set {WriteEnableVariable}=1 and " +
                $"{WriteConfirmVariable}=yes only on an isolated test host.");
        }

        if (Directory.Exists(_cgroupPath) && new DirectoryInfo(_cgroupPath).LinkTarget is not null)
        {
            throw new PlatformNotSupportedException(
                $"Refusing to attach to symlinked cgroup path '{_cgroupPath}'.");
        }

        if (!Directory.Exists(_cgroupPath) || !File.Exists(Path.Combine(_cgroupPath, "cgroup.controllers")))
        {
            throw new PlatformNotSupportedException(
                $"'{_cgroupPath}' is not a cgroup v2 mount; per-executable enforcement needs cgroup v2.");
        }

        _cgroupFd = open(_cgroupPath, 0x10000 | 0x80000); // O_DIRECTORY | O_CLOEXEC
        if (_cgroupFd < 0)
        {
            throw new PlatformNotSupportedException(
                $"Cannot open firewall cgroup '{_cgroupPath}' (errno {Marshal.GetLastPInvokeError()}); " +
                "the service needs CAP_SYS_ADMIN and a writable cgroup v2 hierarchy.");
        }

        try
        {
            foreach (var (name, _) in Hooks)
            {
                var link = _object!.AttachLink(name, _cgroupFd, out var errno);
                if (link == IntPtr.Zero)
                {
                    throw new PlatformNotSupportedException(
                        $"Attaching '{name}' failed (errno {errno}); the service needs " +
                        "CAP_BPF and CAP_NET_ADMIN.");
                }

                _links.Add(link);
            }

            WriteConfig(enabled: true);
            _attached = true;
        }
        catch
        {
            DestroyLinks();
            CloseCgroup();
            throw;
        }
    }

    private void Detach()
    {
        WriteConfig(enabled: false);

        DestroyLinks();
        _attached = false;
        CloseCgroup();
    }

    private void DestroyLinks()
    {
        foreach (var link in _links)
        {
            BpfObject.DestroyLink(link);
        }

        _links.Clear();
    }

    private void CloseCgroup()
    {
        if (_cgroupFd >= 0)
        {
            _ = close(_cgroupFd);
            _cgroupFd = -1;
        }
    }

    private void WriteConfig(bool enabled)
    {
        if (_object is null)
        {
            return;
        }

        var key = new byte[4];
        var value = new byte[8];
        value[0] = enabled ? (byte)1 : (byte)0;
        if (_object.UpdateMap("np_config", key, value) != 0)
        {
            throw new IOException($"Writing the firewall enable flag failed (errno {NativeBpf.LastErrno}).");
        }
    }

    private void EnsureWriteGateOpen()
    {
        if (!_writeGate())
        {
            throw new NotSupportedException(
                $"Firewall writes are disabled. Set {WriteEnableVariable}=1 and " +
                $"{WriteConfirmVariable}=yes only on an isolated test host.");
        }
    }

    private static FirewallCapabilityReport Unavailable(string reason) => new()
    {
        Status = FirewallCapabilityStatus.Unavailable,
        Reason = reason,
        FirewallServiceRunning = null,
        ManagedRulesReadable = false,
        ManagedRuleCount = 0,
    };

    private static RuleApplyResult Failed(Guid id, string code, string message) => new()
    {
        Success = false,
        ManagedRuleId = id,
        State = RuleState.Failed,
        ErrorCode = code,
        ErrorMessage = message,
    };

    private sealed class FirewallPolicyException(string code, string message) : Exception(message)
    {
        public string Code { get; } = code;
    }

    private sealed record ExeSnapshot(
        ExecutableIdentity Identity,
        bool HadExe,
        byte[] ExeValue,
        Dictionary<int, byte[]> Slots);

    [DllImport("libc", EntryPoint = "open", SetLastError = true, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
    private static extern int open(string path, int flags);

    [DllImport("libc", EntryPoint = "close")]
    private static extern int close(int fd);
}
