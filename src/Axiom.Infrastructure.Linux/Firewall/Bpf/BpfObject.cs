// SPDX-License-Identifier: GPL-3.0-or-later
using System.Runtime.InteropServices;

namespace Axiom.Infrastructure.Linux.Firewall.Bpf;

/// <summary>
/// Narrow P/Invoke surface over libbpf. The firewall object and links are owned by this process:
/// they are never pinned to bpffs, so a crash or exit detaches enforcement instead of leaving a
/// stale policy on the host.
/// </summary>
internal sealed class BpfObject : IDisposable
{
    private readonly IntPtr _object;

    private readonly Dictionary<string, IntPtr> _programs = new(StringComparer.Ordinal);

    private readonly Dictionary<string, (IntPtr Handle, int Fd)> _maps = new(StringComparer.Ordinal);

    private bool _disposed;

    private BpfObject(IntPtr obj) => _object = obj;

    public static BpfObject Load(byte[] objectBytes, IReadOnlyList<string> programs, IReadOnlyList<string> maps)
    {
        ArgumentNullException.ThrowIfNull(objectBytes);

        NativeBpf.EnsureAvailable();
        var pinned = GCHandle.Alloc(objectBytes, GCHandleType.Pinned);
        try
        {
            var obj = NativeBpf.ObjectOpenMem(pinned.AddrOfPinnedObject(), (nuint)objectBytes.Length);
            if (obj == IntPtr.Zero)
            {
                throw new PlatformNotSupportedException(
                    $"libbpf could not read the embedded firewall object: errno {NativeBpf.LastErrno}.");
            }

            if (NativeBpf.ObjectLoad(obj) != 0)
            {
                var errno = NativeBpf.LastErrno;
                NativeBpf.ObjectClose(obj);
                throw new PlatformNotSupportedException(
                    $"The kernel rejected the firewall eBPF object (errno {errno}); " +
                    "check CAP_BPF/CAP_SYS_ADMIN and a kernel with BTF.");
            }

            var result = new BpfObject(obj);

            foreach (var name in programs)
            {
                var program = NativeBpf.FindProgram(obj, name);
                if (program == IntPtr.Zero)
                {
                    result.Dispose();
                    throw new PlatformNotSupportedException($"Firewall object is missing program '{name}'.");
                }

                result._programs[name] = program;
            }

            foreach (var name in maps)
            {
                var map = NativeBpf.FindMap(obj, name);
                if (map == IntPtr.Zero)
                {
                    result.Dispose();
                    throw new PlatformNotSupportedException($"Firewall object is missing map '{name}'.");
                }

                result._maps[name] = (map, NativeBpf.MapFd(map));
            }

            return result;
        }
        finally
        {
            pinned.Free();
        }
    }

    public int ProgramFd(string name) =>
        _programs.TryGetValue(name, out var program)
            ? NativeBpf.ProgramFd(program)
            : throw new InvalidOperationException($"Unknown firewall program '{name}'.");

    public int MapFd(string name) =>
        _maps.TryGetValue(name, out var map)
            ? map.Fd
            : throw new InvalidOperationException($"Unknown firewall map '{name}'.");

    public int MapKeySize(string name) =>
        _maps.TryGetValue(name, out var map) ? (int)NativeBpf.MapKeySize(map.Handle) : 0;

    public int MapValueSize(string name) =>
        _maps.TryGetValue(name, out var map) ? (int)NativeBpf.MapValueSize(map.Handle) : 0;

    /// <summary>
    /// Creates a cgroup BPF link. The link is owned by this process; exiting or crashing closes the
    /// fd and detaches enforcement instead of leaving a stale program attached to the hierarchy.
    /// </summary>
    public IntPtr AttachLink(string program, int cgroupFd, out int errno)
    {
        var link = NativeBpf.AttachCgroup(_programs[program], cgroupFd);
        var error = NativeBpf.GetError(link);
        if (error != 0)
        {
            errno = (int)-error;
            return IntPtr.Zero;
        }

        errno = 0;
        return link;
    }

    public static void DestroyLink(IntPtr link)
    {
        if (link != IntPtr.Zero)
        {
            _ = NativeBpf.DestroyLink(link);
        }
    }

    public int UpdateMap(string name, byte[] key, byte[] value) =>
        NativeBpf.MapUpdate(MapFd(name), key, value);

    public int DeleteMap(string name, byte[] key) => NativeBpf.MapDelete(MapFd(name), key);

    public bool TryLookupMap(string name, byte[] key, byte[] value) =>
        NativeBpf.MapLookup(MapFd(name), key, value) == 0;

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        if (_object != IntPtr.Zero)
        {
            NativeBpf.ObjectClose(_object);
        }
    }
}
