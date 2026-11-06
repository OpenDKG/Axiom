// SPDX-License-Identifier: GPL-3.0-or-later
using System.Runtime.InteropServices;

namespace Axiom.Infrastructure.Linux.Firewall.Bpf;

/// <summary>
/// Resolves libbpf lazily so a host without it reports a specific unsupported capability instead
/// of failing at assembly load or at startup.
/// </summary>
internal static class NativeBpf
{
    private static readonly string[] Candidates = ["libbpf.so.1", "libbpf.so", "libbpf.so.0"];

    private static readonly Lazy<Api?> LazyApi = new(Resolve, LazyThreadSafetyMode.ExecutionAndPublication);

    private static Api? _api;

    private static Api Library =>
        LazyApi.Value ?? throw new PlatformNotSupportedException(
            "libbpf is not installed; the per-executable Linux firewall needs libbpf1 " +
            "(package: libbpf1 on Debian/Ubuntu, libbpf on Fedora).");

    public static void EnsureAvailable() => _ = Library;

    public static int LastErrno => Marshal.ReadInt32(ErrnoLocation());

    public static IntPtr ObjectOpenMem(IntPtr buffer, nuint size) =>
        Library.ObjectOpenMem(buffer, size, IntPtr.Zero);

    public static int ObjectLoad(IntPtr obj) => Library.ObjectLoad(obj);

    public static void ObjectClose(IntPtr obj) => Library.ObjectClose(obj);

    public static IntPtr FindProgram(IntPtr obj, string name) =>
        Library.FindProgram(obj, name);

    public static IntPtr FindMap(IntPtr obj, string name) => Library.FindMap(obj, name);

    public static int ProgramFd(IntPtr program) => Library.ProgramFd(program);

    public static int MapFd(IntPtr map) => Library.MapFd(map);

    public static uint MapKeySize(IntPtr map) => Library.MapKeySize(map);

    public static uint MapValueSize(IntPtr map) => Library.MapValueSize(map);

    public static IntPtr AttachCgroup(IntPtr program, int cgroupFd) =>
        Library.AttachCgroup(program, cgroupFd);

    public static int DestroyLink(IntPtr link) => Library.DestroyLink(link);

    public static long GetError(IntPtr pointer) => Library.GetError(pointer);

    public static int MapUpdate(int mapFd, byte[] key, byte[] value)
    {
        unsafe
        {
            fixed (byte* keyPtr = key)
            fixed (byte* valuePtr = value)
            {
                return Library.MapUpdate(mapFd, keyPtr, valuePtr);
            }
        }
    }

    public static int MapLookup(int mapFd, byte[] key, byte[] value)
    {
        unsafe
        {
            fixed (byte* keyPtr = key)
            fixed (byte* valuePtr = value)
            {
                return Library.MapLookup(mapFd, keyPtr, valuePtr);
            }
        }
    }

    public static int MapDelete(int mapFd, byte[] key)
    {
        unsafe
        {
            fixed (byte* keyPtr = key)
            {
                return Library.MapDelete(mapFd, keyPtr);
            }
        }
    }

    private static Api? Resolve()
    {
        foreach (var candidate in Candidates)
        {
            if (!NativeLibrary.TryLoad(candidate, out var handle))
            {
                continue;
            }

            try
            {
                _api = new Api(handle);
                return _api;
            }
            catch (Exception exception) when (exception is EntryPointNotFoundException or DllNotFoundException)
            {
                NativeLibrary.Free(handle);
            }
        }

        return null;
    }

    [DllImport("libc", EntryPoint = "__errno_location")]
    private static extern IntPtr ErrnoLocation();

    private sealed class Api
    {
        private readonly OpenMem _openMem;
        private readonly ObjectLoadDelegate _objectLoad;
        private readonly ObjectCloseDelegate _objectClose;
        private readonly FindProgramDelegate _findProgram;
        private readonly FindMapDelegate _findMap;
        private readonly ProgramFdDelegate _programFd;
        private readonly MapFdDelegate _mapFd;
        private readonly MapSizeDelegate _mapKeySize;
        private readonly MapSizeDelegate _mapValueSize;
        private readonly AttachCgroupDelegate _attachCgroup;
        private readonly DestroyLinkDelegate _destroyLink;
        private readonly GetErrorDelegate _getError;
        private readonly MapUpdateDelegate _mapUpdate;
        private readonly MapLookupDelegate _mapLookup;
        private readonly MapDeleteDelegate _mapDelete;

        public Api(IntPtr handle)
        {
            // Keep the library loaded for the process lifetime: delegates point into it.
            _ = handle;
            _openMem = Bind<OpenMem>(handle, "bpf_object__open_mem");
            _objectLoad = Bind<ObjectLoadDelegate>(handle, "bpf_object__load");
            _objectClose = Bind<ObjectCloseDelegate>(handle, "bpf_object__close");
            _findProgram = Bind<FindProgramDelegate>(handle, "bpf_object__find_program_by_name");
            _findMap = Bind<FindMapDelegate>(handle, "bpf_object__find_map_by_name");
            _programFd = Bind<ProgramFdDelegate>(handle, "bpf_program__fd");
            _mapFd = Bind<MapFdDelegate>(handle, "bpf_map__fd");
            _mapKeySize = Bind<MapSizeDelegate>(handle, "bpf_map__key_size");
            _mapValueSize = Bind<MapSizeDelegate>(handle, "bpf_map__value_size");
            _attachCgroup = Bind<AttachCgroupDelegate>(handle, "bpf_program__attach_cgroup");
            _destroyLink = Bind<DestroyLinkDelegate>(handle, "bpf_link__destroy");
            _getError = Bind<GetErrorDelegate>(handle, "libbpf_get_error");
            _mapUpdate = Bind<MapUpdateDelegate>(handle, "bpf_map_update_elem");
            _mapLookup = Bind<MapLookupDelegate>(handle, "bpf_map_lookup_elem");
            _mapDelete = Bind<MapDeleteDelegate>(handle, "bpf_map_delete_elem");
        }

        public IntPtr ObjectOpenMem(IntPtr buffer, nuint size, IntPtr opts) =>
            _openMem(buffer, size, opts);

        public int ObjectLoad(IntPtr obj) => _objectLoad(obj);

        public void ObjectClose(IntPtr obj) => _objectClose(obj);

        public IntPtr FindProgram(IntPtr obj, string name) => _findProgram(obj, name);

        public IntPtr FindMap(IntPtr obj, string name) => _findMap(obj, name);

        public int ProgramFd(IntPtr program) => _programFd(program);

        public int MapFd(IntPtr map) => _mapFd(map);

        public uint MapKeySize(IntPtr map) => _mapKeySize(map);

        public uint MapValueSize(IntPtr map) => _mapValueSize(map);

        public IntPtr AttachCgroup(IntPtr program, int cgroupFd) => _attachCgroup(program, cgroupFd);

        public int DestroyLink(IntPtr link) => _destroyLink(link);

        public long GetError(IntPtr pointer) => _getError(pointer);

        public unsafe int MapUpdate(int mapFd, byte* key, byte* value) =>
            _mapUpdate(mapFd, key, value, 0);

        public unsafe int MapLookup(int mapFd, byte* key, byte* value) =>
            _mapLookup(mapFd, key, value);

        public unsafe int MapDelete(int mapFd, byte* key) => _mapDelete(mapFd, key);

        private static T Bind<T>(IntPtr handle, string name)
            where T : Delegate
        {
            var address = NativeLibrary.GetExport(handle, name);
            return Marshal.GetDelegateForFunctionPointer<T>(address);
        }
    }

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate IntPtr OpenMem(IntPtr buffer, nuint size, IntPtr opts);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int ObjectLoadDelegate(IntPtr obj);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void ObjectCloseDelegate(IntPtr obj);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    private delegate IntPtr FindProgramDelegate(IntPtr obj, string name);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    private delegate IntPtr FindMapDelegate(IntPtr obj, string name);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int ProgramFdDelegate(IntPtr program);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int MapFdDelegate(IntPtr map);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint MapSizeDelegate(IntPtr map);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate IntPtr AttachCgroupDelegate(IntPtr program, int cgroupFd);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int DestroyLinkDelegate(IntPtr link);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate long GetErrorDelegate(IntPtr pointer);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private unsafe delegate int MapUpdateDelegate(int mapFd, byte* key, byte* value, ulong flags);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private unsafe delegate int MapLookupDelegate(int mapFd, byte* key, byte* value);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private unsafe delegate int MapDeleteDelegate(int mapFd, byte* key);
}
