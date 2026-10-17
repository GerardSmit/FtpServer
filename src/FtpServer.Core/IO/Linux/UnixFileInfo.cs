using System.Collections.Concurrent;
using System.Runtime.InteropServices;

namespace FtpServer.IO;

public static partial class UnixFileInfo
{
    /// <summary>Bounds each name cache; cleared wholesale rather than tracking recency.</summary>
    private const int NameCapacity = 1024;

    /// <summary>
    /// Names already looked up. A listing names the same few owners on every line, and each
    /// lookup goes through NSS, which may be LDAP or another network service.
    /// </summary>
    private static readonly ConcurrentDictionary<uint, string> UserNames = new();

    private static readonly ConcurrentDictionary<uint, string> GroupNames = new();

    /// <summary>
    /// getpwuid and getgrgid return a pointer into a static buffer that the next call overwrites,
    /// so concurrent sessions must not interleave between the call and the copy.
    /// </summary>
    private static readonly Lock LookupGate = new();

    public static string GetUserName(uint uid) => GetCached(UserNames, uid, LookUpUserName);

    public static string GetGroupName(uint gid) => GetCached(GroupNames, gid, LookUpGroupName);

    private static string GetCached(ConcurrentDictionary<uint, string> cache, uint id, Func<uint, string> lookUp)
    {
        if (cache.TryGetValue(id, out var cached))
        {
            return cached;
        }

        string name;

        lock (LookupGate)
        {
            name = lookUp(id);
        }

        if (cache.Count >= NameCapacity)
        {
            cache.Clear();
        }

        cache[id] = name;
        return name;
    }

    private static string LookUpUserName(uint uid)
    {
        var pwd = getpwuid(uid);
        if (pwd == IntPtr.Zero)
        {
            return uid.ToString();
        }

        var passwd = Marshal.PtrToStructure<Passwd>(pwd);
        return passwd.pw_name;
    }

    private static string LookUpGroupName(uint gid)
    {
        var grp = getgrgid(gid);
        if (grp == IntPtr.Zero)
        {
            return gid.ToString();
        }

        var group = Marshal.PtrToStructure<Group>(grp);
        return group.gr_name;
    }

    [LibraryImport("libc")]
    private static partial IntPtr getpwuid(uint uid);

    [LibraryImport("libc")]
    private static partial IntPtr getgrgid(uint gid);

    [StructLayout(LayoutKind.Sequential)]
    private struct Passwd
    {
        public string pw_name;
        public string pw_passwd;
        public uint pw_uid;
        public uint pw_gid;
        public string pw_gecos;
        public string pw_dir;
        public string pw_shell;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Group
    {
        public string gr_name;
        public string gr_passwd;
        public uint gr_gid;
        public IntPtr gr_mem;
    }
}
