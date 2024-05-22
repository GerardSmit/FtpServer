using System.Runtime.InteropServices;

namespace FtpServer.IO;

public static partial class UnixFileInfo
{
    public static string GetUserName(uint uid)
    {
        var pwd = getpwuid(uid);
        if (pwd == IntPtr.Zero)
        {
            return uid.ToString();
        }

        var passwd = Marshal.PtrToStructure<Passwd>(pwd);
        return passwd.pw_name;
    }

    public static string GetGroupName(uint gid)
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
