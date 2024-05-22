using System.Runtime.InteropServices;

namespace FtpServer.IO;

public static partial class NativeMethods
{
    [LibraryImport("libc", EntryPoint = "stat", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    public static partial int stat(string path, out Stat stat);

    [StructLayout(LayoutKind.Sequential)]
    public struct Stat
    {
        public ulong st_dev;
        public ulong st_ino;
        public ulong st_nlink;
        public uint st_mode;
        public uint st_uid;
        public uint st_gid;
        public ulong st_rdev;
        public long st_size;
        public long st_blksize;
        public long st_blocks;
        public long st_atime;
        public long st_atimensec;
        public long st_mtime;
        public long st_mtimensec;
        public long st_ctime;
        public long st_ctimensec;
        public long __unused;
    }
}