using System.Collections.Concurrent;
using System.Runtime.Versioning;
using FtpServer.IO.Results;
using Zio;

namespace FtpServer.IO;

public partial class PermissionProvider
{
    [UnsupportedOSPlatform("windows")]
    private FilePermissionResult GetFilePermissionsUnix(in FileSystemItem item, string path, bool includeNames)
    {
        var mode = File.GetUnixFileMode(path);

        var userRead = (mode & UnixFileMode.UserRead) != 0;
        var userWrite = (mode & UnixFileMode.UserWrite) != 0;
        var userExecute = (mode & UnixFileMode.UserExecute) != 0;
        var userResult = new PermissionResult(userRead, userWrite, userExecute);

        var groupRead = (mode & UnixFileMode.GroupRead) != 0;
        var groupWrite = (mode & UnixFileMode.GroupWrite) != 0;
        var groupExecute = (mode & UnixFileMode.GroupExecute) != 0;
        var groupResult = new PermissionResult(groupRead, groupWrite, groupExecute);

        var otherRead = (mode & UnixFileMode.OtherRead) != 0;
        var otherWrite = (mode & UnixFileMode.OtherWrite) != 0;
        var otherExecute = (mode & UnixFileMode.OtherExecute) != 0;
        var otherResult = new PermissionResult(otherRead, otherWrite, otherExecute);

        string? owner;
        string? group;

        if (includeNames && NativeMethods.stat(path, out var stat) == 0)
        {
            owner = GetCachedName(_userNames, stat.st_uid, UnixFileInfo.GetUserName);
            group = GetCachedName(_groupNames, stat.st_gid, UnixFileInfo.GetGroupName);
        }
        else
        {
            owner = null;
            group = null;
        }

        return new FilePermissionResult(userResult, groupResult, otherResult, owner, group);
    }

    /// <summary>getpwuid/getgrgid read the user and group databases, possibly over NSS/LDAP.</summary>
    private static string GetCachedName(ConcurrentDictionary<uint, string> cache, uint id, Func<uint, string> lookup)
    {
        if (cache.TryGetValue(id, out var cached))
        {
            return cached;
        }

        var name = lookup(id);
        CacheName(cache, id, name);
        return name;
    }
}
