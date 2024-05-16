using System.Runtime.Versioning;
using Zio;

namespace FtpServer.IO;

public partial class PermissionProvider
{
    [UnsupportedOSPlatform("windows")]
    private FilePermissionResult GetFilePermissionsUnix(in FileSystemItem item, string path)
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

        if (NativeMethods.stat(path, out var stat) == 0)
        {
            owner = UnixFileInfo.GetUserName(stat.st_uid);
            group = UnixFileInfo.GetGroupName(stat.st_gid);
        }
        else
        {
            owner = null;
            group = null;
        }

        return new FilePermissionResult(userResult, groupResult, otherResult, owner, group);
    }
}
