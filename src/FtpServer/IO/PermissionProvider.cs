using Zio;

namespace FtpServer.IO;

public sealed partial class PermissionProvider
{
    public FilePermissionResult GetFilePermissions(in FileSystemItem item, string path)
    {
        return OperatingSystem.IsWindows()
            ? GetFilePermissionsWindows(item, path)
            : GetFilePermissionsUnix(item, path);
    }
}
