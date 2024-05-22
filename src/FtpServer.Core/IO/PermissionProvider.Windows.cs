using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using FtpServer.IO.Results;
using Zio;

namespace FtpServer.IO;

public partial class PermissionProvider
{
    [SupportedOSPlatform("windows")]
    private static PermissionResult GetPermissionsWindows(AuthorizationRuleCollection rules)
    {
        var read = false;
        var write = false;
        var execute = false;

        foreach (FileSystemAccessRule rule in rules)
        {
            if (rule.FileSystemRights.HasFlag(FileSystemRights.ReadData))
            {
                read = true;
            }

            if (rule.FileSystemRights.HasFlag(FileSystemRights.WriteData))
            {
                write = true;
            }

            if (rule.FileSystemRights.HasFlag(FileSystemRights.ExecuteFile))
            {
                execute = true;
            }
        }

        return new PermissionResult(read, write, execute);
    }

    [SupportedOSPlatform("windows")]
    private FilePermissionResult GetFilePermissionsWindows(in FileSystemItem item, string path)
    {
        AuthorizationRuleCollection groupRules;
        AuthorizationRuleCollection ownerRules;
        AuthorizationRuleCollection allRules;
        IdentityReference? owner;
        IdentityReference? group;

        if (item.IsDirectory)
        {
            var di = new DirectoryInfo(path);
            var groupAcl = di.GetAccessControl(AccessControlSections.Group);
            var ownerAcl = di.GetAccessControl(AccessControlSections.Owner);
            var allAcl = di.GetAccessControl(AccessControlSections.Access);

            owner = ownerAcl.GetOwner(typeof(NTAccount));
            group = groupAcl.GetGroup(typeof(NTAccount));

            groupRules = groupAcl.GetAccessRules(true, true, typeof(NTAccount));
            ownerRules = ownerAcl.GetAccessRules(true, true, typeof(NTAccount));
            allRules = allAcl.GetAccessRules(true, true, typeof(NTAccount));
        }
        else
        {
            var fi = new FileInfo(path);
            var groupAcl = fi.GetAccessControl(AccessControlSections.Group);
            var ownerAcl = fi.GetAccessControl(AccessControlSections.Owner);
            var allAcl = fi.GetAccessControl(AccessControlSections.Access);

            owner = ownerAcl.GetOwner(typeof(NTAccount));
            group = groupAcl.GetGroup(typeof(NTAccount));

            groupRules = groupAcl.GetAccessRules(true, true, typeof(NTAccount));
            ownerRules = ownerAcl.GetAccessRules(true, true, typeof(NTAccount));
            allRules = allAcl.GetAccessRules(true, true, typeof(NTAccount));
        }

        var groupPermissions = GetPermissionsWindows(groupRules);
        var ownerPermissions = GetPermissionsWindows(ownerRules);
        var allPermissions = GetPermissionsWindows(allRules);

        return new FilePermissionResult(
            ownerPermissions,
            groupPermissions,
            allPermissions,
            owner?.Value,
            group?.Value);
    }
}
