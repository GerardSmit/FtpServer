using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using FtpServer.IO.Results;
using Zio;

namespace FtpServer.IO;

public partial class PermissionProvider
{
    [SupportedOSPlatform("windows")]
    private static readonly SecurityIdentifier Everyone = new(WellKnownSidType.WorldSid, null);

    [SupportedOSPlatform("windows")]
    private FilePermissionResult GetFilePermissionsWindows(in FileSystemItem item, string path, bool includeNames)
    {
        // One fetch covering all three sections: the previous code issued three separate
        // GetAccessControl calls per entry, which dominated the cost of a large listing.
        FileSystemSecurity security = item.IsDirectory
            ? new DirectoryInfo(path).GetAccessControl(AccessControlSections.Access | AccessControlSections.Owner | AccessControlSections.Group)
            : new FileInfo(path).GetAccessControl(AccessControlSections.Access | AccessControlSections.Owner | AccessControlSections.Group);

        var owner = TryGetIdentity(security, isOwner: true, includeNames);
        var group = TryGetIdentity(security, isOwner: false, includeNames);

        var rules = security.GetAccessRules(includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier));

        return new FilePermissionResult(
            Evaluate(rules, owner.Sid),
            Evaluate(rules, group.Sid),
            Evaluate(rules, Everyone),
            owner.Name,
            group.Name);
    }

    [SupportedOSPlatform("windows")]
    private (SecurityIdentifier? Sid, string? Name) TryGetIdentity(FileSystemSecurity security, bool isOwner, bool includeNames)
    {
        try
        {
            var reference = isOwner
                ? security.GetOwner(typeof(SecurityIdentifier))
                : security.GetGroup(typeof(SecurityIdentifier));

            if (reference is not SecurityIdentifier sid)
            {
                return (null, null);
            }

            return (sid, includeNames ? GetAccountName(sid) : null);
        }
        catch (Exception e) when (e is InvalidOperationException or UnauthorizedAccessException)
        {
            return (null, null);
        }
    }

    /// <summary>
    /// Translates a SID to its account name, remembering the answer.
    /// </summary>
    /// <remarks>
    /// A translation is an LSA lookup - and a round trip to a domain controller for a domain
    /// account - costing far more than reading the ACL itself. A directory's entries almost always
    /// share a handful of owners, so without the cache a listing paid that lookup twice per entry.
    /// </remarks>
    [SupportedOSPlatform("windows")]
    private string GetAccountName(SecurityIdentifier sid)
    {
        var key = sid.Value;

        if (_accountNames.TryGetValue(key, out var cached))
        {
            return cached;
        }

        string name;

        try
        {
            name = ((NTAccount)sid.Translate(typeof(NTAccount))).Value;
        }
        catch (IdentityNotMappedException)
        {
            // Orphaned SID (deleted account, or a domain we cannot reach).
            name = key;
        }

        CacheName(_accountNames, key, name);
        return name;
    }

    /// <summary>
    /// Reduces the ACL to a read/write/execute triplet for one identity.
    /// </summary>
    /// <remarks>
    /// Deny entries take precedence over allow entries, matching how Windows itself evaluates a
    /// DACL. The previous implementation OR-ed every rule together regardless of identity or of
    /// <see cref="AccessControlType"/>, so a Deny ACE was reported as granting access.
    /// </remarks>
    [SupportedOSPlatform("windows")]
    private static PermissionResult Evaluate(AuthorizationRuleCollection rules, SecurityIdentifier? identity)
    {
        if (identity is null)
        {
            return default;
        }

        FileSystemRights allowed = 0;
        FileSystemRights denied = 0;

        foreach (var rule in rules)
        {
            if (rule is not FileSystemAccessRule accessRule)
            {
                continue;
            }

            if (accessRule.IdentityReference is not SecurityIdentifier sid || !sid.Equals(identity))
            {
                continue;
            }

            if (accessRule.AccessControlType == AccessControlType.Deny)
            {
                denied |= accessRule.FileSystemRights;
            }
            else
            {
                allowed |= accessRule.FileSystemRights;
            }
        }

        var effective = allowed & ~denied;

        return new PermissionResult(
            (effective & FileSystemRights.ReadData) != 0,
            (effective & FileSystemRights.WriteData) != 0,
            (effective & FileSystemRights.ExecuteFile) != 0);
    }
}
