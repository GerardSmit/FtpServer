using System.Collections.Concurrent;
using System.Runtime.InteropServices;
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

    /// <summary>
    /// Evaluated permissions by raw security descriptor, one map per <c>includeNames</c> setting.
    /// Inherited ACEs are stored in every file's own descriptor, so the entries of one directory
    /// nearly always share the same bytes, and parsing them into managed rule objects for each
    /// entry is what made a listing slow.
    /// </summary>
    [SupportedOSPlatform("windows")]
    private static readonly ConcurrentDictionary<byte[], FilePermissionResult> EvaluatedWithNames = new(ByteArrayComparer.Instance);

    [SupportedOSPlatform("windows")]
    private static readonly ConcurrentDictionary<byte[], FilePermissionResult> EvaluatedWithoutNames = new(ByteArrayComparer.Instance);

    /// <summary>Bounds each evaluated map; cleared wholesale rather than tracking recency.</summary>
    private const int EvaluatedCapacity = 1024;

    [SupportedOSPlatform("windows")]
    private const AccessControlSections RequestedSections =
        AccessControlSections.Access | AccessControlSections.Owner | AccessControlSections.Group;

    [SupportedOSPlatform("windows")]
    private FilePermissionResult GetFilePermissionsWindows(in FileSystemItem item, string path, bool includeNames)
    {
        if (TryGetSecurityDescriptor(path) is not { } descriptor)
        {
            // The native read failed (an unusual path form, say); the managed one reports why.
            return Evaluate(
                item.IsDirectory
                    ? new DirectoryInfo(path).GetAccessControl(RequestedSections)
                    : new FileInfo(path).GetAccessControl(RequestedSections),
                includeNames);
        }

        var evaluated = includeNames ? EvaluatedWithNames : EvaluatedWithoutNames;

        if (evaluated.TryGetValue(descriptor, out var cached))
        {
            return cached;
        }

        var security = new FileSecurity();
        security.SetSecurityDescriptorBinaryForm(descriptor, RequestedSections);

        var result = Evaluate(security, includeNames);

        if (evaluated.Count >= EvaluatedCapacity)
        {
            evaluated.Clear();
        }

        evaluated[descriptor] = result;
        return result;
    }

    [SupportedOSPlatform("windows")]
    private FilePermissionResult Evaluate(FileSystemSecurity security, bool includeNames)
    {
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

    /// <summary>
    /// Reads the owner, group and DACL of <paramref name="path"/> as one self-relative security
    /// descriptor, or returns null when the native call fails.
    /// </summary>
    [SupportedOSPlatform("windows")]
    private static unsafe byte[]? TryGetSecurityDescriptor(string path)
    {
        const int SeFileObject = 1;
        const int OwnerGroupDacl = 0x1 | 0x2 | 0x4;

        var error = GetNamedSecurityInfo(path, SeFileObject, OwnerGroupDacl, null, null, null, null, out var descriptor);

        if (error != 0 || descriptor == IntPtr.Zero)
        {
            return null;
        }

        try
        {
            var length = GetSecurityDescriptorLength(descriptor);
            return new ReadOnlySpan<byte>((void*)descriptor, (int)length).ToArray();
        }
        finally
        {
            LocalFree(descriptor);
        }
    }

    [LibraryImport("advapi32.dll", EntryPoint = "GetNamedSecurityInfoW", StringMarshalling = StringMarshalling.Utf16)]
    private static unsafe partial uint GetNamedSecurityInfo(
        string objectName,
        int objectType,
        int securityInfo,
        void* owner,
        void* group,
        void* dacl,
        void* sacl,
        out IntPtr securityDescriptor);

    [LibraryImport("advapi32.dll")]
    private static partial uint GetSecurityDescriptorLength(IntPtr securityDescriptor);

    [LibraryImport("kernel32.dll")]
    private static partial IntPtr LocalFree(IntPtr memory);

    private sealed class ByteArrayComparer : IEqualityComparer<byte[]>
    {
        public static readonly ByteArrayComparer Instance = new();

        public bool Equals(byte[]? x, byte[]? y) => x.AsSpan().SequenceEqual(y);

        public int GetHashCode(byte[] obj)
        {
            var hash = new HashCode();
            hash.AddBytes(obj);
            return hash.ToHashCode();
        }
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
