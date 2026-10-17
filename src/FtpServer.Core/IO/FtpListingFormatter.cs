using System.Globalization;
using System.Text;
using FtpServer.IO.Results;
using Zio;

namespace FtpServer.IO;

/// <summary>
/// Renders directory entries in the formats clients parse: the Unix "ls -l" long listing and the
/// RFC 3659 MLSx fact list.
/// </summary>
public sealed class FtpListingFormatter(PermissionProvider permissionProvider)
{
    /// <summary>
    /// Entries older than this are listed with a year instead of a time, which is the convention
    /// clients rely on to work out the year of an old file.
    /// </summary>
    private static readonly TimeSpan RecentWindow = TimeSpan.FromDays(180);

    /// <summary>Conventional placeholder size for a directory, as reported by ls on most systems.</summary>
    private const long DirectorySize = 4096;

    public void AppendLongListing(StringBuilder target, IFileSystem fileSystem, FileSystemItem item, DateTimeOffset now)
    {
        var permissions = GetPermissions(fileSystem, item);

        target.Append(item.IsDirectory ? 'd' : '-');
        AppendTriplet(target, permissions.User);
        AppendTriplet(target, permissions.Group);
        AppendTriplet(target, permissions.Other);

        // Link count. Directories conventionally report at least 2 ("." and the parent's entry).
        target.Append(' ').Append(item.IsDirectory ? 2 : 1);

        target.Append(' ').Append(SanitiseIdentity(permissions.OwnerName));
        target.Append(' ').Append(SanitiseIdentity(permissions.GroupName));

        target.Append(' ').Append(GetLength(item).ToString(CultureInfo.InvariantCulture));

        target.Append(' ').Append(FormatDate(item.LastWriteTime, now));

        target.Append(' ').Append(SanitiseName(item.GetName()));
        target.Append("\r\n");
    }

    /// <summary>
    /// Formats a timestamp the way ls does: "MMM dd HH:mm" when recent, "MMM dd  yyyy" otherwise.
    /// </summary>
    internal static string FormatDate(DateTimeOffset timestamp, DateTimeOffset now)
    {
        // Clients interpret the listing in the server's local time.
        var local = timestamp.ToLocalTime().DateTime;
        var age = now.ToLocalTime().DateTime - local;

        return age > RecentWindow || age < -RecentWindow
            ? local.ToString("MMM dd  yyyy", CultureInfo.InvariantCulture)
            : local.ToString("MMM dd HH:mm", CultureInfo.InvariantCulture);
    }

    /// <summary>
    /// Writes one MLSx line. <paramref name="nameOverride"/> lets MLST report the pathname the
    /// client asked for, which RFC 3659 section 7.3.1 requires when TVFS is advertised.
    /// </summary>
    public void AppendMachineListing(
        StringBuilder target,
        IFileSystem fileSystem,
        FileSystemItem item,
        bool canWrite,
        MlsxFacts facts,
        string? typeOverride = null,
        string? nameOverride = null)
    {
        var type = typeOverride ?? (item.IsDirectory ? "dir" : "file");

        if (facts.HasFlag(MlsxFacts.Type))
        {
            target.Append("type=").Append(type).Append(';');
        }

        if (facts.HasFlag(MlsxFacts.Size) && !item.IsDirectory)
        {
            target.Append("size=").Append(GetLength(item).ToString(CultureInfo.InvariantCulture)).Append(';');
        }

        if (facts.HasFlag(MlsxFacts.Modify))
        {
            target.Append("modify=").Append(FormatTimestamp(item.LastWriteTime)).Append(';');
        }

        // On Windows the perm fact comes from the entry's attributes, which the enumeration already
        // read, so only the UNIX.* facts pay for the ACL. On Unix the mode is one stat either way.
        var unixFacts = (facts & (MlsxFacts.UnixMode | MlsxFacts.UnixOwner | MlsxFacts.UnixGroup)) != 0;
        var needsPermissions = unixFacts || (facts.HasFlag(MlsxFacts.Perm) && !OperatingSystem.IsWindows());
        var includeNames = (facts & (MlsxFacts.UnixOwner | MlsxFacts.UnixGroup)) != 0;
        var permissions = needsPermissions ? GetPermissions(fileSystem, item, includeNames) : default;

        if (facts.HasFlag(MlsxFacts.Perm))
        {
            target.Append("perm=").Append(GetPerm(item, canWrite, OperatingSystem.IsWindows() ? default : permissions)).Append(';');
        }

        if ((facts & (MlsxFacts.UnixMode | MlsxFacts.UnixOwner | MlsxFacts.UnixGroup)) != 0)
        {
            if (facts.HasFlag(MlsxFacts.UnixOwner) && permissions.OwnerName is { } owner)
            {
                target.Append("UNIX.owner=").Append(SanitiseIdentity(owner)).Append(';');
            }

            if (facts.HasFlag(MlsxFacts.UnixGroup) && permissions.GroupName is { } group)
            {
                target.Append("UNIX.group=").Append(SanitiseIdentity(group)).Append(';');
            }

            if (facts.HasFlag(MlsxFacts.UnixMode))
            {
                target.Append("UNIX.mode=0").Append(ToOctal(permissions)).Append(';');
            }
        }

        // RFC 3659 section 7.2: exactly one space separates the facts from the pathname.
        target.Append(' ').Append(SanitiseName(nameOverride ?? typeOverride switch
        {
            "cdir" => ".",
            "pdir" => "..",
            _ => item.GetName(),
        }));

        target.Append("\r\n");
    }

    /// <summary>RFC 3659 section 2.3 time-val: YYYYMMDDHHMMSS in UTC.</summary>
    public static string FormatTimestamp(DateTimeOffset timestamp) =>
        timestamp.UtcDateTime.ToString("yyyyMMddHHmmss", CultureInfo.InvariantCulture);

    /// <summary>
    /// Builds the RFC 3659 section 7.5.5 perm fact for one entry.
    /// </summary>
    /// <remarks>
    /// The fact advertises what the client may do, so the session and the object have to agree:
    /// advertising an operation that then fails is worse than not advertising it. On Unix the
    /// object's rights are its owner's mode bits. On Windows they come from the read-only
    /// attribute: the owner's ACL entry says nothing about the account the server runs as, and
    /// reading it cost more than the rest of the listing together.
    /// </remarks>
    private static string GetPerm(FileSystemItem item, bool canWrite, FilePermissionResult permissions)
    {
        bool readable, writable, traversable;

        if (permissions.IsKnown)
        {
            readable = permissions.User.Read;
            writable = canWrite && permissions.User.Write;
            traversable = permissions.User.Execute;
        }
        else
        {
            // Windows, or an entry Zio exposes with no real path: the session's own rights, less
            // what the read-only attribute forbids. Windows ignores that attribute on directories.
            readable = true;
            traversable = true;
            writable = canWrite && (item.IsDirectory || (item.Attributes & FileAttributes.ReadOnly) == 0);
        }

        var perm = new StringBuilder(8);

        if (item.IsDirectory)
        {
            if (traversable)
            {
                perm.Append('e');
            }

            if (readable)
            {
                perm.Append('l');
            }

            if (writable)
            {
                perm.Append('c').Append('m').Append('p').Append('d').Append('f');
            }
        }
        else
        {
            if (readable)
            {
                perm.Append('r');
            }

            if (writable)
            {
                perm.Append('a').Append('w').Append('d').Append('f');
            }
        }

        return perm.ToString();
    }

    private static long GetLength(FileSystemItem item)
    {
        if (item.IsDirectory)
        {
            return DirectorySize;
        }

        try
        {
            return item.Length;
        }
        catch
        {
            // The entry vanished or is not readable; report zero rather than dropping the line.
            return 0;
        }
    }

    private FilePermissionResult GetPermissions(IFileSystem fileSystem, FileSystemItem item, bool includeNames = true)
    {
        // No host path to read an ACL or mode from: the attributes the enumeration returned are
        // all there is, and asking for the path would throw once per entry.
        if (fileSystem is IFtpRemoteFileSystem)
        {
            return GetRemotePermissions(item);
        }

        try
        {
            var internalPath = fileSystem.ConvertPathToInternal(item.Path);
            return permissionProvider.GetFilePermissions(item, internalPath, includeNames);
        }
        catch
        {
            // Zio exposes virtual entries (for example /mnt on Windows) that have no real path.
            return default;
        }
    }

    /// <summary>
    /// What a remote entry allows: everything for the owner, less writing where the read-only
    /// attribute forbids it, and reading for everyone else.
    /// </summary>
    private static FilePermissionResult GetRemotePermissions(FileSystemItem item)
    {
        var writable = item.IsDirectory || (item.Attributes & FileAttributes.ReadOnly) == 0;
        var others = new PermissionResult(read: true, write: false, execute: item.IsDirectory);

        return new FilePermissionResult(
            new PermissionResult(read: true, write: writable, execute: item.IsDirectory),
            others,
            others,
            "ftp",
            "ftp");
    }

    private static void AppendTriplet(StringBuilder target, PermissionResult permission)
    {
        target.Append(permission.Read ? 'r' : '-');
        target.Append(permission.Write ? 'w' : '-');
        target.Append(permission.Execute ? 'x' : '-');
    }

    private static int ToOctal(FilePermissionResult permissions) =>
        (ToDigit(permissions.User) * 100) + (ToDigit(permissions.Group) * 10) + ToDigit(permissions.Other);

    private static int ToDigit(PermissionResult permission) =>
        (permission.Read ? 4 : 0) + (permission.Write ? 2 : 0) + (permission.Execute ? 1 : 0);

    /// <summary>
    /// Owner and group are single space-delimited columns, so any space would shift every
    /// following field and break the client's parser.
    /// </summary>
    private static string SanitiseIdentity(string? identity)
    {
        if (string.IsNullOrEmpty(identity))
        {
            return "unknown";
        }

        Span<char> buffer = stackalloc char[identity.Length];

        for (var i = 0; i < identity.Length; i++)
        {
            var c = identity[i];
            buffer[i] = char.IsControl(c) || c is ' ' or '\\' ? '-' : c;
        }

        return new string(buffer);
    }

    /// <summary>
    /// A CR or LF in a file name would inject extra lines into the listing, letting a name
    /// fabricate entries. Control characters are replaced rather than dropped so the name
    /// still round-trips to a distinguishable string.
    /// </summary>
    internal static string SanitiseName(string name)
    {
        var needsSanitising = false;

        foreach (var c in name)
        {
            if (char.IsControl(c))
            {
                needsSanitising = true;
                break;
            }
        }

        if (!needsSanitising)
        {
            return name;
        }

        Span<char> buffer = name.Length <= 256 ? stackalloc char[name.Length] : new char[name.Length];

        for (var i = 0; i < name.Length; i++)
        {
            buffer[i] = char.IsControl(name[i]) ? '?' : name[i];
        }

        return new string(buffer);
    }
}
