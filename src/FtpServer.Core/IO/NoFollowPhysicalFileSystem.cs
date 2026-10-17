using Zio;
using Zio.FileSystems;

namespace FtpServer.IO;

/// <summary>
/// A <see cref="PhysicalFileSystem"/> that refuses any path whose real location - once every
/// junction, symbolic link and mount point along the way has been resolved - falls outside the
/// configured root.
/// </summary>
/// <remarks>
/// The check lives in <see cref="ConvertPathToInternalImpl"/> because every Zio operation passes
/// through it exactly once - open, enumerate, stat, create, delete, and both endpoints of a rename.
///
/// Resolution is deliberately not cached: a directory can be replaced by a link after the fact, and
/// a stale "safe" answer is the mistake this class exists to prevent. The cost is one attribute read
/// per path component below the root per operation; the root itself was resolved once at
/// construction, and the components above it are outside anything a client can change.
/// </remarks>
public sealed class NoFollowPhysicalFileSystem : PhysicalFileSystem
{
    private static readonly char[] Separators = ['/', '\\'];

    /// <summary>Bounds a link chain, and with it a cycle.</summary>
    private const int MaxLinkHops = 64;

    private readonly string _root;

    /// <param name="root">Native path of the directory every operation must stay within.</param>
    public NoFollowPhysicalFileSystem(string root)
    {
        // The root may itself be a link; what matters is where it lands.
        _root = Path.TrimEndingDirectorySeparator(ResolveLinks(Path.GetFullPath(root)));
    }

    protected override string ConvertPathToInternalImpl(UPath path)
    {
        var internalPath = base.ConvertPathToInternalImpl(path);

        if (!IsInsideRoot(ResolveLinks(internalPath, _root)))
        {
            throw new UnauthorizedAccessException($"'{path}' resolves outside the server root.");
        }

        return internalPath;
    }

    private bool IsInsideRoot(string candidate)
    {
        var comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        var trimmed = Path.TrimEndingDirectorySeparator(candidate);

        return trimmed.Equals(_root, comparison) ||
               trimmed.StartsWith(_root + Path.DirectorySeparatorChar, comparison);
    }

    /// <summary>
    /// Resolves <paramref name="path"/> component by component, following any link encountered on
    /// the way, and returns where it really lands.
    /// </summary>
    /// <remarks>
    /// Resolving only the last component - all <c>ResolveLinkTarget</c> reports - would miss a
    /// junction half-way up the path, which is the ordinary shape of the problem. A component that
    /// does not exist yet is not a link and is simply appended, so a path being created is checked
    /// as thoroughly as one being read.
    /// </remarks>
    /// <param name="path">The native path to resolve.</param>
    /// <param name="resolvedPrefix">
    /// A directory already known to contain no links - the root, resolved at construction. Its
    /// components are not walked again when <paramref name="path"/> lies beneath it, which is
    /// what keeps a deep root from costing a stat per ancestor on every operation.
    /// </param>
    internal static string ResolveLinks(string path, string? resolvedPrefix = null)
    {
        var full = Path.GetFullPath(path);
        var hops = 0;

        while (true)
        {
            var (current, remainder) = SplitAtPrefix(full, resolvedPrefix);
            var components = remainder.Split(Separators, StringSplitOptions.RemoveEmptyEntries);
            var followed = false;

            for (var i = 0; i < components.Length; i++)
            {
                current = Path.Combine(current, components[i]);

                if (ReadLink(current, out var exists) is not { } target)
                {
                    if (!exists)
                    {
                        // Nothing below a missing component exists either, so none of it can be
                        // a link: the rest is appended as-is, as a path being created would be.
                        return i + 1 < components.Length
                            ? Path.Combine(current, string.Join(Path.DirectorySeparatorChar, components[(i + 1)..]))
                            : current;
                    }

                    continue;
                }

                if (++hops > MaxLinkHops)
                {
                    throw new IOException($"Too many levels of links resolving '{path}'.");
                }

                // A relative target is relative to the directory holding the link.
                var resolved = Path.GetFullPath(
                    Path.IsPathRooted(target) ? target : Path.Combine(Path.GetDirectoryName(current)!, target));

                // Restart from the target: its own components may be links too, and have not been
                // walked yet.
                full = i + 1 < components.Length
                    ? Path.Combine(resolved, string.Join(Path.DirectorySeparatorChar, components[(i + 1)..]))
                    : resolved;

                followed = true;
                break;
            }

            if (!followed)
            {
                return current;
            }
        }
    }

    /// <summary>
    /// Splits <paramref name="full"/> into the part already known to be free of links and the
    /// components still to be walked.
    /// </summary>
    private static (string Resolved, string Remainder) SplitAtPrefix(string full, string? resolvedPrefix)
    {
        if (resolvedPrefix is { Length: > 0 })
        {
            var comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;

            if (full.Equals(resolvedPrefix, comparison))
            {
                return (resolvedPrefix, string.Empty);
            }

            if (full.Length > resolvedPrefix.Length &&
                full.StartsWith(resolvedPrefix, comparison) &&
                Array.IndexOf(Separators, full[resolvedPrefix.Length]) >= 0)
            {
                return (resolvedPrefix, full[(resolvedPrefix.Length + 1)..]);
            }
        }

        var pathRoot = Path.GetPathRoot(full) ?? string.Empty;
        return (pathRoot, full[pathRoot.Length..]);
    }

    /// <summary>The immediate target of <paramref name="path"/>, or null when it is not a link.</summary>
    /// <param name="exists">False when nothing, not even a dangling link, is at <paramref name="path"/>.</param>
    private static string? ReadLink(string path, out bool exists)
    {
        exists = true;

        FileAttributes attributes;

        try
        {
            // One attribute read answers the common case: neither GetFileAttributesEx nor lstat
            // follows a link, so an ordinary entry needs nothing further.
            attributes = File.GetAttributes(path);
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
        {
            // Possibly a dangling link, whose target is exactly what must be checked before
            // something creates it. Asked of the link itself rather than its target.
            return TryReadLinkTarget(new FileInfo(path), out exists);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException)
        {
            // Unreadable: treat it as an ordinary component and let the operation itself fail.
            return null;
        }

        if ((attributes & FileAttributes.ReparsePoint) == 0)
        {
            return null;
        }

        // Null for reparse points that are not links, such as cloud-file placeholders.
        FileSystemInfo info = (attributes & FileAttributes.Directory) != 0 ? new DirectoryInfo(path) : new FileInfo(path);
        return TryReadLinkTarget(info, out _);
    }

    private static string? TryReadLinkTarget(FileSystemInfo info, out bool exists)
    {
        try
        {
            var target = info.LinkTarget;
            exists = target is not null;
            return target;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException)
        {
            // Unreadable: treat it as an ordinary component and let the operation itself fail.
            exists = true;
            return null;
        }
    }
}
