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
/// Resolution below the root is deliberately not cached: a directory can be replaced by a link
/// after the fact, and a stale "safe" answer is the mistake this class exists to prevent. The cost
/// is one stat per path component below the root per operation.
///
/// The root's own components are not walked per operation: the root is resolved at construction,
/// and each walk starts from where it landed, so the cost does not grow with how deep the root sits
/// on the disk. The trade-off is that a directory at or above the root being swapped for a link is
/// only noticed when the root is next re-resolved - at most <see cref="DefaultRootRecheckInterval"/>
/// later - after which a root that no longer lands where it did refuses everything. That part of
/// the disk is the operator's, outside the tree any FTP user can write to.
///
/// One more exception is an entry of a directory that is being enumerated: the directory itself
/// was resolved when the enumeration started, so for its children only the last component is
/// checked. That is what keeps a listing linear in the number of entries rather than in entries
/// times depth. The shortcut ends with the enumeration.
/// </remarks>
public sealed class NoFollowPhysicalFileSystem : PhysicalFileSystem
{
    private static readonly char[] Separators = ['/', '\\'];

    /// <summary>Bounds a link chain, and with it a cycle.</summary>
    private const int MaxLinkHops = 64;

    /// <summary>How long a successful re-resolution of the root is trusted.</summary>
    internal static readonly TimeSpan DefaultRootRecheckInterval = TimeSpan.FromSeconds(1);

    /// <summary>Where the root really lands, resolved once at construction.</summary>
    private readonly string _root;

    /// <summary>The root as configured: the prefix Zio's native paths start with.</summary>
    private readonly string _configuredRoot;

    private readonly long _rootRecheckMilliseconds;

    /// <summary>
    /// <see cref="Environment.TickCount64"/> until which the root is known to still land on
    /// <see cref="_root"/>.
    /// </summary>
    private long _rootTrustedUntil;

    /// <summary>
    /// Directories with an enumeration in progress, keyed by native path, with a count so nested or
    /// concurrent enumerations of the same directory do not end each other's shortcut.
    /// </summary>
    private readonly Dictionary<string, int> _enumerating = new(
        OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal);

    /// <param name="root">Native path of the directory every operation must stay within.</param>
    public NoFollowPhysicalFileSystem(string root)
        : this(root, DefaultRootRecheckInterval)
    {
    }

    /// <param name="root">Native path of the directory every operation must stay within.</param>
    /// <param name="rootRecheckInterval">
    /// How long a resolution of the root is trusted. <see cref="TimeSpan.Zero"/> re-resolves it on
    /// every operation.
    /// </param>
    internal NoFollowPhysicalFileSystem(string root, TimeSpan rootRecheckInterval)
    {
        _configuredRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(root));

        // The root may itself be a link; what matters is where it lands.
        _root = Path.TrimEndingDirectorySeparator(ResolveLinks(_configuredRoot));

        _rootRecheckMilliseconds = (long)rootRecheckInterval.TotalMilliseconds;
        _rootTrustedUntil = Environment.TickCount64 + _rootRecheckMilliseconds;
    }

    private static StringComparison PathComparison =>
        OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;

    protected override string ConvertPathToInternalImpl(UPath path)
    {
        var internalPath = base.ConvertPathToInternalImpl(path);

        // A child of a directory being enumerated: its parent was resolved inside the root when the
        // enumeration began, so the child is inside too unless it is itself a link.
        if (IsEnumerating(Path.GetDirectoryName(internalPath)) && ReadLink(internalPath) is null)
        {
            return internalPath;
        }

        if (!IsInsideRoot(Resolve(internalPath)))
        {
            throw new UnauthorizedAccessException($"'{path}' resolves outside the server root.");
        }

        return internalPath;
    }

    protected override IEnumerable<FileSystemItem> EnumerateItemsImpl(UPath path, SearchOption searchOption, SearchPredicate? searchPredicate)
    {
        // Validates the directory, and throws before anything is registered when it is outside.
        var directory = Path.TrimEndingDirectorySeparator(ConvertPathToInternalImpl(path));

        return Enumerate(directory, base.EnumerateItemsImpl(path, searchOption, searchPredicate));
    }

    private IEnumerable<FileSystemItem> Enumerate(string directory, IEnumerable<FileSystemItem> items)
    {
        lock (_enumerating)
        {
            _enumerating[directory] = _enumerating.GetValueOrDefault(directory) + 1;
        }

        try
        {
            foreach (var item in items)
            {
                yield return item;
            }
        }
        finally
        {
            lock (_enumerating)
            {
                if (--_enumerating[directory] == 0)
                {
                    _enumerating.Remove(directory);
                }
            }
        }
    }

    private bool IsEnumerating(string? directory)
    {
        if (directory is null)
        {
            return false;
        }

        lock (_enumerating)
        {
            return _enumerating.Count > 0 && _enumerating.ContainsKey(Path.TrimEndingDirectorySeparator(directory));
        }
    }

    private bool IsInsideRoot(string candidate) => TryGetRelative(candidate, _root, out _);

    /// <summary>
    /// Resolves a native path, walking only what lies below the root while the root is known to
    /// land where it did.
    /// </summary>
    private string Resolve(string internalPath)
    {
        if (!IsRootIntact())
        {
            // Walked in full; nothing lands inside a root that has moved.
            return ResolveLinks(internalPath);
        }

        var full = Path.GetFullPath(internalPath);

        // Zio reports paths under the root as configured. When the root is itself a link, that
        // prefix is not where it lands, and the walk continues from the landing place instead.
        if (TryGetRelative(full, _configuredRoot, out var relative))
        {
            full = relative.Length == 0 ? _root : Path.Join(_root, relative);
        }

        return ResolveLinks(full, _root);
    }

    /// <summary>Whether the root still resolves to <see cref="_root"/>, re-checked periodically.</summary>
    private bool IsRootIntact()
    {
        var now = Environment.TickCount64;

        if (now < Volatile.Read(ref _rootTrustedUntil))
        {
            return true;
        }

        string resolved;

        try
        {
            resolved = Path.TrimEndingDirectorySeparator(ResolveLinks(_configuredRoot));
        }
        catch (IOException)
        {
            return false;
        }

        if (!resolved.Equals(_root, PathComparison))
        {
            // Not remembered: every operation walks in full until the root lands where it did.
            return false;
        }

        Volatile.Write(ref _rootTrustedUntil, now + _rootRecheckMilliseconds);
        return true;
    }

    /// <summary>
    /// The part of <paramref name="path"/> below <paramref name="prefix"/>, empty when both name
    /// the same directory. False when the path is neither the prefix nor under it.
    /// </summary>
    private static bool TryGetRelative(string path, string prefix, out string relative)
    {
        relative = string.Empty;
        var trimmed = Path.TrimEndingDirectorySeparator(path);

        if (trimmed.Equals(prefix, PathComparison))
        {
            return true;
        }

        // A volume root keeps its separator through the trim.
        var withSeparator = Path.EndsInDirectorySeparator(prefix) ? prefix : prefix + Path.DirectorySeparatorChar;

        if (!trimmed.StartsWith(withSeparator, PathComparison))
        {
            return false;
        }

        relative = trimmed[withSeparator.Length..];
        return true;
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
    internal static string ResolveLinks(string path) => ResolveLinks(path, resolvedPrefix: null);

    /// <param name="path">The path to resolve.</param>
    /// <param name="resolvedPrefix">
    /// A directory known to contain no links. A walk that starts at or below it - the path itself,
    /// or wherever a link leads - begins there instead of at the volume root.
    /// </param>
    private static string ResolveLinks(string path, string? resolvedPrefix)
    {
        var full = Path.GetFullPath(path);
        var hops = 0;

        while (true)
        {
            string current;
            string remainder;

            if (resolvedPrefix is not null && TryGetRelative(full, resolvedPrefix, out var relative))
            {
                current = resolvedPrefix;
                remainder = relative;
            }
            else
            {
                current = Path.GetPathRoot(full) ?? string.Empty;
                remainder = full[current.Length..];
            }

            var components = remainder.Split(Separators, StringSplitOptions.RemoveEmptyEntries);
            var followed = false;

            for (var i = 0; i < components.Length; i++)
            {
                current = Path.Combine(current, components[i]);

                if (ReadLink(current) is not { } target)
                {
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

    /// <summary>The immediate target of <paramref name="path"/>, or null when it is not a link.</summary>
    /// <remarks>
    /// The attributes come from one stat that does not follow the link, and only an entry flagged
    /// as a reparse point (Windows) or symbolic link (Unix, reported the same way) pays for reading
    /// the target. FileInfo serves directories as well here: neither call depends on the kind.
    /// </remarks>
    private static string? ReadLink(string path)
    {
        try
        {
            var info = new FileInfo(path);
            var attributes = info.Attributes;

            // -1 is what a missing entry reports, every flag set.
            if ((int)attributes == -1 || (attributes & FileAttributes.ReparsePoint) == 0)
            {
                return null;
            }

            // Null for a reparse point that is not a link (a OneDrive placeholder, say).
            return info.LinkTarget;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException)
        {
            // Unreadable: treat it as an ordinary component and let the operation itself fail.
            return null;
        }
    }
}
