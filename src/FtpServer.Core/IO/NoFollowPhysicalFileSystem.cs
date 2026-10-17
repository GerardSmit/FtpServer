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
/// a stale "safe" answer is the mistake this class exists to prevent. The cost is one stat per path
/// component per operation.
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

        if (!IsInsideRoot(ResolveLinks(internalPath)))
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
    internal static string ResolveLinks(string path)
    {
        var full = Path.GetFullPath(path);
        var hops = 0;

        while (true)
        {
            var pathRoot = Path.GetPathRoot(full) ?? string.Empty;
            var components = full[pathRoot.Length..].Split(Separators, StringSplitOptions.RemoveEmptyEntries);
            var current = pathRoot;
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
    private static string? ReadLink(string path)
    {
        try
        {
            FileSystemInfo info = Directory.Exists(path) ? new DirectoryInfo(path) : new FileInfo(path);

            // Null for an ordinary entry and for one that does not exist alike.
            return info.LinkTarget;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException)
        {
            // Unreadable: treat it as an ordinary component and let the operation itself fail.
            return null;
        }
    }
}
