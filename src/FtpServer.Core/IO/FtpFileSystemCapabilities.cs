using System.Diagnostics.CodeAnalysis;
using Zio;
using Zio.FileSystems;

namespace FtpServer.IO;

/// <summary>
/// Finds the file system that answers for a path, and what it can do: the session's tree is often
/// a <see cref="MountFileSystem"/>, and the folder mounted at a path may be remote, read-only or
/// able to compute checksums where the outer tree is not.
/// </summary>
internal static class FtpFileSystemCapabilities
{
    /// <summary>
    /// Finds the outermost file system on the way to <paramref name="path"/> that implements
    /// <typeparamref name="T"/>, and the path relative to it.
    /// </summary>
    /// <remarks>
    /// Outermost first, so a tree that composes its own mounts and implements the interface itself
    /// answers for everything inside it.
    /// </remarks>
    public static bool TryResolve<T>(IFileSystem fileSystem, UPath path, [NotNullWhen(true)] out T? capability, out UPath innerPath)
        where T : class
    {
        while (true)
        {
            if (fileSystem is T found)
            {
                capability = found;
                innerPath = path;
                return true;
            }

            if (!TryDescend(ref fileSystem, ref path))
            {
                capability = null;
                innerPath = default;
                return false;
            }
        }
    }

    /// <summary>
    /// Whether <paramref name="path"/> lies on this host, so <see cref="IFileSystem.ConvertPathToInternal"/>
    /// can be asked for it.
    /// </summary>
    public static bool HasHostPath(IFileSystem fileSystem, UPath path) =>
        !TryResolve<IFtpRemoteFileSystem>(fileSystem, path, out _, out _);

    /// <summary>
    /// Whether <paramref name="path"/> is inside a folder mounted read-only, or one that says the
    /// path is read-only through <see cref="IFtpReadOnlyPaths"/>.
    /// </summary>
    public static bool IsReadOnly(IFileSystem fileSystem, UPath path)
    {
        while (true)
        {
            if (fileSystem is ReadOnlyFileSystem)
            {
                return true;
            }

            if (fileSystem is IFtpReadOnlyPaths paths && paths.IsReadOnly(path))
            {
                return true;
            }

            if (!TryDescend(ref fileSystem, ref path))
            {
                return false;
            }
        }
    }

    private static bool TryDescend(ref IFileSystem fileSystem, ref UPath path)
    {
        if (fileSystem is MountFileSystem mounts &&
            path.IsAbsolute &&
            mounts.TryGetMount(path, out _, out var target, out var targetPath) &&
            target is not null)
        {
            fileSystem = target;
            path = targetPath ?? UPath.Root;
            return true;
        }

        return false;
    }
}
