using FtpServer.Options;
using Microsoft.Extensions.Logging;
using Zio;
using Zio.FileSystems;

namespace FtpServer.IO;

/// <summary>
/// Builds the trees sessions are served from: the server-wide root, a user's home directory, and
/// any virtual folders grafted onto it.
/// </summary>
/// <remarks>
/// Every tree is built fresh per session, because a session owns and disposes what it is given.
/// </remarks>
public class FtpFileSystemFactory(FtpOptionsProvider options, ILogger<FtpFileSystemFactory> logger)
{
    /// <summary>Absolute path of the configured server root, for startup logging and validation.</summary>
    public string RootPath => ResolveRoot(options.Current.Path);

    /// <summary>
    /// Creates a file system rooted at the server-wide root, with the server-wide virtual folders
    /// mounted onto it. This is what a session that has no user of its own is served from.
    /// </summary>
    public virtual IFileSystem CreateRoot() => CreateForUser(new FtpUserOptions());

    /// <summary>
    /// Creates the tree for a user: their home directory, with the server-wide virtual folders and
    /// then their own mounted onto it.
    /// </summary>
    public virtual IFileSystem CreateForUser(FtpUserOptions user)
    {
        var root = ResolveRoot(options.Current.Path);
        var home = Mount(ResolveHome(root, user.HomeDirectory), options.Current.FollowLinks);

        var folders = Combine(options.Current.VirtualFolders, user.VirtualFolders);

        if (folders.Count == 0)
        {
            return home;
        }

        // Owned, so disposing the mount file system disposes the home and every mounted folder
        // with it - which is what the session's Dispose ends up doing.
        var mounts = new MountFileSystem(home, owned: true);

        try
        {
            foreach (var folder in folders)
            {
                MountVirtualFolder(mounts, user, folder, root);
            }
        }
        catch
        {
            mounts.Dispose();
            throw;
        }

        return mounts;
    }

    /// <summary>
    /// The folders a user actually gets: the server-wide ones, with their own taking the place of
    /// any that mount on the same path.
    /// </summary>
    /// <remarks>
    /// A user's entry has to replace rather than accompany the server's, because Zio refuses a
    /// second mount on the same name - and because the narrower definition is the one an operator
    /// writing it per user meant.
    /// </remarks>
    private static List<FtpVirtualFolderOptions> Combine(
        IList<FtpVirtualFolderOptions> serverWide,
        IList<FtpVirtualFolderOptions> perUser)
    {
        var folders = new List<FtpVirtualFolderOptions>(serverWide.Count + perUser.Count);

        foreach (var folder in serverWide)
        {
            var overridden = false;

            foreach (var candidate in perUser)
            {
                if (string.Equals(
                        FtpOptionsValidator.Normalise(candidate.Path),
                        FtpOptionsValidator.Normalise(folder.Path),
                        StringComparison.Ordinal))
                {
                    overridden = true;
                    break;
                }
            }

            if (!overridden)
            {
                folders.Add(folder);
            }
        }

        folders.AddRange(perUser);

        return folders;
    }

    /// <summary>
    /// A source that rebuilds <see cref="CreateForUser"/> per session, for an authenticator to hand
    /// to an <see cref="Authentication.FtpUser"/>.
    /// </summary>
    public IFtpFileSystemSource SourceFor(FtpUserOptions user) => new ConfiguredUserSource(this, user);

    private void MountVirtualFolder(MountFileSystem mounts, FtpUserOptions user, FtpVirtualFolderOptions folder, string root)
    {
        // The physical path is deliberately not confined to the server root: mapping a directory
        // from elsewhere on the host is the whole point of a virtual folder. Confinement still
        // applies within the mount, so only the mapped subtree is reachable through it.
        var physicalPath = Path.IsPathRooted(folder.PhysicalPath)
            ? Path.GetFullPath(folder.PhysicalPath)
            : Path.GetFullPath(Path.Combine(root, folder.PhysicalPath));

        IFileSystem fileSystem;

        try
        {
            fileSystem = Mount(physicalPath, folder.FollowLinks ?? options.Current.FollowLinks);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException)
        {
            // A folder on a disconnected share must not cost the user their whole login; the rest
            // of the tree is still serviceable, and the missing mount is visible in the log.
            Log.VirtualFolderMountFailed(logger, folder.Path, string.IsNullOrEmpty(user.Name) ? "(every user)" : user.Name, ex);
            return;
        }

        try
        {
            if (folder.ReadOnly)
            {
                fileSystem = new ReadOnlyFileSystem(fileSystem, owned: true);
            }

            mounts.Mount(FtpOptionsValidator.Normalise(folder.Path), fileSystem);
        }
        catch
        {
            fileSystem.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Mounts <paramref name="path"/> as the whole of a session's visible file system.
    /// </summary>
    /// <remarks>
    /// The <see cref="SubFileSystem"/> wrapper is unconditional. Skipping it for a root of "/"
    /// would expose every drive on the host, which is exactly what a mis-set default must not do.
    /// </remarks>
    protected IFileSystem Mount(string rootedPath, bool followLinks)
    {
        // A plain PhysicalFileSystem resolves links the way the host does, so the sub-filesystem
        // below only clamps the pathname and not the object it lands on.
        var physical = followLinks
            ? new PhysicalFileSystem()
            : new NoFollowPhysicalFileSystem(rootedPath);

        try
        {
            if (!Directory.Exists(rootedPath))
            {
                Directory.CreateDirectory(rootedPath);
            }

            var internalPath = physical.ConvertPathFromInternal(rootedPath);
            return new SubFileSystem(physical, internalPath, owned: true);
        }
        catch
        {
            physical.Dispose();
            throw;
        }
    }

    public static string ResolveRoot(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            path = "ftproot";
        }

        return Path.GetFullPath(path);
    }

    /// <summary>
    /// Resolves a per-user home to an absolute path that is guaranteed to lie under the server
    /// root. Anything that escapes falls back to the root itself.
    /// </summary>
    public string ResolveHome(string homeDirectory) => ResolveHome(ResolveRoot(options.Current.Path), homeDirectory);

    internal static string ResolveHome(string root, string? homeDirectory)
    {
        if (string.IsNullOrWhiteSpace(homeDirectory))
        {
            return root;
        }

        // Rooted homes are rejected rather than reinterpreted: "C:\" must not become the disk.
        if (Path.IsPathRooted(homeDirectory))
        {
            return root;
        }

        var combined = Path.GetFullPath(Path.Combine(root, homeDirectory));
        var normalisedRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(root));

        var comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;

        if (!combined.Equals(normalisedRoot, comparison) &&
            !combined.StartsWith(normalisedRoot + Path.DirectorySeparatorChar, comparison))
        {
            return root;
        }

        return combined;
    }

    private sealed class ConfiguredUserSource(FtpFileSystemFactory factory, FtpUserOptions user) : IFtpFileSystemSource
    {
        public IFileSystem Create() => factory.CreateForUser(user);
    }
}
