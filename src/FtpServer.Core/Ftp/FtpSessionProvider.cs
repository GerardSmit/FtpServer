using System.IO.Pipelines;
using FtpServer.Authentication;
using FtpServer.IO;
using Zio;

namespace FtpServer;

public class FtpSessionProvider(
    IServiceProvider provider,
    FtpOptionsProvider options,
    FtpFileSystemFactory fileSystems)
{
    public FtpSession CreateSession(IDuplexPipe pipe)
    {
        var session = new FtpSession(pipe, provider, CreateFileSystem())
        {
            IsReadOnly = options.Current.ReadOnly,
        };

        return session;
    }

    /// <summary>Creates a file system rooted at the server-wide root, as REIN needs to restore.</summary>
    /// <remarks>
    /// Override this (and register the derived provider) to serve something other than a physical
    /// directory - an in-memory tree, a composite mount, or a remote store. For a tree that differs
    /// per user, have the authenticator put an <see cref="IFtpFileSystemSource"/> on the
    /// <see cref="FtpUser"/> instead.
    /// </remarks>
    public virtual IFileSystem CreateFileSystem() => fileSystems.CreateRoot();

    /// <summary>
    /// Narrows the session to the tree the user logged in to.
    /// </summary>
    public virtual void ApplyUser(FtpSession session, FtpUser user)
    {
        session.IsReadOnly = options.Current.ReadOnly || user.IsReadOnly;

        // Mounted unconditionally, so a login never keeps the tree the previous one was given.
        // A home directory narrows a user; ResolveHome is what stops it widening them.
        session.ReplaceFileSystem(CreateFileSystem(user));

        session.CurrentDirectory = UPath.Root;
    }

    /// <summary>
    /// Builds the tree for a logged-in user: whatever the authenticator supplied, else their home
    /// directory, else the server-wide root.
    /// </summary>
    protected virtual IFileSystem CreateFileSystem(FtpUser user)
    {
        if (user.FileSystem is { } source)
        {
            return source.Create();
        }

        return string.IsNullOrWhiteSpace(user.HomeDirectory)
            ? CreateFileSystem()
            : fileSystems.CreateForUser(new Options.FtpUserOptions
            {
                Name = user.Name,
                HomeDirectory = user.HomeDirectory,
            });
    }

    /// <summary>Absolute path of the configured server root, for startup logging and validation.</summary>
    public string RootPath => fileSystems.RootPath;

    /// <summary>
    /// Resolves a per-user home to an absolute path that is guaranteed to lie under the server
    /// root. Anything that escapes falls back to the root itself.
    /// </summary>
    public string ResolveHome(string homeDirectory) => fileSystems.ResolveHome(homeDirectory);
}
