using Zio;

namespace FtpServer.IO;

/// <summary>
/// Supplies the tree a logged-in session sees, in place of the configured home directory.
/// </summary>
/// <remarks>
/// A source rather than an <see cref="IFileSystem"/>, because the session owns what it is given:
/// <see cref="FtpSession.ReplaceFileSystem"/> disposes the previous file system and
/// <c>DisposeAsync</c> disposes the last one. An <see cref="Authentication.FtpUser"/> may be handed
/// to several sessions - and is, for every login of the same account - so it cannot carry an
/// instance that the first session to log out would dispose out from under the others.
/// </remarks>
public interface IFtpFileSystemSource
{
    /// <summary>
    /// Creates a file system for one session, which takes ownership of it.
    /// </summary>
    IFileSystem Create();
}
