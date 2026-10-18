using Zio;

namespace FtpServer.IO;

/// <summary>
/// A file system in which some paths may not be modified, told to the server so it can say so
/// before acting.
/// </summary>
/// <remarks>
/// <para>
/// Without it the server only learns a path is read-only when the file system throws, which for
/// STOR is after the data connection opened, and listings advertise write permissions that then
/// fail. With it, modifying commands are refused with 550 up front and the MLSx perm fact leaves
/// out the write permissions.
/// </para>
/// <para>
/// Looked up per path, so it can be the session's whole file system or one mounted inside a
/// <see cref="Zio.FileSystems.MountFileSystem"/>. The path it receives is relative to itself.
/// </para>
/// </remarks>
public interface IFtpReadOnlyPaths
{
    /// <summary>
    /// Whether <paramref name="path"/> may not be created, written, renamed or deleted; for a
    /// directory, that also covers creating or removing entries in it.
    /// </summary>
    bool IsReadOnly(UPath path);
}
