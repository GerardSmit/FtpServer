using Zio;

namespace FtpServer.IO;

/// <summary>
/// A file system that reports the free space AVBL answers with: for a tree on another machine,
/// or one held to a quota smaller than its volume.
/// </summary>
/// <remarks>
/// Looked up per path, so it can be the session's whole file system or one mounted inside a
/// <see cref="Zio.FileSystems.MountFileSystem"/>. The path it receives is relative to itself.
/// </remarks>
public interface IFtpAvailableSpaceProvider
{
    /// <summary>The free space, in bytes, available to <paramref name="path"/>, or <c>null</c> when unknown.</summary>
    ValueTask<long?> GetAvailableSpaceAsync(UPath path, CancellationToken token);
}
