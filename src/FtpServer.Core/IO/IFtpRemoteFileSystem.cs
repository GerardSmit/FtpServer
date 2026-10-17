using Zio;

namespace FtpServer.IO;

/// <summary>
/// A file system whose files are not on this host, such as one that forwards every call to
/// another machine.
/// </summary>
/// <remarks>
/// <para>
/// Implementing it tells the handlers there is no host path behind the tree, so they never call
/// <see cref="IFileSystem.ConvertPathToInternal"/>: listings take their permissions from the
/// entry's attributes instead of throwing and catching an exception per entry, and SITE CHMOD,
/// SITE SYMLINK and the UNIX.mode fact of MFF are not attempted.
/// </para>
/// <para>
/// It also lets the work that needs the file's content or its volume happen where the file is:
/// without it a checksum reads the whole file across the network only to digest it here.
/// </para>
/// </remarks>
public interface IFtpRemoteFileSystem
{
    /// <summary>
    /// Digests <paramref name="path"/> from <paramref name="start"/> up to the exclusive
    /// <paramref name="end"/>.
    /// </summary>
    /// <param name="algorithm">One of <c>CRC32</c>, <c>MD5</c>, <c>SHA-1</c>, <c>SHA-256</c> or <c>SHA-512</c>.</param>
    /// <returns>
    /// The digest as hexadecimal (CRC32 big-endian, as on the wire), or <c>null</c> to have the
    /// server read the file through <see cref="IFileSystem.OpenFile"/> and digest it itself.
    /// </returns>
    ValueTask<string?> ComputeChecksumAsync(UPath path, string algorithm, long start, long end, CancellationToken token);

    /// <summary>The free space, in bytes, of the volume that holds <paramref name="path"/>, or <c>null</c> when unknown.</summary>
    ValueTask<long?> GetAvailableSpaceAsync(UPath path, CancellationToken token);
}
