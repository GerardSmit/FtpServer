using Zio;

namespace FtpServer.IO;

/// <summary>
/// A file system that computes checksums itself, for HASH and the XCRC/XMD5/XSHA* commands:
/// where the file is, or from a digest it already knows.
/// </summary>
/// <remarks>
/// Looked up per path, so it can be the session's whole file system or one mounted inside a
/// <see cref="Zio.FileSystems.MountFileSystem"/>. The path it receives is relative to itself.
/// </remarks>
public interface IFtpChecksumProvider
{
    /// <summary>
    /// Digests <paramref name="path"/> from <paramref name="start"/> up to the exclusive
    /// <paramref name="end"/>.
    /// </summary>
    /// <param name="algorithm">One of the <see cref="FtpChecksumAlgorithm"/> names.</param>
    /// <returns>
    /// The digest as hexadecimal (CRC32 big-endian, as on the wire), or <c>null</c> to have the
    /// server read the file through <see cref="IFileSystem.OpenFile"/> and digest it itself.
    /// </returns>
    ValueTask<string?> ComputeChecksumAsync(UPath path, string algorithm, long start, long end, CancellationToken token);
}
