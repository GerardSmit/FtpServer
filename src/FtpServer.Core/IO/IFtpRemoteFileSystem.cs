using Zio;

namespace FtpServer.IO;

/// <summary>
/// Marks a file system whose files are not on this host, such as one that forwards every call to
/// another machine.
/// </summary>
/// <remarks>
/// <para>
/// It tells the handlers there is no host path behind the tree, so they never call
/// <see cref="IFileSystem.ConvertPathToInternal"/> for a path inside it: listings take their
/// permissions from the entry's attributes instead of throwing and catching an exception per
/// entry, SITE CHMOD and SITE SYMLINK are not attempted, and MFF refuses the UNIX.mode fact.
/// </para>
/// <para>
/// The tree may be the session's whole file system or be mounted inside a
/// <see cref="Zio.FileSystems.MountFileSystem"/>; the handlers look it up per path. A remote tree
/// usually also implements <see cref="IFtpChecksumProvider"/> and
/// <see cref="IFtpAvailableSpaceProvider"/>, because without them a checksum reads the whole
/// file across the network only to digest it here, and AVBL has no volume to ask.
/// </para>
/// </remarks>
public interface IFtpRemoteFileSystem;
