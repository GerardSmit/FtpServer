namespace FtpServer.IO;

/// <summary>
/// The checksum algorithms the server offers, by the names HASH uses on the wire
/// (draft-bryan-ftpext-hash), which is also what <see cref="IFtpChecksumProvider"/> receives.
/// </summary>
public static class FtpChecksumAlgorithm
{
    public const string Crc32 = "CRC32";
    public const string Md5 = "MD5";
    public const string Sha1 = "SHA-1";
    public const string Sha256 = "SHA-256";
    public const string Sha512 = "SHA-512";
}
