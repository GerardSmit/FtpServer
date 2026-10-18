using System.Buffers;
using System.IO.Hashing;
using System.Security.Cryptography;
using FtpServer.Extensions;
using FtpServer.IO;
using Zio;

namespace FtpServer.Handlers;

public partial class DefaultFtpCommandHandler
{
    public override ValueTask CalculateCrc32ChecksumAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
        => ChecksumAsync(session, data, HashAlgorithms.Crc32, legacy: true, token);

    public override ValueTask CalculateMd5ChecksumAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
        => ChecksumAsync(session, data, HashAlgorithms.Md5, legacy: true, token);

    public override ValueTask CalculateSha1ChecksumAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
        => ChecksumAsync(session, data, HashAlgorithms.Sha1, legacy: true, token);

    public override ValueTask CalculateSha256ChecksumAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
        => ChecksumAsync(session, data, HashAlgorithms.Sha256, legacy: true, token);

    public override ValueTask CalculateSha512ChecksumAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
        => ChecksumAsync(session, data, HashAlgorithms.Sha512, legacy: true, token);

    public override ValueTask HashAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
        => ChecksumAsync(session, data, session.HashAlgorithm, legacy: false, token);

    /// <summary>
    /// RANG selects the byte range used by the next command (draft-bryan-ftp-range).
    /// </summary>
    /// <remarks>
    /// Both offsets are inclusive, so "RANG 0 49" selects 50 octets. A start greater than the end
    /// is the defined way to clear the range rather than an error.
    /// </remarks>
    public override ValueTask HashRangeAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        if (TryRejectAnonymous(session, FtpCommand.HashRange, out var rejected))
        {
            return rejected;
        }

        // The grammar requires both arguments, so a bare RANG is a syntax error.
        if (data.IsEmpty)
        {
            session.HashRange = null;
            return session.WriteAsync("501 Syntax error in parameters or arguments.\r\n"u8, token);
        }

        var fields = data.GetString(session.Encoding).Split(' ', StringSplitOptions.RemoveEmptyEntries);

        if (fields.Length != 2 ||
            !long.TryParse(fields[0], out var start) ||
            !long.TryParse(fields[1], out var end) ||
            start < 0 || end < 0)
        {
            return session.WriteAsync("501 Syntax error in parameters or arguments.\r\n"u8, token);
        }

        // "RANG 1 0" is the defined reset. Any other inverted range is invalid, and the draft
        // says the server both rejects it with 501 and resets the selection.
        if (start > end)
        {
            session.HashRange = null;

            return start == 1 && end == 0
                ? session.WriteAsync("350 Range reset.\r\n"u8, token)
                : session.WriteAsync("501 Syntax error in parameters or arguments.\r\n"u8, token);
        }

        session.HashRange = (start, end);
        return session.WriteAsync($"350 Range set to {start}-{end}.\r\n", token);
    }

    private async ValueTask ChecksumAsync(FtpSession session, ReadOnlySequence<byte> data, string algorithm, bool legacy, CancellationToken token)
    {
        if (TryRejectAnonymous(session, FtpCommand.CalculateCrc32Checksum, out var rejected))
        {
            await rejected;
            return;
        }

        var features = options.Current.Features;

        if (legacy ? !features.XCRC : !features.Hash)
        {
            await session.WriteAsync("502 Command not implemented.\r\n"u8, token);
            return;
        }

        // HASH takes a pathname and nothing else; only the de-facto X* commands carry a range in
        // their argument, so the trailing-number heuristic must not be applied to HASH or a file
        // whose name ends in a number becomes unreachable. For the X* commands an existing file
        // named by the whole argument still wins over the heuristic.
        var parsed = legacy
            ? data.TryGetChecksumRequest(session.CurrentDirectory, session.Encoding, out var request, session.FileSystem.FileExists)
            : TryGetPathOnly(data, session, out request);

        if (!parsed)
        {
            await session.WriteAsync("501 Syntax error in parameters or arguments.\r\n"u8, token);
            return;
        }

        if (session.FileSystem.DirectoryExists(request.Path))
        {
            await session.WriteAsync("553 Requested action not taken: not a regular file.\r\n"u8, token);
            return;
        }

        if (!session.FileSystem.FileExists(request.Path))
        {
            await session.WriteAsync("550 File not found.\r\n"u8, token);
            return;
        }

        var length = session.FileSystem.GetFileLength(request.Path);

        // The X* commands carry an exclusive end in their own argument, which is the de-facto
        // convention ("XCRC f 0 <size>" digests the whole file). RANG's end is inclusive, so it
        // is converted to the same exclusive form here.
        var (start, end) = legacy
            ? (request.Start ?? 0, request.End ?? length)
            : (session.HashRange?.Start ?? 0, session.HashRange is { } range ? range.End + 1 : length);

        // A range applies to exactly one command.
        session.HashRange = null;

        if (start > length || end > length || start > end)
        {
            await session.WriteAsync("550 Requested action not taken: range is outside the file.\r\n"u8, token);
            return;
        }

        string digest;

        try
        {
            // A tree that digests files itself - where they are, or from a digest it already
            // knows - saves streaming the whole file here first.
            digest = FtpFileSystemCapabilities.TryResolve<IFtpChecksumProvider>(session.FileSystem, request.Path, out var provider, out var providerPath) &&
                     await provider.ComputeChecksumAsync(providerPath, algorithm, start, end, token) is { } providedDigest
                ? providedDigest.ToLowerInvariant()
                : await ComputeAsync(session, request.Path, algorithm, start, end, token);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            await session.WriteAsync("550 Requested action not taken.\r\n"u8, token);
            return;
        }

        if (legacy)
        {
            // The de-facto X* commands answer 250 with the bare upper-case hex digest and nothing
            // after it. Indy's TIdFTP (Beyond Compare among others) accepts no other code and
            // reads the rest of the line as the digest, so 213 fails every comparison.
            await session.WriteAsync("250 "u8,digest.ToUpperInvariant(), "\r\n"u8, token);
            return;
        }

        // draft-bryan-ftpext-hash section 3. The reported range is inclusive, matching RANG.
        await session.WriteAsync($"213 {algorithm} {start}-{Math.Max(start, end - 1)} {digest} {request.Path.FullName}\r\n", token);
    }

    /// <summary>Treats the whole argument as a pathname, with no range heuristic.</summary>
    private static bool TryGetPathOnly(ReadOnlySequence<byte> data, FtpSession session, out ChecksumRequest request)
    {
        request = default;

        var text = data.GetString(session.Encoding).Trim();

        if (text.Length == 0 || !Extensions.SequenceExtensions.TryResolvePath(text, session.CurrentDirectory, out var path))
        {
            return false;
        }

        request = new ChecksumRequest(path, null, null);
        return true;
    }

    private static async ValueTask<string> ComputeAsync(FtpSession session, UPath path, string algorithm, long start, long end, CancellationToken token)
    {
        await using var stream = session.FileSystem.OpenFile(path, FileMode.Open, FileAccess.Read, FileShare.Read);

        if (start > 0)
        {
            stream.Seek(start, SeekOrigin.Begin);
        }

        var remaining = end - start;
        var buffer = ArrayPool<byte>.Shared.Rent(81920);

        try
        {
            if (algorithm == HashAlgorithms.Crc32)
            {
                var crc = new Crc32();
                await ReadAllAsync(stream, buffer, remaining, chunk => crc.Append(chunk.Span), token);

                Span<byte> hash = stackalloc byte[4];
                crc.GetCurrentHash(hash);
                hash.Reverse(); // Crc32 emits little-endian; the wire format is big-endian.
                return Convert.ToHexStringLower(hash);
            }

            using var incremental = IncrementalHash.CreateHash(HashAlgorithms.ToHashAlgorithmName(algorithm));
            await ReadAllAsync(stream, buffer, remaining, chunk => incremental.AppendData(chunk.Span), token);
            return Convert.ToHexStringLower(incremental.GetCurrentHash());
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    /// <summary>
    /// Streams at most <paramref name="remaining"/> bytes through <paramref name="consume"/>,
    /// asynchronously so the calling thread is never blocked on file I/O.
    /// </summary>
    private static async ValueTask ReadAllAsync(Stream stream, byte[] buffer, long remaining, Action<ReadOnlyMemory<byte>> consume, CancellationToken token)
    {
        while (remaining > 0)
        {
            var want = (int)Math.Min(buffer.Length, remaining);
            var read = await stream.ReadAsync(buffer.AsMemory(0, want), token);

            if (read == 0)
            {
                break;
            }

            consume(buffer.AsMemory(0, read));
            remaining -= read;
        }
    }

    // ---- space and size reporting -----------------------------------------

    public override ValueTask GetAvailableSpaceAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        if (TryRejectAnonymous(session, FtpCommand.GetAvailableSpace, out var rejected))
        {
            return rejected;
        }

        var path = session.CurrentDirectory;

        if (!data.IsEmpty && !data.TryResolvePath(session.CurrentDirectory, session.Encoding, out path))
        {
            return session.WriteAsync("550 Invalid path.\r\n"u8, token);
        }

        if (!session.FileSystem.DirectoryExists(path))
        {
            return session.WriteAsync("550 Directory not found.\r\n"u8, token);
        }

        if (FtpFileSystemCapabilities.TryResolve<IFtpAvailableSpaceProvider>(session.FileSystem, path, out var provider, out var providerPath))
        {
            return GetProvidedAvailableSpaceAsync(session, provider, providerPath, token);
        }

        // A remote tree that cannot say has no volume here to ask either.
        if (!FtpFileSystemCapabilities.HasHostPath(session.FileSystem, path))
        {
            return session.WriteAsync("550 Requested action not taken.\r\n"u8, token);
        }

        try
        {
            var internalPath = session.FileSystem.ConvertPathToInternal(path);
            var drive = new DriveInfo(Path.GetPathRoot(internalPath) ?? internalPath);
            return session.WriteAsync("213 "u8, drive.AvailableFreeSpace.ToString(), "\r\n"u8, token);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            return session.WriteAsync("550 Requested action not taken.\r\n"u8, token);
        }
    }

    private static async ValueTask GetProvidedAvailableSpaceAsync(FtpSession session, IFtpAvailableSpaceProvider provider, UPath path, CancellationToken token)
    {
        long? available;

        try
        {
            available = await provider.GetAvailableSpaceAsync(path, token);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            available = null;
        }

        if (available is not { } bytes)
        {
            await session.WriteAsync("550 Requested action not taken.\r\n"u8, token);
            return;
        }

        await session.WriteAsync("213 "u8, bytes.ToString(System.Globalization.CultureInfo.InvariantCulture), "\r\n"u8, token);
    }

    public override ValueTask GetDirectorySizeAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        if (TryRejectAnonymous(session, FtpCommand.GetDirectorySize, out var rejected))
        {
            return rejected;
        }

        var path = session.CurrentDirectory;

        if (!data.IsEmpty && !data.TryResolvePath(session.CurrentDirectory, session.Encoding, out path))
        {
            return session.WriteAsync("550 Invalid path.\r\n"u8, token);
        }

        if (!session.FileSystem.DirectoryExists(path))
        {
            return session.WriteAsync("550 Directory not found.\r\n"u8, token);
        }

        long total = 0;
        var remaining = options.Current.List.MaxEntries;

        // Driven a directory at a time rather than by SearchOption.AllDirectories, whose internal
        // descent would never present the subdirectories for the file system's containment check.
        if (!TryMeasure(path, 0, ref total, ref remaining))
        {
            return session.WriteAsync("550 Requested action not taken: directory is too large to measure.\r\n"u8, token);
        }

        return session.WriteAsync("213 "u8, total.ToString(), "\r\n"u8, token);

        bool TryMeasure(UPath directory, int depth, ref long sum, ref int budget)
        {
            if (depth >= options.Current.List.RecursionLimit)
            {
                return true;
            }

            foreach (var item in EnumerateSafely(session, directory))
            {
                if (budget-- <= 0)
                {
                    return false;
                }

                if (item.IsDirectory)
                {
                    if (!TryMeasure(item.Path, depth + 1, ref sum, ref budget))
                    {
                        return false;
                    }

                    continue;
                }

                try
                {
                    sum += item.Length;
                }
                catch (IOException)
                {
                    // Entry vanished mid-walk.
                }
            }

            return true;
        }
    }
}

internal static class HashAlgorithms
{
    public const string Crc32 = FtpChecksumAlgorithm.Crc32;
    public const string Md5 = FtpChecksumAlgorithm.Md5;
    public const string Sha1 = FtpChecksumAlgorithm.Sha1;
    public const string Sha256 = FtpChecksumAlgorithm.Sha256;
    public const string Sha512 = FtpChecksumAlgorithm.Sha512;

    public static readonly string[] Supported = [Sha256, Sha512, Sha1, Md5, Crc32];

    public static bool TryNormalise(string value, out string algorithm)
    {
        algorithm = value.Replace("-", string.Empty).ToUpperInvariant() switch
        {
            "CRC32" => Crc32,
            "MD5" => Md5,
            "SHA1" => Sha1,
            "SHA256" => Sha256,
            "SHA512" => Sha512,
            _ => string.Empty,
        };

        return algorithm.Length > 0;
    }

    public static HashAlgorithmName ToHashAlgorithmName(string algorithm) => algorithm switch
    {
        Md5 => HashAlgorithmName.MD5,
        Sha1 => HashAlgorithmName.SHA1,
        Sha512 => HashAlgorithmName.SHA512,
        _ => HashAlgorithmName.SHA256,
    };

    /// <summary>Renders the FEAT line, with an asterisk marking the currently selected algorithm.</summary>
    public static string FeatureLine(string selected) =>
        string.Join(';', Supported.Select(a => a == selected ? a + "*" : a));
}
