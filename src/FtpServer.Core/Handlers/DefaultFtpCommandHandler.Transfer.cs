using System.Buffers;
using FtpServer.Data;
using FtpServer.Extensions;
using FtpServer.IO;
using Zio;

namespace FtpServer.Handlers;

public partial class DefaultFtpCommandHandler
{
    private const int TransferBufferSize = 81920;

    // ---- transfer parameters ---------------------------------------------

    public override ValueTask SetTransferTypeAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        if (TryRejectAnonymous(session, FtpCommand.SetTransferType, out var rejected))
        {
            return rejected;
        }

        if (data.IsEmpty)
        {
            return session.WriteAsync("501 Syntax error in parameters or arguments.\r\n"u8, token);
        }

        Span<byte> argument = stackalloc byte[8];

        if (data.Length > argument.Length)
        {
            return session.WriteAsync("504 Command not implemented for that parameter.\r\n"u8, token);
        }

        var length = (int)data.Length;
        data.CopyTo(argument);

        var code = char.ToUpperInvariant((char)argument[0]);

        // RFC 959 section 5.3.2: the type code is a single character, optionally followed by one
        // format/byte-size parameter. Anything else is a syntax error - "TYPE Ix" is not "TYPE I".
        var parameter = argument[1..length].Trim((byte)' ');

        switch (code)
        {
            case 'A' or 'E':
                // RFC 1123 section 4.1.2.2: a host with no Telnet-format distinction accepts "T"
                // as "N". Carriage control ("C") is a different representation and unimplemented.
                if (parameter.Length > 1 ||
                    (parameter.Length == 1 && parameter[0] is not ((byte)'N' or (byte)'n' or (byte)'T' or (byte)'t')))
                {
                    return session.WriteAsync("504 Command not implemented for that parameter.\r\n"u8, token);
                }

                if (code == 'E')
                {
                    return session.WriteAsync("504 Command not implemented for that parameter.\r\n"u8, token);
                }

                session.TransferType = FtpTransferType.Ascii;
                session.RestartOffset = 0;
                return session.WriteAsync("200 Type set to A.\r\n"u8, token);

            case 'I':
                if (parameter.Length > 0)
                {
                    return session.WriteAsync("501 Syntax error in parameters or arguments.\r\n"u8, token);
                }

                session.TransferType = FtpTransferType.Image;
                return session.WriteAsync("200 Type set to I.\r\n"u8, token);

            case 'L':
                if (parameter.Length != 1 || parameter[0] != (byte)'8')
                {
                    return session.WriteAsync("504 Command not implemented for that parameter.\r\n"u8, token);
                }

                session.TransferType = FtpTransferType.Image;
                return session.WriteAsync("200 Type set to L 8.\r\n"u8, token);

            default:
                return session.WriteAsync("501 Syntax error in parameters or arguments.\r\n"u8, token);
        }
    }

    public override ValueTask SetTransferModeAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        if (TryRejectAnonymous(session, FtpCommand.SetTransferMode, out var rejected))
        {
            return rejected;
        }

        // RFC 959 minimum implementation: only stream mode is required, and it is all we support.
        if (data.EqualsIgnoreCase("S"u8))
        {
            return session.WriteAsync("200 Mode set to S.\r\n"u8, token);
        }

        return data.EqualsIgnoreCase("B"u8) || data.EqualsIgnoreCase("C"u8)
            ? session.WriteAsync("504 Command not implemented for that parameter.\r\n"u8, token)
            : session.WriteAsync("501 Syntax error in parameters or arguments.\r\n"u8, token);
    }

    public override ValueTask FileTransferStructureAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        if (TryRejectAnonymous(session, FtpCommand.FileTransferStructure, out var rejected))
        {
            return rejected;
        }

        if (data.EqualsIgnoreCase("F"u8))
        {
            return session.WriteAsync("200 Structure set to F.\r\n"u8, token);
        }

        return data.EqualsIgnoreCase("R"u8) || data.EqualsIgnoreCase("P"u8)
            ? session.WriteAsync("504 Command not implemented for that parameter.\r\n"u8, token)
            : session.WriteAsync("501 Syntax error in parameters or arguments.\r\n"u8, token);
    }

    public override ValueTask AllocateDiskSpaceAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        if (TryRejectAnonymous(session, FtpCommand.AllocateDiskSpace, out var rejected))
        {
            return rejected;
        }

        // RFC 959: a server that needs no pre-allocation answers 202.
        return session.WriteAsync("202 No storage allocation necessary.\r\n"u8, token);
    }

    public override ValueTask RestartTransferAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        if (TryRejectAnonymous(session, FtpCommand.RestartTransfer, out var rejected))
        {
            return rejected;
        }

        if (!data.TryGetInt64(out var offset) || offset < 0)
        {
            return session.WriteAsync("501 Syntax error in parameters or arguments.\r\n"u8, token);
        }

        if (session.TransferType == FtpTransferType.Ascii && offset != 0)
        {
            // RFC 3659 section 5: a restart marker is only meaningful for a binary stream. This
            // is a permanent refusal of the parameter, not a transient local error.
            return session.WriteAsync("504 Restart not supported in ASCII mode.\r\n"u8, token);
        }

        session.RestartOffset = offset;
        return session.WriteAsync("350 Restarting at "u8, offset.ToString(), ". Send STORE or RETRIEVE.\r\n"u8, token);
    }

    public override ValueTask AbortAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        if (TryRejectAnonymous(session, FtpCommand.Abort, out var rejected))
        {
            return rejected;
        }

        // A transfer in flight is intercepted by the connection handler; reaching here means
        // there is nothing to abort, which RFC 959 answers with 226.
        return session.WriteAsync("226 No transfer in progress.\r\n"u8, token);
    }

    // ---- file transfers ---------------------------------------------------

    public override ValueTask RetrieveFileAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
        => TransferAsync(session, data, TransferDirection.Download, FileMode.Open, token);

    public override ValueTask StoreFileAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
        => TransferAsync(session, data, TransferDirection.Upload, FileMode.Create, token);

    public override ValueTask AppendAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
        => TransferAsync(session, data, TransferDirection.Upload, FileMode.Append, token);

    public override async ValueTask StoreFileUniquelyAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        if (TryRejectAnonymous(session, FtpCommand.StoreFileUniquely, out var rejected))
        {
            await rejected;
            return;
        }

        if (TryRejectReadOnly(session, out var readOnly))
        {
            await readOnly;
            return;
        }

        var directory = session.CurrentDirectory;

        if (!data.IsEmpty && !data.TryResolvePath(session.CurrentDirectory, session.Encoding, out directory))
        {
            await session.WriteAsync("550 Invalid path.\r\n"u8, token);
            return;
        }

        if (TryRejectReadOnlyPath(session, directory, out readOnly))
        {
            await readOnly;
            return;
        }

        // Checked before the 150, so a bad target is refused outright rather than mid-transfer.
        if (!session.FileSystem.DirectoryExists(directory))
        {
            await session.WriteAsync("550 Directory not found.\r\n"u8, token);
            return;
        }

        UPath path;
        var attempt = 0;

        do
        {
            // 12 hex digits of the GUID, not 12 characters of "ftp" + GUID.
            path = directory / ("ftp" + Guid.NewGuid().ToString("N")[..12]);
            attempt++;
        }
        while (session.FileSystem.FileExists(path) && attempt < 10);

        // RFC 959 requires the generated name to be reported in the 150 reply. It is written by
        // RunTransferAsync so that the cancellation source is published before any await - a
        // transfer the teardown path cannot see is one it cannot cancel.
        await RunTransferAsync(session, path, TransferDirection.Upload, FileMode.CreateNew, sendOpeningReply: true, token, $"150 FILE: {path.ToQuotedPath()}\r\n");
    }

    private enum TransferDirection
    {
        Download,
        Upload,
    }

    private async ValueTask TransferAsync(FtpSession session, ReadOnlySequence<byte> data, TransferDirection direction, FileMode mode, CancellationToken token)
    {
        var command = direction == TransferDirection.Download ? FtpCommand.RetrieveFile : FtpCommand.StoreFile;

        if (TryRejectAnonymous(session, command, out var rejected))
        {
            await rejected;
            return;
        }

        if (direction == TransferDirection.Upload && TryRejectReadOnly(session, out var readOnly))
        {
            await readOnly;
            return;
        }

        if (!TryResolve(session, data, out var path, out var reply))
        {
            await reply;
            return;
        }

        if (direction == TransferDirection.Upload && TryRejectReadOnlyPath(session, path, out readOnly))
        {
            await readOnly;
            return;
        }

        // Everything that can fail outright is checked before the 150, so the client never sees
        // the illegal "150 then 550" sequence.
        if (direction == TransferDirection.Download)
        {
            if (session.FileSystem.DirectoryExists(path))
            {
                await session.WriteAsync("550 Not a regular file.\r\n"u8, token);
                return;
            }

            if (!session.FileSystem.FileExists(path))
            {
                await session.WriteAsync("550 File not found.\r\n"u8, token);
                return;
            }
        }
        else
        {
            if (session.FileSystem.DirectoryExists(path))
            {
                await session.WriteAsync("550 Cannot overwrite a directory.\r\n"u8, token);
                return;
            }

            var parent = path.GetDirectory();

            if (!parent.IsNull && parent != UPath.Root && !session.FileSystem.DirectoryExists(parent))
            {
                await session.WriteAsync("550 Directory not found.\r\n"u8, token);
                return;
            }
        }

        await RunTransferAsync(session, path, direction, mode, sendOpeningReply: true, token);
    }

    private async ValueTask RunTransferAsync(
        FtpSession session,
        UPath path,
        TransferDirection direction,
        FileMode mode,
        bool sendOpeningReply,
        CancellationToken token,
        string? openingReply = null)
    {
        var offset = session.RestartOffset;
        session.RestartOffset = 0;
        var inactivity = options.Current.DataConnection.InactivityTimeout;

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(token);

        // Published before the first await: the connection handler's teardown reads this to
        // cancel an in-flight transfer, and a transfer it cannot see is one it cannot stop.
        session.TransferCancellation = cts;

        try
        {
            if (sendOpeningReply)
            {
                if (openingReply is null)
                {
                    await session.WriteAsync("150 Starting data transfer.\r\n"u8, token);
                }
                else
                {
                    await session.WriteAsync(openingReply, token);
                }
            }

            // Scoped so the data connection is fully closed - including the TLS close_notify -
            // before the completion reply is sent. In stream mode that close is the EOF marker.
            await using (var channel = await session.DataStreamProvider.CreateDataChannelAsync(session, cts.Token))
            {
                if (direction == TransferDirection.Download)
                {
                    await DownloadAsync(session, path, channel.Stream, offset, inactivity, cts.Token);
                }
                else
                {
                    await UploadAsync(session, path, channel.Stream, mode, offset, inactivity, cts.Token);
                }
            }

            await session.WriteAsync("226 Transfer complete.\r\n"u8, token);
        }
        catch (OperationCanceledException) when (cts.IsCancellationRequested && !token.IsCancellationRequested)
        {
            // ABOR: the connection handler sends the 226 that confirms the abort itself.
            await session.WriteAsync("426 Connection closed; transfer aborted.\r\n"u8, CancellationToken.None);
        }
        catch (FtpDataConnectionException ex)
        {
            await session.WriteAsync(ex.Reply + "\r\n", token);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Log.RequestException(logger, ex);
            await session.WriteAsync("451 Requested action aborted. Local error in processing.\r\n"u8, token);
        }
        finally
        {
            session.TransferCancellation = null;
        }
    }

    private static async ValueTask DownloadAsync(FtpSession session, UPath path, Stream destination, long offset, TimeSpan inactivity, CancellationToken token)
    {
        await using var source = session.FileSystem.OpenFile(path, FileMode.Open, FileAccess.Read, FileShare.Read);

        if (offset > 0)
        {
            if (offset > source.Length)
            {
                throw new FtpDataConnectionException("554 Requested action not taken: restart offset is past the end of the file.");
            }

            source.Seek(offset, SeekOrigin.Begin);
        }

        if (session.TransferType == FtpTransferType.Ascii)
        {
            await AsciiTransfer.ToNetworkAsync(source, destination, inactivity, token);
        }
        else
        {
            await CopyAsync(source, destination, inactivity, token);
        }

        await destination.FlushAsync(token);
    }

    /// <summary>
    /// Copies with an inactivity deadline on every read and write, so a peer that stops sending or
    /// reading is abandoned rather than holding the session open forever.
    /// </summary>
    internal static async ValueTask CopyAsync(Stream source, Stream destination, TimeSpan inactivity, CancellationToken token)
    {
        var buffer = ArrayPool<byte>.Shared.Rent(TransferBufferSize);
        using var deadline = new TransferDeadline(inactivity, token);

        try
        {
            while (true)
            {
                var read = await deadline.ReadAsync(source, buffer);

                if (read == 0)
                {
                    return;
                }

                await deadline.WriteAsync(destination, buffer.AsMemory(0, read));
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    /// <summary>
    /// A single write bounded by the inactivity deadline, for callers that write once rather than
    /// stream; a transfer uses <see cref="TransferDeadline"/>.
    /// </summary>
    /// <remarks>
    /// Writes need a deadline as much as reads do. Bounding only reads leaves a download
    /// unbounded: the source is a local file that never stalls, while the peer that has stopped
    /// reading blocks the write once its receive window closes. That is the direction a
    /// slow-read denial of service uses.
    /// </remarks>
    internal static async ValueTask WriteWithDeadlineAsync(Stream destination, ReadOnlyMemory<byte> buffer, TimeSpan inactivity, CancellationToken token)
    {
        if (inactivity <= TimeSpan.Zero)
        {
            await destination.WriteAsync(buffer, token);
            return;
        }

        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(inactivity);

        try
        {
            await destination.WriteAsync(buffer, deadline.Token);
        }
        catch (OperationCanceledException) when (!token.IsCancellationRequested)
        {
            throw new FtpDataConnectionException("426 Transfer stalled; closing the data connection.");
        }
    }

    private static async ValueTask UploadAsync(FtpSession session, UPath path, Stream source, FileMode mode, long offset, TimeSpan inactivity, CancellationToken token)
    {
        // A restart marker must not truncate: FileMode.Create zeroes the file at open, so the seek
        // would land at 0 and the resumed tail would overwrite the start.
        //
        // RFC 3659 section 5.3: an accepted marker makes APPE behave exactly as STOR would, so it
        // wins over the append.
        if (offset > 0 && mode is FileMode.Create or FileMode.Append)
        {
            mode = FileMode.OpenOrCreate;
        }

        await using var destination = session.FileSystem.OpenFile(path, mode, FileAccess.Write, FileShare.None);

        if (offset > 0)
        {
            if (offset > destination.Length)
            {
                throw new FtpDataConnectionException("554 Requested action not taken: restart offset is past the end of the file.");
            }

            destination.Seek(offset, SeekOrigin.Begin);
        }

        if (session.TransferType == FtpTransferType.Ascii)
        {
            await AsciiTransfer.FromNetworkAsync(source, destination, inactivity, token);
        }
        else
        {
            await CopyAsync(source, destination, inactivity, token);
        }

        await destination.FlushAsync(token);
    }

    // ---- metadata ---------------------------------------------------------

    public override async ValueTask FileSizeAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        if (TryRejectAnonymous(session, FtpCommand.FileSize, out var rejected))
        {
            await rejected;
            return;
        }

        if (!TryResolve(session, data, out var path, out var reply))
        {
            await reply;
            return;
        }

        if (!session.FileSystem.FileExists(path))
        {
            await session.WriteAsync("550 File not found.\r\n"u8, token);
            return;
        }

        var length = session.FileSystem.GetFileLength(path);

        // RFC 3659 section 4: SIZE reports the octets that would be transferred, which is not the
        // size on disk once line endings are translated. Counting them means reading the file.
        if (session.TransferType == FtpTransferType.Ascii)
        {
            try
            {
                length = await asciiSizeCache.GetAsync(session.FileSystem, path, length, token);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                await session.WriteAsync("550 Requested action not taken.\r\n"u8, token);
                return;
            }
        }

        await session.WriteAsync("213 "u8, length.ToString(), "\r\n"u8, token);
    }

    public override ValueTask LastModifiedTimeAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        if (TryRejectAnonymous(session, FtpCommand.LastModifiedTime, out var rejected))
        {
            return rejected;
        }

        if (!TryResolve(session, data, out var path, out var reply))
        {
            return reply;
        }

        // RFC 3659 section 3 defines MDTM over retrievable objects, and shows 550 for a directory.
        if (!session.FileSystem.FileExists(path))
        {
            return session.WriteAsync("550 File not found.\r\n"u8, token);
        }

        var timestamp = session.FileSystem.GetLastWriteTime(path);
        return session.WriteAsync("213 "u8, FtpListingFormatter.FormatTimestamp(timestamp), "\r\n"u8, token);
    }

    public override ValueTask ModifyLastModificationTimeAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        if (TryRejectAnonymous(session, FtpCommand.ModifyLastModificationTime, out var rejected))
        {
            return rejected;
        }

        if (TryRejectReadOnly(session, out var readOnly))
        {
            return readOnly;
        }

        // MFMT <time-val> SP <pathname>
        var text = data.GetString(session.Encoding);
        var space = text.IndexOf(' ');

        if (space < 0)
        {
            return session.WriteAsync("501 Syntax error in parameters or arguments.\r\n"u8, token);
        }

        if (!TryParseTimeVal(text[..space], out var timestamp))
        {
            return session.WriteAsync("501 Invalid time-val.\r\n"u8, token);
        }

        if (!Extensions.SequenceExtensions.TryResolvePath(text[(space + 1)..], session.CurrentDirectory, out var path))
        {
            return session.WriteAsync("550 Invalid path.\r\n"u8, token);
        }

        if (TryRejectReadOnlyPath(session, path, out readOnly))
        {
            return readOnly;
        }

        if (!session.FileSystem.FileExists(path) && !session.FileSystem.DirectoryExists(path))
        {
            return session.WriteAsync("550 File not found.\r\n"u8, token);
        }

        try
        {
            session.FileSystem.SetLastWriteTime(path, timestamp.UtcDateTime);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return session.WriteAsync("550 Requested action not taken.\r\n"u8, token);
        }

        return session.WriteAsync("213 Modify="u8, FtpListingFormatter.FormatTimestamp(timestamp) + "; " + path.FullName, "\r\n"u8, token);
    }

    private static bool TryParseTimeVal(string value, out DateTimeOffset timestamp)
    {
        timestamp = default;

        // RFC 3659 section 2.3: YYYYMMDDHHMMSS, optionally with a fractional part, always UTC.
        var dot = value.IndexOf('.');
        var whole = dot < 0 ? value : value[..dot];

        if (!DateTime.TryParseExact(whole, "yyyyMMddHHmmss", System.Globalization.CultureInfo.InvariantCulture,
                System.Globalization.DateTimeStyles.AssumeUniversal | System.Globalization.DateTimeStyles.AdjustToUniversal, out var parsed))
        {
            return false;
        }

        timestamp = new DateTimeOffset(parsed, TimeSpan.Zero);
        return true;
    }

    public override ValueTask ModifyCreationTimeAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
        => session.WriteAsync("502 Command not implemented.\r\n"u8, token);

    public override ValueTask ModifyFactAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
        => session.WriteAsync("502 Command not implemented.\r\n"u8, token);
}

/// <summary>
/// TYPE A translation. On the wire an ASCII transfer uses CRLF line endings regardless of what
/// the host file system uses (RFC 959 section 3.1.1.1).
/// </summary>
internal static class AsciiTransfer
{
    private const int BufferSize = 32768;

    public static async ValueTask ToNetworkAsync(Stream source, Stream destination, TimeSpan inactivity, CancellationToken token)
    {
        var read = ArrayPool<byte>.Shared.Rent(BufferSize);

        // Worst case is an all-LF or all-CR chunk, where every byte becomes two.
        var write = ArrayPool<byte>.Shared.Rent((BufferSize * 2) + 1);
        using var deadline = new TransferDeadline(inactivity, token);

        try
        {
            var pendingCr = false;
            int count;

            while ((count = await deadline.ReadAsync(source, read)) > 0)
            {
                var written = 0;

                for (var i = 0; i < count; i++)
                {
                    var b = read[i];
                    var afterCr = pendingCr;

                    if (afterCr)
                    {
                        pendingCr = false;

                        // NVT-ASCII has no bare CR: one that does not begin a CRLF travels as
                        // CR NUL (RFC 959 section 3.1.1.1, RFC 854).
                        if (b != (byte)'\n')
                        {
                            write[written++] = 0;
                        }
                    }

                    if (b == (byte)'\r')
                    {
                        pendingCr = true;
                        write[written++] = b;
                        continue;
                    }

                    // A LF of its own gains the CR the wire format needs.
                    if (b == (byte)'\n' && !afterCr)
                    {
                        write[written++] = (byte)'\r';
                    }

                    write[written++] = b;
                }

                await deadline.WriteAsync(destination, write.AsMemory(0, written));
            }

            if (pendingCr)
            {
                // The file ended on a CR, which still may not travel bare.
                await deadline.WriteAsync(destination, new byte[] { 0 });
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(read);
            ArrayPool<byte>.Shared.Return(write);
        }
    }

    /// <summary>
    /// Counts the octets <see cref="ToNetworkAsync"/> would put on the wire for this file.
    /// </summary>
    public static async ValueTask<long> MeasureAsync(Stream source, CancellationToken token)
    {
        var read = ArrayPool<byte>.Shared.Rent(BufferSize);

        try
        {
            var pendingCr = false;
            long total = 0;
            int count;

            while ((count = await source.ReadAsync(read, token)) > 0)
            {
                for (var i = 0; i < count; i++)
                {
                    var b = read[i];
                    var afterCr = pendingCr;

                    pendingCr = b == (byte)'\r';

                    // Each CR gains a NUL unless a LF follows, and each unpaired LF gains a CR.
                    if ((afterCr && b != (byte)'\n') || (!afterCr && b == (byte)'\n'))
                    {
                        total++;
                    }

                    total++;
                }
            }

            // A file ending on CR still needs its NUL.
            return pendingCr ? total + 1 : total;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(read);
        }
    }

    public static async ValueTask FromNetworkAsync(Stream source, Stream destination, TimeSpan inactivity, CancellationToken token)
    {
        // A line ending needs no translation where the host already stores CRLF; CR NUL does, on
        // every platform, the NUL being a wire escape rather than part of the file.
        var lineEndingIsCrLf = OperatingSystem.IsWindows();

        var read = ArrayPool<byte>.Shared.Rent(BufferSize);

        // Two bytes of headroom: a CR held over from the previous chunk, and the CRLF that writes
        // two bytes for the one byte that triggered it.
        var write = ArrayPool<byte>.Shared.Rent(BufferSize + 2);
        using var deadline = new TransferDeadline(inactivity, token);

        try
        {
            var pendingCr = false;
            int count;

            while ((count = await deadline.ReadAsync(source, read)) > 0)
            {
                var written = 0;

                for (var i = 0; i < count; i++)
                {
                    var b = read[i];

                    if (pendingCr)
                    {
                        pendingCr = false;

                        switch (b)
                        {
                            case (byte)'\n':
                                // CRLF: a line ending, stored in whatever form the host uses.
                                if (lineEndingIsCrLf)
                                {
                                    write[written++] = (byte)'\r';
                                }

                                write[written++] = (byte)'\n';
                                continue;

                            case 0:
                                // CR NUL: an escaped bare CR, so the NUL is dropped.
                                write[written++] = (byte)'\r';
                                continue;

                            default:
                                // The CR stood alone; keep it and handle the byte that followed.
                                write[written++] = (byte)'\r';
                                break;
                        }
                    }

                    if (b == (byte)'\r')
                    {
                        pendingCr = true;
                        continue;
                    }

                    write[written++] = b;
                }

                await destination.WriteAsync(write.AsMemory(0, written), token);
            }

            if (pendingCr)
            {
                await destination.WriteAsync(new byte[] { (byte)'\r' }, token);
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(read);
            ArrayPool<byte>.Shared.Return(write);
        }
    }
}

/// <summary>
/// The inactivity deadline of one transfer: every read and write must make progress within it.
/// </summary>
/// <remarks>
/// One timer re-armed per operation, where a linked token source per chunk would allocate a
/// source and a timer for every 80 KB moved.
/// </remarks>
internal sealed class TransferDeadline : IDisposable
{
    private readonly CancellationTokenSource? _deadline;
    private readonly TimeSpan _inactivity;
    private readonly CancellationToken _token;

    public TransferDeadline(TimeSpan inactivity, CancellationToken token)
    {
        _inactivity = inactivity;
        _token = token;

        if (inactivity > TimeSpan.Zero)
        {
            _deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        }
    }

    public async ValueTask<int> ReadAsync(Stream source, Memory<byte> buffer)
    {
        if (_deadline is null)
        {
            return await source.ReadAsync(buffer, _token);
        }

        _deadline.CancelAfter(_inactivity);

        try
        {
            return await source.ReadAsync(buffer, _deadline.Token);
        }
        catch (OperationCanceledException) when (!_token.IsCancellationRequested)
        {
            throw Stalled();
        }
    }

    public async ValueTask WriteAsync(Stream destination, ReadOnlyMemory<byte> buffer)
    {
        if (_deadline is null)
        {
            await destination.WriteAsync(buffer, _token);
            return;
        }

        _deadline.CancelAfter(_inactivity);

        try
        {
            await destination.WriteAsync(buffer, _deadline.Token);
        }
        catch (OperationCanceledException) when (!_token.IsCancellationRequested)
        {
            throw Stalled();
        }
    }

    private static FtpDataConnectionException Stalled() =>
        new("426 Transfer stalled; closing the data connection.");

    public void Dispose() => _deadline?.Dispose();
}
