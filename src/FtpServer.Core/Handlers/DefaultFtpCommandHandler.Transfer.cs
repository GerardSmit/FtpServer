using System.Buffers;
using System.IO.Compression;
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

        // RFC 959 requires only stream mode. Block and compressed modes are not implemented; the
        // deflate extension (MODE Z) is, when enabled.
        if (data.EqualsIgnoreCase("S"u8))
        {
            session.TransferMode = FtpTransferMode.Stream;
            return session.WriteAsync("200 Mode set to S.\r\n"u8, token);
        }

        if (data.EqualsIgnoreCase("Z"u8) && options.Current.Features.ModeZ)
        {
            session.TransferMode = FtpTransferMode.Deflate;
            return session.WriteAsync("200 Mode set to Z.\r\n"u8, token);
        }

        if (data.EqualsIgnoreCase("Z"u8))
        {
            return session.WriteAsync("504 Command not implemented for that parameter.\r\n"u8, token);
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

        // Accepted whatever the current TYPE: RFC 3659 section 5 defines REST for stream mode, and
        // the type that matters is the one in force at RETR/STOR, which may still change. Refusing
        // here also broke resume detection in clients that probe with "REST 1" right after login,
        // while the session is still in the default TYPE A (Indy's TIdFTP, Beyond Compare).
        // A nonzero marker that is still in TYPE A at transfer time is refused there with 554.
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
        // Before the 150, and before the restart marker is consumed: the client can fix its
        // protection level and repeat the command.
        if (TryRejectClearData(session, out var clearData))
        {
            await clearData;
            return;
        }

        var offset = session.RestartOffset;
        session.RestartOffset = 0;
        var inactivity = options.Current.DataConnection.InactivityTimeout;
        var maxUploadSize = options.Current.DataConnection.MaxUploadSize;

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(token);

        // Published before the first await: the connection handler's teardown reads this to
        // cancel an in-flight transfer, and a transfer it cannot see is one it cannot stop.
        session.TransferCancellation = cts;

        try
        {
            // Checked before the 150, so a refused marker is never the illegal "150 then 554".
            if (offset > 0 && !TryValidateRestart(session, path, direction, offset, out var refusal))
            {
                await session.WriteAsync(refusal, token);
                return;
            }

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
                    await UseDataStreamAsync(session, channel.Stream, sending: true,
                        stream => DownloadAsync(session, path, stream, offset, inactivity, cts.Token));
                }
                else
                {
                    await UseDataStreamAsync(session, channel.Stream, sending: false,
                        stream => UploadAsync(session, path, stream, mode, offset, inactivity, maxUploadSize, cts.Token));
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
        catch (InvalidDataException ex)
        {
            // MODE Z upload whose compressed stream does not decode.
            Log.RequestException(logger, ex);
            await session.WriteAsync("451 Requested action aborted: the compressed data is invalid.\r\n"u8, token);
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

    /// <summary>
    /// Decides whether a restart marker can be honoured by the transfer it precedes.
    /// </summary>
    /// <remarks>
    /// In TYPE A the marker would count octets of the translated stream, which do not map onto
    /// file offsets without reading the file up to that point; a resume only makes sense in
    /// TYPE I. RFC 959 reserves 554 for exactly this: "invalid REST parameter".
    /// </remarks>
    private static bool TryValidateRestart(FtpSession session, UPath path, TransferDirection direction, long offset, out string refusal)
    {
        refusal = string.Empty;

        if (session.TransferType == FtpTransferType.Ascii)
        {
            refusal = "554 Requested action not taken: restart is only supported in TYPE I.\r\n";
            return false;
        }

        long length;

        try
        {
            // A file that does not exist yet has nothing to resume, so any marker is past its end.
            length = session.FileSystem.FileExists(path) ? session.FileSystem.GetFileLength(path) : 0;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Let the transfer itself report what is wrong with the file.
            return true;
        }

        if (offset > length)
        {
            refusal = "554 Requested action not taken: restart offset is past the end of the file.\r\n";
            return false;
        }

        return true;
    }

    /// <summary>
    /// Runs <paramref name="transfer"/> over the data connection, through zlib when MODE Z is in
    /// effect: compressing what the server sends, decompressing what it receives.
    /// </summary>
    internal static async ValueTask UseDataStreamAsync(FtpSession session, Stream connection, bool sending, Func<Stream, ValueTask> transfer)
    {
        if (session.TransferMode != FtpTransferMode.Deflate)
        {
            await transfer(connection);
            return;
        }

        var zlib = sending
            ? new ZLibStream(connection, new ZLibCompressionOptions { CompressionLevel = session.DeflateLevel }, leaveOpen: true)
            : new ZLibStream(connection, CompressionMode.Decompress, leaveOpen: true);

        try
        {
            await transfer(zlib);

            // Disposing writes the final deflate block, which is part of the transfer: it has to
            // reach the client before the data connection closes.
            await zlib.DisposeAsync();
        }
        finally
        {
            try
            {
                // A no-op after the dispose above. After a failure, the attempt to finish the
                // stream may itself fail on the broken connection; that must not hide why.
                zlib.Dispose();
            }
            catch (Exception ex) when (ex is IOException or ObjectDisposedException or OperationCanceledException)
            {
            }
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

    private static async ValueTask UploadAsync(FtpSession session, UPath path, Stream source, FileMode mode, long offset, TimeSpan inactivity, long? maxSize, CancellationToken token)
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

        // Counted on what reaches the file, so MODE Z cannot expand past it and TYPE A's line
        // ending translation is taken into account. The limit is on the size of the file the
        // upload leaves behind, so an APPE or a resumed upload only gets what room is left.
        Stream target = maxSize is { } limit
            ? new CappedWriteStream(destination, Math.Max(0, limit - destination.Position))
            : destination;

        try
        {
            if (session.TransferType == FtpTransferType.Ascii)
            {
                await AsciiTransfer.FromNetworkAsync(source, target, inactivity, token);
            }
            else
            {
                await CopyAsync(source, target, inactivity, token);
            }

            await destination.FlushAsync(token);
        }
        finally
        {
            // OpenOrCreate keeps whatever followed the marker, so a resumed upload shorter than
            // the old file would leave stale bytes after its end. Cut at what was written, also
            // when the transfer is interrupted: the next SIZE then reports the valid prefix, which
            // is what the client resumes from.
            if (offset > 0)
            {
                destination.SetLength(destination.Position);
            }
        }
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
            // Not a file by that name: perhaps the pre-MFMT "MDTM <time> <path>" that sets the time,
            // which some clients still send. A file whose name really begins with a timestamp was
            // matched above, so reading always wins over writing.
            return TrySetModifyTimeLegacy(session, data, token, out var setReply)
                ? setReply
                : session.WriteAsync("550 File not found.\r\n"u8, token);
        }

        var timestamp = session.FileSystem.GetLastWriteTime(path);
        return session.WriteAsync("213 "u8, FtpListingFormatter.FormatTimestamp(timestamp), "\r\n"u8, token);
    }

    /// <summary>
    /// Handles <c>MDTM YYYYMMDDHHMMSS[+-TZ] &lt;path&gt;</c>, the form servers used to set a
    /// timestamp before MFMT existed. The optional suffix is the client's offset from UTC in
    /// minutes (Serv-U); without it the time is UTC.
    /// </summary>
    /// <returns>False when the argument is not in that form, leaving the caller's 550 to stand.</returns>
    private static bool TrySetModifyTimeLegacy(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token, out ValueTask reply)
    {
        reply = ValueTask.CompletedTask;

        var text = data.GetString(session.Encoding);
        var space = text.IndexOf(' ');

        if (space < 0 || !TryParseZonedTimeVal(text[..space], out var timestamp))
        {
            return false;
        }

        if (TryPrepareMetadataChange(session, text[(space + 1)..], out var path, out reply))
        {
            reply = SetTimesAsync(session, path, timestamp, creation: null, token);
        }

        return true;
    }

    /// <summary>A time-val optionally followed by the client's offset from UTC in minutes.</summary>
    private static bool TryParseZonedTimeVal(string value, out DateTimeOffset timestamp)
    {
        timestamp = default;

        // The sign can only follow the 14 digits, which also keeps it clear of a fraction.
        var sign = value.Length > 14 ? value.IndexOfAny(['+', '-'], 14) : -1;

        if (sign < 0)
        {
            return TryParseTimeVal(value, out timestamp);
        }

        if (!TryParseTimeVal(value[..sign], out var local) ||
            !int.TryParse(value.AsSpan(sign + 1), System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var minutes) ||
            minutes > 24 * 60)
        {
            return false;
        }

        // The digits are the client's local time; taking its offset away gives UTC.
        timestamp = local - TimeSpan.FromMinutes(value[sign] == '-' ? -minutes : minutes);
        return true;
    }

    /// <summary>
    /// The checks shared by every command that changes an object's metadata: a writable session,
    /// a valid path outside any read-only folder, and an object that exists.
    /// </summary>
    private static bool TryPrepareMetadataChange(FtpSession session, string pathText, out UPath path, out ValueTask reply)
    {
        path = default;

        if (TryRejectReadOnly(session, out reply))
        {
            return false;
        }

        if (!Extensions.SequenceExtensions.TryResolvePath(pathText, session.CurrentDirectory, out path))
        {
            reply = session.WriteAsync("550 Invalid path.\r\n"u8);
            return false;
        }

        if (TryRejectReadOnlyPath(session, path, out reply))
        {
            return false;
        }

        if (!session.FileSystem.FileExists(path) && !session.FileSystem.DirectoryExists(path))
        {
            reply = session.WriteAsync("550 File not found.\r\n"u8);
            return false;
        }

        reply = ValueTask.CompletedTask;
        return true;
    }

    /// <summary>Sets the time given and replies in the draft-somers-ftp-mfxx form.</summary>
    private static ValueTask SetTimesAsync(FtpSession session, UPath path, DateTimeOffset? modify, DateTimeOffset? creation, CancellationToken token)
    {
        try
        {
            if (modify is { } m)
            {
                session.FileSystem.SetLastWriteTime(path, m.UtcDateTime);
            }

            if (creation is { } c)
            {
                session.FileSystem.SetCreationTime(path, c.UtcDateTime);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or PlatformNotSupportedException)
        {
            return session.WriteAsync("550 Requested action not taken.\r\n"u8, token);
        }

        var fact = modify is { } modified
            ? "Modify=" + FtpListingFormatter.FormatTimestamp(modified)
            : "Create=" + FtpListingFormatter.FormatTimestamp(creation!.Value);

        return session.WriteAsync("213 "u8, fact + "; " + path.FullName, "\r\n"u8, token);
    }

    public override ValueTask ModifyLastModificationTimeAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        if (TryRejectAnonymous(session, FtpCommand.ModifyLastModificationTime, out var rejected))
        {
            return rejected;
        }

        return SetTimeCommandAsync(session, data, creation: false, token);
    }

    /// <summary>MFMT and MFCT: <c>&lt;time-val&gt; SP &lt;pathname&gt;</c> (draft-somers-ftp-mfxx).</summary>
    private static ValueTask SetTimeCommandAsync(FtpSession session, ReadOnlySequence<byte> data, bool creation, CancellationToken token)
    {
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

        if (!TryPrepareMetadataChange(session, text[(space + 1)..], out var path, out var reply))
        {
            return reply;
        }

        return creation
            ? SetTimesAsync(session, path, modify: null, timestamp, token)
            : SetTimesAsync(session, path, timestamp, creation: null, token);
    }

    /// <summary>
    /// Whether the host can set a creation time. Linux has no call that writes a birth time, so
    /// MFCT and the MFF create fact are not offered there.
    /// </summary>
    internal static bool CanSetCreationTime => OperatingSystem.IsWindows() || OperatingSystem.IsMacOS();

    /// <summary>Whether the MFF UNIX.mode fact can be applied: only where there are Unix mode bits.</summary>
    internal static bool CanSetUnixMode => !OperatingSystem.IsWindows();

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
    {
        if (TryRejectAnonymous(session, FtpCommand.ModifyCreationTime, out var rejected))
        {
            return rejected;
        }

        if (!CanSetCreationTime)
        {
            return session.WriteAsync("502 Command not implemented: this platform cannot set a creation time.\r\n"u8, token);
        }

        return SetTimeCommandAsync(session, data, creation: true, token);
    }

    /// <summary>
    /// MFF <c>&lt;fact&gt;=&lt;value&gt;;... SP &lt;pathname&gt;</c> (draft-somers-ftp-mfxx section 3.3).
    /// </summary>
    /// <remarks>
    /// All or nothing: every fact is validated before any is applied, and one the server cannot
    /// change refuses the whole command with 504. The reply echoes the facts that were set.
    /// </remarks>
    public override ValueTask ModifyFactAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        if (TryRejectAnonymous(session, FtpCommand.ModifyFact, out var rejected))
        {
            return rejected;
        }

        var text = data.GetString(session.Encoding);
        var space = text.IndexOf(' ');

        if (space <= 0)
        {
            return session.WriteAsync("501 Syntax error in parameters or arguments.\r\n"u8, token);
        }

        DateTimeOffset? modify = null;
        DateTimeOffset? create = null;
        int? mode = null;
        string? modeFact = null;
        var applied = new List<string>();

        foreach (var fact in text[..space].Split(';', StringSplitOptions.RemoveEmptyEntries))
        {
            var equals = fact.IndexOf('=');

            if (equals <= 0)
            {
                return session.WriteAsync("501 Syntax error in parameters or arguments.\r\n"u8, token);
            }

            var name = fact[..equals];
            var value = fact[(equals + 1)..];

            switch (name.ToLowerInvariant())
            {
                case "modify":
                    if (!TryParseTimeVal(value, out var modified))
                    {
                        return session.WriteAsync("501 Invalid value for fact "u8, name, ".\r\n"u8, token);
                    }

                    modify = modified;
                    applied.Add(name + "=" + FtpListingFormatter.FormatTimestamp(modified));
                    break;

                case "create" when CanSetCreationTime:
                    if (!TryParseTimeVal(value, out var created))
                    {
                        return session.WriteAsync("501 Invalid value for fact "u8, name, ".\r\n"u8, token);
                    }

                    create = created;
                    applied.Add(name + "=" + FtpListingFormatter.FormatTimestamp(created));
                    break;

                case "unix.mode" when CanSetUnixMode:
                    // Up to four octal digits, leading zeros allowed, but only the permission bits.
                    var digits = value.TrimStart('0');

                    if (value.Length > 5 || digits.Length > 4 ||
                        !TryParseOctal(digits.Length == 0 ? "0" : digits, out var bits) ||
                        bits > MaxPermissionBits)
                    {
                        return session.WriteAsync("501 Invalid value for fact "u8, name, ".\r\n"u8, token);
                    }

                    mode = bits;
                    modeFact = name;
                    applied.Add(name + "=" + value);
                    break;

                default:
                    return session.WriteAsync("504 Fact "u8, name, " cannot be modified.\r\n"u8, token);
            }
        }

        if (applied.Count == 0)
        {
            return session.WriteAsync("501 Syntax error in parameters or arguments.\r\n"u8, token);
        }

        if (!TryPrepareMetadataChange(session, text[(space + 1)..], out var path, out var reply))
        {
            return reply;
        }

        // Refused before anything is applied, because MFF is all or nothing.
        if (modeFact is not null && path == UPath.Root)
        {
            return session.WriteAsync("550 Requested action not taken: the mode of the root directory cannot be changed.\r\n"u8, token);
        }

        // A remote tree has no host path to set the mode on.
        if (modeFact is not null && !FtpFileSystemCapabilities.HasHostPath(session.FileSystem, path))
        {
            return session.WriteAsync("504 Fact "u8, modeFact, " cannot be modified.\r\n"u8, token);
        }

        try
        {
            if (modify is { } m)
            {
                session.FileSystem.SetLastWriteTime(path, m.UtcDateTime);
            }

            if (create is { } c)
            {
                session.FileSystem.SetCreationTime(path, c.UtcDateTime);
            }

            if (mode is { } unixMode && !OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(session.FileSystem.ConvertPathToInternal(path), (UnixFileMode)unixMode);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or PlatformNotSupportedException)
        {
            return session.WriteAsync("550 Requested action not taken.\r\n"u8, token);
        }

        return session.WriteAsync("213 "u8, string.Join(';', applied) + "; " + path.FullName, "\r\n"u8, token);
    }

    /// <summary>
    /// The MFF facts this host can change in the session's tree, as FEAT lists them. A remote
    /// tree has no mode bits to change.
    /// </summary>
    internal static string ModifiableFacts(FtpSession session) =>
        "modify;" +
        (CanSetCreationTime ? "create;" : string.Empty) +
        (CanSetUnixMode && FtpFileSystemCapabilities.HasHostPath(session.FileSystem, UPath.Root) ? "UNIX.mode;" : string.Empty);
}

/// <summary>
/// Passes writes through to a file until <c>remaining</c> bytes have been written, and refuses the
/// write that would go past it with the 552 an over-sized upload is answered with.
/// </summary>
/// <remarks>
/// Refuses before writing rather than cutting the chunk, so the file never exceeds the limit and
/// nothing is written that is about to be reported as aborted.
/// </remarks>
internal sealed class CappedWriteStream(Stream inner, long remaining) : Stream
{
    private long _remaining = remaining;

    public override bool CanRead => false;

    public override bool CanSeek => false;

    public override bool CanWrite => true;

    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    private void Reserve(int count)
    {
        if (count > _remaining)
        {
            throw new FtpDataConnectionException("552 Requested file action aborted. Exceeded storage allocation.");
        }

        _remaining -= count;
    }

    public override void Write(byte[] buffer, int offset, int count)
    {
        Reserve(count);
        inner.Write(buffer, offset, count);
    }

    public override void Write(ReadOnlySpan<byte> buffer)
    {
        Reserve(buffer.Length);
        inner.Write(buffer);
    }

    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        Reserve(buffer.Length);
        return inner.WriteAsync(buffer, cancellationToken);
    }

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        Reserve(count);
        return inner.WriteAsync(buffer, offset, count, cancellationToken);
    }

    public override void Flush() => inner.Flush();

    public override Task FlushAsync(CancellationToken cancellationToken) => inner.FlushAsync(cancellationToken);

    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();
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
