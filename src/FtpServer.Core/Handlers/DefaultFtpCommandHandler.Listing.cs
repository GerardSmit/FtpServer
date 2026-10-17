using System.Buffers;
using System.Text;
using FtpServer.Extensions;
using FtpServer.IO;
using Zio;

namespace FtpServer.Handlers;

public partial class DefaultFtpCommandHandler
{
    /// <summary>Bytes buffered before the listing is pushed to the data connection.</summary>
    private const int ListingFlushThreshold = 16 * 1024;

    private enum ListingFormat
    {
        /// <summary>Unix "ls -l" long listing (LIST).</summary>
        Long,

        /// <summary>Bare names, one per line (NLST).</summary>
        Names,

        /// <summary>RFC 3659 fact lines (MLSD).</summary>
        Machine,
    }

    private readonly record struct ListingRequest(UPath Path, bool Recursive, bool IsFile);

    public override ValueTask ListInformationAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
        => ListAsync(session, data, ListingFormat.Long, token);

    public override ValueTask ListFileNamesAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
        => ListAsync(session, data, ListingFormat.Names, token);

    public override ValueTask ListDirectoryContentsAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
        => ListAsync(session, data, ListingFormat.Machine, token);

    private async ValueTask ListAsync(FtpSession session, ReadOnlySequence<byte> data, ListingFormat format, CancellationToken token)
    {
        if (TryRejectAnonymous(session, FtpCommand.ListInformation, out var rejected))
        {
            await rejected;
            return;
        }

        if (!TryParseListArgument(session, data, format, out var request))
        {
            await session.WriteAsync("550 Invalid path.\r\n"u8, token);
            return;
        }

        if (!request.IsFile && !session.FileSystem.DirectoryExists(request.Path))
        {
            await session.WriteAsync("550 Directory not found.\r\n"u8, token);
            return;
        }

        // With recursion switched off "-R" is one more presentation flag, like "-a".
        if (request.Recursive && !options.Current.Features.LISTR)
        {
            request = request with { Recursive = false };
        }

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(token);
        session.TransferCancellation = cts;

        try
        {
            await session.WriteAsync("150 Here comes the directory listing.\r\n"u8, token);

            await using (var channel = await session.DataStreamProvider.CreateDataChannelAsync(session, cts.Token))
            {
                await WriteListingAsync(session, channel.Stream, request, format, cts.Token);
            }

            await session.WriteAsync("226 Transfer complete.\r\n"u8, token);
        }
        catch (OperationCanceledException) when (cts.IsCancellationRequested && !token.IsCancellationRequested)
        {
            await session.WriteAsync("426 Connection closed; transfer aborted.\r\n"u8, CancellationToken.None);
        }
        catch (Data.FtpDataConnectionException ex)
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

    /// <summary>
    /// Splits a LIST/NLST argument into its ls-style flags and an optional pathname.
    /// </summary>
    /// <remarks>
    /// Clients send anything from nothing at all to "-al /pub". Ignoring the argument entirely
    /// would silently list the wrong directory.
    /// </remarks>
    private static bool TryParseListArgument(FtpSession session, ReadOnlySequence<byte> data, ListingFormat format, out ListingRequest request)
    {
        request = new ListingRequest(session.CurrentDirectory, Recursive: false, IsFile: false);

        var text = data.GetString(session.Encoding).Trim();

        if (text.Length == 0)
        {
            return true;
        }

        var recursive = false;
        string? pathText = null;

        // MLSD takes a pathname and nothing else (RFC 3659 section 7), so "MLSD -foo" lists the
        // directory "-foo". A quoted argument is a pathname in its entirety too.
        if (format == ListingFormat.Machine || (text.Length >= 2 && text[0] == '"' && text[^1] == '"'))
        {
            pathText = text;
        }
        else
        {
            var remainder = new List<string>();

            foreach (var token in text.Split(' ', StringSplitOptions.RemoveEmptyEntries))
            {
                if (token.Length > 1 && token[0] == '-')
                {
                    if (token.Contains('R') || token.Contains('r'))
                    {
                        recursive = true;
                    }

                    // Every other ls flag (-a, -l, -t, ...) affects presentation only.
                    continue;
                }

                remainder.Add(token);
            }

            if (remainder.Count > 0)
            {
                pathText = string.Join(' ', remainder);
            }
        }

        // MLSD takes a pathname, never ls flags.
        recursive = format == ListingFormat.Long && recursive;

        var path = session.CurrentDirectory;

        if (pathText is not null && !SequenceExtensions.TryResolvePath(pathText, session.CurrentDirectory, out path))
        {
            return false;
        }

        // "LIST somefile" is legal and lists just that entry.
        var isFile = format != ListingFormat.Machine && session.FileSystem.FileExists(path);

        request = new ListingRequest(path, recursive, isFile);
        return true;
    }

    private async ValueTask WriteListingAsync(FtpSession session, Stream stream, ListingRequest request, ListingFormat format, CancellationToken token)
    {
        var builder = new StringBuilder();
        var now = DateTimeOffset.UtcNow;
        var remaining = options.Current.List.MaxEntries;
        var inactivity = options.Current.DataConnection.InactivityTimeout;
        var truncated = false;

        if (request.IsFile)
        {
            AppendEntry(builder, ToItem(session, request.Path, isDirectory: false), format, now);
            await FlushAsync(session, stream, builder, inactivity, token, force: true);
            return;
        }

        // RFC 3659 section 7.2: MLSD begins with the directory itself and its parent. Sections
        // 7.5.1.2 and 7.5.1.4 identify those entries by their type fact; without it, section
        // 7.3.1 forbids a bare "." or "..".
        if (format == ListingFormat.Machine && session.EnabledFacts.HasFlag(MlsxFacts.Type))
        {
            AppendMachineSpecial(builder, session, request.Path, "cdir");

            if (request.Path != UPath.Root)
            {
                AppendMachineSpecial(builder, session, request.Path.GetDirectory(), "pdir");
            }
        }

        await WriteDirectoryAsync(request.Path, depth: 0);

        // Only the human-readable listing can carry a notice. In NLST it would parse as a
        // filename, and RFC 3659 section 7.2 forbids extra lines in MLSD output entirely.
        if (truncated && format == ListingFormat.Long)
        {
            builder.Append("Listing truncated: too many entries.\r\n");
        }

        await FlushAsync(session, stream, builder, inactivity, token, force: true);

        if (truncated)
        {
            Log.ListingTruncated(logger, request.Path.FullName, options.Current.List.MaxEntries);
        }

        return;

        async ValueTask WriteDirectoryAsync(UPath directory, int depth)
        {
            token.ThrowIfCancellationRequested();

            if (request.Recursive && depth > 0)
            {
                // ls -R separates each block with a blank line and a "path:" header.
                builder.Append("\r\n").Append(FtpListingFormatter.SanitiseName(directory.FullName)).Append(":\r\n");
            }

            var subdirectories = request.Recursive ? new List<UPath>() : null;

            foreach (var item in EnumerateSafely(session, directory))
            {
                if (remaining-- <= 0)
                {
                    truncated = true;
                    return;
                }

                AppendEntry(builder, item, format, now);

                if (subdirectories is not null && item.IsDirectory)
                {
                    subdirectories.Add(item.Path);
                }

                if (builder.Length >= ListingFlushThreshold)
                {
                    await FlushAsync(session, stream, builder, inactivity, token);
                }
            }

            if (subdirectories is null || depth + 1 >= options.Current.List.RecursionLimit)
            {
                return;
            }

            foreach (var subdirectory in subdirectories)
            {
                await WriteDirectoryAsync(subdirectory, depth + 1);

                if (truncated)
                {
                    return;
                }
            }
        }

        void AppendEntry(StringBuilder target, FileSystemItem item, ListingFormat entryFormat, DateTimeOffset reference)
        {
            switch (entryFormat)
            {
                case ListingFormat.Names:
                    // RFC 1123 section 4.1.2.7: every name must be usable as-is by a later
                    // transfer command, which a bare basename is only for the working directory.
                    target
                        .Append(FtpListingFormatter.SanitiseName(
                            request.Path == session.CurrentDirectory ? item.GetName() : item.Path.FullName))
                        .Append("\r\n");
                    break;

                case ListingFormat.Machine:
                    listingFormatter.AppendMachineListing(target, session.FileSystem, item, session.CanWrite, session.EnabledFacts);
                    break;

                default:
                    listingFormatter.AppendLongListing(target, session.FileSystem, item, reference);
                    break;
            }
        }
    }

    private void AppendMachineSpecial(StringBuilder builder, FtpSession session, UPath path, string type)
    {
        try
        {
            listingFormatter.AppendMachineListing(builder, session.FileSystem, ToItem(session, path, isDirectory: true), session.CanWrite, session.EnabledFacts, type);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // A missing parent is not worth failing the whole listing over.
        }
    }

    /// <summary>
    /// Enumerates a directory, skipping entries that disappear or cannot be read.
    /// </summary>
    /// <remarks>
    /// Filtering here rather than inside the formatter keeps a failing entry from leaving a
    /// half-written line behind.
    /// </remarks>
    private static IEnumerable<FileSystemItem> EnumerateSafely(FtpSession session, UPath directory)
    {
        IEnumerator<FileSystemItem> enumerator;

        try
        {
            enumerator = session.FileSystem.EnumerateItems(directory, SearchOption.TopDirectoryOnly).GetEnumerator();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            yield break;
        }

        using (enumerator)
        {
            while (true)
            {
                FileSystemItem item;

                try
                {
                    if (!enumerator.MoveNext())
                    {
                        break;
                    }

                    item = enumerator.Current;
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    break;
                }

                yield return item;
            }
        }
    }

    private static async ValueTask FlushAsync(FtpSession session, Stream stream, StringBuilder builder, TimeSpan inactivity, CancellationToken token, bool force = false)
    {
        if (builder.Length == 0 && !force)
        {
            return;
        }

        var text = builder.ToString();
        builder.Clear();

        if (text.Length == 0)
        {
            return;
        }

        var buffer = ArrayPool<byte>.Shared.Rent(session.Encoding.GetMaxByteCount(text.Length));

        try
        {
            var length = session.Encoding.GetBytes(text, buffer);

            // Bounded like a file transfer: a client that stops reading the listing must not be
            // able to pin the session open.
            await WriteWithDeadlineAsync(stream, buffer.AsMemory(0, length), inactivity, token);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    // ---- MLST -------------------------------------------------------------

    public override async ValueTask ListObjectDetailsAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        if (TryRejectAnonymous(session, FtpCommand.ListObjectDetails, out var rejected))
        {
            await rejected;
            return;
        }

        var path = session.CurrentDirectory;

        if (!data.IsEmpty && !data.TryResolvePath(session.CurrentDirectory, session.Encoding, out path))
        {
            await session.WriteAsync("550 Invalid path.\r\n"u8, token);
            return;
        }

        var isDirectory = session.FileSystem.DirectoryExists(path);

        if (!isDirectory && !session.FileSystem.FileExists(path))
        {
            await session.WriteAsync("550 File not found.\r\n"u8, token);
            return;
        }

        var builder = new StringBuilder();

        // RFC 3659 section 7.3.1: with TVFS advertised the entry names the requested path, not
        // just the base name, so a client can match the reply to what it asked about.
        listingFormatter.AppendMachineListing(
            builder,
            session.FileSystem,
            ToItem(session, path, isDirectory),
            session.CanWrite,
            session.EnabledFacts,
            nameOverride: path.FullName);

        // RFC 3659 section 7.2: the single fact line is sent as a continuation line of a 250
        // reply, indented by one space.
        var entry = builder.ToString().TrimEnd('\r', '\n');

        await session.WriteAsync($"250-Listing {path.FullName}\r\n {entry}\r\n250 End\r\n", token);
    }

    // ---- STAT -------------------------------------------------------------

    public override async ValueTask ServerStatusAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        if (data.IsEmpty)
        {
            // RFC 959 section 4.1.3: STAT with no argument reports the connection's state, and
            // may be sent while a transfer is running.
            var status = new List<string>
            {
                $"Connected to {Describe(session.RemoteEndPoint)}",
                session.IsAuthenticated ? $"Logged in as {session.User?.Name}" : "Not logged in",
                $"TYPE: {(session.TransferType == FtpTransferType.Ascii ? "ASCII" : "BINARY")}, STRUcture: File, transfer MODE: Stream",
                session.IsProtected ? "TLS: control connection is protected" : "TLS: control connection is in the clear",
                session.TransferCancellation is not null ? "Status: transfer in progress" : "Status: idle",
            };

            if (session.VirtualHost is { } virtualHost)
            {
                status.Insert(1, $"Virtual host: {virtualHost}");
            }

            await session.WriteMultilineAsync("211", status, "End of status", token);
            return;
        }

        if (TryRejectAnonymous(session, FtpCommand.ServerStatus, out var rejected))
        {
            await rejected;
            return;
        }

        if (!TryParseListArgument(session, data, ListingFormat.Long, out var request))
        {
            await session.WriteAsync("550 Invalid path.\r\n"u8, token);
            return;
        }

        if (!request.IsFile && !session.FileSystem.DirectoryExists(request.Path))
        {
            await session.WriteAsync("550 File not found.\r\n"u8, token);
            return;
        }

        // STAT <path> returns the listing over the control connection, no data connection needed.
        var builder = new StringBuilder();
        var now = DateTimeOffset.UtcNow;

        if (request.IsFile)
        {
            listingFormatter.AppendLongListing(builder, session.FileSystem, ToItem(session, request.Path, isDirectory: false), now);
        }
        else
        {
            var remaining = options.Current.List.MaxEntries;

            foreach (var item in EnumerateSafely(session, request.Path))
            {
                if (remaining-- <= 0)
                {
                    break;
                }

                listingFormatter.AppendLongListing(builder, session.FileSystem, item, now);
            }
        }

        // RFC 959 section 4.2: 212 is directory status, 213 is file status.
        var code = request.IsFile ? "213" : "212";
        var lines = builder.ToString().Split("\r\n", StringSplitOptions.RemoveEmptyEntries);

        await session.WriteMultilineAsync(code, lines, "End of status", token);
    }

    private static string Describe(System.Net.EndPoint? endPoint) => endPoint?.ToString() ?? "unknown";

    /// <summary>
    /// Builds an entry for a single path. <see cref="FileSystemItem"/>'s constructor only records
    /// the path, so the metadata a listing needs has to be fetched explicitly - otherwise every
    /// single-entry listing reports size 0 and a default timestamp.
    /// </summary>
    private static FileSystemItem ToItem(FtpSession session, UPath path, bool isDirectory)
    {
        var fileSystem = session.FileSystem;

        var item = new FileSystemItem(fileSystem, path, isDirectory)
        {
            Attributes = fileSystem.GetAttributes(path),
            CreationTime = fileSystem.GetCreationTime(path),
            LastAccessTime = fileSystem.GetLastAccessTime(path),
            LastWriteTime = fileSystem.GetLastWriteTime(path),
        };

        if (!isDirectory)
        {
            item.Length = fileSystem.GetFileLength(path);
        }

        return item;
    }
}
