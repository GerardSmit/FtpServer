using System.Buffers;
using System.Collections.Concurrent;
using System.Globalization;
using System.IO.Hashing;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Text;
using FtpServer.Data;
using FtpServer.Extensions;
using FtpServer.IO;
using FtpServer.Options;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Zio;

namespace FtpServer.Handlers;

public class DefaultFtpCommandHandler(
    PermissionProvider permissionProvider,
    PassivePortProvider passivePortProvider,
    IOptions<FtpOptions> options
) : FtpCommandHandler
{
    protected override ValueTask UnknownAsync(FtpSession session, FtpCommand command, ReadOnlySequence<byte> data, CancellationToken token)
    {
        return session.WriteAsync("502 Command not implemented.\r\n"u8);
    }

    public override ValueTask AbortAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        return base.AbortAsync(session, data, token);
    }

    public override ValueTask AccountInformationAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        return base.AccountInformationAsync(session, data, token);
    }

    public override ValueTask AuthenticationSecurityDataAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        return base.AuthenticationSecurityDataAsync(session, data, token);
    }

    public override ValueTask AllocateDiskSpaceAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        return base.AllocateDiskSpaceAsync(session, data, token);
    }

    public override ValueTask AppendAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        return base.AppendAsync(session, data, token);
    }

    public override ValueTask AuthenticationSecurityMechanismAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        // If we got here, the FtpConnectionHandler didn't handle the AUTH command.
        return session.WriteAsync("502 Command not implemented.\r\n"u8);
    }

    public override ValueTask GetAvailableSpaceAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        return base.GetAvailableSpaceAsync(session, data, token);
    }

    public override ValueTask ClearCommandChannelAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        return base.ClearCommandChannelAsync(session, data, token);
    }

    public override ValueTask ChangeToParentDirectoryAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        if (session.CurrentDirectory != UPath.Root)
        {
            session.CurrentDirectory = session.CurrentDirectory.GetDirectory();
        }

        return session.WriteAsync("200 Command okay.\r\n"u8);
    }

    public override ValueTask ConfidentialityProtectionAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        return base.ConfidentialityProtectionAsync(session, data, token);
    }

    public override ValueTask ClientServerIdentificationAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        return base.ClientServerIdentificationAsync(session, data, token);
    }

    public override ValueTask ChangeWorkingDirectoryAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        var path = data.GetUPath(session.CurrentDirectory, session.Encoding);

        if (!session.FileSystem.DirectoryExists(path))
        {
            return session.WriteAsync("550 Requested action not taken.\r\n"u8);
        }

        session.CurrentDirectory = path;
        return session.WriteAsync("250 Requested file action okay, completed.\r\n"u8);
    }

    public override ValueTask DeleteFileAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        return base.DeleteFileAsync(session, data, token);
    }

    public override ValueTask GetDirectorySizeAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        return base.GetDirectorySizeAsync(session, data, token);
    }

    public override ValueTask PrivacyProtectedChannelAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        return base.PrivacyProtectedChannelAsync(session, data, token);
    }

    public override ValueTask ExtendedPortAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        if (!data.TryGetExtendedPort(out var endPoint))
        {
            return session.WriteAsync("501 Syntax error in parameters or arguments.\r\n"u8);
        }

        session.ActiveDataIp = endPoint;
        return session.WriteAsync("200 Command okay.\r\n"u8);
    }

    public override ValueTask ExtendedPassiveModeAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        return StartPassiveModeAsync(
            session,
            async static (endPoint, token) => endPoint switch
            {
                IPEndPoint ipEndPoint => ipEndPoint.Address,
                DnsEndPoint dnsEndPoint => (await Dns.GetHostAddressesAsync(dnsEndPoint.Host, token)).FirstOrDefault(),
                _ => throw new InvalidOperationException("Invalid endpoint type."),
            },
            static (session, ip, port, token) => session.WriteExtendedPassiveModeAsync("227 Entering Extended Passive Mode ("u8, port, ")\r\n"u8, token),
            token);
    }

    public override async ValueTask FeatureListAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        var features = options.Value.Features;

        await session.WriteAsync("211-Features:\r\n"u8);

        await session.WriteAsync(" EPRT\r\n"u8);
        // await session.WriteAsync(" MLST type*;size*;modify*;\r\n"u8);

        if (options.Value.Ftps)
        {
            await session.WriteAsync(" AUTH TLS\r\n"u8);
        }

        if (features.XCRC)
        {
            await session.WriteAsync(" XCRC \"filename\" SP EP\r\n"u8);
        }

        await session.WriteAsync("211 End\r\n"u8);
    }

    public override ValueTask HelpAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        return base.HelpAsync(session, data, token);
    }

    public override ValueTask IdentifyVirtualHostAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        return base.IdentifyVirtualHostAsync(session, data, token);
    }

    public override ValueTask LanguageNegotiationAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        return base.LanguageNegotiationAsync(session, data, token);
    }

    public override async ValueTask ListInformationAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        await session.WriteAsync("150 Starting data transfer.\r\n"u8);

        await using var dataChannel = await session.DataStreamProvider.CreateDataChannelAsync(session, token);
        var stream = dataChannel.Stream;

        var sb = new StringBuilder();

        if (options.Value.Features.LISTR && (data.SequenceEquals("-R"u8) || data.SequenceEquals("-r"u8)))
        {
            var results = new ConcurrentDictionary<UPath, string>();
            var paths = session.FileSystem
                .EnumerateDirectories(session.CurrentDirectory, "*", SearchOption.AllDirectories)
                .ToArray();

            if (paths.Length > 0)
            {
                Parallel.For(
                    0,
                    paths.Length,
                    new ParallelOptions
                    {
                        CancellationToken = token,
                        MaxDegreeOfParallelism = Environment.ProcessorCount
                    },
                    () => new StringBuilder(),
                    (index, _, sb) =>
                    {
                        var path = paths[index];

                        sb.Append("\r\n.");
                        sb.Append(path.FullName);
                        sb.Append(":\r\n");
                        WriteDirectory(sb, session.FileSystem.EnumerateItems(path, SearchOption.TopDirectoryOnly));

                        results.TryAdd(path, sb.ToString());
                        sb.Clear();

                        return sb;
                    },
                    _ => { });
            }


            sb.Append("\r\n.");
            sb.Append(session.CurrentDirectory.FullName);
            sb.Append(":\r\n");
            WriteDirectory(sb, session.FileSystem.EnumerateItems(session.CurrentDirectory, SearchOption.TopDirectoryOnly));

            foreach (var path in paths)
            {
                if (results.TryGetValue(path, out var value))
                {
                    sb.Append(value);
                }
            }
        }
        else
        {
            WriteDirectory(sb, session.FileSystem.EnumerateItems(session.CurrentDirectory, SearchOption.TopDirectoryOnly));
        }

        var buffer = session.Encoding.GetBytes(sb.ToString());

        await stream.WriteAsync(buffer, token);
        await stream.FlushAsync(token);

        await session.WriteAsync("226 Transfer complete.\r\n"u8);
        return;

        void WriteDirectory(StringBuilder target, IEnumerable<FileSystemItem> items)
        {
            foreach (var item in items)
            {
                try
                {
                    target.Append(item.IsDirectory ? 'd' : '-');

                    string? path = null;

                    try
                    {
                        path = session.FileSystem.ConvertPathToInternal(item.Path);
                    }
                    catch
                    {
                        // Special directory by Zio, e.g. /mnt on Windows
                    }

                    var result = path != null
                        ? permissionProvider.GetFilePermissions(item, path)
                        : default;

                    target.Append(result.User.Read ? 'r' : '-');
                    target.Append(result.User.Write ? 'w' : '-');
                    target.Append(result.User.Execute ? 'x' : '-');

                    target.Append(result.Group.Read ? 'r' : '-');
                    target.Append(result.Group.Write ? 'w' : '-');
                    target.Append(result.Group.Execute ? 'x' : '-');

                    target.Append(result.Other.Read ? 'r' : '-');
                    target.Append(result.Other.Write ? 'w' : '-');
                    target.Append(result.Other.Execute ? 'x' : '-');

                    target.Append(" 0 ");

                    target.Append(result.OwnerName?.Replace(' ', '-') ?? "unknown");
                    target.Append(' ');
                    target.Append(result.GroupName?.Replace(' ', '-') ?? "unknown");

                    target.Append(' ');
                    target.Append(item.IsDirectory ? 0 : item.Length);
                    target.Append(' ');

                    var lastWriteTime = item.LastWriteTime.UtcDateTime;
                    target.Append(lastWriteTime.ToString("MMM dd HH:mm", CultureInfo.InvariantCulture));

                    target.Append(' ');

                    target.Append(item.GetName());
                    target.Append("\r\n");
                }
                catch
                {
                    // ignore
                }
            }
        }
    }

    private class Local
    {
        public UPath Path { get; set; }

        public StringBuilder StringBuilder { get; } = new();
    }

    public override ValueTask LongPortAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        return base.LongPortAsync(session, data, token);
    }

    public override ValueTask LongPassiveModeAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        return base.LongPassiveModeAsync(session, data, token);
    }

    public override ValueTask LastModifiedTimeAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        return base.LastModifiedTimeAsync(session, data, token);
    }

    public override ValueTask ModifyCreationTimeAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        return base.ModifyCreationTimeAsync(session, data, token);
    }

    public override ValueTask ModifyFactAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        return base.ModifyFactAsync(session, data, token);
    }

    public override ValueTask ModifyLastModificationTimeAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        return base.ModifyLastModificationTimeAsync(session, data, token);
    }

    public override ValueTask IntegrityProtectedCommandAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        return base.IntegrityProtectedCommandAsync(session, data, token);
    }

    public override ValueTask MakeDirectoryAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        return base.MakeDirectoryAsync(session, data, token);
    }

    public override ValueTask ListDirectoryContentsAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        return base.ListDirectoryContentsAsync(session, data, token);
    }

    public override ValueTask ListObjectDetailsAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        return base.ListObjectDetailsAsync(session, data, token);
    }

    public override ValueTask SetTransferModeAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        return base.SetTransferModeAsync(session, data, token);
    }

    public override ValueTask ListFileNamesAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        return base.ListFileNamesAsync(session, data, token);
    }

    public override ValueTask NoOperationAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        return base.NoOperationAsync(session, data, token);
    }

    public override ValueTask SelectFeatureOptionsAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        return base.SelectFeatureOptionsAsync(session, data, token);
    }

    public override ValueTask AuthenticationPasswordAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        // TODO: Implement authentication
        return session.WriteAsync("230 User logged in, proceed.\r\n"u8);
    }

    private async ValueTask StartPassiveModeAsync(
        FtpSession session,
        Func<EndPoint?, CancellationToken, ValueTask<IPAddress?>> getAddress,
        Func<FtpSession, IPAddress, int, CancellationToken, ValueTask> openPort,
        CancellationToken token)
    {
        var remoteEndPoint = await getAddress(session.RemoteEndPoint, token);
        var localEndPoint = await getAddress(session.LocalEndPoint, token);

        if (localEndPoint is null)
        {
            await session.WriteAsync("425 Can't open data connection.\r\n"u8);
            return;
        }

        if (!passivePortProvider.TryRent(remoteEndPoint, out var socketOwner))
        {
            await session.WriteAsync("425 Can't open data connection.\r\n"u8);
            return;
        }

        try
        {
            var port = await socketOwner.OpenPortAsync();

            await openPort(session, localEndPoint, port, token);

            var socket = await socketOwner.GetSocketAsync().WaitAsync(TimeSpan.FromSeconds(3), token);
            var stream = new NetworkStream(socket, ownsSocket: true);

            if (session.DataConnectionMode == FtpDataConnectionMode.Clear)
            {
                session.DataStreamProvider = new FtpDataStreamProviderPassive(stream, socket, socketOwner);
                return;
            }

            var sslStream = new SslStream(stream, leaveInnerStreamOpen: false);

            try
            {
                var certificateProvider = session.RootServiceProvider.GetRequiredService<CertificateProvider>();

                await sslStream.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
                {
                    ServerCertificate = certificateProvider.GetCertificate(),
                }, token);
            }
            catch
            {
                await sslStream.DisposeAsync();
                throw;
            }

            session.DataStreamProvider = new FtpDataStreamProviderPassive(sslStream, socket, socketOwner);
        }
        catch (TimeoutException)
        {
            await session.WriteAsync("425 Can't open data connection.\r\n"u8);
            socketOwner.Dispose();
        }
        catch
        {
            socketOwner.Dispose();
            throw;
        }
    }

    public override ValueTask PassiveModeAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        return StartPassiveModeAsync(
            session,
            async static (endPoint, token) =>
            {
                var result = endPoint switch
                {
                    IPEndPoint ipEndPoint => ipEndPoint.Address,
                    DnsEndPoint dnsEndPoint => (await Dns.GetHostAddressesAsync(dnsEndPoint.Host, token)).FirstOrDefault(i => i.AddressFamily == AddressFamily.InterNetwork),
                    _ => throw new InvalidOperationException("Invalid endpoint type."),
                };

                if (result is null)
                {
                    return null;
                }

                if (result.IsIPv4MappedToIPv6)
                {
                    result = result.MapToIPv4();
                }

                return result.AddressFamily == AddressFamily.InterNetwork ? result : null;
            },
            static (session, ip, port, token) => session.WritePassiveModeAsync("227 Entering Passive Mode "u8, ip, port >> 8, port & 0xFF, "\r\n"u8, token),
            token);
    }

    public override ValueTask ProtectionBufferSizeAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        if (!data.TryGetInt32(out var size))
        {
            return session.WriteAsync("501 Syntax error in parameters or arguments.\r\n"u8);
        }

        session.BufferSize = size;
        return session.WriteAsync("200 Command okay.\r\n"u8);
    }

    public override ValueTask PortAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        if (!data.TryGetDataPort(out var endPoint))
        {
            return session.WriteAsync("501 Syntax error in parameters or arguments.\r\n"u8);
        }

        session.ActiveDataIp = endPoint;
        return session.WriteAsync("200 Command okay.\r\n"u8);
    }

    public override ValueTask DataChannelProtectionAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        if (data.Length < 1)
        {
            return session.WriteAsync("501 Syntax error in parameters or arguments.\r\n"u8);
        }

        FtpDataConnectionMode? mode = (char)data.FirstSpan[0] switch
        {
            'C' or 'c' => FtpDataConnectionMode.Clear,
            'S' or 's' => FtpDataConnectionMode.Safe,
            'E' or 'e' => FtpDataConnectionMode.Confidential,
            'P' or 'p' => FtpDataConnectionMode.Private,
            _ => null
        };

        if (mode is null)
        {
            return session.WriteAsync("504 Command not implemented for that parameter.\r\n"u8);
        }

        session.DataConnectionMode = mode.Value;
        return session.WriteAsync("200 Command okay.\r\n"u8);
    }

    public override ValueTask PrintWorkingDirectoryAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        return session.WriteAsync("257 \""u8, session.CurrentDirectory.FullName, "\" is the current directory.\r\n"u8, token);
    }

    public override ValueTask DisconnectAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        // TODO: Implement disconnect
        return session.WriteAsync("221 Service closing control connection.\r\n"u8);
    }

    public override ValueTask ReinitializeConnectionAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        return base.ReinitializeConnectionAsync(session, data, token);
    }

    public override ValueTask RestartTransferAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        return base.RestartTransferAsync(session, data, token);
    }

    public override async ValueTask RetrieveFileAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        await session.WriteAsync("150 Starting data transfer.\r\n"u8);

        var path = data.GetUPath(session.CurrentDirectory, session.Encoding);
        var file = session.FileSystem.GetFileEntry(path);

        if (!file.Exists)
        {
            await session.WriteAsync("550 Requested action not taken.\r\n"u8);
            return;
        }

        await using var dataChannel = await session.DataStreamProvider.CreateDataChannelAsync(session, token);
        var stream = dataChannel.Stream;

        await using (var fileStream = file.Open(FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            await fileStream.CopyToAsync(stream, token);
        }

        await session.WriteAsync("226 Transfer complete.\r\n"u8);
    }

    public override ValueTask RemoveDirectoryAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        return base.RemoveDirectoryAsync(session, data, token);
    }

    public override ValueTask RemoveDirectoryTreeAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        return base.RemoveDirectoryTreeAsync(session, data, token);
    }

    public override ValueTask RenameFromAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        return base.RenameFromAsync(session, data, token);
    }

    public override ValueTask RenameToAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        return base.RenameToAsync(session, data, token);
    }

    public override ValueTask SiteSpecificCommandsAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        return base.SiteSpecificCommandsAsync(session, data, token);
    }

    public override ValueTask FileSizeAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        return base.FileSizeAsync(session, data, token);
    }

    public override ValueTask MountFileStructureAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        return base.MountFileStructureAsync(session, data, token);
    }

    public override ValueTask SinglePortPassiveModeAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        return base.SinglePortPassiveModeAsync(session, data, token);
    }

    public override ValueTask ServerStatusAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        return base.ServerStatusAsync(session, data, token);
    }

    public override async ValueTask StoreFileAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        await session.WriteAsync("150 Starting data transfer.\r\n"u8);

        var path = data.GetUPath(session.CurrentDirectory, session.Encoding);
        var file = session.FileSystem.GetFileEntry(path);

        await using var dataChannel = await session.DataStreamProvider.CreateDataChannelAsync(session, token);
        var stream = dataChannel.Stream;

        await using (var fileStream = file.Open(FileMode.Create, FileAccess.Write))
        {
            await stream.CopyToAsync(fileStream, token);
        }

        await session.WriteAsync("226 Transfer complete.\r\n"u8);
    }

    public override ValueTask StoreFileUniquelyAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        return base.StoreFileUniquelyAsync(session, data, token);
    }

    public override ValueTask FileTransferStructureAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        return base.FileTransferStructureAsync(session, data, token);
    }

    public override ValueTask SystemTypeAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        return base.SystemTypeAsync(session, data, token);
    }

    public override ValueTask GetThumbnailAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        return base.GetThumbnailAsync(session, data, token);
    }

    public override ValueTask SetTransferTypeAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        // TODO: Store the transfer type. Currently it's always binary.
        return session.WriteAsync("200 Command okay.\r\n"u8);
    }

    public override ValueTask AuthenticationUsernameAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        // TODO: Implement authentication
        return session.WriteAsync("331 User name okay, need password.\r\n"u8);
    }

    public override ValueTask ChangeToParentDirectoryExtendedAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        return base.ChangeToParentDirectoryExtendedAsync(session, data, token);
    }

    public override ValueTask MakeDirectoryExtendedAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        return base.MakeDirectoryExtendedAsync(session, data, token);
    }

    public override ValueTask PrintWorkingDirectoryExtendedAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        return base.PrintWorkingDirectoryExtendedAsync(session, data, token);
    }

    public override ValueTask XRemoteCopyAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        return base.XRemoteCopyAsync(session, data, token);
    }

    public override ValueTask RemoveDirectoryExtendedAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        return base.RemoveDirectoryExtendedAsync(session, data, token);
    }

    public override ValueTask XRemoteSearchQueryAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        return base.XRemoteSearchQueryAsync(session, data, token);
    }

    public override ValueTask SendOrMailAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        return base.SendOrMailAsync(session, data, token);
    }

    public override ValueTask SendToTerminalAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        return base.SendToTerminalAsync(session, data, token);
    }

    public override async ValueTask CalculateCrc32ChecksumAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        if (!options.Value.Features.XCRC)
        {
            await session.WriteAsync("502 Command not implemented.\r\n"u8);
            return;
        }

        if (!data.TryGetXCRC(session.CurrentDirectory, session.Encoding, out var request))
        {
            await session.WriteAsync("501 Syntax error in parameters or arguments.\r\n"u8);
            return;
        }

        var file = session.FileSystem.GetFileEntry(request.Path);

        if (!file.Exists)
        {
            await session.WriteAsync("550 Requested action not taken.\r\n"u8);
            return;
        }

        var crc32 = new Crc32();

        await using (var fileStream = file.Open(FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            if (request.Start is not null)
            {
                fileStream.Seek(request.Start.Value, SeekOrigin.Begin);
            }

            // Sync is faster than async for big files.
            // ReSharper disable once MethodHasAsyncOverloadWithCancellation
            crc32.Append(fileStream);
        }

        var pool = ArrayPool<byte>.Shared;
        var array = pool.Rent(crc32.HashLengthInBytes * 2);
        var length = WriteCrc32(array, crc32);

        await session.WriteAsync("250 "u8, array.AsSpan(0, length), "\r\n"u8);

        pool.Return(array);
        return;

        int WriteCrc32(Span<byte> dst, Crc32 crc32)
        {
            Span<byte> src = stackalloc byte[crc32.HashLengthInBytes];
            crc32.GetCurrentHash(src);

            src.Reverse();

            var i = 0;
            var j = 0;
            var b = src[i++];
            dst[j++] = ToCharUpper(b >> 4);
            dst[j++] = ToCharUpper(b);
            while (i < src.Length)
            {
                b = src[i++];
                dst[j++] = ToCharUpper(b >> 4);
                dst[j++] = ToCharUpper(b);
            }

            return j;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        static byte ToCharUpper(int value)
        {
            value = (value & 0xF) + '0';

            if (value > '9')
            {
                value += 'A' - ('9' + 1);
            }

            return (byte)value;
        }
    }
}
