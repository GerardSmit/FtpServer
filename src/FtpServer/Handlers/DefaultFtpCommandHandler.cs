using System.Buffers;
using System.Globalization;
using System.Text;
using FtpServer.Extensions;
using FtpServer.IO;
using Zio;

namespace FtpServer;

public class DefaultFtpCommandHandler(
    PermissionProvider permissionProvider
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
        return base.ChangeToParentDirectoryAsync(session, data, token);
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
        var directory = session.FileSystem.GetDirectoryEntry(path);

        if (!directory.Exists)
        {
            return session.WriteAsync("550 Requested action not taken.\r\n"u8);
        }

        session.CurrentDirectory = directory.Path;
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
        return base.ExtendedPortAsync(session, data, token);
    }

    public override ValueTask ExtendedPassiveModeAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        return base.ExtendedPassiveModeAsync(session, data, token);
    }

    public override ValueTask FeatureListAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        return base.FeatureListAsync(session, data, token);
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
        await using var dataChannel = await session.Mode.CreateDataChannelAsync(session, token);
        var stream = dataChannel.Stream;

        var items = session.FileSystem.EnumerateItems(session.CurrentDirectory, SearchOption.TopDirectoryOnly);

        var sb = new StringBuilder();

        foreach (var item in items)
        {
            sb.Append(item.IsDirectory ? 'd' : '-');

            var path = session.FileSystem.ConvertPathToInternal(item.Path);

            var result = permissionProvider.GetFilePermissions(item, path);

            sb.Append(result.User.Read ? 'r' : '-');
            sb.Append(result.User.Write ? 'w' : '-');
            sb.Append(result.User.Execute ? 'x' : '-');

            sb.Append(result.Group.Read ? 'r' : '-');
            sb.Append(result.Group.Write ? 'w' : '-');
            sb.Append(result.Group.Execute ? 'x' : '-');

            sb.Append(result.Other.Read ? 'r' : '-');
            sb.Append(result.Other.Write ? 'w' : '-');
            sb.Append(result.Other.Execute ? 'x' : '-');

            sb.Append(" 0 ");

            sb.Append(result.OwnerName ?? "unknown");
            sb.Append(' ');
            sb.Append(result.GroupName ?? "unknown");

            sb.Append(' ');
            sb.Append(item.IsDirectory ? 0 : item.Length);
            sb.Append(' ');

            var lastWriteTime = item.LastWriteTime.UtcDateTime;
            sb.Append(lastWriteTime.ToString("MMM dd HH:mm", CultureInfo.InvariantCulture));

            sb.Append(' ');

            sb.Append(item.GetName());
            sb.Append("\r\n");
        }

        var buffer = session.Encoding.GetBytes(sb.ToString());

        await stream.WriteAsync(buffer, token);
        await stream.FlushAsync(token);

        await session.WriteAsync("226 Transfer complete.\r\n"u8);
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

    public override ValueTask PassiveModeAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        return base.PassiveModeAsync(session, data, token);
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
        var path = data.GetUPath(session.CurrentDirectory, session.Encoding);
        var file = session.FileSystem.GetFileEntry(path);

        if (!file.Exists)
        {
            await session.WriteAsync("550 Requested action not taken.\r\n"u8);
            return;
        }

        await using var dataChannel = await session.Mode.CreateDataChannelAsync(session, token);
        var stream = dataChannel.Stream;

        await using (var fileStream = file.Open(FileMode.Open, FileAccess.Read))
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
        var path = data.GetUPath(session.CurrentDirectory, session.Encoding);
        var file = session.FileSystem.GetFileEntry(path);

        await using var dataChannel = await session.Mode.CreateDataChannelAsync(session, token);
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
}
