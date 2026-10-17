using System.Buffers;
using FtpServer.Authentication;
using FtpServer.Data;
using FtpServer.Extensions;
using FtpServer.IO;
using FtpServer.Options;
using Microsoft.Extensions.Logging;
using Zio;

namespace FtpServer.Handlers;

public partial class DefaultFtpCommandHandler(
    FtpListingFormatter listingFormatter,
    PassivePortProvider passivePortProvider,
    IFtpAuthenticator authenticator,
    FtpSessionProvider sessionProvider,
    AsciiSizeCache asciiSizeCache,
    FtpOptionsProvider options,
    ILogger<DefaultFtpCommandHandler> logger
) : FtpCommandHandler
{
    /// <summary>
    /// Commands a client may issue before logging in (RFC 959 section 5.4, RFC 2228 section 3,
    /// RFC 7151 section 3.1).
    /// </summary>
    private static bool IsAllowedBeforeLogin(FtpCommand command) => command is
        FtpCommand.AuthenticationUsername or
        FtpCommand.AuthenticationPassword or
        FtpCommand.AccountInformation or
        FtpCommand.AuthenticationSecurityMechanism or
        FtpCommand.AuthenticationSecurityData or
        FtpCommand.ProtectionBufferSize or
        FtpCommand.DataChannelProtection or
        FtpCommand.IdentifyVirtualHost or
        FtpCommand.FeatureList or
        FtpCommand.SelectFeatureOptions or
        FtpCommand.LanguageNegotiation or
        FtpCommand.ClientName or
        FtpCommand.NoOperation or
        FtpCommand.Help or
        FtpCommand.Disconnect or
        FtpCommand.ReinitializeConnection;

    protected override ValueTask UnknownAsync(FtpSession session, FtpCommand command, ReadOnlySequence<byte> data, CancellationToken token)
    {
        // Debug, not warning: a client probing for optional commands is routine, and logging it
        // at warning level lets a peer fill the log at will.
        Log.UnhandledCommand(logger, command.ToCommand());

        return session.WriteAsync("502 Command not implemented.\r\n"u8, token);
    }

    /// <summary>
    /// Rejects a command that requires a login. Returns <c>true</c> when the caller should stop.
    /// </summary>
    private static bool TryRejectAnonymous(FtpSession session, FtpCommand command, out ValueTask reply)
    {
        if (session.IsAuthenticated || IsAllowedBeforeLogin(command))
        {
            reply = ValueTask.CompletedTask;
            return false;
        }

        reply = session.WriteAsync("530 Not logged in.\r\n"u8);
        return true;
    }

    private static bool TryRejectReadOnly(FtpSession session, out ValueTask reply)
    {
        if (session.CanWrite)
        {
            reply = ValueTask.CompletedTask;
            return false;
        }

        reply = session.WriteAsync("550 Permission denied: the server is read-only.\r\n"u8);
        return true;
    }

    /// <summary>
    /// Rejects a command that would modify a path inside a read-only virtual folder. Checked once
    /// the pathname is known, where <see cref="TryRejectReadOnly"/> only knows about the session.
    /// </summary>
    private static bool TryRejectReadOnlyPath(FtpSession session, UPath path, out ValueTask reply)
    {
        if (session.CanWriteTo(path))
        {
            reply = ValueTask.CompletedTask;
            return false;
        }

        reply = session.WriteAsync("550 Permission denied: this folder is read-only.\r\n"u8);
        return true;
    }

    /// <summary>
    /// Resolves a client pathname, or writes the 5xx reply and returns <c>false</c>.
    /// </summary>
    private static bool TryResolve(FtpSession session, ReadOnlySequence<byte> data, out UPath path, out ValueTask reply)
    {
        if (data.IsEmpty)
        {
            path = default;
            reply = session.WriteAsync("501 Syntax error in parameters or arguments.\r\n"u8);
            return false;
        }

        if (!data.TryResolvePath(session.CurrentDirectory, session.Encoding, out path))
        {
            reply = session.WriteAsync("550 Invalid path.\r\n"u8);
            return false;
        }

        reply = ValueTask.CompletedTask;
        return true;
    }

    // ---- authentication ---------------------------------------------------

    public override async ValueTask AuthenticationUsernameAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        if (data.IsEmpty)
        {
            await session.WriteAsync("501 Syntax error in parameters or arguments.\r\n"u8, token);
            return;
        }

        if (options.Current.RequireTls && !session.IsProtected)
        {
            await session.WriteAsync("534 Request denied for policy reasons: use AUTH TLS first.\r\n"u8, token);
            return;
        }

        // A second USER restarts the login sequence (RFC 959 section 5.4). Releasing the data
        // provider first matters: the reset returns it to Active, and a port rented by an earlier
        // PASV would otherwise be left registered with nobody able to claim or free it.
        if (session.IsAuthenticated)
        {
            await session.DataStreamProvider.ReleaseAsync();
            session.ResetForNewUser();

            // The previous login may have been narrowed to a home directory, which the next one
            // must not inherit - including when the next user has no home of their own.
            session.ReplaceFileSystem(sessionProvider.CreateFileSystem());
            session.IsReadOnly = options.Current.ReadOnly;
        }

        var userName = data.GetString(session.Encoding);
        var result = await authenticator.AuthenticateUserAsync(userName, session.RemoteEndPoint, token);

        switch (result.Status)
        {
            case FtpAuthenticationStatus.Success when result.User is { } user:
                CompleteLogin(session, user);
                await session.WriteAsync("230 User logged in, proceed.\r\n"u8, token);
                return;

            case FtpAuthenticationStatus.TooManyAttempts:
                // 421 means the control connection is being closed, so it has to actually close.
                session.CloseRequested = true;
                await session.WriteAsync("421 Too many failed login attempts.\r\n"u8, token);
                return;

            case FtpAuthenticationStatus.Failed:
                await session.WriteAsync("530 Not logged in.\r\n"u8, token);
                return;

            default:
                session.PendingUserName = userName;
                await session.WriteAsync("331 User name okay, need password.\r\n"u8, token);
                return;
        }
    }

    public override async ValueTask AuthenticationPasswordAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        if (session.PendingUserName is not { } userName)
        {
            // RFC 959: PASS must be preceded by USER.
            await session.WriteAsync("503 Bad sequence of commands.\r\n"u8, token);
            return;
        }

        var password = data.GetString(session.Encoding);
        var result = await authenticator.AuthenticatePasswordAsync(userName, password, session.RemoteEndPoint, token);

        switch (result.Status)
        {
            case FtpAuthenticationStatus.Success when result.User is { } user:
                CompleteLogin(session, user);
                await session.WriteAsync("230 User logged in, proceed.\r\n"u8, token);
                return;

            case FtpAuthenticationStatus.TooManyAttempts:
                // 421 means the control connection is being closed, so it has to actually close.
                session.CloseRequested = true;
                await session.WriteAsync("421 Too many failed login attempts.\r\n"u8, token);
                return;

            default:
                session.PendingUserName = null;
                await session.WriteAsync("530 Not logged in.\r\n"u8, token);
                return;
        }
    }

    private void CompleteLogin(FtpSession session, FtpUser user)
    {
        session.SignIn(user);
        sessionProvider.ApplyUser(session, user);
    }

    public override ValueTask AccountInformationAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
        // No account concept: RFC 959 defines 202 for a command that is not needed at this site.
        => session.WriteAsync("202 Command not implemented, superfluous at this site.\r\n"u8, token);

    public override async ValueTask ReinitializeConnectionAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        await session.DataStreamProvider.ReleaseAsync();

        var wasProtected = session.IsProtected;
        session.ResetForReinitialize();

        // Restores the server-wide root that a per-user home may have replaced.
        session.ReplaceFileSystem(sessionProvider.CreateFileSystem());
        session.IsReadOnly = options.Current.ReadOnly;

        // RFC 4217 section 13: the reply goes out inside the TLS session, and the session is
        // cleared afterwards. The connection handler owns the transport, so it performs the
        // teardown once this reply has been written.
        await session.WriteAsync("220 Service ready for new user.\r\n"u8, token);

        session.ClearProtectionRequested = wasProtected;
    }

    public override ValueTask DisconnectAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
        // The connection handler closes the control connection once this reply has been sent.
        => session.WriteAsync("221 Service closing control connection.\r\n"u8, token);

    // ---- RFC 2228 security ------------------------------------------------

    public override ValueTask AuthenticationSecurityMechanismAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        // Reached only when FTPS is disabled; the connection handler performs the upgrade itself.
        if (!options.Current.Ftps)
        {
            return session.WriteAsync("534 Request denied for policy reasons: TLS is not enabled.\r\n"u8, token);
        }

        return session.WriteAsync("503 Bad sequence of commands: already authenticated.\r\n"u8, token);
    }

    public override ValueTask AuthenticationSecurityDataAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
        // TLS needs no ADAT exchange; RFC 2228 defines 503 when no AUTH is in progress.
        => session.WriteAsync("503 Bad sequence of commands.\r\n"u8, token);

    public override ValueTask ProtectionBufferSizeAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        if (!session.IsProtected)
        {
            return session.WriteAsync("503 Bad sequence of commands: use AUTH first.\r\n"u8, token);
        }

        if (!data.TryGetInt32(out var size))
        {
            return session.WriteAsync("501 Syntax error in parameters or arguments.\r\n"u8, token);
        }

        // RFC 4217 section 9: with TLS the buffer size is meaningless, so the server accepts
        // whatever the client offers and answers with the value it will actually use.
        session.BufferSize = 0;
        session.ProtectionBufferNegotiated = true;

        _ = size;
        return session.WriteAsync("200 PBSZ=0\r\n"u8, token);
    }

    public override ValueTask DataChannelProtectionAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        if (!session.ProtectionBufferNegotiated)
        {
            // RFC 2228 section 3: PROT must be preceded by PBSZ.
            return session.WriteAsync("503 Bad sequence of commands: use PBSZ first.\r\n"u8, token);
        }

        if (data.Length != 1)
        {
            return session.WriteAsync("501 Syntax error in parameters or arguments.\r\n"u8, token);
        }

        Span<byte> level = stackalloc byte[1];
        data.CopyTo(level);

        switch ((char)level[0])
        {
            case 'C' or 'c':
                session.DataConnectionMode = FtpDataConnectionMode.Clear;
                return session.WriteAsync("200 Protection level set to C.\r\n"u8, token);

            case 'P' or 'p':
                session.DataConnectionMode = FtpDataConnectionMode.Private;
                return session.WriteAsync("200 Protection level set to P.\r\n"u8, token);

            case 'S' or 's' or 'E' or 'e':
                // TLS provides only C and P (RFC 4217 section 9). RFC 2228 assigns 536 to
                // "requested PROT level not supported by mechanism"; 521 is not in its reply set.
                return session.WriteAsync("536 Requested PROT level not supported by mechanism.\r\n"u8, token);

            default:
                return session.WriteAsync("504 Command not implemented for that parameter.\r\n"u8, token);
        }
    }

    public override ValueTask ClearCommandChannelAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
        // Dropping back to cleartext would expose the rest of the session; refuse by policy.
        => session.WriteAsync("534 Request denied for policy reasons.\r\n"u8, token);

    public override ValueTask IntegrityProtectedCommandAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
        => session.WriteAsync("502 Command not implemented.\r\n"u8, token);

    public override ValueTask ConfidentialityProtectionAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
        => session.WriteAsync("502 Command not implemented.\r\n"u8, token);

    public override ValueTask PrivacyProtectedChannelAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
        => session.WriteAsync("502 Command not implemented.\r\n"u8, token);

    // ---- navigation -------------------------------------------------------

    public override ValueTask ChangeWorkingDirectoryAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        if (TryRejectAnonymous(session, FtpCommand.ChangeWorkingDirectory, out var rejected))
        {
            return rejected;
        }

        if (!TryResolve(session, data, out var path, out var reply))
        {
            return reply;
        }

        if (!session.FileSystem.DirectoryExists(path))
        {
            return session.WriteAsync("550 Failed to change directory.\r\n"u8, token);
        }

        session.CurrentDirectory = path;
        return session.WriteAsync("250 Requested file action okay, completed.\r\n"u8, token);
    }

    public override ValueTask ChangeToParentDirectoryAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        if (TryRejectAnonymous(session, FtpCommand.ChangeToParentDirectory, out var rejected))
        {
            return rejected;
        }

        if (session.CurrentDirectory != UPath.Root)
        {
            session.CurrentDirectory = session.CurrentDirectory.GetDirectory();
        }

        return session.WriteAsync("250 Requested file action okay, completed.\r\n"u8, token);
    }

    public override ValueTask ChangeToParentDirectoryExtendedAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
        => ChangeToParentDirectoryAsync(session, data, token);

    public override ValueTask ChangeWorkingDirectoryExtendedAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
        => ChangeWorkingDirectoryAsync(session, data, token);

    public override ValueTask PrintWorkingDirectoryAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        if (TryRejectAnonymous(session, FtpCommand.PrintWorkingDirectory, out var rejected))
        {
            return rejected;
        }

        return session.WriteAsync("257 \""u8, session.CurrentDirectory.ToQuotedPath(), "\" is the current directory.\r\n"u8, token);
    }

    public override ValueTask PrintWorkingDirectoryExtendedAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
        => PrintWorkingDirectoryAsync(session, data, token);

    public override ValueTask MakeDirectoryAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        if (TryRejectAnonymous(session, FtpCommand.MakeDirectory, out var rejected))
        {
            return rejected;
        }

        if (TryRejectReadOnly(session, out var readOnly))
        {
            return readOnly;
        }

        if (!TryResolve(session, data, out var path, out var reply))
        {
            return reply;
        }

        if (TryRejectReadOnlyPath(session, path, out readOnly))
        {
            return readOnly;
        }

        if (path == UPath.Root || session.FileSystem.DirectoryExists(path) || session.FileSystem.FileExists(path))
        {
            return session.WriteAsync("550 Requested action not taken: the path already exists.\r\n"u8, token);
        }

        try
        {
            session.FileSystem.CreateDirectory(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return session.WriteAsync("550 Requested action not taken.\r\n"u8, token);
        }

        return session.WriteAsync("257 \""u8, path.ToQuotedPath(), "\" created.\r\n"u8, token);
    }

    public override ValueTask MakeDirectoryExtendedAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
        => MakeDirectoryAsync(session, data, token);

    public override ValueTask RemoveDirectoryAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
        => RemoveDirectoryCoreAsync(session, data, recursive: false, token);

    public override ValueTask RemoveDirectoryExtendedAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
        => RemoveDirectoryCoreAsync(session, data, recursive: false, token);

    public override ValueTask RemoveDirectoryTreeAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
        => RemoveDirectoryCoreAsync(session, data, recursive: true, token);

    private ValueTask RemoveDirectoryCoreAsync(FtpSession session, ReadOnlySequence<byte> data, bool recursive, CancellationToken token)
    {
        if (TryRejectAnonymous(session, FtpCommand.RemoveDirectory, out var rejected))
        {
            return rejected;
        }

        if (TryRejectReadOnly(session, out var readOnly))
        {
            return readOnly;
        }

        if (!TryResolve(session, data, out var path, out var reply))
        {
            return reply;
        }

        if (TryRejectReadOnlyPath(session, path, out readOnly))
        {
            return readOnly;
        }

        if (path == UPath.Root)
        {
            return session.WriteAsync("550 Requested action not taken: cannot remove the root directory.\r\n"u8, token);
        }

        if (!session.FileSystem.DirectoryExists(path))
        {
            return session.WriteAsync("550 Directory not found.\r\n"u8, token);
        }

        try
        {
            session.FileSystem.DeleteDirectory(path, recursive);
        }
        catch (IOException)
        {
            return session.WriteAsync("550 Requested action not taken: the directory is not empty or is in use.\r\n"u8, token);
        }
        catch (UnauthorizedAccessException)
        {
            return session.WriteAsync("550 Permission denied.\r\n"u8, token);
        }

        // If the client deleted the directory it was standing in, move it somewhere valid.
        if (session.CurrentDirectory == path || session.CurrentDirectory.IsInDirectory(path, recursive: true))
        {
            session.CurrentDirectory = path.GetDirectory();
        }

        return session.WriteAsync("250 Requested file action okay, completed.\r\n"u8, token);
    }

    public override ValueTask DeleteFileAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        if (TryRejectAnonymous(session, FtpCommand.DeleteFile, out var rejected))
        {
            return rejected;
        }

        if (TryRejectReadOnly(session, out var readOnly))
        {
            return readOnly;
        }

        if (!TryResolve(session, data, out var path, out var reply))
        {
            return reply;
        }

        if (TryRejectReadOnlyPath(session, path, out readOnly))
        {
            return readOnly;
        }

        if (!session.FileSystem.FileExists(path))
        {
            return session.WriteAsync("550 File not found.\r\n"u8, token);
        }

        try
        {
            session.FileSystem.DeleteFile(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return session.WriteAsync("550 Requested action not taken.\r\n"u8, token);
        }

        return session.WriteAsync("250 Requested file action okay, completed.\r\n"u8, token);
    }

    public override ValueTask RenameFromAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        if (TryRejectAnonymous(session, FtpCommand.RenameFrom, out var rejected))
        {
            return rejected;
        }

        if (TryRejectReadOnly(session, out var readOnly))
        {
            return readOnly;
        }

        if (!TryResolve(session, data, out var path, out var reply))
        {
            return reply;
        }

        if (TryRejectReadOnlyPath(session, path, out readOnly))
        {
            return readOnly;
        }

        if (!session.FileSystem.FileExists(path) && !session.FileSystem.DirectoryExists(path))
        {
            return session.WriteAsync("550 File not found.\r\n"u8, token);
        }

        session.RenameFrom = path;
        return session.WriteAsync("350 Requested file action pending further information.\r\n"u8, token);
    }

    public override ValueTask RenameToAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
    {
        if (TryRejectAnonymous(session, FtpCommand.RenameTo, out var rejected))
        {
            return rejected;
        }

        if (TryRejectReadOnly(session, out var readOnly))
        {
            return readOnly;
        }

        if (session.RenameFrom is not { } source)
        {
            return session.WriteAsync("503 Bad sequence of commands: use RNFR first.\r\n"u8, token);
        }

        // The marker is consumed whatever the outcome, so a failed RNTO cannot be retried blind.
        session.RenameFrom = null;

        if (!TryResolve(session, data, out var destination, out var reply))
        {
            return reply;
        }

        // Both ends, because a rename removes the source as surely as it creates the destination.
        if (TryRejectReadOnlyPath(session, destination, out readOnly) ||
            TryRejectReadOnlyPath(session, source, out readOnly))
        {
            return readOnly;
        }

        if (session.FileSystem.FileExists(destination) || session.FileSystem.DirectoryExists(destination))
        {
            return session.WriteAsync("553 Requested action not taken: the destination already exists.\r\n"u8, token);
        }

        try
        {
            if (session.FileSystem.DirectoryExists(source))
            {
                session.FileSystem.MoveDirectory(source, destination);
            }
            else
            {
                session.FileSystem.MoveFile(source, destination);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return session.WriteAsync("550 Requested action not taken.\r\n"u8, token);
        }

        return session.WriteAsync("250 Requested file action okay, completed.\r\n"u8, token);
    }

    public override ValueTask MountFileStructureAsync(FtpSession session, ReadOnlySequence<byte> data, CancellationToken token)
        // A single mounted tree per session; RFC 959 allows 502 for SMNT.
        => session.WriteAsync("502 Command not implemented.\r\n"u8, token);
}
